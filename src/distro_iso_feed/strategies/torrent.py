"""Torrent handling: parse a `.torrent`, resolve a torrent-only variant, attach a co-located one.

The second concern split out of the old `_common.py`. `torrents.py` (top-level) holds the bencode
primitives; this is the strategy-level handling that turns them into a `Release` or enriches one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from urllib.parse import urljoin

from .. import checksums, torrents
from ..client import Client
from ..models import Release
from ..tokens import from_filename
from .build import build_release
from .integrity import _expand, fetch_sums


@dataclass(frozen=True, slots=True)
class TorrentRef:
    """A `.torrent` that was fetched, parsed, and asked what it serves."""

    url: str
    data: bytes  # kept so its hash can be checked without fetching twice
    info_hash: str
    magnet: str
    payload_name: str  # `info.name` -- the artifact filename
    payload_size: int | None

    @property
    def size(self) -> int:
        """Bytes of the `.torrent` file itself, not of the payload it serves."""
        return len(self.data)

    def verified_by(self, algo: str | None, expected: str | None) -> bool:
        """Do these bytes hash to the checksum the upstream signed?

        A torrent's piece hashes prove the payload matches *that torrent file*. They
        say nothing about whether the torrent file is the project's -- a tampered one
        is perfectly self-consistent, and every client reports success. Only a signed
        hash of the torrent itself breaks that circle.
        """
        if not algo or not expected:
            return False
        return hashlib.new(algo, self.data).hexdigest() == expected.lower()


def fetch_torrent(client: Client, *, url: str) -> TorrentRef | None:
    """Fetch and parse a `.torrent`. None when it is not one.

    A variant without a torrent is normal, not an error -- so this returns None
    rather than raising, like every other resolver path.

    Nothing is downloaded or seeded here; a `.torrent` is a small metadata file.
    """
    response = client.get(url)
    if not response or not response.content:
        return None

    data = response.content
    try:
        return TorrentRef(
            url=url,
            data=data,
            info_hash=torrents.info_hash(data),
            magnet=torrents.magnet(data),
            payload_name=torrents.payload_name(data),
            payload_size=torrents.total_length(data),
        )
    except torrents.BencodeError:
        # An HTML error page served with a 200 lands here, which is the whole point.
        return None


def resolve_torrent_only(
    client: Client,
    *,
    distro: str,
    variant: str,
    params: dict,
    torrent_url: str,
    base: str = "",
    version_dirname: str = "",
) -> Release | None:
    """A variant whose only artifact is a `.torrent`.

    Kali lists three images in its signed `SHA256SUMS` whose `.iso` 404s; AnduinOS
    publishes 22 assets and every one is a torrent. Resolution runs backwards from
    the usual order, because the filename is not known until the torrent is read:

    1. fetch and parse the torrent
    2. **`filename` is `info.name`** -- never the URL with `.torrent` stripped off,
       which is a guess that breaks the moment a project names the two differently
    3. `version_pattern` runs on that filename, so `guid()` keeps its usual shape
    4. one checksum-file fetch, two lookups: the ISO's hash to publish, the
       torrent's to check the bytes in hand
    """
    ref = fetch_torrent(client, url=torrent_url)
    if not ref:
        return None

    filename = ref.payload_name
    version = (
        from_filename(filename, params["version_pattern"])
        if params.get("version_pattern")
        else version_dirname
    )
    if not version:
        return None

    checksum = algo = torrent_checksum = torrent_algo = None
    text = fetch_sums(
        client,
        base=base,
        filename=filename,  # the ISO: `checksum` always describes `filename`
        version=version_dirname or version,
        sums=params.get("sums"),
    )
    if text:
        if found := checksums.lookup(text, filename):
            algo, checksum = found
        if found := checksums.lookup(text, torrent_url.rsplit("/", 1)[-1]):
            torrent_algo, torrent_checksum = found

    # The torrent verifies its payload against itself. Only a signed hash of the
    # torrent breaks that circle -- so where one exists, it is not optional.
    if torrent_checksum and not ref.verified_by(torrent_algo, torrent_checksum):
        return None

    signature_url = None
    if sig := params.get("sig"):
        signature_url = urljoin(
            base, _expand(sig, filename=filename, version=version_dirname or version)
        )

    return build_release(
        distro,
        variant,
        version,
        filename=filename,
        download_url=None,  # there is no HTTP artifact; that is the whole point
        params=params,
        size=ref.payload_size,
        checksum=checksum,
        checksum_algo=algo,
        signature_url=signature_url,
        torrent_url=ref.url,
        torrent_size=ref.size,
        torrent_checksum=torrent_checksum,
        torrent_checksum_algo=torrent_algo,
        info_hash=ref.info_hash,
        magnet_uri=ref.magnet,
    )


def attach_torrent(client: Client, release: Release, params: dict) -> Release:
    """Enrich a resolved ISO with a co-located `.torrent`, or leave it untouched.

    The mirror image of `resolve_torrent_only`: there the torrent *is* the artifact;
    here the ISO is, and the torrent is a second retrieval channel on the same entry
    so a consumer can pick. Debian, Ubuntu, Arch and openSUSE Tumbleweed all publish
    `{filename}.torrent` beside (or a sibling dir over from) the ISO.

    Every path returns the release **unchanged** rather than failing. A bad torrent
    must never break an entry whose direct download is fine -- integrity for that
    consumer already came from the ISO's own signed checksum.

    The one non-obvious check is `version in info.name`, not `info.name == filename`.
    openSUSE resolves the `-Current.iso` symlink while its torrent names the dated
    snapshot (`...-Snapshot20260708-Media.iso`), so an equality test would reject a
    perfectly good torrent. The version substring ties the torrent to *this* release
    -- a right-release test. Integrity is the checksum's job, not this line's.
    """
    if not release.download_url:  # a torrent-only release has nothing to hang this on
        return release
    torrent = params.get("torrent")
    if not torrent:
        return release

    url = urljoin(
        release.download_url,
        _expand(torrent, filename=release.filename, version=release.version),
    )
    ref = fetch_torrent(client, url=url)
    if not ref:  # not published, or not a torrent -- the direct download still works
        return release
    if not (release.version and release.version in ref.payload_name):
        return release  # a stale or wrong-release torrent

    torrent_algo = torrent_checksum = None
    if tsums := params.get("torrent_sums"):
        text = client.text(
            urljoin(
                release.download_url,
                _expand(tsums, filename=release.filename, version=release.version),
            )
        )
        if text and (found := checksums.lookup(text, url.rsplit("/", 1)[-1])):
            torrent_algo, torrent_checksum = found
            # Signed but tampered: omit the torrent, keep the direct download.
            if not ref.verified_by(torrent_algo, torrent_checksum):
                return release

    return replace(
        release,
        torrent_url=ref.url,
        torrent_size=ref.size,
        torrent_checksum=torrent_checksum,
        torrent_checksum_algo=torrent_algo,
        info_hash=ref.info_hash,
        magnet_uri=ref.magnet,
    )
