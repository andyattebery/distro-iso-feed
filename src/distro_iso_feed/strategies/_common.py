"""Integrity: the fourth axis, shared by every strategy that has a sidecar."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from urllib.parse import urljoin

from .. import checksums, gpgverify, torrents
from ..client import Client
from ..models import Release
from ..tokens import from_filename
from .base import title_for

_SIG_EXTS = (".sign", ".gpg", ".asc")


def _norm_fpr(value: str) -> str:
    return "".join(value.split()).upper()


def _expand(template: str, *, filename: str, version: str) -> str:
    """`{stem}` is the filename without its extension.

    KDE neon's sidecar is `neon-desktop-current.sha256sum` and Bluestar's is
    `bslx-....md5` -- both drop the artifact's extension rather than appending to it.
    """
    stem = filename.rsplit(".", 1)[0]
    return template.format(filename=filename, stem=stem, version=version)


def fetch_sums(
    client: Client,
    *,
    base: str,
    filename: str,
    version: str,
    sums: str | None,
    sums_url: str | None = None,
) -> str | None:
    """The raw checksum file, fetched once.

    Extracted so a caller can look up two names in it. A torrent-only variant needs
    both: the ISO's hash to publish, and the `.torrent`'s to verify the bytes it
    just fetched. Fetching the file twice for that would be rude to the mirror.
    """
    if not (sums or sums_url):
        return None
    url = sums_url or urljoin(base, _expand(sums, filename=filename, version=version))
    return client.text(url)


def fetch_integrity(
    client: Client,
    *,
    base: str,
    filename: str,
    version: str,
    sums: str | None,
    sig: str | None,
    sums_url: str | None = None,
    sole_entry: bool = False,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(checksum, algo, signature_url)``.

    Handles all three checksum-file shapes the catalog contains: a per-artifact
    sidecar, an aggregate file listing many artifacts (Q4OS), and a bare hash with
    no filename column at all (Batocera).

    ``sole_entry`` accepts a single-artifact sidecar whose filename column differs
    from the download filename -- the `stable_symlink` case.
    """
    checksum = algo = None

    text = fetch_sums(
        client, base=base, filename=filename, version=version, sums=sums, sums_url=sums_url
    )
    if text:
        find = checksums.sole if sole_entry else checksums.lookup
        if found := find(text, filename):
            algo, checksum = found

    signature_url = None
    if sig:
        signature_url = urljoin(base, _expand(sig, filename=filename, version=version))

    return checksum, algo, signature_url


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

    arch = params.get("arch", "x86_64")
    return Release(
        distro=distro,
        variant=variant,
        version=version,
        title=title_for(distro, variant, version, arch, params.get("label")),
        download_url=None,  # there is no HTTP artifact; that is the whole point
        filename=filename,
        arch=arch,
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
        page_url=params.get("page_url"),
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


# The result of the build-time GPG gate, so the caller can log/act without re-deriving.
VERIFIED = "verified"  # signature chains to the pinned key -> publish the pin
BAD = "bad"  # a signature that fails its own key -> drop the gpg claim
DEFERRED = "deferred"  # transient/gpg-absent -> keep as resolved, add no pin


def verify_signing_key(client: Client, release: Release, params: dict) -> tuple[Release, str]:
    """Prove the GPG chain before the feed publishes the pinned key.

    A hand-entered fingerprint is only as good as the data entry, so every build
    re-checks it against the *actual signature* on the current artifact:

      checksums -- the sig covers a small SHA*SUMS/.sha256 file, so `gpgv` the whole
                   thing under only the pinned key, then confirm the checksum the feed
                   ships is inside that verified file. Full authentication.
      image     -- the sig covers the multi-GB ISO we do not download, so confirm the
                   signature's issuer is the pinned key (primary or subkey). Proves
                   the signature is *from* the pinned key; the consumer does the rest.

    Returns `(release, outcome)`:
      VERIFIED -> the pin is attached;
      BAD      -> `signature_url` is cleared, so `verify` degrades to `checksum`
                  (a signed checksum that fails its signature is not forwardable);
      DEFERRED -> the entry is returned exactly as resolved (a network blip or a dev
                  box without gpg must never flap the claim), no pin this run.
    """
    key_conf = params.get("signing_key")
    if not key_conf or not release.signature_url:
        return release, DEFERRED

    # `signature_target` is a static fact -- what the sig signs -- known from config
    # regardless of whether gpg can verify the pin this run. Stage it now so it rides
    # every non-BAD path (a dev box without gpg still emits it); `_drop` clears it.
    covers = key_conf.get("covers")
    staged = replace(release, signature_target=covers)

    if not gpgverify.gpg_available():
        return staged, DEFERRED  # keep the claim; the environment, not the sig, is at fault

    key = client.get(key_conf["url"])
    if not key or not key.content:
        return staged, DEFERRED  # transient: don't drop over a key-server blip
    key_bytes = key.content

    pinned = _norm_fpr(str(key_conf["fingerprint"]))
    if gpgverify.primary_fingerprint(key_bytes) != pinned:
        return _drop(release), BAD  # the URL is not serving the key we pinned

    sig = client.get(release.signature_url)
    if not sig or not sig.content:
        return staged, DEFERRED
    sig_bytes = sig.content

    if covers == "checksums":
        signed_url = _strip_sig_ext(release.signature_url)
        signed = client.get(signed_url)
        if not signed or not signed.content:
            return staged, DEFERRED
        text = signed.content.decode("utf-8", "replace")
        good = gpgverify.verify_detached(key_bytes, sig_bytes, signed.content)
        # The checksum the feed publishes must be the one the signature vouches for.
        if not (good and release.checksum and release.checksum.lower() in text.lower()):
            return _drop(release), BAD
    elif covers == "image":
        issuer = gpgverify.sig_issuer(sig_bytes)
        if not issuer:
            return staged, DEFERRED  # couldn't parse the sig -> don't punish the entry
        if not gpgverify.issuer_in_key(issuer, key_bytes):
            return _drop(release), BAD
    else:  # a config with signing_key but no/unknown `covers` verifies nothing
        return staged, DEFERRED

    return replace(
        staged, signing_key_url=key_conf["url"], signing_key_fingerprint=pinned
    ), VERIFIED


def _drop(release: Release) -> Release:
    """Strip the gpg claim so `verify` falls back to `checksum`."""
    return replace(
        release,
        signature_url=None,
        signing_key_url=None,
        signing_key_fingerprint=None,
        signature_target=None,
    )


def _strip_sig_ext(url: str) -> str:
    for ext in _SIG_EXTS:
        if url.endswith(ext):
            return url[: -len(ext)]
    return url
