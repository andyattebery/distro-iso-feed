"""Checksum sidecars: fetch the sums file, and resolve `(checksum, algo, signature_url)`.

The first of the three concerns split out of the old `_common.py` -- just the checksum side. It
knows nothing about torrents or GPG; `torrent.py` reuses `fetch_sums`/`_expand`, and the GPG policy
lives in the top-level `signing.py`.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .. import checksums
from ..client import Client


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
    sums: str | None = None,
    sig: str | None = None,
    sums_url: str | None = None,
    sig_url: str | None = None,
    sole_entry: bool = False,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(checksum, algo, signature_url)``.

    Handles all three checksum-file shapes the catalog contains: a per-artifact
    sidecar, an aggregate file listing many artifacts (Q4OS), and a bare hash with
    no filename column at all (Batocera).

    ``sums``/``sig`` are `urljoin`-relative to ``base``; ``sums_url``/``sig_url`` are absolute
    overrides for sources whose sidecars are not relative (SourceForge's per-file `.../download`
    URLs, a GitHub sibling asset), so those callers no longer hand-build the signature URL.
    ``sole_entry`` accepts a single-artifact sidecar whose filename column differs from the
    download filename -- the `stable_symlink` case.
    """
    checksum = algo = None

    text = fetch_sums(
        client, base=base, filename=filename, version=version, sums=sums, sums_url=sums_url
    )
    if text:
        find = checksums.sole if sole_entry else checksums.lookup
        if found := find(text, filename):
            algo, checksum = found

    signature_url = sig_url
    if sig and not signature_url:
        signature_url = urljoin(base, _expand(sig, filename=filename, version=version))

    return checksum, algo, signature_url
