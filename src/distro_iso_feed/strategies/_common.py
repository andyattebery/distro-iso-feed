"""Integrity: the fourth axis, shared by every strategy that has a sidecar."""

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

    if sums or sums_url:
        url = sums_url or urljoin(base, _expand(sums, filename=filename, version=version))
        text = client.text(url)
        if text:
            find = checksums.sole if sole_entry else checksums.lookup
            if found := find(text, filename):
                algo, checksum = found

    signature_url = None
    if sig:
        signature_url = urljoin(base, _expand(sig, filename=filename, version=version))

    return checksum, algo, signature_url
