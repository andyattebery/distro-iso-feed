"""Checksum sidecars: fetch the sums file, and resolve `(checksum, algo, signature_url)`.

The first of the three concerns split out of the old `_common.py` -- just the checksum side. It
knows nothing about torrents or GPG; `torrent.py` reuses `fetch_sums`/`_expand`, and the GPG policy
lives in the top-level `signing.py`.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .. import checksums, escalate
from ..client import Client


class SumsUnavailable(Exception):
    """A checksum sidecar IS configured and the fetch failed *transiently*.

    Distinct from `fetch_sums` returning None, which means no sums is configured at all (tails
    ships no sidecar -- a design choice, not a failure). When a configured sidecar does not
    arrive, we do not KNOW the checksum, and publishing `None` in its place is how
    `debian:netinst:*` shipped `verify: gpg` with `checksum: null` and nobody noticed for days.

    Raised, not returned, so it lands on `run_refresh`'s existing resolver `try/except` and is
    classed TRANSIENT -- entry left untouched, retried next run, no issue, gate green. Returning
    None instead would route through `diagnose`, which hardcodes STRUCTURAL and would file a
    bogus regression per variant.

    **Only transient.** A 404 keeps the old behaviour (checksum=None, still resolves): several
    sources carry optional per-file sidecars, and failing the resolve on a structurally-absent
    one would freeze those entries forever -- trading silent degradation for a silent stall.
    """

    def __init__(self, url: str, failure_class: str = escalate.TRANSIENT) -> None:
        super().__init__(f"checksum file unreachable ({failure_class}): {url}")
        self.url = url
        self.failure_class = failure_class


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

    `None` means **no sums is configured**. A configured-but-transiently-unreachable sidecar
    raises `SumsUnavailable` instead -- the two used to collapse into the same `None`, which is
    the bug that let a timed-out mirror publish a checksum-less entry.

    Goes through `get_cached`: `signing` reads the same SHA*SUMS again to verify it, and one
    fetch for both closes that TOCTOU.
    """
    if not (sums or sums_url):
        return None  # not configured -- tails et al. Unchanged.
    url = sums_url or urljoin(base, _expand(sums, filename=filename, version=version))
    mark = len(client.trace)
    r = client.get_cached(url)
    if r is None:
        # The slice covers exactly the fetch just performed, in this call, with nothing
        # interleaved -- the one place `client.trace` can be read without the mark/slice
        # discipline `diagnose` needs.
        outcomes = [o for _, o in client.trace[mark:]]
        if escalate.classify_outcomes(outcomes) == escalate.TRANSIENT:
            raise SumsUnavailable(url)
        return None  # 404/structural: deliberately still resolves, checksum-less. See the class.
    return r.text


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
