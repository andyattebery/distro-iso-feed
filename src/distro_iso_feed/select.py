"""Candidate selection: the half of every strategy that is identical.

`directory_index`, `sourceforge`, `page_index` and `github_releases` differ only in
how they obtain a candidate list. Everything after -- reject prereleases, reject
decoys, pick the newest -- happens here, once.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

# Every prerelease marker present in the seeded catalog: Manjaro's `-pre`, MX's
# `_beta1_`, Aurora's `-beta-`, elementary's `-rc3`, Zorin's `Beta`.
#
# Boundaries are "not alphanumeric" rather than a fixed `[-_.]` set, because atom
# titles carry trailing punctuation: elementary's is `8.1.0-rc3: RC`, and a `[-_.]`
# boundary would let the `rc3` through. `prune` and `precise` still do not match.
#
# The markers that can carry an ordinal all take `\d*` -- Ubuntu's milestone images are
# `ubuntu-26.10-snapshot2-desktop-amd64.iso`, and a bare `snapshot` failed the trailing
# boundary on the `2` and let them through. openSUSE is unaffected: its `Snapshot20260714`
# is a *version* read from a sidecar, never a name this filter sees.
PRERELEASE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:pre|alpha\d*|beta\d*|rc\d*|nightly|daily|testing|snapshot\d*)"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_VERSION_TOKEN = re.compile(r"\d+(?:[._]\d+)*")


def is_prerelease(name: str) -> bool:
    """Filter on the name, never on GitHub's `prerelease` flag.

    elementary tags `8.1.0-rc3` with ``prerelease: false``.
    """
    return bool(PRERELEASE.search(name))


def reject_prereleases(names: Iterable[str]) -> list[str]:
    return [n for n in names if not is_prerelease(n)]


def dedupe(names: Iterable[str]) -> list[str]:
    """SourceForge emits every ``<item>`` twice; order-preserving dedupe."""
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def matching(names: Iterable[str], pattern: str) -> list[str]:
    """Anchored regex match. Callers anchor on ``\\.iso$`` to reject `.zsync`/`.sig`."""
    rx = re.compile(pattern)
    return [n for n in names if rx.search(n)]


def excluding(names: Iterable[str], patterns: Iterable[str]) -> list[str]:
    """Drop decoys: `debian-edu-`, `arm64`, `-musl-`, `aarch64`, `_386`, ..."""
    rxs = [re.compile(p) for p in patterns]
    return [n for n in names if not any(r.search(n) for r in rxs)]


def version_key(text: str, pattern: str | None = None) -> tuple:
    """A sortable key for a version-ish string.

    ``pattern`` extracts the token first. EndeavourOS names ISOs by codename
    (`Gemini`, `Titan-Neo`), which do not sort -- the date embedded in the filename
    does, and this is where that is enforced.
    """
    token = text
    if pattern:
        m = re.search(pattern, text)
        if not m:
            return (0, ())
        token = m.group(m.lastindex or 0)

    try:
        return (2, Version(token.replace("_", ".")).release)
    except InvalidVersion:
        pass

    nums = _VERSION_TOKEN.findall(token)
    if nums:
        parts: list[int] = []
        for chunk in nums:
            parts.extend(int(p) for p in re.split(r"[._]", chunk))
        return (1, tuple(parts))
    return (0, ())


def newest(names: Iterable[str], pattern: str | None = None) -> str | None:
    """Pick the highest-versioned candidate, keyed on the extracted token.

    Ties break on the full name, which is what orders Manjaro's co-published kernel
    builds: `linux70` (kernel 7.0) sorts above `linux618` (6.18) lexicographically,
    whereas comparing them as integers gets it backwards.
    """
    candidates = list(names)
    if not candidates:
        return None
    return max(candidates, key=lambda n: (version_key(n, pattern), n))


def is_lts(version: str) -> bool:
    """Ubuntu LTS is an even year with a `.04` month. `25.04` is interim, not LTS."""
    m = re.match(r"^(\d{2})\.04(?:\.\d+)?$", version)
    return bool(m) and int(m.group(1)) % 2 == 0


# The `channel` values `by_channel` dispatches on. This is the single source of truth:
# `config.py` imports it to validate `channel`, so the validator and the dispatch cannot name
# different sets. Without it an unknown value fell through to "no filter" -- `channel: lastest`
# silently behaved as `latest`.
CHANNELS = frozenset({"lts", "latest"})


def by_channel(versions: Iterable[str], channel: str) -> list[str]:
    """Narrow a version list to a channel.

    `lts` pins to the long-term-support line. `latest` is every version -- the caller takes the
    newest that actually *has* a matching artifact, so an in-development dir (26.10, holding only
    milestone subdirs) is skipped rather than picked.

    There is deliberately no `interim`. Wanting a non-LTS release is really wanting the newest
    thing, LTS or not; nobody on 25.10 wants to stay on 25.10. The useful axis is latest-vs-LTS,
    and an `interim` channel could also name a release line a flavour does not publish at all --
    which is how `ubuntu-unity:desktop-interim` sat unresolved from the day it was added.
    """
    if channel == "lts":
        return [v for v in versions if is_lts(v)]
    return list(versions)


def choose(
    names: Iterable[str],
    *,
    match: str,
    ignore: Iterable[str] = (),
    version_pattern: str | None = None,
    sort_pattern: str | None = None,
    allow_prerelease: bool = False,
) -> str | None:
    """The whole downstream pipeline, in call order.

    `sort_pattern` separates *ordering* from *identity*. Manjaro's token must carry
    the kernel (different kernel, different bytes, different guid), but the kernel
    must not decide which build is newest -- `linux70` beats `linux618` as a kernel
    and loses to it as an integer. Defaults to `version_pattern`.
    """
    cands = dedupe(names)
    cands = matching(cands, match)
    cands = excluding(cands, ignore)
    if not allow_prerelease:
        cands = reject_prereleases(cands)
    return newest(cands, sort_pattern or version_pattern)
