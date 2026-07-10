"""Checksum-file parsing.

Three formats appear across the seeded catalog, and a parser that knows only the
first silently returns nothing for FreeBSD and Batocera:

1. GNU     ``<hash>  <name>``                       -- most sources
2. BSD     ``SHA256 (<name>) = <hash>``             -- FreeBSD
3. bare    ``<hash>``                               -- Batocera's ``.md5``

Algorithms are told apart by exact hex length, so Garuda's co-listed ``.iso.sha1``
is never mistaken for its ``.iso.sha256``.
"""

from __future__ import annotations

import re

# Exact hex length -> algorithm. sha1 is here because Garuda publishes one as a decoy.
ALGO_BY_LENGTH: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# Strongest first: when a source publishes several, prefer the best available.
ALGO_STRENGTH: dict[str, int] = {"md5": 0, "sha1": 1, "sha256": 2, "sha512": 3}

_GNU = re.compile(r"^(?P<hash>[0-9a-fA-F]{32,128})\s+[*]?(?P<name>\S.*)$")
_BSD = re.compile(
    r"^(?P<algo>MD5|SHA1|SHA256|SHA512)\s*\((?P<name>[^)]+)\)\s*=\s*(?P<hash>[0-9a-fA-F]{32,128})$",
    re.IGNORECASE,
)
_BARE = re.compile(r"^(?P<hash>[0-9a-fA-F]{32,128})$")


def normalize_name(name: str) -> str:
    """Nobara's sidecar names ``./Nobara-...iso``; strip that or every lookup misses."""
    name = name.strip()
    if name.startswith("./"):
        name = name[2:]
    return name.rsplit("/", 1)[-1]


def algo_for_hash(value: str) -> str | None:
    return ALGO_BY_LENGTH.get(len(value))


def parse(text: str, *, default_name: str | None = None) -> dict[str, tuple[str, str]]:
    """Parse a checksum file into ``{filename: (algo, hash)}``.

    ``default_name`` supplies the filename for bare-hash files, which have none.
    When a file lists the same artifact under several algorithms, the strongest wins.
    """
    found: dict[str, tuple[str, str]] = {}

    def offer(name: str, algo: str, value: str) -> None:
        name = normalize_name(name)
        current = found.get(name)
        if current is None or ALGO_STRENGTH[algo] > ALGO_STRENGTH[current[0]]:
            found[name] = (algo, value.lower())

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if m := _BSD.match(line):
            algo = m["algo"].lower()
            offer(m["name"], algo, m["hash"])
            continue

        if m := _GNU.match(line):
            algo = algo_for_hash(m["hash"])
            if algo:
                offer(m["name"], algo, m["hash"])
            continue

        if (m := _BARE.match(line)) and default_name:
            algo = algo_for_hash(m["hash"])
            if algo:
                offer(default_name, algo, m["hash"])

    return found


def lookup(text: str, filename: str) -> tuple[str, str] | None:
    """Find ``filename``'s checksum. Bare-hash files match unconditionally."""
    table = parse(text, default_name=filename)
    return table.get(normalize_name(filename))


def sole(text: str, filename: str) -> tuple[str, str] | None:
    """Take the one entry in a single-artifact sidecar, whatever it is named.

    The filename column deliberately does NOT equal the download filename for
    `stable_symlink` sources: neon's sidecar names `neon-desktop-20260707-0147.iso`
    while you fetch `neon-desktop-current.iso`. That mismatch is where the
    change-token comes from, so matching on name here would discard the checksum.

    Falls back to a name lookup when the file lists many artifacts.
    """
    table = parse(text, default_name=filename)
    if len(table) == 1:
        return next(iter(table.values()))
    return table.get(normalize_name(filename))
