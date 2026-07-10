"""Where `version` comes from.

`version` is the *change-token*, not the marketing version: anything that changes
the bytes must change it, or `guid()` does not move and no subscriber ever learns
about the new artifact. Fedora respins are the proof -- version stays "44" while
the ISO and its sha256 both change.
"""

from __future__ import annotations

import re

from . import checksums


def from_filename(filename: str, pattern: str) -> str | None:
    """e.g. ``Fedora-Workstation-Live-44-1.7.x86_64.iso`` -> ``44-1.7``.

    Several capture groups are joined with ``-``: Nobara's token is a release number
    *and* a date (``43-2026-04-19``), which are not adjacent in the filename.

    CachyOS is why this never reads the containing directory: it publishes
    ``/gui-installer/handheld/250626/cachyos-handheld-linux-260426.iso``, where the
    directory disagrees with the filename by two months.
    """
    m = re.search(pattern, filename)
    if not m:
        return None
    if m.re.groups > 1:
        return "-".join(g for g in m.groups() if g)
    return m.group(m.lastindex or 0)


def from_sidecar_filename(sidecar_text: str, pattern: str) -> str | None:
    """The `stable_symlink` token source.

    The download URL is version-less by definition (``neon-desktop-current.iso``),
    but the sidecar names the dated artifact (``neon-desktop-20260707-0147.iso``).
    That mismatch is the mechanism, not a bug.
    """
    table = checksums.parse(sidecar_text)
    for name in table:
        if token := from_filename(name, pattern):
            return token
    return None


def from_json_field(row: dict, fields: list[str], separator: str = "-") -> str | None:
    """Pop!_OS needs ``version`` + ``build`` to make a token that actually moves."""
    parts = [str(row[f]) for f in fields if row.get(f) not in (None, "")]
    return separator.join(parts) if parts else None


def from_atom_tag(tag: str, pattern: str | None = None) -> str | None:
    """ublue's `-CHECKSUM` names a version-less ISO, so the token is the atom tag.

    Bazzite's entry title is ``stable-20260708: Stable (F44.20260708, #81d640c)``.
    """
    tag = tag.split(":", 1)[0].strip()
    if pattern:
        return from_filename(tag, pattern)
    return tag or None
