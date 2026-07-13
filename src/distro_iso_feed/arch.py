"""Upstream arch token -> canonical arch name.

An architecture has one canonical name (x86_64, aarch64, ...) but distros label the same thing
differently in filenames and paths (amd64, arm64, ppc64el). Discovery finds the tokens; this maps
them to the canonical name that keys the feed. Only the aliases where they differ are listed --
everything else (riscv64, s390x, armhf, x86, i386) is already its own canonical, so the fallback is
identity. Keeping `amd64 -> x86_64` is what lets the x86_64 key stay implicit (`models.arch_tag`),
so a discovered arch never moves an existing entry's id.
"""

from __future__ import annotations

# The implicit default arch: it keys the feed with a bare id (no `:arch` suffix, see
# `models.arch_tag`), so every "which arch is this when none is given" fallback resolves here.
DEFAULT_ARCH = "x86_64"

_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "arm64": "aarch64",
    "ppc64el": "ppc64le",
}


def canonical(token: str) -> str:
    """Canonical arch name for an upstream token; identity when it is not a known alias."""
    return _ALIASES.get(token, token)
