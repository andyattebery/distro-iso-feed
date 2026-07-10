"""Release-candidate generators for sources with no listable release index.

Two upstreams publish releases that cannot be read, only guessed and confirmed:
NixOS (`channels.nixos.org/` renders its listing client-side) and Pop!_OS
(`api.pop-os.org` exposes exactly one endpoint, `builds/{version}/{channel}`).

A generator must not encode "which releases upstream currently bothers to ship."
Pop's API still serves `20.10`, `21.04` and `21.10`, so an LTS-only candidate list
would be a fresh pin wearing a probe's clothes -- it would break silently the day
System76 resumes interim releases. Generate the whole shape; let the probe decide.

`now` is injectable so the generators are testable and so no clock reaches a
generated artifact.
"""

from __future__ import annotations

from datetime import UTC, datetime


def _year(now: datetime | None) -> int:
    return (now or datetime.now(UTC)).year % 100


def nixos_channels(now: datetime | None = None, lookahead: int = 1, back: int = 2) -> list[str]:
    """NixOS ships `YY.05` and `YY.11`, newest first."""
    year = _year(now)
    out: list[str] = []
    for y in range(year + lookahead, year - back, -1):
        out.extend([f"{y:02d}.11", f"{y:02d}.05"])
    return out


def ubuntu_style(now: datetime | None = None, lookahead: int = 1, back: int = 4) -> list[str]:
    """`YY.04` and `YY.10`, newest first -- Ubuntu's scheme, which Pop!_OS follows.

    Both months, deliberately. Pop currently ships LTS only, but its API still
    answers for `20.10`/`21.04`/`21.10`, and a generator that assumed otherwise
    would re-introduce the pin this module exists to remove.
    """
    year = _year(now)
    out: list[str] = []
    for y in range(year + lookahead, year - back, -1):
        out.extend([f"{y:02d}.10", f"{y:02d}.04"])
    return out


GENERATORS = {"nixos": nixos_channels, "ubuntu_style": ubuntu_style}


def candidates_for(spec: dict, now: datetime | None = None) -> list[str]:
    """Resolve a `probe_versions:` block to an ordered candidate list.

    Explicit `candidates:` wins; otherwise name a generator.
    """
    if explicit := spec.get("candidates"):
        return list(explicit)
    generator = GENERATORS.get(spec.get("generator", "nixos"))
    if generator is None:
        return []
    return generator(now)
