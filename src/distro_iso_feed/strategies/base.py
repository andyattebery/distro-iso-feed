"""Strategy ABC.

`resolve()` MUST NOT raise on ordinary upstream errors -- it returns None and the
runner logs it, so one dead mirror never aborts a run or empties the feed.

`discover_variants()` is implemented *once*, here. A lister already returns every
candidate by definition, so grouping its output gives variant discovery for free
on every source that enumerates. It is not a per-strategy method anyone has to
remember to write.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from ..client import Client
from ..listers import Candidate
from ..models import Release, VariantSpec
from ..select import is_prerelease


class Strategy(ABC):
    name: str

    @abstractmethod
    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        """The single latest Release for this variant, with a final download URL."""

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        """Everything the upstream currently publishes. Default: nothing."""
        return []

    def discover_variants(self, distro: str, params: dict, client: Client) -> list[VariantSpec]:
        discover = params.get("discover") or {}
        group = discover.get("group")
        if not group:
            return []

        # `match` keeps non-artifact rows out (Fedora's JSON also lists qcow2, vhd,
        # tar.xz). `ignore` must be written against the CANDIDATE (a filename or
        # path), not against the variant key it produces.
        keep = re.compile(discover["match"]) if discover.get("match") else None
        ignore = [re.compile(p, re.IGNORECASE) for p in discover.get("ignore") or []]
        rx = re.compile(group)
        seen: set[str] = set()
        out: list[VariantSpec] = []

        for cand in self.candidates(distro, params, client):
            name = cand.name
            if keep and not keep.search(name):
                continue
            if is_prerelease(name) or any(r.search(name) for r in ignore):
                continue
            m = rx.search(name)
            if not m:
                continue
            key = (m.group(m.lastindex or 0)).lower()
            if key and key not in seen:
                seen.add(key)
                out.append(VariantSpec(distro=distro, variant=key))
        return sorted(out, key=lambda v: v.variant)


def title_for(distro: str, variant: str, version: str, arch: str, label: str | None) -> str:
    """Human text comes from `label`; the variant key is a permanent identifier."""
    name = label or f"{distro.replace('-', ' ').title()} {variant.replace('-', ' ').title()}"
    return f"{name} {version} ({arch})"
