"""Strategy ABC.

`resolve()` MUST NOT raise on ordinary upstream errors -- it returns None and the
runner logs it, so one dead mirror never aborts a run or empties the feed.

`discover_all()` is implemented *once*, here. A lister already returns every
candidate by definition, so grouping its output gives variant discovery for free
on every source that enumerates. It is not a per-strategy method anyone has to
remember to write.

Two things this file gets right that are easy to get wrong:

* Enumeration unions **every configured variant's params**, not the first one's.
  Debian's `index` is per-variant, so enumerating `variants[0]` sees `iso-cd/` and
  is structurally blind to the eight live editions in `iso-hybrid/`.
* The **discovery surface is not always the resolve surface**. Aurora resolves a
  fixed URL while `dl.getaurora.dev/` is a plain index; neon resolves
  `images/<ed>/current/` while `images/` lists the editions. `discover.index`
  points enumeration at the right URL.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from ..client import Client
from ..listers import Candidate, autoindex
from ..models import Release, VariantSpec
from ..select import is_prerelease, version_key

# Params that determine *what gets fetched*. Two variants sharing these share a
# listing, so it is fetched once. Debian has nine variants across two indexes.
_LISTING_KEYS = ("url", "index", "version_dir", "repo", "project", "path", "attr")


def listing_key(params: dict) -> tuple:
    return tuple(str(params.get(k, "")) for k in _LISTING_KEYS)


def variant_key(match: re.Match) -> str:
    """The config key a matched candidate maps to.

    Several capture groups join with `-` so Debian's `live` prefix and its desktop
    name produce `live-gnome`, the key that is actually configured. Underscores
    normalize to hyphens: MX publishes `MX-25.2_Xfce_ahs_x64.iso`, whose edition is
    `Xfce_ahs`, and the configured key is `xfce-ahs`.

    A regex that matches with no groups, or only empty ones, yields "" -- the
    caller skips it. That is how a single-artifact source (Arch, Tails) proposes
    nothing today yet still surfaces a genuinely new edition tomorrow.
    """
    groups = [g for g in match.groups() if g] if match.re.groups else []
    raw = "-".join(groups) if groups else ""
    return raw.lower().replace("_", "-")


class Strategy(ABC):
    name: str

    @abstractmethod
    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        """The single latest Release for this variant, with a final download URL."""

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        """Everything the upstream currently publishes. Default: nothing."""
        return []

    def claims(self, candidate: Candidate, params: dict) -> bool:
        """Does this variant cover this artifact?

        Default is the `match` regex. `json_api` selects on a JSON field and
        `stable_symlink` on a fixed URL, so both override. `propose.py` asks the
        strategy rather than assuming a regex, which is how it finds the artifact a
        configured variant currently selects -- the exemplar it copies from. Assume a
        regex and Fedora has no siblings at all, since no Fedora variant has one.
        """
        pattern = params.get("match")
        return bool(pattern) and bool(re.search(pattern, candidate.name))

    def arch_tokens(self, params: dict, client: Client) -> list[str]:
        """Upstream arch tokens this variant could resolve -- the enumeration step of arch
        discovery. Default: none, and most strategies keep it (they are single-arch). The three
        that override are `directory_index` (a `{token}` path segment or filename capture),
        `json_api` (the JSON `arch` row field), and `stable_symlink` (a fixed candidate set that
        resolve-verify prunes). Operates on the RAW params (`{token}` unexpanded), since discovery
        precedes config expansion.
        """
        return []

    # ---------------------------------------------------------------- enumeration

    def enumerate_all(
        self,
        distro: str,
        variant_params: list[dict],
        discover: dict,
        client: Client,
    ) -> list[Candidate]:
        """Every artifact the distro publishes, across all its variants' listings."""
        if index := discover.get("index"):
            # A `discover.index` is a human page, not a machine listing: neon's
            # `images/` carries forty links of KDE site navigation alongside its six
            # image directories. Keep only what lives *under* the index. That is
            # structural -- an `ignore` list would need editing whenever KDE adds a
            # footer link, and would silently swallow a real new edition the day one
            # collided with a nav word.
            cands = [c for c in autoindex(client, index) if (c.url or "").startswith(index)]
        else:
            seen_listings: set[tuple] = set()
            by_name: dict[str, Candidate] = {}
            for params in variant_params:
                key = listing_key(params)
                if key in seen_listings:
                    continue
                seen_listings.add(key)
                for cand in self.candidates(distro, params, client):
                    by_name.setdefault(cand.name, cand)
            cands = list(by_name.values())

        # `extra_index` (opt-in) unions an ADDITIONAL static listing, deduped by name. openSUSE is
        # the case: Leap editions come from the version-dir variant listings above, but the
        # Tumbleweed/MicroOS `-Current.iso` editions live only in `/tumbleweed/iso/`, which the
        # fixed-URL stable_symlink variants never enumerate. Index-only distros (neon, aurora) set
        # none, so their result is unchanged.
        if extra := discover.get("extra_index"):
            merged = {c.name: c for c in cands}
            for cand in autoindex(client, extra):
                if (cand.url or "").startswith(extra):
                    merged.setdefault(cand.name, cand)
            cands = list(merged.values())

        return cands

    def discover_all(
        self,
        distro: str,
        variant_params: list[dict],
        discover: dict,
        client: Client,
    ) -> list[VariantSpec]:
        group = discover.get("group")
        if not group or discover.get("enumerable") is False:
            return []

        # `match` keeps non-artifact rows out (Fedora's JSON also lists qcow2, vhd,
        # tar.xz). `ignore` must be written against the CANDIDATE (a filename or
        # path), not against the variant key it produces.
        keep = re.compile(discover["match"]) if discover.get("match") else None
        ignore = [re.compile(p, re.IGNORECASE) for p in discover.get("ignore") or []]
        rx = re.compile(group)

        # `group_field` reads a structured field instead of the filename. Fedora needs
        # it: the artifact is `Fedora-MATE_Compiz-Live-...` while the subvariant is
        # `Mate`, so grouping on the filename proposes `mate_compiz` as new -- a
        # duplicate of a variant that already exists under its real name.
        field = discover.get("group_field")
        arch = variant_params[0].get("arch") if variant_params else None

        best: dict[str, Candidate] = {}

        for cand in self.enumerate_all(distro, variant_params, discover, client):
            name = cand.name
            if keep and not keep.search(name):
                continue
            if is_prerelease(name) or any(r.search(name) for r in ignore):
                continue
            # Fedora's releases.json carries aarch64 beside x86_64. The arch is
            # structured data, not something to spell out in an `ignore` list -- and
            # an aarch64 exemplar would send `propose.py` off to synthesize a config
            # for an artifact this feed does not publish.
            row_arch = (cand.row or {}).get("arch")
            if arch and row_arch and row_arch != arch:
                continue

            subject = str((cand.row or {}).get(field, "")) if field else name
            if not subject:
                continue

            m = rx.search(subject)
            if not m:
                continue
            key = variant_key(m)
            if not key:
                continue
            # Newest wins. A key is usually published once per release, so the first
            # candidate is whichever one upstream happened to serialize first -- and
            # `propose.py` verifies a synthesized node against this exemplar, while
            # `resolve()` always selects the newest. They have to agree.
            if key not in best or version_key(name) > version_key(best[key].name):
                best[key] = cand

        # The evidence `propose.py` synthesizes from: the artifact that produced this
        # key, and its JSON row when the lister had one.
        return [
            VariantSpec(
                distro=distro,
                variant=key,
                params={"sample": cand.name, "row": cand.row, "url": cand.url},
            )
            for key, cand in sorted(best.items())
        ]


