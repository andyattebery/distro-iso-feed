"""Discover the architectures a variant could publish, and propose them into its `arches` map.

The arch analog of `propose_variants`, and simpler: a variant proposal synthesizes a whole config
node; an arch proposal is one `canonical: token` line. It verifies the same way -- substitute the
token, `strategy.resolve()`, keep it only if a real artifact comes back -- so a merged PR is
mergeable as-is. The runtime is untouched: this only edits config; resolution reads the `arches` map
the human merges.

Works on the **raw doc**, because `config.py` expands the `arches` map and `{token}` template away
at load. The `{token}` template is reconstructed by overlaying the raw variant/distro params (which
still hold `{token}`) onto an already-expanded variant's params (which carry the resolved
distro-level `sums`/`sig`/`signing_key`), then `substitute_token` fills in the candidate arch.
"""

from __future__ import annotations

from .arch import canonical
from .client import Client
from .config import substitute_token
from .models import Source
from .propose_common import ArchProposal, Rejected, carries_integrity
from .strategies import REGISTRY


def propose_arches(
    source: Source, doc: dict, client: Client
) -> tuple[list[ArchProposal], list[Rejected]]:
    """One `ArchProposal` per newly-discovered, resolvable architecture of an `arches` variant.

    Also returns `Rejected`s -- but only for a token that *resolved a real artifact yet published no
    integrity*, a genuine gap otherwise dropped silently. A token that resolves to nothing is a
    non-arch directory (`source/`, `trace/`), the common case, and reporting those would be noise,
    not the signal the variant proposer's `Rejected` carries (its candidates are pre-filtered by a
    `group`; arch tokens are a raw enumeration)."""
    distro_node = (doc.get("distros") or {}).get(source.name) or {}
    raw_variants = distro_node.get("variants") or {}
    raw_distro_params = distro_node.get("params") or {}
    # `arch_ignore` (distro-level, in `discover:`) makes a declined arch stay declined -- matched
    # against the upstream token AND its canonical, so `arm64` or `aarch64` both silence Kali's.
    arch_ignore = {str(a) for a in (source.discover.get("arch_ignore") or [])}

    # Any one expanded variant per name carries the fully-merged, distro-level params.
    base_by_name: dict[str, object] = {}
    for v in source.variants:
        base_by_name.setdefault(v.name, v)

    out: list[ArchProposal] = []
    rejected: list[Rejected] = []
    for vname, vnode in raw_variants.items():
        if not isinstance(vnode, dict):
            continue
        arches = vnode.get("arches")
        if not arches:  # arch discovery is opt-in: only variants that carry an `arches` map
            continue
        base = base_by_name.get(vname)
        if base is None:
            continue

        strategy = REGISTRY[base.strategy]()
        # Re-introduce the `{token}` template over the resolved base params (raw params override,
        # so any `{token}`-bearing field -- variant or distro level -- comes back unexpanded).
        template = {**base.params, **raw_distro_params, **(vnode.get("params") or {})}

        # The token already seeded for each arch -- a bare string, or an override dict's `token`
        # (defaulting to the canonical key), exactly as config.py expands it. Matching on the raw
        # dict repr would miss a hand-seeded override arch and re-propose it.
        known = {
            str(v.get("token", c) if isinstance(v, dict) else v) for c, v in arches.items()
        }
        for token in strategy.arch_tokens(template, client):
            if token in known:
                continue
            if token in arch_ignore or canonical(token) in arch_ignore:
                continue
            arch = canonical(token)
            params = substitute_token(template, token)
            params["arch"] = arch
            try:
                release = strategy.resolve(source.name, vname, params, client)
            except Exception:  # a junk dir must never abort discovery
                continue
            if release is None:
                continue  # a non-arch dir (source/, trace/) resolves to nothing -- drop it
            # The token is substituted into both the path and the match, so a resolving artifact is
            # necessarily this arch; the only thing left to prove is that it carries integrity.
            if problem := carries_integrity(release):
                rejected.append(Rejected(source.name, f"{vname}:{arch}", release.filename, problem))
                continue
            out.append(ArchProposal(source.name, vname, arch, token, release))

    return out, rejected
