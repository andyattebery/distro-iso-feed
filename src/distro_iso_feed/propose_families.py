"""Family discovery: propose a whole new distro *block* for a new member of a declared family.

The block-level analog of `propose_arches`. A `families:` entry (validated in config.py) names a
listable `root` and a `model` sibling to clone. A member directory the root lists but config does
not yet track is proposed as a new distro block -- the model's YAML node with the member name
substituted in -- but only after that block RESOLVES live, the same "executed, not guessed"
discipline `propose_variants` uses, lifted from variant to block.

The runtime is untouched: this only edits config. The safety property (nothing re-adds a distro
left out on purpose) is preserved by the family's `ignore` list, which is both the non-member
filter and the sticky-decline for members deliberately excluded.
"""

from __future__ import annotations

from .client import Client
from .config import substitute
from .listers import version_dir
from .models import Release, Source
from .propose_common import FamilyProposal, Rejected, carries_integrity
from .strategies import REGISTRY


def _tokens(model_name: str, member: str) -> list[tuple[str, str]]:
    """Substitutions that turn the model into the member, everywhere it names itself.

    Two forms: the lowercase name (`kubuntu` in `version_dir`/`version_pattern`/`match`/`page_url`)
    and the Capitalized display name (`Kubuntu` in variant labels). The model is chosen so its
    name-to-label is regular (`kubuntu` -> `Kubuntu`); the result is still flagged for review.
    """
    display = member.replace("-", " ").title()
    return [(model_name, member), (model_name.capitalize(), display)]


def _resolves_for(
    model: Source, tokens: list[tuple[str, str]], member: str, client: Client
) -> tuple[Release | None, str | None]:
    """Resolve the member against the model's variants (each under its own strategy).

    Returns `(release, None)` on the first variant that resolves and carries integrity;
    `(release, problem)` when one resolved but is unverifiable (a real gap to report); and
    `(None, None)` when nothing resolved -- a directory with no matching desktop ISO (infra dirs,
    `ubuntu-server`), the common non-flavor case, dropped silently to keep the report signal.
    """
    unverifiable: tuple[Release, str] | None = None
    for mv in model.variants:
        strategy = REGISTRY[mv.strategy]()
        params = substitute(dict(mv.params), tokens)
        try:
            release = strategy.resolve(member, mv.name, params, client)
        except Exception:  # a synthesized config must never abort discovery
            release = None
        if release is None:
            continue
        if problem := carries_integrity(release):
            unverifiable = (release, problem)
            continue
        return release, None
    return unverifiable if unverifiable else (None, None)


def propose_families(
    sources: list[Source], doc: dict, client: Client
) -> tuple[list[FamilyProposal], list[Rejected]]:
    """One `FamilyProposal` per newly-discovered, resolvable member of each declared family.

    Also returns `Rejected`s -- but, like arch discovery, only for a member that *resolved a real
    ISO yet published no integrity*; a member that resolves to nothing is a non-flavor directory,
    filtered silently rather than reported as noise.
    """
    families = doc.get("families") or {}
    by_name = {s.name: s for s in sources}

    out: list[FamilyProposal] = []
    rejected: list[Rejected] = []
    for fam_name, fam in families.items():
        model = by_name.get(fam.get("model"))
        model_node = (doc.get("distros") or {}).get(fam.get("model"))
        if model is None or not isinstance(model_node, dict):
            continue

        ignore = {str(m) for m in (fam.get("ignore") or [])}
        match = str(fam.get("member_match") or r"^[a-z].*$")
        for member in version_dir(client, str(fam["root"]), match):
            if member in by_name or member in ignore:  # already tracked, or declined
                continue
            tokens = _tokens(model.name, member)
            release, problem = _resolves_for(model, tokens, member, client)
            if problem:
                rejected.append(Rejected(member, "-", release.filename, problem))
                continue
            if release is None:
                continue
            # Clone the model block. `substitute` rewrites every string leaf: the lowercase name
            # fixes version_dir/version_pattern/match/page_url, the Capitalized name fixes labels.
            node = substitute(model_node, tokens)
            out.append(FamilyProposal(fam_name, member, node, release))

    return out, rejected
