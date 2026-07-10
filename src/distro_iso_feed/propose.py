"""Turn a discovered variant key into config that already works.

`match: TODO` made the discovery PR a to-do list, and a to-do list is a thing you
skim. Eight Fedora spins and five Nobara editions sat unconfigured while that PR
stayed open saying, accurately, that something was missing. So a proposal here is
not a name; it is a config node that has been **executed**.

The primary synthesis is a diff between two filenames, not a template:

    sibling  debian-live-13.5.0-amd64-gnome.iso   match: '^debian-live-[0-9.]+-amd64-gnome\\.iso$'
    new      debian-live-13.5.0-amd64-lxde.iso
    tokens   gnome -> lxde
    result                                        match: '^debian-live-[0-9.]+-amd64-lxde\\.iso$'

Substituting into the *sibling's own YAML node* means the proposal inherits whatever
shape that distro uses -- Debian's per-variant `index`, Kali's bare `match`, Fedora's
`select` -- without this module knowing anything about any of them. The sibling's
regex was already correct for the sibling. We change only what the filenames say
changed, and the version token is not one of those things: it is identical between
two editions of the same release, so `[0-9.]+` is never touched.

Substitution cannot express an *insertion*, and an insertion is how most distros name
a new edition (`aurora-stable-...` -> `aurora-nvidia-open-stable-...`). Two fallbacks
cover it, in `_nodes_for`: the URL enumeration already observed, and a `match`
generalized from the artifact's own name.

Then the part that matters: **verify**. Every candidate node is passed to
`strategy.resolve()`, and is kept only if it resolves to *the exact artifact that
produced the key*. A node that resolves to the sibling's ISO silently duplicates a
variant, and it is the single most likely way a plausible synthesis goes wrong.
Anything that does not resolve is dropped and reported under "could not synthesize",
so a merged PR is always mergeable as-is.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from .client import Client
from .listers import Candidate
from .models import Release, Source, VariantSpec
from .select import version_key
from .strategies import REGISTRY
from .strategies.base import Strategy

# A one-character substitution is a coincidence, not an edition name.
_MIN_TOKEN = 2


@dataclass(frozen=True, slots=True)
class Proposal:
    distro: str
    variant: str
    node: dict
    release: Release
    sibling: str

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.variant}"


@dataclass(frozen=True, slots=True)
class Rejected:
    distro: str
    variant: str
    sample: str
    reason: str

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.variant}"


def _split(name: str) -> list[str]:
    """Filename to separator-delimited tokens, separators kept."""
    return [t for t in re.split(r"([-_./])", name) if t]


def diff_tokens(old: str, new: str) -> list[tuple[str, str]]:
    """The literal substrings that differ between two artifact names.

    Diffing runs over *tokens*, not characters. Character granularity finds the `n`,
    `a`, `n` that `standard` and `cinnamon` happen to share, and shatters one clean
    edition rename into sub-word fragments that substitute into gibberish. Splitting
    on `-_./` first makes `standard -> cinnamon` a single replacement.

    Only `replace` opcodes are returned. An insert or a delete means the two names
    have different *structure* (`aurora-stable-...` against
    `aurora-nvidia-open-stable-...`), and no substitution can bridge that -- so the
    sibling is the wrong one to copy, and the caller moves on.

    Purely numeric tokens are dropped: two editions of one release share a version,
    so a digit difference means these are different *releases*, and proposing a
    variant from that is how a superseded ISO becomes a config entry. It is also how
    Nobara's `2026-04-25` would be substituted into a sibling's date regex.
    """
    old_t, new_t = _split(old), _split(new)
    out: list[tuple[str, str]] = []
    for tag, i1, i2, j1, j2 in SequenceMatcher(None, old_t, new_t, autojunk=False).get_opcodes():
        if tag != "replace":
            continue
        a, b = "".join(old_t[i1:i2]), "".join(new_t[j1:j2])
        if len(a) < _MIN_TOKEN or len(b) < _MIN_TOKEN:
            continue
        if a.strip("0123456789.-_") == "" or b.strip("0123456789.-_") == "":
            continue
        out.append((a, b))
    return out


def substitute(node: dict, tokens: list[tuple[str, str]]) -> dict:
    """Rewrite every string leaf of a YAML node with the token substitutions."""

    def walk(value):
        if isinstance(value, str):
            for old, new in tokens:
                value = value.replace(old, new)
            return value
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return walk(copy.deepcopy(node))


def _claimed(strategy: Strategy, params: dict, candidates: list[Candidate]) -> Candidate | None:
    """The artifact a configured variant currently selects: its newest claim."""
    mine = [c for c in candidates if strategy.claims(c, params)]
    if not mine:
        return None
    return max(mine, key=lambda c: version_key(c.name))


def _pretty(distro: str, variant: str) -> str:
    return f"{distro.replace('-', ' ').title()} {variant.replace('-', ' ').title()}"


def _raw_node(doc: dict, distro: str, variant: str) -> dict | None:
    node = ((doc.get("distros") or {}).get(distro) or {}).get("variants") or {}
    entry = node.get(variant)
    return dict(entry) if isinstance(entry, dict) else None


def _node_url(node: dict) -> str:
    return str((node.get("params") or {}).get("url") or node.get("url") or "")


def _set_node_url(node: dict, url: str) -> None:
    if isinstance(node.get("params"), dict) and "url" in node["params"]:
        node["params"]["url"] = url
    else:
        node["url"] = url


def _basename(name: str) -> str:
    """SourceForge names a candidate by its full path, every other lister by filename."""
    return name.rsplit("/", 1)[-1]


def _suffix(name: str) -> str:
    tail = _basename(name)
    return tail[tail.index(".") :] if "." in tail else ""


def _confirms(release: Release, candidate: Candidate) -> str | None:
    """Did the synthesized node resolve to *the artifact that produced the key*?

    This is what makes a proposal evidence rather than a guess. A node that resolves
    to the sibling's ISO is a silent duplicate variant, and that is precisely what a
    plausible-but-wrong substitution yields.

    What "the artifact" means depends on what was enumerated:

    * A `.torrent` row names an ISO it does not share a filename with, so the test is
      that the release points at *that torrent*. Comparing `filename` here would
      compare `x.iso` to `x.iso.torrent` and reject every torrent-only variant.
    * Aurora's rows are ISOs and SourceForge's are paths ending in one, so the
      filename must match.
    * Neon's rows are *directories* -- the ISO sits two segments below one -- so the
      resolved download must live under the directory the key came from. Comparing a
      filename to a directory name would reject every neon edition forever, on a
      technicality, in a message no reader could act on.
    """
    if _basename(candidate.name).endswith(".torrent"):
        if release.torrent_url != candidate.url:
            return f"resolved to torrent `{release.torrent_url}`, not the one behind this key"
    elif _suffix(candidate.name):
        if release.filename != _basename(candidate.name):
            return f"resolved to `{release.filename}`, not the artifact behind this key"
    elif not candidate.url:
        # No extension and no URL: nothing ties this release to the key. Today every
        # lister sets one, and "cannot happen" is what was said about `enumerable`.
        return "no artifact or URL to confirm this key against"
    elif not (release.download_url or "").startswith(candidate.url):
        return f"resolved to `{release.download_url}`, which is outside `{candidate.url}`"
    if not (release.checksum or release.signature_url or release.info_hash):
        return "resolves, but publishes no checksum, signature or infohash"
    return None


# A number, unless it sits inside a word. `q4os` and `i3` are names; `6.7` and the
# `1` of `r1` are values. Loosening the `4` of `q4os` yields a regex that works and
# reads like a mistake -- and this one gets committed for a human to review.
_NUMBER = re.compile(r"(?<![A-Za-z])\d+(?:\.\d+)*|(?<=[A-Za-z])\d+(?:\.\d+)*(?![A-Za-z])")


def generalize(name: str) -> str:
    """An anchored `match` for exactly this artifact, with its numbers loosened.

    `q4os-6.7-x64-tde.r1.iso` becomes `q4os\\-[0-9.]+\\-x[0-9.]+\\-tde\\.r[0-9.]+\\.iso$`,
    which survives the next release and the next revision. Every literal is escaped,
    so a `.` in the name cannot become a wildcard.
    """
    out, last = [], 0
    for m in _NUMBER.finditer(name):
        out.append(re.escape(name[last : m.start()]))
        out.append("[0-9.]+")
        last = m.end()
    out.append(re.escape(name[last:]))
    return "".join(out) + "$"


def _node_match_key(node: dict) -> str | None:
    if isinstance(node.get("params"), dict) and "match" in node["params"]:
        return "params"
    return "match" if "match" in node else None


def _nodes_for(node: dict, sibling_sample: str, candidate: Candidate) -> list[dict]:
    """Candidate config nodes for one discovered artifact, best first.

    Three mechanisms. Each later one exists because the one above it cannot express
    an *insertion*, and an insertion is how most distros name a new edition.

    1. **Token substitution.** Whatever the two filenames say changed, changes --
       everywhere in the node. Garuda's `match` names its edition twice, once in a
       path and once in a filename, and both move together. This is first because it
       inherits a regex that was already correct for the sibling, so the diff a human
       reviews is one word.

    2. **The observed URL.** Aurora publishes `aurora-nvidia-open-stable-...` beside
       `aurora-stable-...`: an insertion, so (1) correctly declines. But enumeration
       already saw that artifact's real URL. Copying an address the server handed us
       is not a guess, and for a fixed-URL strategy it is the entire config.

       Guarded on the file extension matching the sibling's URL, because a candidate
       is not always the artifact: neon's rows are *directories*, and the ISO lives
       two segments below one. There, (1) is the only sound path.

    3. **A match generalized from the artifact.** Q4OS publishes `q4os-6.7-x64.r1.iso`
       and `q4os-6.7-x64-tde.r1.iso` -- an insertion again, on a strategy with no URL
       to copy. The artifact's own name, escaped and with its numbers loosened, is a
       `match` that selects it and nothing else. Last, because it discards the
       sibling's hand-tuned regex for a mechanical one.

    A `.torrent` candidate is always case (3), and additionally carries
    `torrent_only: true`. Kali's siblings all `match` an `\\.iso$`; appending
    `.torrent` is an insertion, so substitution declines and no amount of copying a
    sibling would ever produce a working node. Without this branch a new torrent-only
    edition is reported "could not synthesize" every week until a human notices.
    """
    out: list[dict] = []
    is_torrent = _basename(candidate.name).endswith(".torrent")

    if not is_torrent and (tokens := diff_tokens(sibling_sample, candidate.name)):
        out.append(substitute(node, tokens))

    url = _node_url(node)
    if not is_torrent and url and candidate.url and _suffix(url) == _suffix(candidate.url) != "":
        observed = copy.deepcopy(node)
        _set_node_url(observed, candidate.url)
        out.append(observed)

    if (where := _node_match_key(node)) and _suffix(candidate.name):
        derived = copy.deepcopy(node)
        target = derived["params"] if where == "params" else derived
        # The full name, not the basename: SourceForge's `match` anchors on a path.
        target["match"] = generalize(candidate.name)
        if is_torrent:
            # Beside `match`, not at the node's top level: a sibling that is already
            # torrent-only carries it in `params`, and writing both would commit a
            # duplicated key for a human to puzzle over.
            target["torrent_only"] = True
        out.append(derived)

    return out


def propose_for(
    source: Source,
    specs: list[VariantSpec],
    candidates: list[Candidate],
    doc: dict,
    client: Client,
) -> tuple[list[Proposal], list[Rejected]]:
    """Synthesize and verify a config node for each discovered key."""
    strategy = REGISTRY[source.variants[0].strategy]()
    group_field = (source.discover or {}).get("group_field")

    # Every configured variant, paired with the artifact it selects today and the
    # raw YAML node it is written as. A sibling with neither is no use as a model.
    siblings = []
    for variant in source.variants:
        node = _raw_node(doc, source.name, variant.name)
        claimed = _claimed(strategy, variant.params, candidates)
        if node and claimed:
            siblings.append((variant, claimed, node))

    proposals: list[Proposal] = []
    rejected: list[Rejected] = []

    for spec in specs:
        sample = str(spec.params.get("sample") or "")
        row = spec.params.get("row") or {}
        if not siblings:
            rejected.append(
                Rejected(source.name, spec.variant, sample, "no configured variant to copy from")
            )
            continue

        # Closest sibling first: the one whose artifact name differs least is the one
        # whose regex needs the smallest, most reviewable change.
        ranked = sorted(
            siblings,
            key=lambda s: SequenceMatcher(None, s[1].name, sample, autojunk=False).ratio(),
            reverse=True,
        )

        why = "no sibling produced a node that resolves to this artifact"
        found = None
        for variant, claimed, node in ranked:
            candidate = Candidate(name=sample, url=spec.params.get("url"), row=row)
            for new_node in _nodes_for(node, claimed.name, candidate):
                new_node["label"] = _pretty(source.name, spec.variant)

                # Fedora's Mate ships as `Fedora-MATE_Compiz-Live-...` while its
                # subvariant is `Mate`. A filename diff cannot know that; the row can.
                # Where a distro groups on a structured field, the field wins.
                select = new_node.get("select") or (new_node.get("params") or {}).get("select")
                if group_field and isinstance(select, dict) and group_field in row:
                    select[group_field] = row[group_field]

                params = {**source.variants[0].params, **(new_node.get("params") or {})}
                params.update({k: v for k, v in new_node.items() if k not in ("label", "params")})
                params["label"] = new_node["label"]

                try:
                    release = strategy.resolve(source.name, spec.variant, params, client)
                except Exception as exc:  # a synthesized regex must never abort discovery
                    why = f"resolve raised {type(exc).__name__}: {exc}"
                    continue

                if release is None:
                    why = "synthesized config resolved to nothing"
                    continue
                if problem := _confirms(release, candidate):  # the teeth
                    why = problem
                    continue

                found = Proposal(source.name, spec.variant, new_node, release, variant.name)
                break
            if found:
                break

        if found:
            proposals.append(found)
        else:
            rejected.append(Rejected(source.name, spec.variant, sample, why))

    return proposals, rejected


def pr_body(proposals: list[Proposal], rejected: list[Rejected]) -> str:
    """The evidence, so review is reading a table rather than trusting a name."""
    lines = ["## Proposed variants", ""]

    if proposals:
        lines += [
            "Each row was synthesized from the sibling named, then **resolved live**. "
            "Every artifact below was fetched and its checksum read; nothing here is a "
            "placeholder. Labels are generated -- reword them.",
            "",
            "| Variant | Copied from | Artifact | Version | Verify | Source |",
            "|---|---|---|---|---|---|",
        ]
        for p in sorted(proposals, key=lambda p: p.key):
            algo = f" ({p.release.checksum_algo})" if p.release.checksum_algo else ""
            # A torrent-only variant has no HTTP artifact. Say which one it is, or a
            # reviewer cannot tell why the node carries `torrent_only: true`.
            source = f"[torrent]({p.release.torrent_url})" if not p.release.download_url else "http"
            lines.append(
                f"| `{p.key}` | `{p.sibling}` | `{p.release.filename}` | "
                f"`{p.release.version}` | {p.release.verify}{algo} | {source} |"
            )
        lines.append("")
    else:
        lines += ["None.", ""]

    if rejected:
        lines += [
            "## Could not synthesize",
            "",
            "Upstream publishes these and no variant tracks them, but no config node "
            "could be generated that resolves to them. They need a human.",
            "",
            "| Variant | Artifact | Why |",
            "|---|---|---|",
        ]
        for r in sorted(rejected, key=lambda r: r.key):
            lines.append(f"| `{r.key}` | `{r.sample or '-'}` | {r.reason} |")
        lines.append("")

    return "\n".join(lines)
