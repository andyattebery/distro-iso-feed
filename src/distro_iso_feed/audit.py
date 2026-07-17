"""What does each upstream publish that we don't track, and why don't we?

Two findings are signal:

  UNEXPLAINED  an edition upstream publishes that no variant tracks
  PINNED       a source frozen to a literal release

`PINNED` is the more dangerous, and the one no other check in this repo can see.
A missing variant is visible -- nothing appears in the feed. A pinned one resolves
cleanly, publishes a valid checksum, and serves a stale release forever.

**Why this compares keys, not artifacts.** The first draft diffed every artifact an
upstream publishes against every artifact a variant selects, then classified the
difference (superseded / other arch / prerelease / sidecar). Run live, it produced
259 findings: `.sig` files, `.zsync` files, atom tags, and eight years of retired
EndeavourOS ISOs. That is precisely the unreadable noise this module exists to
prevent -- and every one of those categories is *already* filtered, structurally,
by the `group` regex that discovery uses. None of them produce a variant key.

So the audit asks the question discovery already answers: which keys does this
upstream yield that the config does not have? Same finding, no classifier, and the
audit cannot drift from the discovery it explains.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from . import escalate
from .client import Client
from .escalate import endpoint_of
from .models import Source
from .strategies import REGISTRY

# Params that name *what gets fetched*. A release literal here freezes the source.
# `version_pattern` is excluded on purpose: EndeavourOS's `(\d{4}\.\d{2}\.\d{2})`
# and Batocera's `([0-9.]+-\d{8})` are token *extractors*, not locations. `torrent`
# is a fetched artifact location like `url`; `torrent_sums` parallels `sums` (a
# checksum file, not the artifact) and is not audited, same as `sums`.
LOCATION_PARAMS = ("url", "index", "path", "match", "torrent")

# A release-shaped literal: `24.04`, `13.5`, `antiX-26`.
#
# The trailing lookahead on the second alternative keeps `cinnamon-64bit` out. That
# false positive is not hypothetical -- Mint's `match` carries it, and it stayed
# invisible only because Mint reads its release from `version_dir` and is skipped
# before the scan. The first distro to pin a bare `match` would have inherited it.
_RELEASE_LITERAL = re.compile(
    r"(?<![\d\\{])\d{2}\.\d{1,2}(?![\d}])|[A-Za-z]+-\d{2}(?![\d.\-\]_a-zA-Z])"
)

# The variant discovers its release some other way, so a literal cannot freeze it.
_DYNAMIC = ("version_dir", "probe_versions")


class Reason(StrEnum):
    UNEXPLAINED = "UNEXPLAINED"
    PINNED = "PINNED"
    UNRESOLVABLE = "UNRESOLVABLE"
    NOT_ENUMERABLE = "NOT_ENUMERABLE"
    LISTER_FAILED = "LISTER_FAILED"

    @property
    def is_signal(self) -> bool:
        return self in (Reason.UNEXPLAINED, Reason.PINNED, Reason.UNRESOLVABLE)


@dataclass(frozen=True, slots=True)
class Finding:
    distro: str
    reason: Reason
    subject: str
    detail: str = ""


def pins(source: Source) -> list[Finding]:
    """Location params carrying a release literal, with no dynamic release lookup."""
    out: list[Finding] = []
    for variant in source.variants:
        if any(variant.params.get(k) for k in _DYNAMIC) or variant.params.get("pinned_ok"):
            continue
        for key in LOCATION_PARAMS:
            value = str(variant.params.get(key, ""))
            if m := _RELEASE_LITERAL.search(value):
                out.append(
                    Finding(
                        distro=source.name,
                        reason=Reason.PINNED,
                        subject=f"{variant.name}:{key}",
                        detail=f"literal `{m.group(0)}` in `{value}`",
                    )
                )
    return out


def unresolvable(source: Source, client: Client) -> list[Finding]:
    """Configured variants that produce no artifact at all.

    The config->upstream direction, and the one the rest of this module does not cover: everything
    else here asks which keys upstream yields that the config lacks. Nothing asked the reverse --
    does this key we wrote down actually name something real? The docs handed that job to the audit
    ("a never-resolved config problem is `distro-iso-feed-audit`'s job at add time") and the check
    was never built, so `ubuntu-unity:desktop-interim` sat dead from the day it was added: it asked
    for a non-LTS Ubuntu Unity, and Ubuntu Unity ships LTS only.

    Discovery already proves this for anything it proposes (`propose_variants` drops a candidate
    that "resolved to nothing"). This gives hand-written config the same proof.

    **Structural only.** A variant that fails to resolve because a mirror timed out is stale, not
    wrong -- reporting it would turn a bad night at cdimage into a wall of false findings. The
    `trace` slice is marked per variant, exactly as `run_refresh.diagnose` does it.
    """
    out: list[Finding] = []
    for variant in source.variants:
        params = dict(variant.params)
        params.setdefault("label", variant.label)
        params.setdefault("page_url", source.page_url)
        mark = len(client.trace)
        strategy = REGISTRY[variant.strategy]()
        try:
            release = strategy.resolve(source.name, variant.name, params, client)
        except Exception as exc:
            # Same classifier the refresh uses: a network error (or a `SumsUnavailable` that
            # declares itself transient) is a sick mirror; a parse/key/type error is a real
            # config or code problem worth naming.
            if escalate.exc_class(exc) == escalate.TRANSIENT:
                continue
            out.append(
                Finding(source.name, Reason.UNRESOLVABLE, variant.name, f"resolve raised {exc}")
            )
            continue
        if release is not None:
            continue
        outcomes = [o for _, o in client.trace[mark:]]
        if escalate.classify_outcomes(outcomes) == escalate.TRANSIENT:
            continue  # a sick mirror, not a dead variant -- it will be back tomorrow
        out.append(
            Finding(
                source.name,
                Reason.UNRESOLVABLE,
                variant.name,
                f"resolves to nothing at {endpoint_of(params)}",
            )
        )
    return out


def audit_source(source: Source, client: Client) -> list[Finding]:
    """Pins, unresolvable variants, plus every edition upstream publishes that no variant tracks."""
    findings = pins(source) + unresolvable(source, client)
    discover = source.discover or {}

    # A source that cannot be enumerated has nothing to diff. Its variants are still
    # checked for pins and resolvability above -- the axes are independent, and Pop's pin hid
    # for a week behind exactly this label (as did unity's dead variant, whose declared reason
    # was the very channel mechanic that broke it).
    if discover.get("enumerable") is False:
        findings.append(
            Finding(source.name, Reason.NOT_ENUMERABLE, "-", discover.get("reason", ""))
        )
        return findings

    if not discover.get("group"):
        return findings

    strategy = REGISTRY[source.variants[0].strategy]()
    variant_params = [dict(v.params) for v in source.variants]

    try:
        found = strategy.discover_all(source.name, variant_params, discover, client)
    except Exception as exc:  # a broken lister must not abort the audit
        findings.append(
            Finding(source.name, Reason.LISTER_FAILED, "-", f"{type(exc).__name__}: {exc}")
        )
        return findings

    configured = {v.name for v in source.variants}
    for spec in found:
        if spec.variant not in configured:
            findings.append(
                Finding(
                    source.name,
                    Reason.UNEXPLAINED,
                    spec.variant,
                    f"`{spec.params.get('sample', '')}`",
                )
            )
    return findings


def report(findings: list[Finding]) -> str:
    """Markdown. Signal first; everything else collapsed to a count."""
    signal = [f for f in findings if f.reason.is_signal]
    quiet = [f for f in findings if not f.reason.is_signal]

    lines = ["## distro-iso-feed audit", ""]
    if not signal:
        lines += ["No untracked editions, no pinned releases.", ""]
    else:
        lines += ["| Distro | Finding | Subject | Detail |", "|---|---|---|---|"]
        for f in sorted(signal, key=lambda f: (f.reason.value, f.distro, f.subject)):
            lines.append(f"| `{f.distro}` | **{f.reason.value}** | `{f.subject}` | {f.detail} |")
        lines.append("")

    failed = [f for f in quiet if f.reason is Reason.LISTER_FAILED]
    if failed:
        lines += ["### Listers that failed (upstream reachable?)", ""]
        for f in failed:
            lines.append(f"- `{f.distro}`: {f.detail}")
        lines.append("")

    skipped = [f for f in quiet if f.reason is Reason.NOT_ENUMERABLE]
    if skipped:
        lines += ["<details><summary>Not enumerable (by declared reason)</summary>", ""]
        for f in sorted(skipped, key=lambda f: f.distro):
            lines.append(f"- `{f.distro}` — {f.detail}")
        lines += ["", "</details>", ""]

    return "\n".join(lines)
