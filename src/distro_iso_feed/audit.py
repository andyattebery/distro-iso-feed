"""What does each upstream publish that we don't track, and why don't we?

Six findings are signal:

  UNEXPLAINED      an edition upstream publishes that no variant tracks
  PINNED           a source frozen to a literal release
  UNRESOLVABLE     a configured variant that names nothing real
  NO_CHECKSUM      a variant that resolves, but without the checksum its config asks for
  NO_TORRENT       a variant that resolves, but without the torrent its config asks for
  SKIPPED_RELEASE  a newer release upstream lists that a variant fell back past

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
audit cannot drift from the discovery it explains. A key is "had" when a variant is
named for it or already selects its artifact (`propose_variants.selected`) -- the
same test discovery applies, so a variant whose name predates an upstream rename
is neither proposed again nor reported here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from . import escalate
from .client import Client
from .escalate import endpoint_of
from .models import Source
from .propose_variants import selected
from .strategies import REGISTRY
from .strategies.integrity import SumsUnavailable, expects_checksum
from .strategies.torrent import TorrentMissing, attach_torrent

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
_DYNAMIC = ("version_dir", "version_page", "probe_versions")


class Reason(StrEnum):
    UNEXPLAINED = "UNEXPLAINED"
    PINNED = "PINNED"
    UNRESOLVABLE = "UNRESOLVABLE"
    NO_CHECKSUM = "NO_CHECKSUM"
    NO_TORRENT = "NO_TORRENT"
    SKIPPED_RELEASE = "SKIPPED_RELEASE"
    NOT_ENUMERABLE = "NOT_ENUMERABLE"
    LISTER_FAILED = "LISTER_FAILED"

    @property
    def is_signal(self) -> bool:
        return self in (
            Reason.UNEXPLAINED,
            Reason.PINNED,
            Reason.UNRESOLVABLE,
            Reason.NO_CHECKSUM,
            Reason.NO_TORRENT,
            Reason.SKIPPED_RELEASE,
        )

    @property
    def opens_issue(self) -> bool:
        """Signal the weekly audit tickets: what the refresh cannot see, because everything
        resolves. PINNED has its own daily ticket, and a tracked variant that stops resolving or
        loses a file has a `refresh failure` one: one break, one ping. A variant that never
        resolved has no record to regress from, so those fail `config-audit` on its push."""
        return self in (Reason.UNEXPLAINED, Reason.SKIPPED_RELEASE)


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


def resolve_findings(source: Source, client: Client) -> list[Finding]:
    """Resolve each configured variant once: what names no artifact, and what lost its checksum.

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

    **NO_CHECKSUM and NO_TORRENT come from the same resolve**, because a second pass would fetch
    everything twice. They are the push-time half of the refresh's rule that a file the config
    names must arrive: the refresh raises it for a tracked variant, and a variant that never
    resolved has no record to regress from. A timed-out file never reaches either check.
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
            if not release.checksum and expects_checksum(params):
                out.append(
                    Finding(
                        source.name,
                        Reason.NO_CHECKSUM,
                        variant.name,
                        f"`{release.filename}` resolved without its configured checksum",
                    )
                )
            if params.get("torrent"):
                try:
                    attach_torrent(client, release, params)
                except TorrentMissing as exc:
                    detail = f"{exc.reason}: {exc.url} (status `{exc.status}`)"
                    out.append(Finding(source.name, Reason.NO_TORRENT, variant.name, detail))
                except SumsUnavailable:
                    pass  # a sick mirror, not a dead variant
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


def skipped_releases(source: Source, client: Client) -> list[Finding]:
    """Newer version dirs a variant fell back past. Resolving succeeds, so nothing else sees this:
    Leap sat on 15.6 for months beneath a `16.1/` with no `iso/`. Variants that would walk alike are
    walked once. Transient failures are left out, by the same rule `resolve_findings` applies.
    """
    out: list[Finding] = []
    walked: set[tuple[str, ...]] = set()
    for variant in source.variants:
        params = variant.params
        parent = params.get("version_dir")
        # What decides the walk's result. `channel`: Ubuntu's `-lts` and `-latest` share a listing,
        # and read different dirs. `match`: whether a dir counts as skipped depends on it.
        listing = tuple(str(params.get(k)) for k in ("version_dir", "index", "channel", "match"))
        if not parent or listing in walked:
            continue
        walked.add(listing)
        if skipped := REGISTRY[variant.strategy]().skipped_releases(dict(params), client):
            dirs = ", ".join(f"`{name}`" for name in skipped)
            detail = f"{dirs} under {parent} serve nothing this variant can use ({variant.arch})"
            out.append(Finding(source.name, Reason.SKIPPED_RELEASE, variant.name, detail))
    return out


def audit_source(source: Source, client: Client) -> list[Finding]:
    """Pins, what resolving each variant turns up, and every edition no variant tracks."""
    findings = pins(source) + resolve_findings(source, client) + skipped_releases(source, client)
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
        candidates = strategy.enumerate_all(source.name, variant_params, discover, client)
    except Exception as exc:  # a broken lister must not abort the audit
        findings.append(
            Finding(source.name, Reason.LISTER_FAILED, "-", f"{type(exc).__name__}: {exc}")
        )
        return findings

    configured = {v.name for v in source.variants}
    tracked = selected(source, candidates)
    for spec in found:
        if spec.variant not in configured and spec.params.get("sample") not in tracked:
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
