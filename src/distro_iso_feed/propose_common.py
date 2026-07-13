"""Shared machinery for the three discovery proposers (`propose_variants`, `propose_arches`,
`propose_families`).

The result types (`Proposal`/`ArchProposal`/`FamilyProposal`/`Rejected`), the resolve-to-verify
teeth, and the PR-body table live here so every proposer builds on one base rather than importing
from another. A proposal is only ever written after it resolved against live upstream, so a merged
PR is mergeable as-is. Two strengths of teeth: `_confirms` cross-checks a variant against the
independent exemplar that produced its key; `carries_integrity` is the honest floor for arch and
family, whose token is substituted into both path and match so identity is guaranteed by
construction and only "does it publish a verifier" is left to prove.
"""

from __future__ import annotations

from dataclasses import dataclass

from .listers import Candidate
from .models import Release


@dataclass(frozen=True, slots=True)
class Proposal:
    """A discovered variant, synthesized into a config node and resolved."""

    distro: str
    variant: str
    node: dict
    release: Release
    sibling: str

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.variant}"


@dataclass(frozen=True, slots=True)
class ArchProposal:
    """A discovered architecture for an existing variant: one `arches` map line, resolved."""

    distro: str
    variant: str
    arch: str  # canonical (x86_64/aarch64/...) -- the `arches` map key
    token: str  # upstream token (amd64/arm64/...) -- the map value
    release: Release

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.variant}"


@dataclass(frozen=True, slots=True)
class FamilyProposal:
    """A discovered family member: a whole new distro block, cloned from a model and resolved."""

    family: str
    distro: str
    node: dict  # the synthesized distro block
    release: Release  # the model variant, resolved for the member, that proved it real

    @property
    def key(self) -> str:
        return self.distro


@dataclass(frozen=True, slots=True)
class Rejected:
    distro: str
    variant: str
    sample: str
    reason: str

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.variant}"


def _basename(name: str) -> str:
    """SourceForge names a candidate by its full path, every other lister by filename."""
    return name.rsplit("/", 1)[-1]


def _suffix(name: str) -> str:
    tail = _basename(name)
    return tail[tail.index(".") :] if "." in tail else ""


def carries_integrity(release: Release) -> str | None:
    """A resolved release must publish something a consumer can verify against, else the proposal
    is a name with nothing behind it. `None` if it does, a reason if it does not.

    This is the *whole* verification for arch and family discovery: their token is substituted into
    both the path AND the match, so a resolving artifact is necessarily the one behind the key --
    identity is guaranteed by construction, and only "does it carry integrity" is left to check.
    Variant discovery layers the artifact cross-check (`_confirms`) on top, because it enumerated an
    independent exemplar that the synthesized node could plausibly-but-wrongly miss.
    """
    if not (release.checksum or release.signature_url or release.info_hash):
        return "resolves, but publishes no checksum, signature or infohash"
    return None


def _confirms(release: Release, candidate: Candidate) -> str | None:
    """Did the synthesized config resolve to *the artifact that produced the key*? (Variant
    discovery only -- it has an independent enumerated exemplar to cross-check against.)

    A node that resolves to the sibling's ISO is a silent duplicate variant, and that is precisely
    what a plausible-but-wrong substitution yields. What "the artifact" means depends on what was
    enumerated:

    * A `.torrent` row names an ISO it does not share a filename with, so the test is that the
      release points at *that torrent*. Comparing `filename` here would compare `x.iso` to
      `x.iso.torrent` and reject every torrent-only variant.
    * Aurora's rows are ISOs and SourceForge's are paths ending in one, so the filename must match.
    * Neon's rows are *directories* -- the ISO sits two segments below one -- so the resolved
      download must live under the directory the key came from. Comparing a filename to a directory
      name would reject every neon edition forever, on a technicality, in a message no reader could
      act on.
    """
    if _basename(candidate.name).endswith(".torrent"):
        if release.torrent_url != candidate.url:
            return f"resolved to torrent `{release.torrent_url}`, not the one behind this key"
    elif _suffix(candidate.name):
        if release.filename != _basename(candidate.name):
            return f"resolved to `{release.filename}`, not the artifact behind this key"
    elif not candidate.url:
        # No extension and no URL: nothing ties this release to the key. Today every lister sets
        # one, and "cannot happen" is what was said about `enumerable`.
        return "no artifact or URL to confirm this key against"
    elif not (release.download_url or "").startswith(candidate.url):
        return f"resolved to `{release.download_url}`, which is outside `{candidate.url}`"
    return carries_integrity(release)


def pr_body(
    proposals: list[Proposal],
    arch_proposals: list[ArchProposal],
    family_proposals: list[FamilyProposal],
    rejected: list[Rejected],
) -> str:
    """The evidence, so review is reading a table rather than trusting a name. Sections are
    emitted in parameter order: variants, architectures, flavors, could-not-synthesize."""
    lines: list[str] = ["## Proposed variants", ""]

    if proposals:
        lines += [
            "Each row was synthesized from the sibling named, then **resolved live**. Every "
            "artifact below was fetched and its checksum read; nothing here is a placeholder. "
            "Labels are generated -- reword them.",
            "",
            "| Variant | Copied from | Artifact | Version | Verify | Source |",
            "|---|---|---|---|---|---|",
        ]
        for p in sorted(proposals, key=lambda p: p.key):
            algo = f" ({p.release.checksum_algo})" if p.release.checksum_algo else ""
            # A torrent-only variant has no HTTP artifact. Say which one it is, or a reviewer
            # cannot tell why the node carries `torrent_only: true`.
            source = f"[torrent]({p.release.torrent_url})" if not p.release.download_url else "http"
            lines.append(
                f"| `{p.key}` | `{p.sibling}` | `{p.release.filename}` | "
                f"`{p.release.version}` | {p.release.verify}{algo} | {source} |"
            )
        lines.append("")
    else:
        lines += ["None.", ""]

    if arch_proposals:
        lines += [
            "## Proposed architectures",
            "",
            "Each architecture was resolved live against its own directory before being written "
            "into the variant's `arches` map. The runtime is unaffected -- these only add config.",
            "",
            "| Variant | Arch | Token | Artifact | Version | Verify |",
            "|---|---|---|---|---|---|",
        ]
        for a in sorted(arch_proposals, key=lambda a: (a.key, a.arch)):
            algo = f" ({a.release.checksum_algo})" if a.release.checksum_algo else ""
            lines.append(
                f"| `{a.key}` | `{a.arch}` | `{a.token}` | `{a.release.filename}` | "
                f"`{a.release.version}` | {a.release.verify}{algo} |"
            )
        lines.append("")

    if family_proposals:
        lines += [
            "## Proposed flavors",
            "",
            "A new member of a family root, cloned from the model distro and **resolved live** "
            "before proposal. The `version_dir`/`version_pattern`/`match` are executed and "
            "correct; the **label and page_url are best-effort from the member name -- review**.",
            "",
            "| Distro | Family | Artifact | Version | Verify |",
            "|---|---|---|---|---|",
        ]
        for f in sorted(family_proposals, key=lambda f: f.key):
            algo = f" ({f.release.checksum_algo})" if f.release.checksum_algo else ""
            lines.append(
                f"| `{f.distro}` | `{f.family}` | `{f.release.filename}` | "
                f"`{f.release.version}` | {f.release.verify}{algo} |"
            )
        lines.append("")

    if rejected:
        lines += [
            "## Could not synthesize",
            "",
            "Upstream publishes these and no variant tracks them, but no config node could be "
            "generated that resolves to them. They need a human.",
            "",
            "| Variant | Artifact | Why |",
            "|---|---|---|",
        ]
        for r in sorted(rejected, key=lambda r: r.key):
            lines.append(f"| `{r.key}` | `{r.sample or '-'}` | {r.reason} |")
        lines.append("")

    return "\n".join(lines)
