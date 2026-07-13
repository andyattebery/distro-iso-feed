"""Weekly discovery: propose new variants and new *family members*, never removals.

Opening a PR rather than committing is the checkpoint against a bad enumeration
silently adding junk. Discovery proposes new *variants* of already-configured distros
and, for a declared `families:` root, new *distro blocks* for members it does not yet
track -- but never re-adds a distro left out on purpose: a variant needs a configured
sibling, and a family member stays out via the family's `ignore` list.

Every proposal is resolved against the live upstream before it is written, so the
branch this opens is mergeable as-is rather than a list of `TODO`s. What could not
be synthesized is reported too -- a discovery run that silently drops what it cannot
explain is how eight Fedora spins stayed missing.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .client import Client
from .config import load, load_raw, yaml_rt
from .propose_arches import propose_arches
from .propose_common import ArchProposal, FamilyProposal, Proposal, Rejected, pr_body
from .propose_families import propose_families
from .propose_variants import propose_for
from .strategies import REGISTRY

log = logging.getLogger("distro-iso-feed-discover")

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "sources.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-discover")
    parser.add_argument("--dry-run", action="store_true", help="print proposals; write nothing")
    parser.add_argument("--only", metavar="DISTRO", help="restrict to one distro")
    parser.add_argument("--config", metavar="FILE", help="read and write this config instead")
    parser.add_argument("--pr-body", metavar="FILE", help="write the evidence table here")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    config = Path(args.config) if args.config else CONFIG
    defaults, all_sources = load(config, set(REGISTRY))
    sources = all_sources
    if args.only:
        sources = [s for s in all_sources if s.name == args.only]
        if not sources:
            log.error("no distro named %s", args.only)
            return 2

    doc = load_raw(config)
    proposals: list[Proposal] = []
    arch_proposals: list[ArchProposal] = []
    family_proposals: list[FamilyProposal] = []
    rejected: list[Rejected] = []

    with Client(defaults["user_agent"]) as client:
        for source in sources:
            # Arch discovery is orthogonal to the variant-`enumerable` flag -- it enumerates the
            # arches of an already-known variant -- so it runs regardless, gated only on the
            # variant carrying an `arches` map.
            try:
                arch_proposals.extend(propose_arches(source, doc, client))
            except Exception as exc:
                log.warning(
                    "%s: arch discovery raised %s: %s", source.name, type(exc).__name__, exc
                )

            if source.discover.get("enumerable") is False:
                continue

            strategy = REGISTRY[source.variants[0].strategy]()
            variant_params = [dict(v.params) for v in source.variants]
            try:
                found = strategy.discover_all(source.name, variant_params, source.discover, client)
                candidates = strategy.enumerate_all(
                    source.name, variant_params, source.discover, client
                )
            except Exception as exc:
                log.warning("%s: discovery raised %s: %s", source.name, type(exc).__name__, exc)
                continue

            configured = {v.name for v in source.variants}
            specs = [s for s in found if s.variant not in configured]
            if not specs:
                continue

            new, bad = propose_for(source, specs, candidates, doc, client)
            proposals.extend(new)
            rejected.extend(bad)

        # Family discovery proposes whole new distro blocks; it needs the FULL tracked set to know
        # what already exists, and it is a whole-catalog scan, so it is skipped under `--only`.
        if not args.only:
            try:
                family_proposals.extend(propose_families(all_sources, doc, client))
            except Exception as exc:
                log.warning("family discovery raised %s: %s", type(exc).__name__, exc)

    for p in proposals:
        log.info("propose %s -> %s (from %s)", p.key, p.release.filename, p.sibling)
    for a in arch_proposals:
        log.info("propose arch %s:%s -> %s", a.key, a.arch, a.release.filename)
    for f in family_proposals:
        log.info("propose flavor %s (family %s) -> %s", f.distro, f.family, f.release.filename)
    for r in rejected:
        log.warning("cannot synthesize %s: %s", r.key, r.reason)

    if args.pr_body:
        body = pr_body(proposals, arch_proposals, rejected, family_proposals)
        Path(args.pr_body).write_text(body, encoding="utf-8")

    if not proposals and not arch_proposals and not family_proposals:
        log.info("no new variants, arches or flavors (%d could not be synthesized)", len(rejected))
        return 0

    if args.dry_run:
        return 0

    for p in proposals:
        doc["distros"][p.distro]["variants"].setdefault(p.variant, p.node)
    for a in arch_proposals:
        # The `arches` map already exists (discovery only runs on variants that carry one).
        doc["distros"][a.distro]["variants"][a.variant]["arches"][a.arch] = a.token
    for f in family_proposals:
        doc["distros"].setdefault(f.distro, f.node)  # a whole new distro block
    with config.open("w", encoding="utf-8") as fh:
        yaml_rt().dump(doc, fh)  # round-trip: comments survive
    log.info(
        "wrote %d variants, %d arches and %d flavors into %s",
        len(proposals),
        len(arch_proposals),
        len(family_proposals),
        config,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
