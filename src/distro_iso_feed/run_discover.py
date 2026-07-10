"""Weekly discovery: propose new variants, never new distros, never removals.

Opening a PR rather than committing is the checkpoint against a bad enumeration
silently adding junk. And because only *variants* of already-configured distros are
proposed, nothing here can ever re-add a distro that was deliberately left out.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .client import Client
from .config import load, load_raw, yaml_rt
from .strategies import REGISTRY

log = logging.getLogger("distro-iso-feed-discover")

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "sources.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-discover")
    parser.add_argument("--dry-run", action="store_true", help="print proposals; write nothing")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    defaults, sources = load(CONFIG, set(REGISTRY))
    proposals: list[tuple[str, str]] = []

    with Client(defaults["user_agent"]) as client:
        for source in sources:
            if not source.discover:
                continue
            configured = {v.name for v in source.variants}
            sample = source.variants[0]
            strategy = REGISTRY[sample.strategy]()
            params = dict(sample.params)
            params["discover"] = source.discover

            try:
                found = strategy.discover_variants(source.name, params, client)
            except Exception as exc:
                log.warning("%s: discovery raised %s", source.name, type(exc).__name__)
                continue

            for spec in found:
                if spec.variant not in configured:
                    proposals.append((source.name, spec.variant))

    if not proposals:
        log.info("no new variants")
        return 0

    for distro, variant in proposals:
        print(f"{distro}: {variant}")

    if args.dry_run:
        return 0

    yaml = yaml_rt()
    doc = load_raw(CONFIG)
    for distro, variant in proposals:
        variants = doc["distros"][distro]["variants"]
        if variant not in variants:
            # Deliberately unusable placeholders: `TODO` matches nothing, so a merged
            # PR that nobody filled in leaves the variant unresolved and loudly
            # reported, rather than quietly publishing the wrong artifact.
            variants[variant] = {"match": "TODO", "version_pattern": "TODO"}
    with CONFIG.open("w", encoding="utf-8") as fh:
        yaml.dump(doc, fh)  # round-trip: comments survive
    log.info("proposed %d variants into %s", len(proposals), CONFIG)
    return 0


if __name__ == "__main__":
    sys.exit(main())
