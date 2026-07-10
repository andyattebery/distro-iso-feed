"""`distro-iso-feed-audit` -- what does upstream publish that we don't track?

Runs live against every source. Not a test: an upstream adding a spin must not turn
an unrelated pull request red. `discover.yml` runs it weekly and posts the report to
the job summary, where it is read alongside the proposals it explains.

`--strict` exits 1 on UNEXPLAINED **or** PINNED. Both are signal; a strict mode that
ignored half its findings would be theatre.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .audit import Reason, audit_source, report
from .client import Client
from .config import load
from .strategies import REGISTRY

log = logging.getLogger("distro-iso-feed-audit")

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "sources.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-audit")
    parser.add_argument("--only", metavar="DISTRO", help="restrict to one distro")
    parser.add_argument("--strict", action="store_true", help="exit 1 on any signal finding")
    parser.add_argument("--summary", metavar="FILE", help="append the markdown report")
    parser.add_argument("--config", metavar="FILE", help="audit this config instead")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    defaults, sources = load(Path(args.config) if args.config else CONFIG, set(REGISTRY))
    if args.only:
        sources = [s for s in sources if s.name == args.only]
        if not sources:
            log.error("no distro named %s", args.only)
            return 2

    findings = []
    with Client(defaults["user_agent"]) as client:
        for source in sources:
            findings.extend(audit_source(source, client))

    text = report(findings)
    print(text)
    if args.summary:
        with Path(args.summary).open("a", encoding="utf-8") as fh:
            fh.write(text)

    signal = [f for f in findings if f.reason.is_signal]
    unexplained = sum(1 for f in signal if f.reason is Reason.UNEXPLAINED)
    pinned = sum(1 for f in signal if f.reason is Reason.PINNED)
    log.info("%d unexplained, %d pinned, %d sources", unexplained, pinned, len(sources))

    return 1 if (args.strict and signal) else 0


if __name__ == "__main__":
    sys.exit(main())
