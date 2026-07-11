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
from .strategies._common import BAD, verify_signing_key

log = logging.getLogger("distro-iso-feed-audit")

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "sources.yaml"


def verify_signing_keys(sources, client) -> list[str]:
    """Run the build-time gate over one gpg variant per distro that pins a key.

    The pin is per-distro, so a single representative variant proves the pinned key
    still verifies the current artifact. Returns the keys ("distro:variant") whose
    signature no longer chains to the pin -- a rotated key or a config typo.
    """
    failures: list[str] = []
    for source in sources:
        if not source.variants[0].params.get("signing_key"):
            continue
        for variant in source.variants:
            params = dict(variant.params)
            params.setdefault("label", variant.label)
            params.setdefault("page_url", source.page_url)
            try:
                release = REGISTRY[variant.strategy]().resolve(
                    source.name, variant.name, params, client
                )
            except Exception:  # a dead mirror must not fail the key audit
                release = None
            if release is None or not release.signature_url:
                continue
            _, outcome = verify_signing_key(client, release, params)
            if outcome == BAD:
                failures.append(variant.key)
            break  # one representative per distro is enough; the key is per-distro
    return failures


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
        key_failures = verify_signing_keys(sources, client)

    text = report(findings)
    print(text)
    if key_failures:
        text += "\n## Signing-key verification FAILED\n\n" + "".join(
            f"- `{k}`: signature no longer chains to the pinned key\n" for k in key_failures
        )
        print("\n".join(f"SIGNING-KEY FAIL: {k}" for k in key_failures))
    if args.summary:
        with Path(args.summary).open("a", encoding="utf-8") as fh:
            fh.write(text)

    signal = [f for f in findings if f.reason.is_signal]
    unexplained = sum(1 for f in signal if f.reason is Reason.UNEXPLAINED)
    pinned = sum(1 for f in signal if f.reason is Reason.PINNED)
    log.info(
        "%d unexplained, %d pinned, %d signing-key failures, %d sources",
        unexplained,
        pinned,
        len(key_failures),
        len(sources),
    )

    return 1 if (args.strict and (signal or key_failures)) else 0


if __name__ == "__main__":
    sys.exit(main())
