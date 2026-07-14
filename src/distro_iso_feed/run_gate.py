"""`distro-iso-feed-refresh-gate` -- turn a refresh report into an issue/exit plan, purely.

The daily refresh writes a JSON report and always renders (a regressed source is stale, not fatal).
This reads that report plus the currently-open `refresh-*` issues (from `gh issue list --json`), and
prints the plan `escalate.plan_escalation` computed: which issues to open, which to close, and the
exit code the job should end with. It **always exits 0 itself** -- the emitted `exit_code` is what
the workflow ends with, AFTER it has run the (best-effort) `gh issue` calls, so a GitHub API hiccup
can neither mask a real regression nor invent one. All the policy is in `escalate` and unit-tested;
this is just I/O.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .escalate import plan_escalation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-refresh-gate")
    parser.add_argument("--report", required=True, metavar="FILE", help="the refresh report JSON")
    parser.add_argument(
        "--open-issues",
        metavar="FILE",
        help="JSON array from `gh issue list --json number,title,labels` (default: none open)",
    )
    args = parser.parse_args(argv)

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    open_issues = (
        json.loads(Path(args.open_issues).read_text(encoding="utf-8")) if args.open_issues else []
    )
    plan = plan_escalation(report, open_issues)
    print(json.dumps(plan, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
