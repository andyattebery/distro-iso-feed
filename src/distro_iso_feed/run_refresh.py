"""Daily refresh: resolve every configured variant, update state, render.

Failure isolation is the whole point of the try/except: one dead mirror must never
abort the run, and a resolver returning None must never remove an entry. The feed
degrades to *stale*, never to *empty*.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

from . import docs, feed, select
from .client import Client
from .config import load
from .models import Variant
from .state import State
from .strategies import REGISTRY
from .tokens import from_filename

log = logging.getLogger("distro-iso-feed")

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "sources.yaml"
STATE = ROOT / "state" / "state.json"
FEED_DIR = ROOT / "feed"
CATALOG = ROOT / "docs" / "catalog.md"


def _selected(variants: list[Variant], only: str | None) -> list[Variant]:
    if not only:
        return variants
    if ":" in only:
        return [v for v in variants if v.key == only]
    return [v for v in variants if v.distro == only]


def endpoint_of(params: dict) -> str:
    """The URL a human should open first when a source breaks.

    `version_dir` comes before `index`, because for those sources `index` is a
    template like ``{version}/`` -- printing it tells the reader nothing.
    """
    for key in ("version_dir", "index", "url", "repo", "project"):
        if value := params.get(key):
            return str(value)
    return "?"


def diagnose(strategy, variant: Variant, params: dict, client: Client) -> str:
    """Say *why* a variant failed, because the two causes have opposite fixes.

    An unreachable endpoint is an upstream problem; a listing full of candidates
    that none of them match is a regex problem in `sources.yaml`. Reporting only
    "unresolved" leaves the reader to re-derive that distinction by hand.
    """
    try:
        candidates = strategy.candidates(variant.distro, params, client)
    except Exception as exc:
        return f"lister raised {type(exc).__name__}: {exc}"

    endpoint = endpoint_of(params)
    if not candidates:
        return f"listing empty or unreachable: {endpoint}"

    names = [c.name for c in candidates]
    match = params.get("match")
    if match:
        chosen = select.choose(
            names,
            match=match,
            ignore=params.get("ignore", ()),
            version_pattern=params.get("version_pattern"),
            sort_pattern=params.get("sort_pattern"),
        )
        if not chosen:
            sample = ", ".join(names[:3])
            return f"listed {len(names)} candidates, none matched `{match}` (e.g. {sample})"

        pattern = params.get("version_pattern")
        if pattern and not from_filename(chosen.rsplit("/", 1)[-1], pattern):
            return f"matched `{chosen}` but `version_pattern` extracted no token"

    return f"resolver returned None; {len(names)} candidates at {endpoint}"


def write_summary(
    path: Path,
    *,
    changed: list[str],
    failed: list[tuple[str, str]],
    total: int,
    dry_run: bool = False,
) -> None:
    """A run that commits nothing must still leave evidence of what it saw.

    Without this, a day on which forty sources broke looks exactly like a day on
    which nothing was released: green, silent, no commit. The run record is the
    receipt, so it carries the health of every source and, for each failure, enough
    to act on without re-running anything locally first.
    """
    lines = [
        "## distro-iso-feed-refresh" + (" (dry run)" if dry_run else ""),
        "",
        f"- resolved: **{total - len(failed)}/{total}**",
        f"- unresolved: **{len(failed)}**",
    ]
    if not dry_run:
        lines.insert(3, f"- changed: **{len(changed)}**")
    lines.append("")

    if changed:
        lines += ["### Changed", ""] + [f"- `{c}`" for c in sorted(changed)] + [""]

    if failed:
        lines += [
            "### Unresolved",
            "",
            "Entries are left untouched, so the feed is stale for these, not empty.",
            "",
            "| Variant | Why | Reproduce |",
            "|---|---|---|",
        ]
        for key, reason in sorted(failed):
            repro = f"`uv run distro-iso-feed-refresh --dry-run --only {key} -v`"
            lines.append(f"| `{key}` | {reason} | {repro} |")
        lines += [""]

    if dry_run:
        lines += ["_Dry run: nothing written, nothing committed._", ""]
    elif not changed and not failed:
        lines += ["_Nothing moved upstream; no commit._", ""]

    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-refresh")
    parser.add_argument("--dry-run", action="store_true", help="resolve and print; write nothing")
    parser.add_argument("--only", metavar="DISTRO[:VARIANT]", help="restrict to one distro/variant")
    parser.add_argument("--summary", metavar="FILE", help="append a markdown run summary")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    defaults, sources = load(CONFIG, set(REGISTRY))
    all_variants = [v for s in sources for v in s.variants]
    page_urls = {s.name: s.page_url for s in sources}
    variants = _selected(all_variants, args.only)
    if not variants:
        log.error("no variants matched --only %s", args.only)
        return 2

    state = State.load(STATE)
    failures: list[tuple[str, str]] = []
    changed: list[str] = []

    with Client(defaults["user_agent"]) as client:
        for variant in variants:
            strategy = REGISTRY[variant.strategy]()
            params = dict(variant.params)
            params.setdefault("page_url", page_urls.get(variant.distro))
            params.setdefault("label", variant.label)
            try:
                release = strategy.resolve(variant.distro, variant.name, params, client)
            except Exception as exc:  # a strategy must not take the run down with it
                reason = f"resolver raised {type(exc).__name__}: {exc}"
                log.warning("%s: %s", variant.key, reason)
                failures.append((variant.key, reason))
                continue

            if release is None:
                # Costs one extra listing, and only for variants that already failed.
                reason = diagnose(strategy, variant, params, client)
                log.warning("%s: %s (entry left untouched)", variant.key, reason)
                failures.append((variant.key, reason))
                continue

            # `hash` = the published checksum when there is one, else the infohash,
            # else a digest of the resolved artifact identity. Catches a respin whose
            # version froze. The infohash outranks a URL digest because AnduinOS's
            # torrent URL carries the version tag: a rebuild at the same version
            # moves the infohash and nothing else, which is exactly the case this
            # fallback exists to catch. It also has to cope with `download_url` being
            # None, which a torrent-only release always is.
            url_digest = hashlib.sha256(release.primary_url.encode()).hexdigest()
            payload = release.checksum or release.info_hash or url_digest

            if args.dry_run:
                # Print the artifact, never a status code: a 200 is what misled the
                # design of this project four separate times.
                print(
                    f"{variant.key:38} {release.version:28} "
                    f"{release.verify:8} {release.checksum_algo or '-':7} {release.filename}"
                )
                continue

            if state.update(release, payload):
                changed.append(f"{variant.key} → {release.version}")
                log.info("%s: %s", variant.key, release.version)

    if args.dry_run:
        log.info("%d resolved, %d failed", len(variants) - len(failures), len(failures))
        if args.summary:
            write_summary(
                Path(args.summary),
                changed=[],
                failed=failures,
                total=len(variants),
                dry_run=True,
            )
        return 1 if failures and len(failures) == len(variants) else 0

    state.save(STATE)
    feed.render(state, FEED_DIR)
    docs.render(sources, state, CATALOG)
    log.info("%d changed, %d failed, %d entries", len(changed), len(failures), len(state.records))

    if args.summary:
        write_summary(Path(args.summary), changed=changed, failed=failures, total=len(variants))

    # Individual failures are normal and must never fail the run -- that is what
    # failure isolation is for. Every source failing is not a source problem; it is
    # a broken runner, a dead network, or a bad deploy, and it must be loud.
    if failures and len(failures) == len(variants):
        log.error(
            "every source failed (%d/%d); refusing to call this a healthy run",
            len(failures),
            len(variants),
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
