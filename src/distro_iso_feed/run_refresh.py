"""Daily refresh: resolve every configured variant, update state, render.

Failure isolation is the whole point of the try/except: one dead mirror must never
abort the run, and a resolver returning None must never remove an entry. The feed
degrades to *stale*, never to *empty*.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

from . import audit, docs, escalate, feed, select
from .client import Client
from .config import load
from .escalate import Failure, Pin, Report, SigningFailure
from .gpgverify import gpg_available
from .models import Variant
from .signing import REJECTED, verify_signing_key
from .state import State
from .strategies import REGISTRY
from .strategies.integrity import SumsUnavailable
from .strategies.torrent import attach_torrent
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


# Moved to `escalate` (it fills `Failure.endpoint`, and `audit` needs it too -- importing it from
# here would cycle, since this module imports `audit`). Re-exported so callers and tests that
# reach for `run_refresh.endpoint_of` keep working.
endpoint_of = escalate.endpoint_of


# Moved to `escalate` so `audit`'s resolve check classifies identically -- two classifiers for
# "did this exception mean the mirror or the config?" is exactly how they drift.
_exc_class = escalate.exc_class


def diagnose(strategy, variant: Variant, params: dict, client: Client) -> Failure:
    """Say *why* a variant failed AND classify it, because the two causes have opposite fixes and
    only one should escalate. Reads the `Client` trace for the *real* outcome of its own listing
    fetch -- a 404/200-empty is structural (the page moved or changed), a timeout/5xx transient. The
    candidates the endpoint lists *now* are carried so a fix can see what upstream renamed. Costs
    one extra listing, only for a variant that already failed.
    """
    key, endpoint = variant.key, endpoint_of(params)
    repro = f"uv run distro-iso-feed-refresh --dry-run --only {key} -v"

    def mk(reason, cause, cls, status=None, cands=None):
        return Failure(
            key=key, reason=reason, failure_class=cls, cause=cause, endpoint=endpoint,
            status=status, observed_candidates=cands or [], repro=repro,
        )  # fmt: skip

    mark = len(client.trace)  # only the outcomes of THIS diagnose's fetch, not the whole run
    try:
        candidates = strategy.candidates(variant.distro, params, client)
    except Exception as exc:
        return mk(f"lister raised {type(exc).__name__}: {exc}", "lister-raised", _exc_class(exc))

    outcomes = [o for _, o in client.trace[mark:]]
    fclass = escalate.classify_outcomes(outcomes)
    status = outcomes[-1] if outcomes else None
    names = [c.name for c in candidates]

    if not candidates:
        if fclass == escalate.TRANSIENT:
            return mk(f"listing unreachable ({status}): {endpoint}", "unreachable", fclass, status)
        return mk(
            f"listing empty, endpoint reachable ({status}): {endpoint}",
            "reachable-empty", escalate.STRUCTURAL, status, names,
        )  # fmt: skip

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
            return mk(
                f"listed {len(names)} candidates, none matched `{match}` (e.g. {sample})",
                "none-matched", escalate.STRUCTURAL, status, names,
            )  # fmt: skip

        pattern = params.get("version_pattern")
        if pattern and not from_filename(chosen.rsplit("/", 1)[-1], pattern):
            return mk(
                f"matched `{chosen}` but `version_pattern` extracted no token",
                "no-token", escalate.STRUCTURAL, status, names,
            )  # fmt: skip

    return mk(
        f"resolver returned None; {len(names)} candidates at {endpoint}",
        "resolver-none", escalate.STRUCTURAL, status, names,
    )  # fmt: skip


def _enrich(f: Failure, variant: Variant, state: State) -> Failure:
    """Add the 'was it resolving before' facts from state -- the regression flag + how stale."""
    rec = state.records.get(variant.key)
    f.regression = rec is not None
    if rec:
        f.last_good_version = rec.version
        f.last_resolved = rec.seen
    return f


def write_summary(
    path: Path,
    *,
    changed: list[str],
    failed: list[Failure],
    total: int,
    dry_run: bool = False,
) -> None:
    """A run that commits nothing must still leave evidence of what it saw.

    Without this, a day on which forty sources broke looks exactly like a day on
    which nothing was released: passing, silent, no commit. The run record is the
    receipt, so it carries the health of every source and, for each failure, enough
    to act on without re-running anything locally first. The `Class`/`Was resolving`
    columns say which failures are just stale-and-retrying vs which opened an issue.
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
            "Entries are left untouched, so the feed is stale for these, not empty. A structural "
            "failure that was resolving opens an issue; a transient one just retries.",
            "",
            "| Variant | Class | Was resolving | Why | Reproduce |",
            "|---|---|---|---|---|",
        ]
        for f in sorted(failed, key=lambda f: f.key):
            lines.append(
                f"| `{f.key}` | {f.failure_class} | {'yes' if f.regression else 'no'} "
                f"| {f.reason} | `{f.repro}` |"
            )
        lines += [""]

    if dry_run:
        lines += ["_Dry run: nothing written, nothing committed._", ""]
    elif not changed and not failed:
        lines += ["_Nothing moved upstream; no commit._", ""]

    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def _write_report(
    path: Path,
    sources: list,
    selected_distros: set[str],
    failures: list[Failure],
    signing_failures: list[SigningFailure],
    total: int,
) -> None:
    """The machine-readable failure inventory the workflow's escalation gate consumes. Pins come
    from `audit.pins` (a pure offline config scan) over the selected distros -- a standing config
    smell surfaced alongside the run's resolve/signing failures. Never committed (temp path)."""
    pins = [
        Pin(
            key=f"{finding.distro}:{finding.subject}",
            detail=finding.detail,
            page_url=source.page_url,
        )
        for source in sources
        if source.name in selected_distros
        for finding in audit.pins(source)
    ]
    report = Report(
        total=total,
        resolved=total - len(failures),
        failures=failures,
        pins=pins,
        signing_key_failures=signing_failures,
    )
    path.write_text(
        json.dumps(report.to_json(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="distro-iso-feed-refresh")
    parser.add_argument("--dry-run", action="store_true", help="resolve and print; write nothing")
    parser.add_argument("--only", metavar="DISTRO[:VARIANT]", help="restrict to one distro/variant")
    parser.add_argument("--summary", metavar="FILE", help="append a markdown run summary")
    parser.add_argument("--report", metavar="FILE", help="write the machine-readable report")
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
    failures: list[Failure] = []
    signing_failures: list[SigningFailure] = []
    changed: list[str] = []

    if not gpg_available():
        log.warning(
            "gpg/gpgv not on PATH -- signing-key verification skipped; "
            "gpg entries keep their signature_url but publish no pinned key this run"
        )

    with Client(defaults["user_agent"]) as client:
        for variant in variants:
            strategy = REGISTRY[variant.strategy]()
            params = dict(variant.params)
            params.setdefault("page_url", page_urls.get(variant.distro))
            params.setdefault("label", variant.label)
            try:
                release = strategy.resolve(variant.distro, variant.name, params, client)
            except Exception as exc:  # a strategy must not take the run down with it
                f = Failure(
                    key=variant.key,
                    reason=f"resolver raised {type(exc).__name__}: {exc}",
                    failure_class=_exc_class(exc),
                    cause="resolver-raised",
                    endpoint=endpoint_of(params),
                    repro=f"uv run distro-iso-feed-refresh --dry-run --only {variant.key} -v",
                )
                log.warning("%s: %s", variant.key, f.reason)
                failures.append(_enrich(f, variant, state))
                continue

            if release is None:
                # Costs one extra listing, and only for variants that already failed.
                f = _enrich(diagnose(strategy, variant, params, client), variant, state)
                log.warning("%s: %s (entry left untouched)", variant.key, f.reason)
                failures.append(f)
                continue

            # A co-located `.torrent` is a second retrieval channel on the same entry,
            # not a separate resolve. Attach it (or leave the ISO untouched) before
            # the change token is computed -- these sources all carry an ISO checksum,
            # so the token is the ISO's hash and the torrent cannot move it.
            if params.get("torrent"):
                try:
                    release = attach_torrent(client, release, params)
                except SumsUnavailable as exc:
                    # This call sits OUTSIDE the resolver try/except above, so an escaping
                    # exception would take the whole run down. The torrent's own sums file is
                    # a second sidecar and can time out independently of the ISO's -- a missing
                    # torrent hash is metadata loss, not correctness loss, so keep the release
                    # exactly as resolved rather than failing the variant.
                    log.warning("%s: torrent not attached: %s", variant.key, exc)

            # Prove the GPG chain before publishing the pinned key. A REJECTED signature
            # drops the claim (verify degrades to checksum); a transient/gpg-absent
            # run leaves the entry as resolved. Runs before the token, but cannot move
            # it -- these sources all publish a checksum, so the token is that hash.
            if params.get("signing_key"):
                signing = verify_signing_key(client, release, params)
                release = signing.release
                if signing.verdict == REJECTED:
                    log.warning(
                        "%s: %s -- dropped the gpg claim (verify now %s)",
                        variant.key,
                        signing.reason,
                        release.verify,
                    )
                    sk = params["signing_key"]
                    signing_failures.append(
                        SigningFailure(
                            key=variant.key,
                            reason=signing.reason or "pin no longer verifies",
                            pinned_fpr=str(sk.get("fingerprint")),
                            actual_signer_fpr=signing.signer,
                            key_url=sk.get("url"),
                            covers=sk.get("covers"),
                            page_url=params.get("page_url"),
                        )
                    )

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
            elif state.enrich(release):
                # Same release, new metadata (a torrent attached to a known ISO).
                # `seen` is preserved, so no feed timestamp moves and no reader
                # re-notifies; state.save/feed.render below always run.
                changed.append(f"{variant.key} +torrent")
                log.info("%s: enriched (metadata only)", variant.key)

    # Write the report before any return -- the gate needs it even on the all-failed path.
    if args.report:
        _write_report(
            Path(args.report),
            sources,
            {v.distro for v in variants},
            failures,
            signing_failures,
            len(variants),
        )

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
