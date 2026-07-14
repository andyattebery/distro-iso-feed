"""Failure classification and the escalation gate -- the Python half of "run unattended, ping me
only on real issues".

`run_refresh` produces a `Report` (a resolve-failure / pin / signing-key-failure inventory) and
writes it as JSON. The workflow feeds that report plus the currently-open refresh issues to
`plan_escalation`, which decides -- purely, so it is unit-tested -- the exit code and which issues
to open/close. The workflow only runs the `gh` calls. No GitHub logic lives here, and no state is
persisted: the open `refresh-*` issues ARE the record of what is currently broken.

Two axes, per `docs/failure-escalation-spec.md`:
- STRUCTURAL vs TRANSIENT -- did the request succeed (wrong/absent content) or fail (network)? Only
  structural escalates. This classification is the whole false-alarm gate; no N-day counter.
- regression -- was this key resolving before (a record in state)? Only "was working, now isn't"
  escalates; a never-resolved config problem is `distro-iso-feed-audit`'s job at add time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

STRUCTURAL = "structural"
TRANSIENT = "transient"

# Retryable statuses (mirrors client.RETRY_STATUS): a server error / rate-limit that exhausted its
# retries is transient, not a content regression.
_RETRY_STATUS = {429, 500, 502, 503, 504}

# Above this many structural regressions in one run, treat it as one infrastructure event (a shared
# parser/dependency broke many sources at once), not N separate breaks -- one issue, not a flood.
MASS_OUTAGE_THRESHOLD = 5

LABEL_RESOLVE = "refresh-failure"
LABEL_SIGNING = "refresh-signing-key"
LABEL_PIN = "refresh-pin"
LABEL_MASS = "refresh-mass-outage"


def classify_outcomes(outcomes: list[int | str]) -> str:
    """STRUCTURAL unless the trace shows the request itself failed. A network-error name (str) or a
    retry-class status that exhausted retries is TRANSIENT; a 2xx with wrong/absent content or a
    4xx (moved/removed) is STRUCTURAL. Empty (nothing recorded) is structural -- better to
    over-escalate a genuine break than swallow one behind an unknown."""
    for outcome in outcomes:
        if isinstance(outcome, str) or outcome in _RETRY_STATUS:
            return TRANSIENT
    return STRUCTURAL


@dataclass(slots=True)
class Failure:
    """A resolve failure, classified. `cause` is a short machine tag; `reason` is the human line."""

    key: str
    reason: str
    failure_class: str
    cause: str
    regression: bool = False
    endpoint: str | None = None
    status: int | str | None = None
    observed_candidates: list[str] = field(default_factory=list)
    last_good_version: str | None = None
    last_resolved: str | None = None
    repro: str = ""


@dataclass(slots=True)
class Pin:
    """A source frozen to a literal release -- resolves fine, serves stale forever (audit.pins).

    `key` is `distro:variant:param`; `detail` is the finding line ("literal `24.04` in `...`").
    """

    key: str
    detail: str
    page_url: str | None = None


@dataclass(slots=True)
class SigningFailure:
    """A pinned GPG key that stopped verifying -- the entry silently dropped to `checksum`."""

    key: str
    reason: str
    pinned_fpr: str | None = None
    actual_signer_fpr: str | None = None
    key_url: str | None = None
    covers: str | None = None
    page_url: str | None = None


@dataclass(slots=True)
class Report:
    total: int = 0
    resolved: int = 0
    failures: list[Failure] = field(default_factory=list)
    pins: list[Pin] = field(default_factory=list)
    signing_key_failures: list[SigningFailure] = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- the gate


def _resolve_body(f: dict) -> str:
    cands = f.get("observed_candidates") or []
    listed = "\n".join(f"- `{c}`" for c in cands[:30]) if cands else "_(endpoint listed nothing)_"
    return (
        f"`{f['key']}` stopped resolving.\n\n"
        f"- **cause**: {f['reason']}\n"
        f"- **endpoint**: {f.get('endpoint') or '?'} (status `{f.get('status')}`)\n"
        f"- **last good**: `{f.get('last_good_version')}`"
        f" — last resolved {f.get('last_resolved')}\n\n"
        f"## To resolve\n"
        f"1. Reproduce: `{f.get('repro')}`\n"
        f"2. Fetch the endpoint and compare what it lists now against `params.match`.\n"
        f"3. Edit `config/sources.yaml` for `{f['key']}` — bring"
        f" `match`/`version_pattern`/`index`/`url` back in line, then"
        f" `--dry-run --only {f['key']}` to confirm.\n\n"
        f"**Candidates the endpoint lists now:**\n{listed}\n"
    )


def _signing_body(s: dict) -> str:
    return (
        f"The pinned GPG key for `{s['key']}` no longer verifies —"
        f" the entry has dropped to `checksum`.\n\n"
        f"- **reason**: {s['reason']}\n"
        f"- **pinned**: `{s.get('pinned_fpr')}`\n"
        f"- **now signed by**: `{s.get('actual_signer_fpr')}`\n"
        f"- **key url**: {s.get('key_url')} (`covers: {s.get('covers')}`)\n\n"
        f"## To resolve\n"
        f"A key rotation is the usual cause — but do **NOT** bump the fingerprint blindly. First"
        f" confirm `{s.get('actual_signer_fpr')}` is the project's *announced* new key (official"
        f" channel, or chained to its trust anchor). Only then update `signing_key.fingerprint` in"
        f" `config/sources.yaml`, and dry-run to prove it re-verifies.\n"
    )


def _pin_body(p: dict) -> str:
    return (
        f"`{p['key']}` is frozen to a literal release — it resolves cleanly but serves a stale"
        f" release forever while every check keeps passing.\n\n"
        f"- **finding**: {p['detail']}\n"
        f"- **page**: {p.get('page_url')}\n\n"
        f"## To resolve\n"
        f"Check the upstream root for a listable index; replace the literal with"
        f" `version_dir`/`probe_versions`. If the pin is genuinely intentional, add"
        f" `pinned_ok: true` with a reason instead.\n"
    )


def plan_escalation(report: dict, open_issues: list[dict]) -> dict:
    """Decide the gate, purely. Returns `{exit_code, to_open, to_close, mass_outage}`.

    - `to_open`: `{label, title, body}` for each currently-broken thing with no open issue yet.
    - `to_close`: `{number, title}` for each open `refresh-*` issue whose thing recovered this run.
    - `exit_code`: 1 iff there is an *acute* regression this run (a structural resolve regression or
      a signing-key failure). Pins open a ticket but never fail the job. The exit is authoritative
      and independent of whether the issue API calls succeed.
    - `mass_outage`: structural regressions exceeded the threshold → one issue instead of N.
    """
    regressions = [
        f
        for f in report.get("failures", [])
        if f.get("failure_class") == STRUCTURAL and f.get("regression")
    ]
    signing = report.get("signing_key_failures", [])
    pins = report.get("pins", [])
    mass_outage = len(regressions) > MASS_OUTAGE_THRESHOLD

    # Desired open set: title -> (label, body).
    desired: dict[str, tuple[str, str]] = {}
    if mass_outage:
        keys = ", ".join(sorted(f["key"] for f in regressions))
        desired[f"refresh: {len(regressions)} sources regressed"] = (
            LABEL_MASS,
            f"{len(regressions)} sources regressed structurally in one run — likely a shared "
            f"dependency, not N separate breaks. Investigate together.\n\nAffected: {keys}\n",
        )
    else:
        for f in regressions:
            desired[f"refresh failure: {f['key']}"] = (LABEL_RESOLVE, _resolve_body(f))
    for s in signing:
        desired[f"refresh signing-key: {s['key']}"] = (LABEL_SIGNING, _signing_body(s))
    for p in pins:
        desired[f"refresh pin: {p['key']}"] = (LABEL_PIN, _pin_body(p))

    ours = {LABEL_RESOLVE, LABEL_SIGNING, LABEL_PIN, LABEL_MASS}
    open_by_title = {
        i["title"]: i
        for i in open_issues
        if ours & {label["name"] for label in i.get("labels", [])}
    }

    to_open = [
        {"label": label, "title": title, "body": body}
        for title, (label, body) in desired.items()
        if title not in open_by_title
    ]
    to_close = [
        {"number": i["number"], "title": title}
        for title, i in open_by_title.items()
        if title not in desired
    ]
    return {
        "exit_code": 1 if (regressions or signing) else 0,
        "to_open": to_open,
        "to_close": to_close,
        "mass_outage": mass_outage,
    }
