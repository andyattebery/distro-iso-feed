"""Failure classification and the escalation gate -- the Python half of "run unattended, ping me
only on real issues".

`run_refresh` produces a `Report` (a resolve-failure / pin / signing-key-failure inventory) and
writes it as JSON. The workflow feeds that report plus the currently-open refresh issues to
`plan_escalation`, which decides -- purely, so it is unit-tested -- the exit code and which issues
to open/close. The workflow only runs the `gh` calls. No GitHub logic lives here, and no state is
persisted: the open `refresh-*` issues ARE the record of what is currently broken.

Two axes, per `docs/failure-escalation-spec.md`. **They govern resolve failures only** -- signing
has its own classifier; see `plan_escalation`:
- STRUCTURAL vs TRANSIENT -- did the request succeed (wrong/absent content) or fail (network)? Only
  structural escalates. This classification is the whole false-alarm gate; no N-day counter.
- regression -- was this key resolving before (a record in state)? Only "was working, now isn't"
  escalates; a never-resolved config problem is `distro-iso-feed-audit`'s job at add time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import httpx

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

# Why a pinned key did not verify: `SigningFailure.cause`, set by `signing.verify_signing_key`.
# Defined once, here, because the gate matches on them: two files naming the set separately is how
# they drift. Each needs a different fix, and only FOREIGN_SIGNER can be a key rotation -- reading
# the others as one is how #17 sent the reader after a Parrot key that did not exist.
CAUSE_UNSIGNED = "unsigned"  # no OpenPGP signature at all, or the sig URL answered 4xx
CAUSE_FOREIGN_SIGNER = "foreign-signer"  # signed, by a key that is not the pin's
CAUSE_BAD_SIGNATURE = "bad-signature"  # the pin's own signature no longer matches its bytes
CAUSE_KEY_URL = "key-url"  # the key URL no longer serves the pin (another key, or a 4xx)
CAUSE_CHECKSUM_ABSENT = "checksum-absent"  # the pin's signed file doesn't list this artifact


def exc_class(exc: Exception) -> str:
    """Classify an exception that escaped a resolver.

    A network error is transient; a parse/attribute/key error is structural. (`resolve()` catches
    network errors internally, so this mostly sees the latter.)

    `SumsUnavailable` carries its own verdict in `failure_class` -- read by attribute rather than
    `isinstance`, because it lives in `strategies.integrity`, which imports *this* module. Both
    `run_refresh` and `audit` classify through here so the two cannot drift apart.
    """
    declared = getattr(exc, "failure_class", None)
    if declared in (STRUCTURAL, TRANSIENT):
        return declared
    return TRANSIENT if isinstance(exc, httpx.HTTPError) else STRUCTURAL


def endpoint_of(params: dict) -> str:
    """The URL a human should open first when a source breaks.

    `version_dir` comes before `index`, because for those sources `index` is a
    template like ``{version}/`` -- printing it tells the reader nothing. `version_page` comes
    first of all: where a product page names the release, that page is what broke first.

    Lives here rather than in `run_refresh` because it fills `Failure.endpoint`, and because
    `audit` needs it too -- and `run_refresh` imports `audit`, so the other direction would cycle.
    """
    for key in ("version_page", "version_dir", "index", "url", "repo", "project"):
        if value := params.get(key):
            return str(value)
    return "?"


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
    """A pinned GPG key that stopped verifying. `cause` is one of the `CAUSE_*` tags above."""

    key: str
    reason: str
    cause: str
    pinned_fpr: str | None = None
    actual_signer_fpr: str | None = None
    key_url: str | None = None
    covers: str | None = None
    page_url: str | None = None
    held_version: str | None = None  # the gpg-verified release the feed kept instead, if any


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
        f"2. Fetch the endpoint and compare what it lists now against this variant's"
        f" selection params — `match`/`version_pattern`, or, for a fixed-URL variant"
        f" (`stable_symlink` has no `match`), its `token` source.\n"
        f"3. Usually the fix is `config/sources.yaml` for `{f['key']}`: bring"
        f" `match`/`version_pattern`/`index`/`url` back in line, then"
        f" `--dry-run --only {f['key']}` to confirm.\n"
        f"4. But if the endpoint still publishes the right artifact and the config reads"
        f" correctly, suspect the **lister**, not the config: a windowed listing can push"
        f" the wanted entry off the end with nothing upstream having changed."
        f" (`releases.atom` returns 10 entries — Bazzite's stable tag fell off it behind a"
        f" week of `testing-` builds.)\n\n"
        f"**Candidates the endpoint lists now:**\n{listed}\n"
    )


# What to do, per cause. Only FOREIGN_SIGNER sends the reader after a new key.
_RESOLVE = {
    CAUSE_FOREIGN_SIGNER: (
        "A key rotation is the usual cause — but do **NOT** bump the fingerprint blindly. First"
        " confirm the new signer is the project's *announced* new key (official channel, or chained"
        " to its trust anchor); never bump a fingerprint to whatever signed the artifact, which"
        " voids the pin's entire purpose. Only then update `signing_key.fingerprint` in"
        " `config/sources.yaml`, and dry-run to prove it re-verifies."
    ),
    CAUSE_UNSIGNED: (
        "This is not a key rotation: there is no signature to check, so there is no new key to"
        " verify and the fingerprint must not change. Either the file carries none, or its URL"
        " answered 4xx — the reason line says which. A missing signature usually means a release"
        " published before its signing step finished (the hostile reading is a stripped"
        " signature), and this closes itself on the first run that finds one by the pin again; if"
        " it never comes back, find where upstream signs now and point `sig` at it. A 403 usually"
        " means the host refuses this client (a bot filter): fetch the same file from a copy that"
        " serves it."
    ),
    CAUSE_BAD_SIGNATURE: (
        "This is not a key rotation: the pinned key made this signature, but it no longer checks"
        " out — the bytes it signs changed since (a mirror serving the checksum file and its"
        " signature out of sync), the signature file itself is damaged, or tampering. Leave the"
        " fingerprint alone. Compare both files against the project's own host; a skewed or"
        " half-synced mirror heals on its next sync, and this closes itself when it does."
    ),
    CAUSE_KEY_URL: (
        "The key URL no longer serves the pinned key (a 403 usually means the host refuses this"
        " client, not that the key moved). Find where the project publishes it now: if it is the"
        " same key, update `signing_key.url`; if it is a different key, treat it as a rotation and"
        " verify its provenance before changing `signing_key.fingerprint`."
    ),
    CAUSE_CHECKSUM_ABSENT: (
        "This is not a key rotation: the file the signature covers does not list this artifact's"
        " checksum, or could not be fetched (4xx; a 403 usually means the host refuses this"
        " client). Usually a release whose checksum file has not caught up yet, and this closes"
        " itself when it does. If it persists, check `sums`/`match` against what upstream lists."
    ),
}


def _signing_body(s: dict) -> str:
    cause = s["cause"]
    signer = s.get("actual_signer_fpr")
    lead = f"- **now signed by**: `{signer}`\n" if cause == CAUSE_FOREIGN_SIGNER else ""
    if held := s.get("held_version"):
        effect = f"the feed keeps `{held}` (gpg-verified) until this release verifies"
    else:
        effect = "the gpg claim was dropped from this release"
    return (
        f"The pinned GPG key for `{s['key']}` no longer verifies — {effect}.\n\n"
        f"- **cause**: `{cause}` — {s['reason']}\n"
        f"- **pinned**: `{s.get('pinned_fpr')}`\n"
        f"{lead}"
        f"- **key url**: {s.get('key_url')} (`covers: {s.get('covers')}`)\n\n"
        f"## To resolve\n"
        f"{_RESOLVE[cause]}\n"
    )


def _rotation_verdict(group: list[dict]) -> str:
    """Among signatures by a key that is not the pin's, the distinct signer set is the tell: one
    shared new signer reads as a rotation; N different ones read as something else. Never empty:
    `signing` names the signer on every `foreign-signer` outcome (read off the signature packet)."""
    signers = sorted({fpr for s in group if (fpr := s.get("actual_signer_fpr"))})
    if len(signers) == 1:
        return (
            f"All {len(group)} are now signed by **one** key, `{signers[0]}` — consistent with a"
            f" single key rotation."
        )
    listed = ", ".join(f"`{s}`" for s in signers)
    return (
        f"They are signed by **{len(signers)} different** keys ({listed}) — that is not a simple"
        f" rotation. Investigate before trusting any of them."
    )


def _signing_mass_body(signing: list[dict]) -> str:
    """One event, not N breaks. A single key backs many variants -- 28 share Ubuntu's, 14 Debian's
    -- so one upstream event trips every one of them in the same run. Grouped by cause, because only
    `foreign-signer` can be a rotation: #17's six unsigned Parrot files were headlined "likely a
    single upstream rotation" and sent the reader after a key that did not exist."""
    by_cause: dict[str, list[dict]] = {}
    for s in sorted(signing, key=lambda s: s["key"]):
        by_cause.setdefault(s["cause"], []).append(s)
    sections = []
    for cause, group in sorted(by_cause.items()):
        verdict = _rotation_verdict(group) + "\n\n" if cause == CAUSE_FOREIGN_SIGNER else ""
        keys = "\n".join(
            f"- `{s['key']}`" + (f" — feed keeps `{h}`" if (h := s.get("held_version")) else "")
            for s in group
        )
        sections.append(
            f"## `{cause}` ({len(group)})\n\n{verdict}{_RESOLVE[cause]}\n\n**Affected:**\n{keys}\n"
        )
    head = (
        f"{len(signing)} pinned GPG keys stopped verifying in one run. Investigate them together,"
        f" by cause — only `{CAUSE_FOREIGN_SIGNER}` can be a key rotation."
    )
    return head + "\n\n" + "\n".join(sections)


def _pin_body(p: dict) -> str:
    return (
        f"`{p['key']}` is frozen to a literal release — it resolves cleanly but serves a stale"
        f" release forever while every check keeps passing.\n\n"
        f"- **finding**: {p['detail']}\n"
        f"- **page**: {p.get('page_url')}\n\n"
        f"## To resolve\n"
        f"Check the upstream root for a listable index; replace the literal with"
        f" `version_dir`/`version_page`/`probe_versions`. If the pin is genuinely intentional, add"
        f" `pinned_ok: true` with a reason instead.\n"
    )


def plan_escalation(report: dict, open_issues: list[dict]) -> dict:
    """Decide the gate, purely. Returns `{exit_code, to_open, to_close, mass_outage}`.

    - `to_open`: `{label, title, body}` for each currently-broken thing with no open issue yet.
    - `to_close`: `{number, title}` for each open `refresh-*` issue whose thing recovered this run.
    - `exit_code`: 1 iff there is an *acute* regression this run (a structural resolve regression or
      a signing-key failure). Pins open a ticket but never fail the job. The exit is authoritative
      and independent of whether the issue API calls succeed.
    - `mass_outage`: structural regressions **or** signing failures exceeded the threshold → one
      issue instead of N. The two collapse into *separate* buckets (their bodies say different
      things and a merged ticket is unreadable); this flag is true if either tripped.

    `signing` is deliberately NOT filtered by failure_class the way `regressions` is, and carries
    no such field. `verify_signing_key` already IS the classifier: it only returns REJECTED on
    evidence -- gpg read a signature that is not the pin's (or found none at all), or a required
    fetch (the key, the signature, and for `covers: checksums` the signed body) was answered
    structurally, a 4xx or an empty 200. A network failure, or a gpg that could not read the
    signature, is couldn't-check: DEFERRED, and it never reaches this report at all. A
    `failure_class` here could only ever be the constant "structural", and a filter on it could
    only ever be a no-op whose one failure mode is silently swallowing a real key rotation.
    """
    regressions = [
        f
        for f in report.get("failures", [])
        if f.get("failure_class") == STRUCTURAL and f.get("regression")
    ]
    signing = report.get("signing_key_failures", [])
    pins = report.get("pins", [])
    regressions_mass = len(regressions) > MASS_OUTAGE_THRESHOLD
    # One key backs many variants (28 share Ubuntu's, 14 Debian's), so one rotation trips them
    # all at once. Without this it would file an issue per variant.
    signing_mass = len(signing) > MASS_OUTAGE_THRESHOLD
    mass_outage = regressions_mass or signing_mass

    # Desired open set: title -> (label, body).
    desired: dict[str, tuple[str, str]] = {}
    if regressions_mass:
        keys = ", ".join(sorted(f["key"] for f in regressions))
        desired[f"refresh: {len(regressions)} sources regressed"] = (
            LABEL_MASS,
            f"{len(regressions)} sources regressed structurally in one run — likely a shared "
            f"dependency, not N separate breaks. Investigate together.\n\nAffected: {keys}\n",
        )
    else:
        for f in regressions:
            desired[f"refresh failure: {f['key']}"] = (LABEL_RESOLVE, _resolve_body(f))
    if signing_mass:
        desired[f"refresh signing-key: {len(signing)} pins stopped verifying"] = (
            LABEL_SIGNING,
            _signing_mass_body(signing),
        )
    else:
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
