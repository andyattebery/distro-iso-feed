# Spec: structural-failure escalation for the daily refresh

## The property to deliver

Today, `run_refresh` isolates failures from the feed correctly (a resolver returning `None`
leaves the entry stale, never empty) and produces an excellent per-failure diagnosis via
`diagnose()`. What's missing is **escalation**: the job only exits non-zero when *every* source
fails (`if failures and len(failures) == len(variants)`), so a single `page_index` source breaking
is recorded in the step summary but the run passes and nobody is notified.

Deliver: when a source that **was** resolving **stops** resolving for a **structural** reason,
(a) the nightly job fails, and (b) a deduplicated GitHub issue is opened with the diagnosis —
and is auto-closed when the source recovers. Transient (network) failures and mass outages must
**not** trigger this, or the signal drowns in false alarms.

Keep the two existing invariants intact: the feed never breaks (isolation stays), and the repo
stays deterministic (no clock/committed operational state — see `docs/architecture.md`).

---

## 1. The core distinction: structural vs transient

This classification is the whole false-alarm gate. Sharpen the boundary so it's **"did the request
succeed?"**, not "was there an error":

- **STRUCTURAL** — the request *succeeded* but the content was wrong or absent. These essentially
  never self-heal; escalate. Maps from the current `diagnose()` outcomes:
  - `lister raised <ParseError>` — a parse/attribute/key error (not a network error)
  - `listing empty` **when the endpoint was reachable** (HTTP 200 / a real directory that came back
    with zero candidates) — the page changed shape
  - `listed N candidates, none matched \`match\`` — regex/layout regression
  - `matched \`X\` but version_pattern extracted no token`
  - `resolver returned None; N candidates at <endpoint>`
- **TRANSIENT** — the request itself *failed*. Usually self-heals by tomorrow; do **not**
  escalate per-source.
  - connect/read timeout, DNS failure, connection refused, TLS error, 5xx, 429
  - i.e. the network-exception class, and `listing … unreachable`

**Key refinement to `diagnose()`:** it currently lumps "empty **or** unreachable" into one string.
Split them — *reachable-but-empty* is STRUCTURAL (the thing moved / the page was redesigned),
*unreachable* is TRANSIENT. This split is what lets most real breaks (moved page, changed layout)
escalate immediately while genuine network flakiness stays quiet, **without needing an N-day
threshold or any persisted failure counter.** The classification is the gate.

Similarly split the top-level `except` in `main()`: a resolver raising a **client/network**
exception is TRANSIENT; raising anything else (parse, key, type) is STRUCTURAL. Classify by
exception type, not by the fact that it raised.

Implementation: have `diagnose()` (and the top-level except path) return a structured result
`(reason: str, failure_class: Literal["structural","transient"])` rather than a bare string. The
existing human-readable `reason` is preserved verbatim for the issue body and summary.

### 1a. Signing failures classify themselves

This spec's two axes govern **resolve** failures. Signing has its own classifier and deliberately
does not carry a `failure_class`: `verify_signing_key` returns REJECTED **only** when every
required fetch (key, signature, and for `covers: checksums` the signed body) returned 2xx *and*
gpg produced contrary evidence. Couldn't-check — gpg absent, a key/sig/sums fetch that failed,
or no checksum to check against — is DEFERRED and never reaches the report. **The verdict IS the
classification: DEFERRED is transient, REJECTED is structural.**

A `failure_class` field on `SigningFailure` would therefore be the constant `"structural"`
forever, and a filter on it could only ever be a no-op whose one failure mode is silently
swallowing a real key rotation. Do not add one. Classifying signing from the `Client` trace is
worse: the trace is global to the run, and even a correctly-scoped slice would flip a genuine
rotation to TRANSIENT the moment one retried-then-succeeded timeout landed in it — suppressing
exactly the tamper case that must never be suppressed.

The invariant that keeps this honest: **an environmental hiccup must never strip a valid pin or
flap an entry's `verify` level.** A `checksum=None` (the sums fetch did not land) is the case that
once broke it — it fell into "the checksum is absent from the signed file" and was reported as a
key rotation, on a key that had not rotated.

### 1b. A configured sidecar that did not arrive is TRANSIENT, not a checksum-less entry

Resolving one variant is a multi-fetch operation (index, sums, torrent, torrent-sums, key, sig).
Against a flaky host each fetch independently succeeds or fails, and without care the published
`Release` is an arbitrary combination of survivors. `fetch_sums` returning `None` must mean
**no sums configured** (tails ships none — a design choice). A *configured* sidecar that failed
transiently raises `SumsUnavailable`, which routes through the existing resolver `except` as
TRANSIENT: entry untouched, retried next run, no issue.

Deliberate asymmetry: a **404** sidecar keeps resolving with `checksum=None`. Failing the resolve
on a structurally-absent sidecar would freeze every source with an optional per-file sidecar,
trading silent degradation for a silent stall.

### 1c. Per-host failure budget

A host that fails `client.DEFAULT_HOST_BUDGET` fetches *transiently* in one run has the rest of
its URLs skipped, recording a `BUDGET_EXHAUSTED` trace entry (a `str`, so it classifies TRANSIENT
— skipping must never read as a content regression). Counting rules that matter:

- **Only transient failures count.** A 4xx means the host answered and the file is gone; charging
  those would skip a healthy mirror serving optional sidecars that legitimately 404.
- **Cumulative, never consecutive.** In the incident that motivated this, successes were
  interleaved among the failures, so a consecutive counter — what every off-the-shelf circuit
  breaker implements — would have reset constantly and never tripped.
- **No half-open recovery.** For a nightly batch, "this host is having a bad night; leave its
  entries alone and retry tomorrow" is the correct semantics.

---

## 2. The escalation trigger

A failure escalates (red job + issue) iff **both**:

1. **`failure_class == "structural"`**, and
2. **the variant has a record in `state.json`** at load time — i.e. it *was* resolving. A variant
   that never resolved is a config/PR-time problem already covered by `distro-iso-feed-audit` and
   `--dry-run` at add time; don't double-handle it here. This is the "was resolving, now isn't"
   semantics.

Call a failure meeting both a **structural regression**.

**Mass-outage guard.** If the structural-regression *count* exceeds a threshold (e.g. `> 5`
sources, or `> 25%` of selected), treat it as an infrastructure event, **not** N separate source
breaks: still fail the job, but open **one** "refresh: multiple sources regressed" issue rather
than flooding the tracker. (A true mirror-network outage mostly lands in TRANSIENT and won't reach
here anyway, but this guards the case where a shared dependency breaks many parsers at once.)

---

## 3. Changes to `run_refresh.py`

- **Classify** every failure into `(reason, failure_class)` per §1 (both the `resolve()` except and
  the `diagnose()` path).
- **Record regression flag**: for each failure, compute `regression = key in state` (state is
  already loaded as `State.load(STATE)` before the loop).
- **Emit a machine-readable report** via a new `--report <path>` flag: write JSON to the given path
  (a temp path — see §5 determinism). Schema:
  ```json
  {
    "generated_run": "<opaque run id or ISO timestamp — NOT committed>",
    "total": 55,
    "resolved": 53,
    "failures": [
      {
        "key": "nobara:kde",
        "reason": "listed 12 candidates, none matched `Nobara-…` (e.g. …)",
        "failure_class": "structural",
        "regression": true,
        "endpoint": "https://…",
        "last_good_version": "41-1.3",          // from state, or null
        "repro": "uv run distro-iso-feed-refresh --dry-run --only nobara:kde -v"
      }
    ]
  }
  ```
- **Keep the existing exit behaviour for the catastrophic case** (`all failed → return 1`, which
  aborts before commit — correct, there's nothing to publish). Write the report **before**
  returning in that path too.
- **Do NOT move the per-source gate into `run_refresh`'s exit code.** The render must succeed and
  the feed must commit even when a source regressed (the feed is valid — one entry is just stale).
  So `run_refresh` returns `0` for a structural regression, having written the report; the
  **workflow** turns that report into the failing exit and the issues (§4). This keeps rendering and
  health-gating as separate concerns, and keeps all GitHub-specific logic out of the Python, exactly
  as the `discover` PR flow already does.

The existing `write_summary()` (step-summary markdown) stays — it's the human view; add the
`failure_class`/regression columns so the summary distinguishes "stale (transient, will retry)"
from "regressed (structural, issue opened)".

---

## 4. Workflow changes (`.github/workflows/refresh.yml`)

Add `issues: write` to the job `permissions` (currently only `contents: write`).

- **Resolve and render step:** add `--report "$RUNNER_TEMP/report.json"` to the
  `distro-iso-feed-refresh` invocation.
- **Commit step:** change its condition to `if: ${{ always() && !inputs.dry_run }}` so the (valid)
  feed still commits even though a later gate step will fail the job. Its own `git diff --cached
  --quiet` empty-commit guard is unchanged, so the determinism invariant holds.
- **New "Health gate & issues" step** (`if: ${{ always() && !inputs.dry_run }}`, needs
  `issues: write`, reads `$RUNNER_TEMP/report.json`), using `gh` / `actions/github-script`:
  1. **Open/dedupe** an issue for each structural regression (§4 rules).
  2. **Auto-close** issues for sources that recovered.
  3. **Exit non-zero** iff there is ≥1 structural regression this run — *this* is what turns the
     nightly job red. The gate exit is authoritative and independent of the Issues-API calls
     succeeding (issue filing is best-effort; a GitHub API hiccup must not turn a real regression
     pass, nor a clean run fail).

Because the gate lives in its own `always()` step *after* commit, you get all three outcomes at
once: **feed committed, job red, issue opened.**

---

## 5. Issue automation rules

- **Unit = one issue per `distro:variant` key.** Per-source is more actionable and closes cleanly;
  the mass-outage guard (§2) prevents flooding.
- **Dedupe on identity, not occurrence.** Label every issue `refresh-failure` and use a
  deterministic title `refresh failure: <key>`. Before opening, search open issues by that
  label+title; if one exists, **do not open a second**, and **do not comment every night** (that
  rebuilds the noise). Update quietly at most — e.g. edit a "last seen failing: <run>" line in the
  body, or comment only on a *transition*, never on every recurrence.
- **Body = the diagnosis, verbatim.** Title `refresh failure: nobara:kde`; body carries the
  report's `reason`, `endpoint`, `repro` command, `last_good_version` (so the reader sees how stale
  the served entry now is), and the run link. It's a work ticket, not an alert.
- **Auto-close on recovery.** List open `refresh-failure` issues, extract their keys, and **close**
  any whose key is *not* in this run's failures (it resolved cleanly), with a comment
  "resolved as of <run>, now serving <version>". This makes the open-issue set == the currently-broken
  set, self-maintaining.
- **Mass-outage:** if the regression count trips the §2 threshold, open/append a single
  "multiple sources regressed" issue instead of one per key.
- **Transient failures:** no issue, no per-source red. (They remain visible in the step summary.)
- **Never-resolved (non-regression) structural failures:** no issue here — surfaced by
  `distro-iso-feed-audit` / `--dry-run` at add time.

---

## 6. Determinism & separation constraints (do not violate)

- **No committed failure/health state.** Persistence of "which sources are currently broken" lives
  in the **GitHub issues** (an open `refresh-failure` issue *is* the flag), not in a tracked file.
  The report goes to `$RUNNER_TEMP`, never `git add`-ed. This preserves the invariant that a commit
  means "a distro moved" and that a nothing-moved run makes no commit. (A committed health file with
  a per-run failure counter would commit nightly for a persistently-broken source — the exact bug to
  avoid.)
- **Do not bump the feed `schema`.** The report is operational, not the feed format.
- **Python emits structured data; the workflow does GitHub glue and policy.** `run_refresh` writes
  the report and renders; the issue/gate logic is a workflow step. Mirrors the existing `discover` →
  `create-pull-request` split, and keeps the Python unit-testable.

---

## 7. Edge cases / don'ts

- A GitHub API failure in the issue step must **not** mask a regression (still exit non-zero) nor
  invent one (don't fail a clean run because `gh` errored) — gate on the report, treat filing as
  best-effort.
- Don't escalate the catastrophic all-fail case as N per-source issues — `run_refresh` already
  returns 1 and aborts commit there; the mass-outage guard covers the partial version.
- Don't reopen a just-closed issue on a flaky boundary — recovery-close should key on "resolved
  cleanly this run", and a re-break next run legitimately reopens (that's correct, not noise, because
  it means it actually broke again).
- The gate/issue step must be `always()` so it runs after a render that returned 0-with-regressions
  *and* so recovery-close runs on fully-passing days.

---

## 8. Tests

- **Classification** (pure, high-value): feed `diagnose()` fixtures for each outcome and assert the
  `failure_class` — especially the reachable-empty (structural) vs unreachable (transient) split, and
  the exception-type split in the top-level except.
- **Regression flag**: a failure for a key present in a fixture `state.json` → `regression: true`;
  absent → `false`.
- **Report schema**: assert the JSON shape is stable (a consumer/workflow depends on it).
- **Gate decision** (can be a small pure function fed the report): ≥1 structural regression →
  non-zero; only transient / only never-resolved → zero; count over threshold → mass-outage mode.
- The `gh`/issues glue is workflow bash — cover the decision logic in Python and keep the API calls
  thin enough to eyeball.

---

## 9. Non-goals

- No paging/webhook integrations (issue + failing check is the surface; a webhook can consume the issue
  later if wanted).
- No committed health/metrics file, no `schema` change, no per-run timestamps in the tree.
- No change to feed isolation — a regression still degrades to stale-not-empty; escalation is
  purely additive signal.
- No N-day threshold logic — the structural/transient classification replaces it. (If a
  persistently-*transient* source ever needs catching, revisit; today the reachable-empty→structural
  refinement already routes "moved endpoint" into the escalating class.)
