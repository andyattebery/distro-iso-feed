# Operations

How the feed runs unattended, and what to do when it pings you. The goal: **no monitoring on a good
day, one actionable ticket on a bad one.** The design intent and rationale live in
[`failure-escalation-spec.md`](failure-escalation-spec.md); this is the operator's view.

## The two jobs

- **`refresh`** (daily) — resolve every source, render `feed/`, commit. Publishing *is* the commit.
- **`discover`** (weekly) — open a PR proposing new variants; never pushes to `main`.
- **`ci`** (every push/PR) — `pytest` + `ruff`. This is the *only* place tests gate anything. The
  daily refresh deliberately does **not** run the suite: a code or runner-environment problem (a gpg
  version bump on the runner, once) belongs on a PR check, not blocking the whole feed from rendering.

## What breaks silently, and what now doesn't

A source that **was** resolving and **stops** used to leave the job passing (only an all-sources
failure would fail it). Now the daily refresh writes a JSON report and a **health gate** turns it into
issues + the job's pass/fail. The classification is the whole false-alarm filter — no N-day counter:

- **Structural** — the request *succeeded* but the content was wrong or absent (a 404/moved endpoint, a
  200 page that redesigned, a regex that no longer matches, a version token that vanished). These
  essentially never self-heal → escalate.
- **Transient** — the request *failed* (timeout, DNS, connection refused, 5xx, 429). Self-heals by
  tomorrow → **no issue, no failure**; it just shows as stale in the run summary.

A failure escalates only if it is **structural AND a regression** (the key has a record in
`state.json` — it *was* resolving). A never-resolved key is a config/PR-time problem, `audit`'s job.

**Issues are the state.** There is no committed health file. An open `refresh-*` issue *is* the record
that something is broken; the gate auto-closes it when the source recovers. The report lives in
`$RUNNER_TEMP`, never committed, so a nothing-moved day still makes no commit.

## The issues, and the fix each one wants

Every issue is a work order — a `## To resolve` section, the repro command, and a collapsed block of
the raw report JSON. Point Claude Code (or yourself) at one and it has what a fix needs.

| Issue (label) | Trigger | Fails job? | The resolving PR | Key fields the issue carries |
|---|---|---|---|---|
| **resolve regression** (`refresh-failure`) | A *tracked* source stopped resolving structurally: 404/moved, 200-but-empty (redesigned), candidates present but none match, or matched-but-no-version-token | Yes | Edit `config/sources.yaml` for the key — bring `match`/`version_pattern`/`index`/`url` back in line with what upstream lists now; `--dry-run --only <key>` confirms | `cause`, `endpoint`+`status`, `observed_candidates` (what it lists now), current `params`, `last_good` (+`last_resolved`), `page_url`, `repro` |
| **rotated signing key** (`refresh-signing-key`) | The pinned GPG key no longer verifies — the current signature is from a *different* fingerprint (verdict `REJECTED`); the entry dropped to `checksum` | Yes | **Verify the rotation is the project's announced key first** (official channel / chained to trust anchor), *then* update `signing_key.fingerprint`; `--dry-run` proves it re-verifies | `pinned_fpr`, `actual_signer_fpr` (who signs now), `key_url`, `covers` |
| **pinned release** (`refresh-pin`) | A source frozen to a literal release (`audit.pins`) — resolves cleanly, serves stale forever, every check keeps passing | No (ticket only) | Replace the literal with `version_dir`/`probe_versions` if upstream lists; else add `pinned_ok: true` with a reason | `detail` (the literal + where), `page_url` |

**Security note on rotated keys:** never bump the fingerprint to whatever signed the artifact — that
voids the pin's entire purpose. Confirm the new key's provenance first; the ticket says so.

### What deliberately does *not* open an issue

- **Transient** resolve failures — self-heal, shown in the run summary only.
- **`DEFERRED`** signing — gpg absent on the runner, a key-server blip, or no signature to check. Kept
  as-is (no pin published, entry not dropped), retried next run; summary only. The one worth a glance
  is "gpg unavailable on this runner" — a setup problem, not a network one.
- **All sources failed** — the run already fails (a broken runner/network/deploy); no per-source
  issue. A partial mass-regression (> 5 sources at once) opens a single `refresh-mass-outage` issue
  instead of flooding the tracker.
- A failing **`ci.yml`** — a code bug; fix it with a normal code PR, not through this system.

## The signing verdict, for reference

`verify_signing_key` returns one of three verdicts, each with a reason:

- **`VERIFIED`** — the signature chains to the pinned key → the pin is published.
- **`REJECTED`** — a signature exists but does *not* chain to the pin (a rotation, or tampering) → the
  gpg claim is dropped (the entry degrades to `checksum`), and this escalates.
- **`DEFERRED`** — verification couldn't run (gpg absent, or a transient key/sig/SUMS fetch failure).
  The entry is left exactly as resolved and retried next run. This is deliberate: an environmental
  hiccup must never strip a valid pin or flap an entry's `verify` level.

## Dependency freshness

`.github/dependabot.yml` opens monthly, grouped PRs for the pinned actions and the `uv` project — at
most one PR per ecosystem per month, each gated by `ci.yml`. Note `setup-uv`'s major tracks uv's minor
(v8 ↔ uv 0.8), so an action bump there is a uv-toolchain change — review it, ideally alongside the `uv`
update.
