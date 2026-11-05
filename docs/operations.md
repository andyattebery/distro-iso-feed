# Operations

How the feed runs unattended, and what to do when it pings you. The goal: **no monitoring on a good
day, one actionable ticket on a bad one.** The design intent and rationale live in
[`failure-escalation-spec.md`](failure-escalation-spec.md); this is the operator's view.

## The two jobs

- **`refresh`** (daily) — resolve every source, render `feed/`, commit. Publishing *is* the commit.
- **`discover`** (weekly) — open a PR proposing new variants; never pushes to `main`. Also runs the
  audit (non-strict) and opens an `audit-finding` issue per finding, closing it when it clears.
- **`config-audit`** (on push, only when `config/sources.yaml` changes) — resolves every configured
  variant against live upstreams, `--strict`. Discovery proves its own proposals resolve before
  writing them; this gives hand-written config the same proof. See *never-resolved keys* below.
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

**Anything the config names must arrive.** Nothing configured is optional: `sums`, `torrent`,
`torrent_sums`, and a `sig` with no pin are all promises, and a variant without one leaves the param
out, as Tails does with `sums`. If one is missing or wrong, the run fails with a `sidecar-missing`
regression and an issue. A new release publishes anyway, and a torrent problem never holds back the ISO,
but a release that already has its checksum keeps it, so nobody is re-notified, and a gpg-verified
entry holds rather than take a release it cannot verify. Quiet exceptions: a
transient failure, and a torrent that exists but still names the previous release, as Tumbleweed's does
for a while. A pinned signature has this rule already, through the signing gate.

A failure escalates only if it is **structural AND a regression** (the key has a record in
`state.json` — it *was* resolving). A never-resolved key is a config problem, not a 3am page — the
refresh leaves it to the audit's `UNRESOLVABLE` check, which runs on every commit that touches
`config/sources.yaml` (`config-audit`) and again weekly. That handoff used to name a check that did
not exist, which is how `ubuntu-unity:desktop-interim` sat dead from the day it was added: it asked
for a non-LTS Ubuntu Unity, and Unity ships LTS only. `UNRESOLVABLE` reports **structural** failures
only — a mirror that timed out is stale, not wrong. `NO_CHECKSUM` and `NO_TORRENT` come from the same
resolve and draw the same line: a variant that never resolved has no record to regress from, so these
are how a config mistake gets caught on its push.

**Issues are the state.** There is no committed health file. An open `refresh-*` issue *is* the record
that something is broken; the gate auto-closes it when the source recovers. The report lives in
`$RUNNER_TEMP`, never committed, so a nothing-moved day still makes no commit.

## The issues, and the fix each one wants

Every issue is a work order — a `## To resolve` section, the repro command, and a collapsed block of
the raw report JSON. Point Claude Code (or yourself) at one and it has what a fix needs.

| Issue (label) | Trigger | Fails job? | The resolving PR | Key fields the issue carries |
|---|---|---|---|---|
| **resolve regression** (`refresh-failure`) | A *tracked* source stopped resolving structurally, or a file its config names did not arrive (`sidecar-missing`): 404/moved, 200-but-empty (redesigned), candidates present but none match, matched-but-no-version-token, or the resolver returned None with candidates listed *and its own fetches having succeeded* (a listing that failed on the network is transient) | Yes | Usually `config/sources.yaml` for the key — bring `match`/`version_pattern`/`index`/`url` back in line with what upstream lists now; `--dry-run --only <key>` confirms. If upstream still publishes the right artifact, suspect the **lister** instead: a windowed listing can push it off the end with nothing changed upstream (`releases.atom` is 10 entries — that is how Bazzite's three variants broke on 2026-07-28). Third outcome: **upstream retired the edition** — then remove the variant from `config/sources.yaml`; the next refresh drops it from the feed (see below). For `sidecar-missing` the issue shows what upstream lists beside the artifact: another name means fix the config or a rename (`sums` can list alternatives on `directory_index` and `page_index`, for an upstream that renames its sidecar, as EndeavourOS does); nothing means upstream has not published it and this closes itself; stopped for good means remove the param | `cause`, `endpoint`+`status`, `observed_candidates` (what it lists now), current `params`, `last_good` (+`last_good_seen`, when that version first appeared), `page_url`, `repro` |
| **signing key** (`refresh-signing-key`) | The pinned GPG key no longer verifies and there is *evidence* (verdict `REJECTED`; a 4xx other than 429 on the key/signature/signed file counts). `cause` says why: `foreign-signer`, `bad-signature`, `unsigned`, `key-url`, `checksum-absent`. A gpg-verified entry keeps its release (`held_version`); one never verified drops to `checksum`. > 5 at once collapse into one issue, grouped by cause | Yes | Per `cause` — the issue's *To resolve* says which. Only `foreign-signer` can be a rotation: **verify it is the project's announced key first** (official channel / chained to trust anchor), *then* update `signing_key.fingerprint`; `--dry-run` proves it re-verifies. `unsigned`, `bad-signature` and `checksum-absent` close themselves once upstream fixes the file — never touch the fingerprint for them | `cause`, `pinned_fpr`, `actual_signer_fpr` (who signs now, `foreign-signer`), `key_url`, `covers`, `held_version` |
| **pinned release** (`refresh-pin`) | A source frozen to a literal release (`audit.pins`) — resolves cleanly, serves stale forever, every check keeps passing | No (ticket only) | Replace the literal with `version_dir`/`version_page`/`probe_versions` if upstream lists; else add `pinned_ok: true` with a reason | `detail` (the literal + where), `page_url` |
| **audit finding** (`audit-finding`, weekly) | The Monday audit's `UNEXPLAINED` or `SKIPPED_RELEASE`: an edition no variant tracks, or a newer release a variant fell back past, whether its dir serves nothing or no longer holds this variant's file, so an edition dropped from a release reports too. Up to a week late, and left to the audit because both resolve cleanly, so no refresh fails. Everything else has its own daily ticket or fails `config-audit` on the push: `PINNED`, and a `refresh failure` for a tracked variant that stops resolving or loses a file. More than 5 issues collapse into one | No (ticket only), though any of them fails `config-audit` on a push that touches `config/sources.yaml` | Per finding, and the issue says which. `UNEXPLAINED`: merge the discovery PR, or `discover.ignore`. `SKIPPED_RELEASE`: follow the moved layout, read the announced release with `page_index`/`version_page` where a listing lags, as Tails does, or retire the variant if the edition was dropped. An RC-only dir needs its marker in `ignore`, as OPNsense has | `detail`, repro. A transient failure can skip a finding for a run, closing its issue until the next Monday |

**Security note on rotated keys:** never bump the fingerprint to whatever signed the artifact — that
voids the pin's entire purpose. Confirm the new key's provenance first; the ticket says so.

**Retiring a variant upstream dropped.** Remove it from `config/sources.yaml`; that is the whole fix.
`state/state.json` *is* what the feed renders from, so every refresh drops the records of variants that
are no longer configured, and the variant leaves the feed on the next run. Do not hand-edit `state.json`
or regenerate locally for this. The prune reads the whole config, so an `--only` run retires what left the
config but never a configured variant it did not select. It never reads a resolve result, so a variant that
merely failed keeps its record. Say *why* in a comment
beside the surviving variants, or the next person re-adds them from an old filename that still 200s: Nobara
44 unified its images and stopped building a separate NVIDIA ISO, so its four `-nv` variants went on
2026-08-29. Where upstream stopped publishing without saying so, say that instead. If `discover.group` still
matches the old name, an edition that returns comes back as a discovery proposal; on an `enumerable: false`
distro nothing will, so the comment is all that is left.

### What deliberately does *not* open an issue

- **Transient** resolve failures — self-heal, shown in the run summary only. This includes a
  **listing fetch that failed on the network and succeeded on the diagnose re-listing**: the
  classification comes from the trace of the resolve that actually failed, not from `diagnose`'s
  own retry. Until 2026-08-29 it came from the retry, so a mirror blip that had healed seconds
  later opened `refresh failure: debian:netinst` and failed the job. A re-listing that shows the
  regex genuinely stopped matching still escalates — the downgrade applies only in the one
  branch that has no evidence of its own. It also includes a
  **configured checksum sidecar that timed out**: the entry is left exactly as it was rather than
  republished without a checksum, and it retries next run.
- **A host over its failure budget** — after 3 transient failures to one host in a run, its
  remaining URLs are skipped and its entries left untouched. Expect a `skipping its remaining
  URLs` warning in the log and a cluster of transient rows in the summary. That is a sick mirror,
  not a break; it resolves itself by tomorrow.
- **`DEFERRED`** signing — gpg absent on the runner, a network blip on the key/signature/signed
  file, or gpg unable to read the signature. A gpg-verified entry is
  kept exactly as it is: a new release waits, listed under *Held* in the summary, unless it sits at
  the same URL. An entry never verified is published as resolved, unpinned. Retried next run; no
  issue. The one worth a glance is "gpg unavailable on this runner" — a setup problem, not a network
  one.
- **All sources failed** — the run already fails (a broken runner/network/deploy); no per-source
  issue. A partial mass-regression (> 5 sources at once) opens a single `refresh-mass-outage` issue
  instead of flooding the tracker. Signing failures collapse the same way, into one
  `refresh-signing-key` issue — one key backs many variants (28 share Ubuntu's, 14 Debian's), so a
  rotation is one event, not N breaks.
- A failing **`ci.yml`** — a code bug; fix it with a normal code PR, not through this system.

## The signing verdict, for reference

`verify_signing_key` returns one of three verdicts, each with a reason:

- **`VERIFIED`** — the signature chains to the pinned key → the pin is published.
- **`REJECTED`** — evidence the pin did not sign this release; `cause` names it. Possible causes:
  - a signature by another key (`foreign-signer`: a rotation, or tampering);
  - the pin's signature no longer checking out — changed bytes or a damaged file
    (`bad-signature`);
  - no signature at all (`unsigned`);
  - a key URL that no longer serves the pin (`key-url`);
  - a signed file that doesn't list the artifact (`checksum-absent`).

  A 4xx other than 429 on the key, signature or signed file counts. A gpg-verified entry keeps
  its release, and the issue says so. Otherwise the gpg claim is dropped (the entry degrades to
  `checksum`). This escalates.
- **`DEFERRED`** — verification couldn't run: gpg absent, gpg unable to read the signature, or a
  network failure fetching the key/sig/SUMS. A gpg-verified entry is kept exactly as it is; its new
  release waits a run, unless it sits at the same URL. Otherwise the entry is left as resolved.
  Either way it is retried next run. This is deliberate: an environmental hiccup must never strip a
  valid pin or flap an entry's `verify` level.

## Dependency freshness

`.github/dependabot.yml` opens monthly, grouped PRs for the pinned actions and the `uv` project — at
most one PR per ecosystem per month, each gated by `ci.yml`. Note `setup-uv`'s major tracks uv's minor
(v8 ↔ uv 0.8), so an action bump there is a uv-toolchain change — review it, ideally alongside the `uv`
update.
