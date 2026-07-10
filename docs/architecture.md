# Architecture

The thing worth internalising before changing anything here:

> **A `200` is not evidence.** Neither is an RSS item count, nor "the page has no
> `.iso` links". Those are transport-level signals. Read the bytes the strategy
> would read — the atom entries, the redirect chain, the filenames, the page's own
> JavaScript.

Four wrong conclusions were reached during design by trusting the cheap signal:

| Signal trusted | What it actually was |
|---|---|
| `releases.atom` → `200` | Zero `<entry>` elements (Nobara) |
| `curl -L` → `200` | A catch-all `302`, so *every* path "exists" (elementary) |
| RSS → 100 items | An archive of versions 1–11 (Zorin) |
| Page → no `.iso` in HTML | A 95-byte `<meta refresh>` stub (Manjaro) |

`distro-iso-feed-refresh --dry-run` exists to mechanise the fix: it prints the resolved
artifact — filename, version token, checksum, algorithm — and never a status code.

## The five axes

The spec proposed six strategies. Writing 27 of them revealed that the strategies
are *presets*, and the real structure is a product of five orthogonal concerns:

| Axis | Module | Implementations |
|---|---|---|
| **Lister** — where candidates come from | `listers.py` | autoindex, version-dir, candidate-probe, RSS, atom, JSON, product page, GH assets, fixed URL |
| **Selector** — pick the right one | `select.py` | anchored match, decoy `ignore`, prerelease reject, max-version, dedupe |
| **Token** — where `version` comes from | `tokens.py` | filename, sidecar filename column, JSON field, atom tag |
| **Integrity** — checksum + signature | `checksums.py` | GNU / BSD / bare-hash; algo-by-length; aggregate vs sidecar |
| **URL** — how to build `download_url` | strategies | from listing, template, `/download` redirector, fixed, JSON field |

Every seeded source is a point in that space. `strategy:` in `sources.yaml` names a
preset over it, so **adding a distro stays a config edit**.

Two consequences that are not cosmetic:

- **`html_scrape` was never a strategy.** After a candidate list exists, a product
  page and an autoindex go through the identical pipeline. Only the *listing* step
  is fragile, which is why `page_index` names a lister rather than a parallel
  universe, and why the fragility is confined to one function.
- **The ublue projects are not `github_releases`.** GitHub supplies only their
  version string; the download URL is fixed on another host and the checksum is a
  sidecar beside it. That is `stable_symlink` with `token: {from: atom_tag}`.
  `github_releases` is reserved for "the artifact *is* a release asset" — MiniOS.

`discover_variants` is implemented once, in `strategies/base.py`. A lister already
returns every candidate, so grouping its output gives variant discovery for free
wherever enumeration is possible. The feature the spec most wanted falls out of the
seam.

## Invariants worth not breaking

**`version` is the change-token, not the marketing version.** Anything that changes
the bytes must change `version`, or `guid()` doesn't move and no subscriber ever
learns about it. Fedora proves it: `releases.json` says `44` for both the original
and a respin, while the filename and `sha256` both change. So the token is `44-1.7`.

**Three identifiers, not interchangeable.**

| | Value | Purpose |
|---|---|---|
| `state.json` key | `fedora:workstation` | one current record per **variant** |
| `Release.guid()` | `fedora:workstation:44-1.7` | identifies an **artifact**; RSS `<guid>` |
| `feed.atom_id()` | `https://github.com/…/id/fedora/workstation/44-1.7` | Atom `<id>`; an IRI |

Keying state by `guid()` would append a key per release and the feed would grow
forever — the exact bug `N=1` avoids. And the Atom id deliberately is **not** the
`raw.githubusercontent.com` URL: that embeds the host and the branch name, so
renaming `main` would change every id at once and every reader would re-notify on
the entire feed. Ids are identity; links are location. The id URL intentionally 404s.

**Determinism.** No generated file contains a clock. Entry timestamps freeze at
first sight; the feed's `<updated>` is the newest entry's timestamp. A daily commit
must be *empty* when nothing moved, or `git diff` stops meaning "a distro released
something". `docs/catalog.md` is the easiest place to break this, because a build
timestamp feels natural on a docs page.

**Failure isolation.** A resolver returns `None` rather than raising. The variant's
record is left untouched, so the feed degrades to **stale, never empty**.

**No source names its own release.** A missing variant is visible — nothing appears
in the feed. A **pinned** one is not: it resolves cleanly, publishes a valid
checksum, and serves a stale release forever while every check in this repo stays
green. Two shipped that way, `builds/24.04/intel` and `antiX-26`, and nothing here
could see either. So a release-shaped literal in `url`, `index`, `path` or `match`
is a finding: `audit.pins()` flags it, and a test asserts the real config is clean.
A variant that finds its release another way — `version_dir`, `probe_versions` — is
exempt, because that lookup is the mechanism, not an excuse for the literal.

These are two independent questions, and conflating them is what let Pop's pin hide:

| | Question | Enforced by |
|---|---|---|
| Variants | can we enumerate what upstream publishes? | `config.py` requires `discover:` |
| Release | does the source find its own latest release? | `audit.pins()`, offline, in `pytest` |

**Every distro answers the enumeration question.** `discover:` is mandatory: either
a `group` regex, or `enumerable: false` with a **`reason`** saying what was checked.
Twenty-one distros once had neither, so nothing enumerated them and their
completeness rested on a hand audit done once. Silence read the same as "nothing to
find". The `reason` is the product — it separates a fact someone verified from a
label someone reached for. Pop!_OS wore `enumerable: false` while pinned to 24.04.

**A proposal is executed, not guessed.** Discovery synthesizes a config node by
diffing the new artifact's filename against the closest sibling's, substituting the
changed tokens into that sibling's YAML node, and then calling `resolve()`. It is
kept only if it resolves to *the artifact that produced the key* — a node resolving
to the sibling's ISO is a silent duplicate variant, and that is exactly what a
plausible-but-wrong substitution yields. What cannot be synthesized is reported,
never dropped. `match: TODO` made the PR a to-do list, and a to-do list is a thing
you skim: eight Fedora spins and five Nobara editions stayed missing while that PR
sat open, accurately saying something was there.

**The discovery surface is not always the resolve surface.** Aurora resolves a fixed
URL while `dl.getaurora.dev/` is a plain index; neon resolves
`images/<edition>/current/` while `images/` lists the editions. `discover.index`
points enumeration at the right URL, and only rows *under* that URL survive — neon's
listing carries forty links of KDE site navigation beside its six image directories.

## The checksum-format zoo

Three formats, all live:

```
<hash>  <name>                          GNU  — most sources
SHA256 (<name>) = <hash>                BSD  — FreeBSD only
<hash>                                  bare — Batocera's .md5, no filename column
```

Plus the traps: algorithms are told apart by **exact hex length** (md5 32, sha1 40,
sha256 64, sha512 128), because Garuda co-publishes a `.iso.sha1` beside its
`.iso.sha256` and the weaker one must never win. Nobara's filename column reads
`./Nobara-…iso`, so a leading `./` is normalised away. Q4OS publishes **one
aggregate** `md5sum.txt` covering every release including `i386` and older versions,
so "the first hash" would attach an i386 checksum to an x64 ISO.

And the one that looks like a bug but is the mechanism: for `stable_symlink`, the
sidecar's filename column **deliberately differs** from the download filename. neon
serves `neon-desktop-current.iso` while its sidecar names
`neon-desktop-20260707-0147.iso`. That mismatch is where the change-token comes
from, so `checksums.sole()` accepts a single-entry sidecar regardless of its name.

`verify` is derived, never configured: signature ⇒ `gpg`, else checksum ⇒
`checksum`, else `none`. Tails signs without publishing a checksum, so a signature
does not imply one. The `verify: none` path currently has no seeded source, but it
is built and tested — a source can lose its checksums upstream at any time, and the
`WARNING: no published checksum` line is what stands between that and a silently
unverifiable entry. Do not delete it as dead code.

## Adding a source

1. Add a block to `config/sources.yaml`.
2. `uv run distro-iso-feed-refresh --dry-run --only <distro>` and read the artifact it prints.
3. Anchor `match`. Then look at what else lives in that directory and put every
   **decoy** in `ignore` — decoys belong there and not only in `match`, because
   `match` guards the feed while `ignore` guards the weekly discovery PR.
4. Write the `discover:` block. It is mandatory and `load()` rejects the config
   without it: either a `group` regex that yields the variant keys you configured,
   or `enumerable: false` with a `reason` recording what you actually checked.
   A single-artifact source (Arch, Tails) still gets a `group` — one that proposes
   nothing today and catches a genuinely new edition tomorrow. Calling it
   unenumerable would hide a fact behind a label.
5. `uv run distro-iso-feed-audit --only <distro>` — it must report nothing. A
   finding here means the `group` regex produces a key you did not configure.
6. Add a fixture-backed test if the source has an unusual shape.

A genuinely new upstream *shape* needs a new **lister**, not a new strategy. A new
strategy is only warranted when the URL-building rule itself is new.

## Sources considered and not seeded

Recorded so nobody re-investigates them. Several look trivially addable.

| Source | Why not |
|---|---|
| **elementary** | Releases carry zero assets. The download host mints an expiring per-visitor link (`…/download/<base64-unix-timestamp>/…iso`), and the untokenized path is a catch-all `302` — so *any* filename appears to 200 under `curl -L`, including ones that do not exist. Its newest tags are RCs, and GitHub reports `8.1.0-rc3` with `prerelease: false`, so that flag cannot be used either. |
| **AnduinOS** | Every release asset is a `.torrent`. Torrents are out of scope, so there is no eligible artifact. |
| **Zorin** | The download page exposes no ISO link (downloads run through a Paddle checkout), and its SourceForge project `zorin-os` is an **archive**: versions 1, 10, 11 and a `16-Core-Beta`, with `/17` and `/18` empty. The 100-item RSS feed is what makes it look usable. |
| **SparkyLinux** | No `.iso` in its SourceForge RSS at any path tried. |
| **PikaOS** | `pika-os.com/download` 404s and there is no releases feed. |
| **uCore** | Neither `download.ublue.it` nor `dl.ucore.dev` resolves. Bazzite, Bluefin and Aurora are all seeded; uCore alone has no reachable host. |
| **BigLinux** | No SourceForge project under `biglinux`, `biglinux-iso` or `big-linux`. |
| **Kali `live`, `live-everything`, `installer-everything`** | Listed in Kali's `SHA256SUMS`, but all three **404** as direct downloads — they ship by torrent. A checksum file is not an index. |
| **Manjaro via SourceForge** | `manjarolinux` exists with 32 ISOs, and every one is a `-pre` prerelease. Skipping betas leaves nothing, so Manjaro stays a `page_index` source. |
| **openSUSE Leap `-Current.iso`** | Exists, but is not linked from the index, so `directory_index` cannot see it. The listed `Build710.3-Media.iso` carries a better change-token anyway. |

## Mirrors

§2 prefers a first-party endpoint. Four sources are marked `mirror: true` because
they cannot honour it:

- **EndeavourOS** publishes no first-party download host at all.
- **Batocera**'s official host serves **no checksum**; only the o2switch mirror
  co-locates the `.md5`. This trades §2's host preference for §10's integrity
  requirement — a checksum from a mirror beats no checksum from the origin.
- **Mint** and **Arch** are mirror-distributed by design.
