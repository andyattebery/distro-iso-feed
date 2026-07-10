# Distro ISO Feed — Specification

A static-site generator that publishes a **unified RSS/Atom feed of the latest ISO releases**
for a configurable set of Linux (and BSD) distributions. It runs daily as a GitHub Action,
commits the regenerated feed to the repo, and serves it via GitHub Pages. A separate,
heavier "variant discovery" pass runs on its own schedule and proposes newly-appeared
variants as pull requests.

The feed is the product. Downloading is deliberately **out of scope** — any consumer
(Flexget, a fetch script, a reader, n8n) can subscribe to the feed and do the fetching.

---

## 1. Goals & requirements

1. **Config-file driven.** All sources, variants, and strategy parameters live in a
   version-controlled config file. Adding or tuning a source is a config edit, not a code change.
2. **Strategy abstraction.** Each *kind* of upstream (directory index, GitHub releases,
   SourceForge, JSON API, stable symlink, HTML scrape) is one reusable strategy. A distro
   references a strategy plus parameters.
3. **Variants are first-class, and new ones auto-appear.** A distro has many editions/variants
   (e.g. Fedora Workstation/Server/KDE; Bazzite deck/desktop/nvidia/dx; Ubuntu desktop/server).
   All configured variants are emitted. Newly-published variants are **auto-discovered** by a
   separate pass so the fast daily refresh never has to do full enumeration.
4. **Easy to add a new distro.** Adding a distro = add a config block; only a genuinely new
   upstream shape requires a new strategy class.
5. **Hosted on GitHub, daily via GitHub Action.** Static output on Pages; CDN-fronted so it is
   itself a cache-friendly, ETag-bearing poll target for downstream consumers.

---

## 2. Design principles (the "why", carried over from prior analysis)

These shaped the architecture; keep them in mind when implementing strategies.

- **Detection and derivation are separate axes.** "Is there a new version?" and "what's the
  URL?" are different questions. Some sources answer both in one fetch (a JSON API, a
  SourceForge RSS item); others need one call to detect and another to build the URL
  (Fedora's respin suffix, Pop's build number). Model a strategy as: *resolve() → the latest
  Release, including the final download URL*, so the rest of the system doesn't care which axis
  was hard.
- **Poll the smallest authoritative object, never the HTML index if avoidable.** Prefer, in
  order: a JSON/metadata endpoint → a checksums/SUMS file → a stable "current"/"latest" symlink →
  a directory autoindex → an HTML page scrape. The autoindex and page scrape are fragile
  (layout can change without notice) and are last resorts.
- **Don't trust conditional-request semantics upstream — content-diff yourself.** `ETag`/
  `If-Modified-Since` are an *optimization*: send them, but decide "changed?" by comparing the
  fetched payload (or a hash / parsed version) to last-seen state. Many mirrors, redirectors,
  and CDNs strip or weaken validators, especially across a 302 to a mirror.
- **Official first-party endpoint beats a third-party aggregator** (DistroWatch, endoflife.date)
  on timeliness and reliability wherever one exists. Aggregators are a fallback, not a foundation.
- **You are becoming the feed publisher these projects mostly don't offer.** The generated feed,
  hosted on Pages, is the stable, cache-friendly, normalized poll target that upstreams lack.

---

## 3. Suggested stack

- **Language:** Python 3.12+ (rich ecosystem for this: `httpx`, `feedgen` for Atom/RSS,
  `tomllib`/`ruamel.yaml`, `defusedxml`, `packaging.version` for version sorting).
- **Config format:** YAML (readable, comments, anchors for shared blocks). TOML is acceptable.
- **Output:** `public/feed.xml` (Atom 1.0 preferred; also emit RSS 2.0 if trivial) + optional
  per-distro feeds under `public/feeds/<distro>.xml`, plus `public/index.html` (human landing page).
- **Hosting:** GitHub Pages from `public/` (or `gh-pages` branch).
- **State:** `state/state.json` committed to the repo (last-seen version + hash per variant).

Keep strategies pure and unit-testable: a strategy takes params + an HTTP client and returns
`Release` objects; no global state, no feed knowledge.

---

## 4. Repository layout

```
distro-iso-feed/
├── config/
│   └── sources.yaml          # THE config (all distros, variants, strategy params)
├── src/
│   ├── models.py             # Release, Variant, Source dataclasses
│   ├── client.py             # HTTP client: retries, UA, conditional GET, content-diff
│   ├── feed.py               # Atom/RSS emission from Release list
│   ├── state.py              # load/save last-seen state; "is this new?" logic
│   ├── run_refresh.py        # daily: resolve all → write feed → commit if changed
│   ├── run_discover.py       # periodic: enumerate variants → open PR with additions
│   └── strategies/
│       ├── base.py           # Strategy ABC (resolve, discover_variants)
│       ├── directory_index.py
│       ├── stable_symlink.py
│       ├── json_api.py
│       ├── github_releases.py
│       ├── sourceforge.py
│       └── html_scrape.py
├── public/                   # generated; served by Pages
├── state/state.json          # generated; committed
├── tests/
└── .github/workflows/
    ├── refresh.yml           # daily cron
    ├── discover.yml          # weekly cron → PR
    └── pages.yml             # deploy public/ to Pages
```

---

## 5. Data model

```python
@dataclass
class Release:
    distro: str            # "fedora"
    variant: str           # "workstation"
    version: str           # "44" or "2026.2" or "26.05.xxxxx"
    title: str             # "Fedora Workstation 44 (x86_64)"
    download_url: str      # final, resolved, direct URL
    filename: str          # basename of the download
    published: datetime | None
    checksum: str | None
    checksum_algo: str | None      # "sha256" | "sha512"
    signature_url: str | None      # detached sig, if any
    verify: str            # "checksum" | "gpg" | "none"
    notes: str | None      # e.g. "no published checksum — integrity unverifiable"

    def guid(self) -> str:         # stable, unique per released artifact
        return f"{self.distro}:{self.variant}:{self.version}"
```

`guid` is the dedup boundary: an entry appears once, when first seen. Rolling images whose
"version" is date/hash-based (Bazzite, Tumbleweed, NixOS channel) will naturally emit a new
entry when that token changes.

---

## 6. Config file design (`config/sources.yaml`)

The config is the primary interface. Shape:

```yaml
defaults:
  arch: x86_64
  user_agent: "distro-iso-feed/1.0 (+https://github.com/you/distro-iso-feed)"

distros:

  fedora:
    strategy: json_api
    params:
      url: "https://fedoraproject.org/releases.json"
    variants:                       # explicit variants; discovery can append here
      workstation:
        select: { link_contains: "Workstation-Live-x86_64", subvariant: "Workstation" }
      server:
        select: { link_contains: "Server-netinst-x86_64", subvariant: "Server" }
    discover:                       # optional: how the discovery pass finds new variants
      enumerate: subvariants        # list distinct subvariants seen in the JSON
      ignore: ["Cloud", "Container"]

  debian:
    strategy: directory_index
    variants:
      netinst:
        params:
          index: "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"
          match: 'debian-[0-9.]+-amd64-netinst\.iso'
          sums:  "SHA512SUMS"       # relative to index; algo inferred from name
          sig:   "SHA512SUMS.sign"  # optional GPG
      live-gnome:
        params:
          index: "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/"
          match: 'debian-live-[0-9.]+-amd64-gnome\.iso'
          sums:  "SHA512SUMS"

  bazzite:
    strategy: github_releases       # detection; download URL is a fixed domain
    params:
      repo: "ublue-os/bazzite"
      download_base: "https://download.bazzite.gg"
    variants:
      deck:    { file: "bazzite-deck-stable-amd64.iso" }
      desktop: { file: "bazzite-stable-amd64.iso" }
    discover:
      enumerate: download_dir       # list download_base, glob *.iso → propose new variants

  mxlinux:
    strategy: sourceforge
    params:
      project: "mx-linux"
      path: "/Final"                # release subtree
    variants:
      xfce: { match: 'MX-[0-9.]+_x64\.iso' }
      kde:  { match: 'MX-[0-9.]+_KDE_x64\.iso' }
```

**Rules the loader enforces**

- A distro names exactly one `strategy`. Variants may override/extend `params`.
- `select`/`match`/`file` is the per-variant discriminator the strategy uses to pick its artifact.
- `discover:` is optional metadata telling the discovery pass how to enumerate variants for
  that distro (and what to ignore). Absent ⇒ that distro is not auto-expanded (fixed variant list).
- Everything a strategy needs must be expressible in `params`; no hard-coded distro logic in code.

---

## 7. Strategy abstraction

```python
class Strategy(ABC):
    name: str

    @abstractmethod
    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        """Return the single latest Release for this variant, or None on failure.
        MUST NOT raise on ordinary upstream errors — return None and let the runner log it.
        MUST bake the final, direct download_url and (where available) checksum into Release."""

    def discover_variants(self, distro: str, params: dict, client: Client) -> list[VariantSpec]:
        """Optional. Enumerate all variants currently published upstream, so the discovery
        pass can diff against configured variants and propose additions. Default: []."""
        return []
```

Failure isolation: `run_refresh` calls `resolve` per variant inside try/except; one failure
never aborts the run and never removes an existing feed entry.

### 7.1 Concrete strategies (and which distros use them)

| Strategy | How it detects + derives | Distros in scope |
|---|---|---|
| `directory_index` | GET a **stable** dir (a `current/`, `latest/`, or version dir); pick newest filename by regex + `sort -V`; read checksum from the co-located `SHA*SUMS`; optional GPG. | Debian, Kali, Arch, Void, FreeBSD, KDE neon, openSUSE Leap, Proxmox, Mint (`stable/<ver>/`) |
| `stable_symlink` | Fixed, version-less URL (a `*-current.iso` / `latest-*.iso` / rolling name). "New?" = changed sidecar checksum, else `ETag`/`Last-Modified`, else content hash. | Arch (`archlinux-x86_64.iso`), NixOS (`latest-nixos-*`), openSUSE Tumbleweed (`*-Current.iso`), ublue/Bazzite download domains |
| `json_api` | Fetch a JSON/metadata doc; extract version + link + checksum via a configured selector. | Fedora (`releases.json`), Pop!_OS (`api.pop-os.org`), Ubuntu (simplestreams), openSUSE (`.metalink`/`.meta4`) |
| `github_releases` | `https://github.com/<repo>/releases.atom` (feed, not rate-limited like the API) to detect; assets or a `download_base` to derive. Use `GITHUB_TOKEN` if the REST API is needed. | elementary, AnduinOS, Omarchy, EndeavourOS, Nobara(?), memtest86+, ublue variants (detection) |
| `sourceforge` | `https://sourceforge.net/projects/<project>/rss?path=/<dir>` (per-project file RSS) to detect newest; download via `.../files/<path>/<file>/download` redirector. | MX, antiX, Q4OS, SparkyLinux, Bluestar, MiniOS, BigLinux, Garuda (mirror), EndeavourOS (mirror) |
| `html_scrape` | **Last resort.** Regex a known page for version/link. Always content-diff. | Tails, Zorin, CachyOS, Manjaro, Nobara/PikaOS (until a better endpoint is confirmed), Mint (`download_all.php` / blog RSS) |

Notes for implementers:
- `directory_index` and `stable_symlink` share a checksum-parsing helper (`<hash>  <name>`;
  match exact-length hex to avoid grabbing a SHA512 line when you want SHA256).
- `github_releases`: prefer the `.atom` feed for detection (unauthenticated, not subject to the
  60/hr REST limit that will bite in Actions); only call the REST API with `GITHUB_TOKEN`.
- `sourceforge` download links are redirectors that may serve an interstitial or a slow mirror —
  the feed just needs the canonical `/download` URL; leave fetching to the consumer.

---

## 8. Variant discovery (separate pass — requirement #3)

Two workflows, deliberately decoupled:

- **`run_refresh` (daily, fast):** iterates only the variants already in `sources.yaml` and calls
  `resolve`. No enumeration. This is what keeps the feed fresh cheaply.
- **`run_discover` (weekly, heavier):** for each distro with a `discover:` block, calls
  `strategy.discover_variants()`, diffs the result against configured variants, and for any new
  ones **opens a pull request** that appends them to `sources.yaml` (with a sensible default
  `select`/`match`). Human review merges it; then the daily refresh picks them up. Opening a PR
  (rather than auto-committing) keeps a checkpoint against a bad enumeration silently adding junk.

`discover_variants` examples: list subvariants in Fedora's `releases.json`; glob `*.iso` in a
`download_base`; list a SourceForge release dir; enumerate matching files in a directory index.

Discovery must be conservative: apply the distro's `ignore` list, skip betas/RC/nightly by
default, and never *remove* variants (removal is a manual config edit).

---

## 9. Feed generation

- One consolidated **Atom** feed at `public/feed.xml`; optionally per-distro feeds.
- Per entry: `id` = `Release.guid()`; `title`; `updated`/`published`; `link rel="enclosure"` →
  `download_url` with `length`/`type` if cheaply known; `summary` carrying human text +
  **checksum + algo + verify status** (so a consumer can verify without another fetch); a
  `category` per distro and per variant.
- Ordering: newest `published` first. Cap total entries (e.g. keep last N per variant) so the
  feed doesn't grow unbounded; historical entries age out but GUIDs never get reused.
- Determinism: stable serialization (sorted entries, fixed timestamps for unchanged entries) so
  `git diff` only shows real changes and the daily commit is empty when nothing moved.

---

## 10. Integrity & verification

- Strategies populate `checksum`/`checksum_algo`/`signature_url`/`verify` when upstream provides
  them. The feed **carries** this; the generator does not download ISOs to verify.
- `verify: none` (e.g. Batocera — no published checksum) must be surfaced explicitly in the entry
  summary ("integrity unverifiable") rather than silently omitted, so a downstream fetcher can
  decide policy.
- Prefer fetching checksum/signature files over HTTPS from the project's canonical host, not a
  redirected mirror.

---

## 11. HTTP client behaviour

- Identifiable `User-Agent` (from `defaults.user_agent`).
- Retries with backoff; honor `429` + `Retry-After`.
- Conditional GET as an optimization only; **decide "changed" by content-diff/hash** against
  `state.json`, never by trusting a `304` alone.
- Poll cadence is daily; never re-download a multi-GB ISO to "check" — detection touches only
  metadata (JSON/SUMS/atom/HEAD).
- Be aware two things behave differently inside Actions: GitHub's API rate limit (use
  `GITHUB_TOKEN`) and geo-based mirror redirectors (they resolve from GitHub's runner location,
  not yours).

---

## 12. State & change detection

`state/state.json`: `{ "<guid-prefix distro:variant>": { "version": ..., "hash": ..., "seen": ISO8601 } }`.
On refresh: resolve → compare to state → if new version/hash, add feed entry + update state.
The committed feed + state together are the source of truth; a resolver returning `None` leaves
both untouched (fail safe).

---

## 13. GitHub Actions

**`refresh.yml`** (daily):
```yaml
on:
  schedule: [{ cron: "17 6 * * *" }]   # daily; avoid on-the-hour congestion
  workflow_dispatch:
permissions: { contents: write, pages: write, id-token: write }
jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: python -m src.run_refresh
        env: { GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} }   # for github_releases API
      - name: Commit if changed
        run: |
          git config user.name  "iso-feed-bot"
          git config user.email "[email protected]"
          git add public state
          git diff --cached --quiet || git commit -m "feed: $(date -u +%FT%TZ)"
          git push
      # then deploy public/ via pages.yml or actions/deploy-pages
```

**`discover.yml`** (weekly): runs `run_discover`, which uses `peter-evans/create-pull-request`
(or `gh pr create`) to propose new variants. Never pushes to `main` directly.

**`pages.yml`**: standard `actions/upload-pages-artifact` + `actions/deploy-pages` from `public/`.

---

## 14. Adding a new distro (requirement #4)

**Common case — reuse a strategy.** Append a block to `config/sources.yaml`:

```yaml
  void:
    strategy: directory_index
    variants:
      xfce-live:
        params:
          index: "https://repo-default.voidlinux.org/live/current/"
          match: 'void-live-x86_64-[0-9]+-xfce\.iso'
          sums:  "sha256sum.txt"
          sig:   "sha256sum.sig"
```

No code change. Run `run_refresh` locally to confirm it resolves, commit.

**Rare case — new upstream shape.** Add a class under `src/strategies/` implementing
`Strategy.resolve` (+ optional `discover_variants`), register it in the strategy map, then
reference it from config. Add a unit test with a captured fixture of the upstream response.

---

## 15. Source catalog (researched; verify endpoints during implementation)

`x86_64` assumed. "Current (Jul 2026)" is a sanity-check anchor, not something to hardcode —
resolvers must discover it. **⚠ = confirm the exact endpoint/filename while implementing.**
Rolling images have no fixed version; detect via hash/date token.

| # | Distro | Strategy | Detection endpoint | Download pattern | Variants (seed) | Current | Verify |
|---|---|---|---|---|---|---|---|
| 1 | **CachyOS** | html_scrape ⚠ | `cachyos.org/download` page (mirror listing) | mirror `.iso` + `.sha256` + `.sig` | desktop(KDE), handheld, ⚠ | monthly | gpg+sha |
| 2 | **Mint** | directory_index / html_scrape | mirror `stable/` index; official `linuxmint.com/download_all.php`; blog RSS `blog.linuxmint.com/feed/` | `stable/<ver>/linuxmint-<ver>-<edition>-64bit.iso` | cinnamon, mate, xfce | 22.3 | sha+gpg |
| 3 | **MX Linux** | sourceforge | `sourceforge.net/projects/mx-linux` RSS `?path=/Final` | `.../files/Final/.../MX-<ver>_*_x64.iso/download` | xfce, kde, fluxbox | ⚠ | sha ⚠ |
| 4 | **Debian** | directory_index | `cdimage.debian.org/debian-cd/current[-live]/amd64/.../SHA512SUMS` | `debian[-live]-<ver>-amd64-*.iso` | netinst, live-gnome, +DEs | 13.5.0 | sha512+gpg |
| 5 | **Pop!_OS** | json_api | `api.pop-os.org/builds/24.04/{intel,nvidia}` | `iso.pop-os.org/24.04/amd64/<gpu>/<build>/pop-os_*.iso` | intel, nvidia | 24.04 r25 | sha256+gpg |
| 6 | **Zorin** | html_scrape ⚠ | `zorin.com/download` (redirect/mirror; possibly SourceForge) ⚠ | mirror `.iso` | core, lite, pro, education | ⚠ | ⚠ |
| 7 | **EndeavourOS** | github_releases / sourceforge | `github.com/endeavouros-team/EndeavourOS-ISO/releases.atom`; SF mirror | GitHub asset or mirror `EndeavourOS_*.iso` | default (Calamares) | monthly | sha512+sig ⚠ |
| 8 | **Fedora** | json_api | `fedoraproject.org/releases.json` | `link` field (respin suffix only in JSON) | workstation, server, kde, … | 44 | sha256 (in JSON) |
| 9 | **Manjaro** | html_scrape / json_api ⚠ | `manjaro.org/download` (JSON manifest behind the page) ⚠ | mirror `manjaro-<edition>-<ver>-*.iso` + `.sha*` + `.sig` | kde, gnome, xfce (+community) | rolling | sha+gpg ⚠ |
| 10 | **Ubuntu** | json_api / directory_index | simplestreams `cdimage.ubuntu.com/releases/streams/v1/…`; or `releases.ubuntu.com/<ver>/SHA256SUMS` | `releases.ubuntu.com/<ver>/ubuntu-<ver>-<flavor>-amd64.iso` | desktop, live-server | 26.04 LTS / 24.04.x | sha256+gpg |
| 11 | **AnduinOS** | github_releases ⚠ | `github.com/Anduin2017/AnduinOS` releases.atom ⚠ | GitHub release asset `.iso` | default (GNOME) | ⚠ | ⚠ |
| 12 | **Bazzite** (ublue) | github_releases | `github.com/ublue-os/bazzite/releases.atom` | `download.bazzite.gg/<file>.iso` (version-less) | deck, desktop, gnome, nvidia, dx | rolling | sha256 sidecar ⚠ |
| 13 | **openSUSE** | directory_index / stable_symlink | Leap: `download.opensuse.org/distribution/leap/<ver>/iso/`; TW: `.../tumbleweed/iso/` `*-Current.iso`; append `.metalink`/`.sha256` | as above (MirrorCache redirector) | Leap DVD/NET, TW DVD/NET, Aeon, Kalpa | Leap 16.0 / TW rolling | sha256+gpg |
| 14 | **Arch** | json_api + directory_index | `archlinux.org/releng/releases/json/`; `geo.mirror.pkgbuild.com/iso/latest/` | `iso/latest/archlinux-x86_64.iso` (symlink) or dated | iso | 2026.07.01 | sha256+sig |
| 15 | **Nobara** | html_scrape / github_releases ⚠ | `nobaraproject.org` download (JS) or GitHub ⚠ | ⚠ hosted iso | official, gnome, kde, … | ⚠ | ⚠ |
| 16 | **PikaOS** | html_scrape ⚠ | `pika-os.com` download ⚠ | ⚠ | default | ⚠ | ⚠ |
| 17 | **antiX** | sourceforge | `sourceforge.net/projects/antix-linux` RSS `?path=/Final` | `.../Final/antiX-<ver>/antiX-<ver>_x64-*.iso/download` | full, base, core, net | 26 | sha ⚠ |
| 18 | **BigLinux** | sourceforge / github_releases ⚠ | `sourceforge.net/projects/biglinux` RSS ⚠ | SF `/download` | default (KDE) | ⚠ | ⚠ |
| 19 | **NixOS** | stable_symlink + directory_index | `channels.nixos.org/` (pick highest `nixos-XX.YY`); sidecar `latest-nixos-<ed>-x86_64-linux.iso.sha256` | `channels.nixos.org/nixos-<ver>/latest-nixos-<ed>-x86_64-linux.iso` | gnome, kde, minimal | 26.05 | sha256 |
| 20 | **elementary** | github_releases | `github.com/elementary/os/releases.atom` | GitHub release asset / redirect | default | ⚠ (8.x) | sha256 ⚠ |
| 21 | **Bluestar** | sourceforge | `sourceforge.net/projects/bluestarlinux` RSS ⚠ | SF `/download` | default (KDE) | rolling | ⚠ |
| 22 | **Q4OS** | sourceforge | `sourceforge.net/projects/q4os` RSS `?path=/<dir>` | `.../q4os-<ver>-x64.rN.iso/download` | trinity, plasma | 5.x | sha ⚠ |
| 23 | **KDE neon** | stable_symlink / directory_index | `files.kde.org/neon/images/user/current/` | `neon-user-current.iso` (+ `.sha256sum` + `.sig`) | user (+ testing/unstable) | rolling | sha256+gpg ⚠ |
| 24 | **MiniOS** | sourceforge ⚠ | `sourceforge.net/projects/minios-linux` RSS ⚠ | SF `/download` | standard, toolbox, … | ⚠ | ⚠ |
| 25 | **FreeBSD** | directory_index | `download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/<ver>/` + `CHECKSUM.SHA256(.asc)` | `FreeBSD-<ver>-RELEASE-amd64-disc1.iso` (+ memstick) | disc1, dvd1, memstick | ⚠ (14.x/15.x) | sha256+gpg |
| 26 | **Garuda** | sourceforge / html_scrape | `sourceforge.net/projects/garuda-linux` RSS ⚠; `garudalinux.org/downloads` | SF `/download` `garuda-<edition>-*.iso` | dr460nized(KDE), gnome, … | rolling | ⚠ |
| 27 | **Omarchy** | github_releases ⚠ | `github.com/basecamp/omarchy` releases.atom ⚠ | GitHub asset / hosted iso ⚠ | default (Arch/Hyprland) | ⚠ | ⚠ |
| 28 | **SparkyLinux** | sourceforge | `sourceforge.net/projects/sparkylinux` RSS ⚠ | SF `/download` `sparkylinux-<ver>-*.iso` | stable, rolling, DEs | ⚠ | ⚠ |
| 29 | **Void** | directory_index | `repo-default.voidlinux.org/live/current/sha256sum.txt(.sig)` | `void-live-x86_64-<date>-<flavor>.iso` | base, xfce | rolling | sha256+gpg |
| 30 | **Kali** | directory_index | `cdimage.kali.org/current/SHA256SUMS(.gpg)` | `cdimage.kali.org/current/kali-linux-<ver>-<edition>-amd64.iso` | live, installer, everything, qemu, … | 2026.2 | sha256+gpg |

### ublue family (one distro block per project; variants auto-discovered)

| Project | Repo (detection) | Download base | Seed variants |
|---|---|---|---|
| **Bazzite** | `ublue-os/bazzite` | `download.bazzite.gg` | deck, desktop, gnome, (each ± nvidia), dx |
| **Bluefin** | `ublue-os/bluefin` | `download.projectbluefin.io` ⚠ | bluefin, bluefin-dx (± nvidia; gts/stable streams) |
| **Aurora** | `ublue-os/aurora` | `download.getaurora.dev` ⚠ | aurora, aurora-dx (± nvidia) |
| **uCore** | `ublue-os/ucore` | ISO via ublue isogenerator / ghcr ⚠ | ucore, ucore-hci |

ublue images are OCI-first; the ISOs are generated and hosted on the per-project download
domains with (mostly) **version-less filenames** — treat like `stable_symlink` for download and
use `releases.atom` for the "something changed" signal. Confirm the exact filenames per project
(⚠) during implementation.

---

## 16. Things to verify during implementation (don't trust this doc blindly)

The prior analysis established the reliable *shapes*; exact URLs/filenames marked ⚠ above were
not all end-to-end confirmed and upstreams drift. Before shipping each source:
1. Fetch the detection endpoint and confirm it returns what the strategy expects.
2. Confirm the download URL resolves to a real ISO (follow redirects once).
3. Confirm the checksum file exists and its filename column matches the ISO name.
4. For rolling/version-less images, confirm the chosen change-token (hash/date/ETag) actually moves.
5. For `html_scrape` sources, capture a fixture and add a test — these break most often.

Known soft spots to expect: **Batocera** (no published checksum → `verify: none`), **Tails**
(scrape + OpenPGP-only, and its ISO no longer boots from USB), **CachyOS/Manjaro/Nobara/PikaOS/
Zorin** (page-scrape until a JSON/mirror endpoint is confirmed), **SourceForge** download
redirectors (interstitial/slow-mirror), and **GitHub API** rate limits inside Actions (use
`GITHUB_TOKEN`; prefer `.atom`).

---

## 17. Non-goals

- No downloading, mirroring, or Ventoy syncing (that's a *consumer* of the feed).
- No torrents/magnet handling.
- No arch beyond `x86_64` unless a variant is explicitly configured.
- No web UI beyond a static landing page listing current entries.
```
