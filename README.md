# distro-iso-feed

A unified **Atom / RSS / JSON feed of the latest ISO releases** for a curated set of
Linux and BSD distributions. A GitHub Action refreshes it daily and commits the result;
the committed file *is* the published feed.

Downloading is deliberately out of scope. The feed is the product — subscribe with a
reader, Flexget, n8n, or a three-line fetch script, and do the fetching yourself; see
[Downloading](#downloading) for a one-liner and a companion tool that verifies and
maintains an archive.

## Subscribe

| Format | URL |
|---|---|
| Atom | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/feed.xml` |
| RSS | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/feed.rss` |
| JSON | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/latest.json` |
| Torrents (Atom) | `.../main/feed/torrent.xml` |
| Torrents (RSS) | `.../main/feed/torrent.rss` |
| Per distro | `.../main/feed/by-distro/<distro>.xml` |

Every entry carries the **checksum, its algorithm, and the signature URL** where upstream
publishes them, so a consumer can verify without a second fetch. Where upstream publishes
nothing, the entry says so out loud rather than omitting it silently.

**GPG signing keys are pinned and verified at build.** A `verify: gpg` entry also carries
`signing_key_url` + `signing_key_fingerprint`, so a consumer can pin the key and detect a
swapped one. The feed does not merely forward those — every build proves the signature
chains to the pinned key (`gpgv` the signed checksum file where it's small enough to fetch,
or confirm the signature's issuer otherwise) and **refuses to publish a pin that doesn't
verify**, degrading that entry to `checksum`. Some sources have no single pin: Void signs
with signify (not GPG, so it's `checksum`), and MX signs each variant with a different
developer key (kept as `gpg`, unpinned).

**Three retrieval channels, chosen by field presence.** An entry offers any of a
direct download (`download_url`), a torrent file (`torrent_url`), or a magnet
(`magnet_uri`) — a consumer picks whichever it wants with no branching logic. Debian,
Ubuntu, Arch, openSUSE Tumbleweed and Proxmox carry **both** a direct download and a torrent;
Kali's `live` editions and AnduinOS ship **only** a torrent (the ISO 404s, or no ISO
exists). `torrent.rss`'s enclosure **is** the `.torrent`, so a torrent client
subscribes to it directly. `checksum` verifies the ISO; `torrent_checksum` (where the
project publishes one — Debian, Kali) verifies the `.torrent` you download; they are
two hashes of two different files and are never merged. `info_hash` and `magnet_uri`
accompany every torrent. Where upstream signs nothing (AnduinOS), the entry says so
(`verify: torrent`, trust-on-first-use) rather than claiming more than it can.

**Format version.** `latest.json` carries a `schema` integer. **Pin it and ignore fields
you don't recognise** — new optional fields are added without bumping it, so a consumer
written for one `schema` keeps working as the feed grows. It changes only on a *breaking*
format change (a field removed or renamed, a meaning changed, the shape reshaped), which is
your signal to update. Today it is `1`.

`raw.githubusercontent.com` is CDN-fronted and serves `ETag`/`Last-Modified`, so
conditional GET works. (It serves `Content-Type: text/plain`; readers sniff the body. If
that ever matters, jsDelivr fronts the same file with a correct type.)

The current contents are listed in [`docs/catalog.md`](docs/catalog.md), which is generated
— never hand-edited.

## Downloading

Fetching ISOs lives outside this repo — the feed is the product. Two ways to pull from it,
in increasing order of how much they do for you.

**Quick and dirty.** Lift one ISO's URL out of `latest.json` and fetch it. No verification,
no torrent, no resume:

```bash
curl -s https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/latest.json \
  | jq -r '.releases["debian:netinst"].download_url' \
  | xargs curl -LO
```

Swap `debian:netinst` for any key in [`docs/catalog.md`](docs/catalog.md). Torrent-only
entries (Kali `live`, AnduinOS) carry `"download_url": null` — those need a torrent client
or the downloader below.

**The companion downloader.**
[`distro-iso-feed-downloader`](https://github.com/andyattebery/distro-iso-feed-downloader)
reads the same feed and does what the one-liner can't:

```bash
uv tool install git+https://github.com/andyattebery/distro-iso-feed-downloader
```

- **One-off** — `distro-iso-feed-download kali:live` fetches a single key into the current
  directory (`-o` to redirect). Over the one-liner it adds: checksum verification (and GPG
  where the entry carries a signature), torrent-or-HTTP by which fields the entry offers,
  a resumable aria2c-backed download, and atomic placement — nothing lands at the final
  path until it verifies. Stateless: no state file, no pruning, so it never disturbs an
  archive. No install needed — `uvx` runs it in one shot:

  ```bash
  uvx --from git+https://github.com/andyattebery/distro-iso-feed-downloader \
    distro-iso-feed-download kali:live
  ```
- **Archive** — `distro-iso-feed-download` with no key reads a `downloader.yaml` (an
  `output_dir` and a `select:` set of keys) and keeps that directory current: downloads
  each selected variant, verifies it, and prunes versions the feed has superseded. Built
  to run on a schedule — drop it in cron or a systemd timer, or `--interval 86400` to
  self-loop inside a container.

## Adding a distro

Adding a distro is a config edit, not a code change. Append a block to
[`config/sources.yaml`](config/sources.yaml) and check it resolves:

```bash
uv run distro-iso-feed-refresh --dry-run --only void
```

`--dry-run` prints the **resolved artifact** — filename, version token, checksum, algorithm
— and writes nothing. Only a genuinely new upstream *shape* needs a new strategy; see
[`docs/architecture.md`](docs/architecture.md).

## Development

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run distro-iso-feed-refresh --dry-run          # resolve everything, write nothing
uv run distro-iso-feed-discover --dry-run         # propose new variants, arches, flavors; write nothing
uv run distro-iso-feed-audit --strict             # untracked editions, pins, signing keys
```

`audit` answers three questions no other check can: what does an upstream publish that
no variant tracks; is any source frozen to a literal release; and does every pinned GPG
key still verify the current artifact's signature? A pinned *release* is the dangerous
one — it resolves cleanly and publishes a valid checksum while serving a stale release
forever. `--strict` exits 1 on any of the three.

## Repo setting required

**Settings → Actions → General → "Allow GitHub Actions to create and approve pull
requests."** Without it the weekly discovery workflow fails with a 403 that reads like a
token-scope bug. Nothing in this repository can set it.

## Layout

```
config/sources.yaml     the config; adding a distro is an edit here
src/distro_iso_feed/    listers, select, tokens, checksums + six strategies
feed/                   generated: feed.xml, feed.rss, latest.json, torrent.*, by-distro/
state/state.json        generated: one current record per variant
docs/catalog.md         generated: what the feed currently tracks
docs/architecture.md    hand-written: the design, and what was left out and why
```

## License

MIT
