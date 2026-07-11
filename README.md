# distro-iso-feed

A unified **Atom / RSS / JSON feed of the latest ISO releases** for 28 Linux and BSD
distributions (104 variants). A GitHub Action refreshes it daily and commits the result;
the committed file *is* the published feed.

Downloading is deliberately out of scope. The feed is the product — subscribe with a
reader, Flexget, n8n, or a three-line fetch script, and do the fetching yourself.

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
verify**, degrading that entry to `checksum`. Two sources have no single pin: Void signs
with signify (not GPG, so it's `checksum`), and MX signs each variant with a different
developer key (kept as `gpg`, unpinned).

**Three retrieval channels, chosen by field presence.** An entry offers any of a
direct download (`download_url`), a torrent file (`torrent_url`), or a magnet
(`magnet_uri`) — a consumer picks whichever it wants with no branching logic. Debian,
Ubuntu, Arch and openSUSE Tumbleweed carry **both** a direct download and a torrent;
Kali's `live` editions and AnduinOS ship **only** a torrent (the ISO 404s, or no ISO
exists). `torrent.rss`'s enclosure **is** the `.torrent`, so a torrent client
subscribes to it directly. `checksum` verifies the ISO; `torrent_checksum` (where the
project publishes one — Debian, Kali) verifies the `.torrent` you download; they are
two hashes of two different files and are never merged. `info_hash` and `magnet_uri`
accompany every torrent. Where upstream signs nothing (AnduinOS), the entry says so
(`verify: torrent`, trust-on-first-use) rather than claiming more than it can.

`raw.githubusercontent.com` is CDN-fronted and serves `ETag`/`Last-Modified`, so
conditional GET works. (It serves `Content-Type: text/plain`; readers sniff the body. If
that ever matters, jsDelivr fronts the same file with a correct type.)

The current contents are listed in [`docs/catalog.md`](docs/catalog.md), which is generated
— never hand-edited.

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
uv run distro-iso-feed-discover --dry-run         # propose new variants, write nothing
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
