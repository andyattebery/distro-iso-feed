# distro-iso-feed

A unified **Atom / RSS / JSON feed of the latest ISO releases** for 27 Linux and BSD
distributions (82 variants). A GitHub Action refreshes it daily and commits the result;
the committed file *is* the published feed.

Downloading is deliberately out of scope. The feed is the product — subscribe with a
reader, Flexget, n8n, or a three-line fetch script, and do the fetching yourself.

## Subscribe

| Format | URL |
|---|---|
| Atom | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/feed.xml` |
| RSS | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/feed.rss` |
| JSON | `https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main/feed/latest.json` |
| Per distro | `.../main/feed/by-distro/<distro>.xml` |

Every entry carries the **checksum, its algorithm, and the signature URL** where upstream
publishes them, so a consumer can verify without a second fetch. Where upstream publishes
nothing, the entry says so out loud rather than omitting it silently.

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
```

## Repo setting required

**Settings → Actions → General → "Allow GitHub Actions to create and approve pull
requests."** Without it the weekly discovery workflow fails with a 403 that reads like a
token-scope bug. Nothing in this repository can set it.

## Layout

```
config/sources.yaml     the config; adding a distro is an edit here
src/distro_iso_feed/    listers, select, tokens, checksums + six strategies
feed/                   generated: feed.xml, feed.rss, latest.json, by-distro/
state/state.json        generated: one current record per variant
docs/catalog.md         generated: what the feed currently tracks
docs/architecture.md    hand-written: the design, and what was left out and why
```

## License

MIT
