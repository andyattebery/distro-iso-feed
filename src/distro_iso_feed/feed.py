"""Render the feed from state. One entry per variant (N=1).

Written directly with ElementTree rather than via `feedgen`: that library silently
drops `rel` and `type` from entry links, and its `enclosure()` helper requires an
alternate link that most of these entries do not have. The enclosure's type and
length are the point of the feed, so they are not negotiable.

Determinism is the load-bearing property: the daily commit must be empty when
nothing upstream moved, or `git diff` stops being a change signal. There is no
`now()` in this module. Entry timestamps freeze at first sight and the feed-level
`<updated>` is the newest entry's timestamp.
"""

from __future__ import annotations

import json
from email.utils import format_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from .models import TORRENT_TYPE, Release
from .state import Record, State

REPO_URL = "https://github.com/andyattebery/distro-iso-feed"
RAW_BASE = "https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main"
FEED_SELF = f"{RAW_BASE}/feed/feed.xml"
TORRENT_SELF = f"{RAW_BASE}/feed/torrent.xml"
FEED_TITLE = "Distro ISO Feed"
TORRENT_TITLE = "Distro ISO Feed — torrents"
SCHEMA_VERSION = 3
ATOM_NS = "http://www.w3.org/2005/Atom"

WARNING_NO_CHECKSUM = "WARNING: no published checksum — integrity unverifiable"
NOTE_UNSIGNED_TORRENT = "NOTE: infohash is unsigned — trust on first use"


def atom_id(release: Release) -> str:
    """Atom requires an IRI; the spec's bare `fedora:workstation:44` is not one.

    Deliberately NOT the raw.githubusercontent URL: that embeds the host and the
    branch name, so renaming `main` would change every id at once and every reader
    would re-notify on the whole feed. Ids are identity; links are location.
    This URL intentionally 404s.
    """
    return f"{REPO_URL}/id/{release.distro}/{release.variant}/{release.version}"


def summary_for(release: Release) -> str:
    """Machine-greppable, one field per line.

    Checksum, signature and torrent vary independently: Tails signs without
    publishing a checksum, Batocera's algo is md5 rather than sha256, and AnduinOS
    publishes nothing but a torrent -- so no label is ever hardcoded.

    The two hashes carry different prefixes on purpose. `sha256:` is the **ISO**;
    `torrent-sha256:` is the **`.torrent` file**. A consumer greps one and must never
    pick up the other.
    """
    lines = [release.title, f"Filename: {release.filename}"]
    if release.size:
        lines.append(f"Size: {release.size}")
    if release.checksum and release.checksum_algo:
        lines.append(f"{release.checksum_algo}: {release.checksum}")
    if release.signature_url:
        lines.append(f"Signature: {release.signature_url}")
    if release.signing_key_url:
        lines.append(f"Signing-key: {release.signing_key_url}")
    if release.signing_key_fingerprint:
        lines.append(f"Key-fingerprint: {release.signing_key_fingerprint}")
    if release.torrent_url:
        lines.append(f"Torrent: {release.torrent_url}")
    if release.torrent_checksum and release.torrent_checksum_algo:
        lines.append(f"torrent-{release.torrent_checksum_algo}: {release.torrent_checksum}")
    if release.info_hash:
        lines.append(f"Infohash: {release.info_hash}")
    if release.magnet_uri:
        lines.append(f"Magnet: {release.magnet_uri}")
    lines.append(f"Verify: {release.verify}")
    if not release.checksum and not release.info_hash:
        lines.append(WARNING_NO_CHECKSUM)
    # A torrent's piece hashes verify the payload against the torrent, not against
    # the project. Without a signature that is trust on first use, and saying so is
    # the difference between `verify: torrent` and a claim we cannot support.
    if release.info_hash and not release.signature_url and not release.torrent_checksum:
        lines.append(NOTE_UNSIGNED_TORRENT)
    if release.notes:
        lines.append(release.notes)
    return "\n".join(lines)


def _enclosures(r: Release, *, torrent_only: bool = False) -> list[tuple[str, str, str | None]]:
    """`(url, type, length)` for each artifact, HTTP first.

    Type **and** length follow the URL being linked, never the release: RSS defines
    `length` as the size of the enclosure object, not of what it points at. So a
    torrent enclosure carries the size of the `.torrent`, and the ISO's own size
    stays in `Size:` and `latest.json`.
    """
    out: list[tuple[str, str, str | None]] = []
    if not torrent_only and r.download_url:
        out.append((r.download_url, r.content_type, str(r.size) if r.size else None))
    if r.torrent_url:
        out.append((r.torrent_url, TORRENT_TYPE, str(r.torrent_size) if r.torrent_size else None))
    return out


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text is not None:
        el.text = text
    return el


def _stamp(record: Record):
    return record.release.published or record.seen_dt


def _atom(
    records: list[Record],
    *,
    title: str,
    self_url: str,
    feed_id: str,
    torrent_only: bool = False,
) -> bytes:
    feed = ET.Element("feed", {"xmlns": ATOM_NS})
    _sub(feed, "id", feed_id)
    _sub(feed, "title", title)
    _sub(feed, "link", href=self_url, rel="self", type="application/atom+xml")
    _sub(feed, "link", href=REPO_URL, rel="alternate", type="text/html")
    # Newest entry's timestamp, never now(): a clock here means a diff every day.
    _sub(feed, "updated", (max(_stamp(r) for r in records)).isoformat() if records else "")

    for record in records:
        r = record.release
        stamp = _stamp(record).isoformat()
        entry = _sub(feed, "entry")
        _sub(entry, "id", atom_id(r))
        _sub(entry, "title", r.title)
        _sub(entry, "updated", stamp)
        _sub(entry, "published", stamp)
        if r.page_url:
            _sub(entry, "link", href=r.page_url, rel="alternate", type="text/html")
        # Atom permits several enclosures per entry; RSS 2.0 permits exactly one.
        # That asymmetry is why the torrent feed is a separate file.
        for url, mime, length in _enclosures(r, torrent_only=torrent_only):
            _sub(entry, "link", href=url, rel="enclosure", type=mime, length=length)
        _sub(entry, "category", term=r.distro, label="distro")
        _sub(entry, "category", term=r.variant, label="variant")
        _sub(entry, "summary", summary_for(r), type="text")

    ET.indent(feed, space="  ")
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True) + b"\n"


def _rss(records: list[Record], *, title: str, self_url: str, torrent_only: bool = False) -> bytes:
    rss = ET.Element("rss", {"version": "2.0"})
    channel = _sub(rss, "channel")
    _sub(channel, "title", title)
    _sub(channel, "link", REPO_URL)
    _sub(channel, "description", title)
    if records:
        _sub(channel, "lastBuildDate", format_datetime(max(_stamp(r) for r in records)))
    _sub(channel, "docs", self_url)

    for record in records:
        r = record.release
        enclosures = _enclosures(r, torrent_only=torrent_only)
        # `torrent.rss` is `.torrent` files only. The main feed carries everything
        # that has somewhere to point -- including a magnet-only entry, whose magnet
        # cannot be an RSS enclosure (no length, no body) but rides in the link and
        # description. Dropping it here is how the "consistent output" promise breaks.
        link = r.torrent_url if torrent_only else r.primary_url
        if torrent_only and not enclosures:
            continue
        if not link and not enclosures:
            continue

        item = _sub(channel, "item")
        _sub(item, "title", r.title)
        _sub(item, "link", link)
        _sub(item, "guid", r.guid(), isPermaLink="false")
        _sub(item, "pubDate", format_datetime(_stamp(record)))
        _sub(item, "description", summary_for(r))
        # RSS 2.0 allows one enclosure per item. Take the first: HTTP where there is
        # one, the torrent otherwise. A magnet-only entry has none. `feed/torrent.rss`
        # carries the .torrent files.
        if enclosures:
            url, mime, length = enclosures[0]
            _sub(item, "enclosure", url=url, type=mime, length=length or "0")
        _sub(item, "category", r.distro)

    ET.indent(rss, space="  ")
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True) + b"\n"


def latest_json(records: list[Record]) -> str:
    """`checksum` verifies `filename`; `torrent_checksum` verifies `torrent_url`.

    Two files, two hashes, never merged -- a client checks the torrent it fetched
    against one and the ISO that comes out against the other.
    """
    payload = {
        "schema": SCHEMA_VERSION,
        "releases": {
            r.release.state_key: {
                "version": r.release.version,
                "title": r.release.title,
                "download_url": r.release.download_url,
                "filename": r.release.filename,
                "arch": r.release.arch,
                "size": r.release.size,
                "checksum": r.release.checksum,
                "checksum_algo": r.release.checksum_algo,
                "signature_url": r.release.signature_url,
                "signing_key_url": r.release.signing_key_url,
                "signing_key_fingerprint": r.release.signing_key_fingerprint,
                "torrent_url": r.release.torrent_url,
                "torrent_size": r.release.torrent_size,
                "torrent_checksum": r.release.torrent_checksum,
                "torrent_checksum_algo": r.release.torrent_checksum_algo,
                "info_hash": r.release.info_hash,
                "magnet_uri": r.release.magnet_uri,
                "content_type": r.release.content_type,
                "verify": r.release.verify,
                "published": _stamp(r).isoformat(),
            }
            for r in records
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def readme_md(records: list[Record]) -> str:
    lines = [
        "# Feed",
        "",
        "Generated by `distro-iso-feed-refresh`. Do not edit by hand.",
        "",
        f"Subscribe: [`feed.xml`]({FEED_SELF}) · `feed.rss` · `latest.json`",
        "",
        f"Torrents only: [`torrent.xml`]({TORRENT_SELF}) · `torrent.rss`",
        "",
        "| Distro | Variant | Version | Verify | Torrent |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x.release.state_key):
        rel = r.release
        torrent = "✓" if rel.torrent_url else "—"
        lines.append(f"| {rel.distro} | {rel.variant} | {rel.version} | {rel.verify} | {torrent} |")
    return "\n".join(lines) + "\n"


def render(state: State, out_dir: Path) -> None:
    records = state.entries()
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "feed.xml").write_bytes(
        _atom(records, title=FEED_TITLE, self_url=FEED_SELF, feed_id=REPO_URL)
    )
    (out_dir / "feed.rss").write_bytes(_rss(records, title=FEED_TITLE, self_url=FEED_SELF))
    (out_dir / "latest.json").write_text(latest_json(records), encoding="utf-8")
    (out_dir / "README.md").write_text(readme_md(records), encoding="utf-8")

    # A feed a torrent client can subscribe to: every enclosure here is a `.torrent`.
    # Entries reuse `atom_id()`, so a reader following both feeds sees one logical
    # entry rather than a duplicate.
    torrents_ = [r for r in records if r.release.torrent_url]
    (out_dir / "torrent.xml").write_bytes(
        _atom(
            torrents_,
            title=TORRENT_TITLE,
            self_url=TORRENT_SELF,
            feed_id=f"{REPO_URL}/id/torrent",
            torrent_only=True,
        )
    )
    (out_dir / "torrent.rss").write_bytes(
        _rss(torrents_, title=TORRENT_TITLE, self_url=TORRENT_SELF, torrent_only=True)
    )

    by_distro = out_dir / "by-distro"
    by_distro.mkdir(exist_ok=True)
    for distro in sorted({r.release.distro for r in records}):
        subset = [r for r in records if r.release.distro == distro]
        (by_distro / f"{distro}.xml").write_bytes(
            _atom(
                subset,
                title=f"{FEED_TITLE} — {distro}",
                self_url=f"{RAW_BASE}/feed/by-distro/{distro}.xml",
                feed_id=f"{REPO_URL}/id/{distro}",
            )
        )
