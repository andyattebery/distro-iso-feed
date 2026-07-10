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

from .models import Release
from .state import Record, State

REPO_URL = "https://github.com/andyattebery/distro-iso-feed"
RAW_BASE = "https://raw.githubusercontent.com/andyattebery/distro-iso-feed/main"
FEED_SELF = f"{RAW_BASE}/feed/feed.xml"
FEED_TITLE = "Distro ISO Feed"
SCHEMA_VERSION = 1
ATOM_NS = "http://www.w3.org/2005/Atom"

WARNING_NO_CHECKSUM = "WARNING: no published checksum — integrity unverifiable"


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

    Four shapes, because checksum and signature vary independently: Tails signs
    without publishing a checksum, and Batocera's algo is md5, not sha256 -- so the
    label is never hardcoded.
    """
    lines = [release.title, f"Filename: {release.filename}"]
    if release.size:
        lines.append(f"Size: {release.size}")
    if release.checksum and release.checksum_algo:
        lines.append(f"{release.checksum_algo}: {release.checksum}")
    if release.signature_url:
        lines.append(f"Signature: {release.signature_url}")
    lines.append(f"Verify: {release.verify}")
    if not release.checksum:
        lines.append(WARNING_NO_CHECKSUM)
    if release.notes:
        lines.append(release.notes)
    return "\n".join(lines)


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text is not None:
        el.text = text
    return el


def _stamp(record: Record):
    return record.release.published or record.seen_dt


def _atom(records: list[Record], *, title: str, self_url: str, feed_id: str) -> bytes:
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
        _sub(
            entry,
            "link",
            href=r.download_url,
            rel="enclosure",
            type=r.content_type,
            length=str(r.size) if r.size else None,
        )
        _sub(entry, "category", term=r.distro, label="distro")
        _sub(entry, "category", term=r.variant, label="variant")
        _sub(entry, "summary", summary_for(r), type="text")

    ET.indent(feed, space="  ")
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True) + b"\n"


def _rss(records: list[Record], *, title: str, self_url: str) -> bytes:
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
        item = _sub(channel, "item")
        _sub(item, "title", r.title)
        _sub(item, "link", r.download_url)
        _sub(item, "guid", r.guid(), isPermaLink="false")
        _sub(item, "pubDate", format_datetime(_stamp(record)))
        _sub(item, "description", summary_for(r))
        _sub(
            item,
            "enclosure",
            url=r.download_url,
            type=r.content_type,
            length=str(r.size) if r.size else "0",
        )
        _sub(item, "category", r.distro)

    ET.indent(rss, space="  ")
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True) + b"\n"


def latest_json(records: list[Record]) -> str:
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
        "| Distro | Variant | Version | Verify |",
        "|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: x.release.state_key):
        rel = r.release
        lines.append(f"| {rel.distro} | {rel.variant} | {rel.version} | {rel.verify} |")
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
