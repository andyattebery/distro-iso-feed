"""Listers: where candidate artifacts come from.

This is the real seam. `directory_index`, `sourceforge`, `page_index` and
`json_api` differ *only* here; everything downstream (`select`, `tokens`,
`checksums`) is shared. §2 calls page-scraping a last resort because the listing
step is fragile -- so the fragile code lives in this file and nowhere else.

Every lister returns candidates. That is why `discover_all` comes for free.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

from defusedxml import ElementTree

from .client import Client
from .select import is_prerelease

_HREF = re.compile(r'href=["\']([^"\'?#]+)["\']', re.IGNORECASE)
_ABS_ISO = re.compile(r'https?://[^\s"\'<>]+?\.(?:iso|img\.gz|img\.xz|raw\.xz)', re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Candidate:
    """One artifact an upstream is offering."""

    name: str  # filename, or full path for SourceForge
    url: str | None = None  # absolute download URL when the lister knows it
    published: datetime | None = None
    row: dict | None = None  # the raw JSON row, for json_doc
    size: int | None = None
    checksum: str | None = None


def autoindex(client: Client, url: str) -> list[Candidate]:
    """A plain directory listing (Apache/nginx autoindex)."""
    text = client.text(url)
    if not text:
        return []
    base = url if url.endswith("/") else url + "/"
    out = []
    for href in _HREF.findall(text):
        name = href.rstrip("/").rsplit("/", 1)[-1]
        if not name or name.startswith("."):
            continue
        out.append(Candidate(name=name, url=urljoin(base, href)))
    return out


def version_dir(client: Client, url: str, pattern: str = r"^\d+(\.\d+)*$") -> list[str]:
    """List the *version directories* under a parent index.

    FreeBSD, Leap, Tails, Batocera, Ubuntu and Mint all publish one. Hardcoding a
    version instead is how a feed silently pins itself to a stale release.
    """
    text = client.text(url)
    if not text:
        return []
    rx = re.compile(pattern)
    names = {h.rstrip("/").rsplit("/", 1)[-1] for h in _HREF.findall(text) if h.endswith("/")}
    return sorted(n for n in names if rx.match(n))


def candidate_probe(
    client: Client,
    candidates: list[str],
    template: str,
    validate: Callable[[str], bool] | None = None,
) -> str | None:
    """No index exists, so generate candidates and probe. NixOS is the only user.

    `channels.nixos.org/` serves nothing to list, so the highest channel cannot be
    read -- only guessed and confirmed. Distinct from `version_dir`, which reads.

    `validate` inspects the body, because a 200 is not proof the release exists.
    Pop's own web client guards with `if (body.errors != null) throw`, so upstream
    anticipates a 200-with-error-envelope; a probe that trusts the status code would
    select a release that isn't there and pin the feed to it -- silently, which is
    the exact failure this machinery exists to prevent.
    """
    for value in candidates:
        url = template.format(version=value)
        if validate is None:
            if client.exists(url):
                return value
            continue
        text = client.text(url)
        if text and validate(text):
            return value
    return None


def json_has(field: str) -> Callable[[str], bool]:
    """A `candidate_probe` validator: the body parses and carries a non-empty field."""

    def check(text: str) -> bool:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        return isinstance(data, dict) and bool(data.get(field))

    return check


def rss(client: Client, url: str) -> list[Candidate]:
    """SourceForge's per-project file feed.

    Two traps: ``<title>`` is a CDATA *full path*, not a filename, and every item
    appears twice.
    """
    text = client.text(url)
    if not text:
        return []
    try:
        root = ElementTree.fromstring(text)
    except Exception:
        return []

    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not title:
            continue
        published = None
        if raw_date := item.findtext("pubDate"):
            try:
                published = parsedate_to_datetime(raw_date)
            except (TypeError, ValueError):
                published = None
        out.append(Candidate(name=title, url=link or None, published=published))
    return out


def atom(client: Client, repo: str) -> list[Candidate]:
    """GitHub `releases.atom`.

    Unauthenticated, so it dodges the 60/hr REST limit that bites inside Actions.
    Two traps: a 200 with zero entries (Nobara), and entries that are *tags* rather
    than releases (EndeavourOS). Both surface here as an empty or asset-less list.
    """
    text = client.text(f"https://github.com/{repo}/releases.atom")
    if not text:
        return []
    try:
        root = ElementTree.fromstring(text)
    except Exception:
        return []

    ns = {"a": "http://www.w3.org/2005/Atom"}
    out = []
    for entry in root.findall("a:entry", ns):
        title = (entry.findtext("a:title", default="", namespaces=ns) or "").strip()
        if not title:
            continue
        published = None
        if raw := entry.findtext("a:updated", namespaces=ns):
            try:
                published = datetime.fromisoformat(raw)
            except ValueError:
                published = None
        out.append(Candidate(name=title, published=published))
    return out


def gh_assets(client: Client, repo: str, token: str | None = None) -> list[Candidate]:
    """GitHub release *assets*. Only MiniOS uses this.

    This is the one lister that hits the REST API, which is rate-limited to 60/hr
    unauthenticated -- and that limit is shared across every job on the runner, so
    it bites inside Actions. `token` must actually be sent, not merely accepted.

    elementary and AnduinOS are excluded precisely because theirs are empty or
    torrent-only, which the caller sees as a list with no matching artifact.
    """
    url = f"https://api.github.com/repos/{repo}/releases"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    text = client.text(url, headers=headers)
    if not text:
        return []
    try:
        releases = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(releases, list):
        return []

    # Only the current release. Iterating every release resurrects artifacts from
    # years ago: MiniOS still hosts `minios-bookworm-flux-minimum-...iso` from 2023,
    # and discovery cheerfully proposed `minimum`/`maximum` as new variants.
    # The API returns releases newest-first; take the first non-prerelease.
    current = next(
        (r for r in releases if not is_prerelease(r.get("tag_name") or "")),
        None,
    )
    if current is None:
        return []

    tag = current.get("tag_name") or ""
    return [
        Candidate(
            name=asset.get("name", ""),
            url=asset.get("browser_download_url"),
            size=asset.get("size"),
            row={"tag_name": tag},
        )
        for asset in current.get("assets") or []
    ]


def json_doc(client: Client, url: str) -> list[Candidate]:
    """A JSON metadata document: Fedora's releases.json, Pop!_OS's build API."""
    text = client.text(url)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    rows = data if isinstance(data, list) else [data]
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        link = row.get("link") or row.get("url") or ""
        out.append(
            Candidate(
                name=link.rsplit("/", 1)[-1] if link else "",
                url=link or None,
                row=row,
                size=int(row["size"]) if str(row.get("size", "")).isdigit() else None,
                checksum=row.get("sha256") or row.get("sha_sum"),
            )
        )
    return out


def page_index(client: Client, url: str, attr: str | None = None) -> list[Candidate]:
    """ISO links on a product page. Nobara and Manjaro; the last resort.

    `attr` reads a data attribute instead of scraping hrefs -- Nobara exposes
    ``data-url="..."``, which is a far more stable anchor than link markup.
    """
    text = client.text(url)
    if not text:
        return []

    urls: list[str] = []
    if attr:
        urls = re.findall(rf'{re.escape(attr)}=["\']([^"\']+)["\']', text)
    if not urls:
        urls = _ABS_ISO.findall(text)

    out = []
    for u in urls:
        # Resolve against the page URL: TrueNAS and Memtest link relatively, and the
        # strategy derives the sidecar directory from this URL, so it must be absolute.
        # `urljoin` is idempotent on the absolute URLs Nobara/Manjaro already yield.
        resolved = urljoin(url, u)
        out.append(Candidate(name=resolved.rsplit("/", 1)[-1], url=resolved))
    return out


def fixed(url: str) -> list[Candidate]:
    """A single, version-less URL. Enumerates nothing, which is the right answer."""
    return [Candidate(name=url.rsplit("/", 1)[-1], url=url)]
