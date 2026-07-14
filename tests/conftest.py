"""A fake HTTP client, so strategy tests never touch the network.

Fixtures are captured shapes of real upstream responses -- the decoys, the doubled
RSS items, the BSD checksum format. They exist because every one of those cost a
wrong conclusion before it was read.
"""

from __future__ import annotations

import hashlib

import pytest


class FakeResponse:
    """A real response carries bytes. `.torrent` bodies are not valid UTF-8."""

    def __init__(self, url: str, body: str | bytes) -> None:
        self.url = url
        self.status_code = 200
        self.content = body if isinstance(body, bytes) else body.encode()
        self.text = self.content.decode("utf-8", errors="replace")

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class FakeClient:
    """Serves a url->body map. Anything unmapped 404s, like the real world.

    `fail` injects a *failed* fetch outcome for a url -- an int status (e.g. 503) or an exception
    name (e.g. "ConnectTimeout") -- so a test can exercise the transient-vs-structural classification
    that reads `Client.trace`.
    """

    def __init__(
        self,
        pages: dict[str, str | bytes] | None = None,
        existing: set[str] | None = None,
        fail: dict[str, int | str] | None = None,
    ):
        self.pages = pages or {}
        self.existing = existing or set()
        self.fail = fail or {}
        self.requested: list[str] = []
        self.headers_seen: list[dict[str, str] | None] = []
        self.trace: list[tuple[str, int | str]] = []

    def get(self, url: str, headers: dict[str, str] | None = None):
        self.requested.append(url)
        self.headers_seen.append(headers)
        if url in self.fail:
            self.trace.append((url, self.fail[url]))  # simulated network error / retry status
            return None
        if url in self.pages:
            self.trace.append((url, 200))
            return FakeResponse(url, self.pages[url])
        self.trace.append((url, 404))  # unmapped -> 404, like the real world
        return None

    def text(self, url: str, headers: dict[str, str] | None = None) -> str | None:
        r = self.get(url, headers=headers)
        return r.text if r else None

    def exists(self, url: str) -> bool:
        self.requested.append(url)
        return url in self.existing or url in self.pages

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


# Every distro must declare how it is enumerated, or why it cannot be. Fixtures that
# exercise something else say so explicitly rather than inheriting a default -- the
# rule exists because twenty-one distros once inherited silence.
NOT_ENUMERABLE = "    discover: {enumerable: false, reason: fixture}\n"


def autoindex_html(names: list[str]) -> str:
    links = "\n".join(f'<a href="{n}">{n}</a>' for n in names)
    return f"<html><body><pre>{links}</pre></body></html>"


def sf_rss(paths: list[str], *, doubled: bool = True) -> str:
    """SourceForge emits every item twice; the default reproduces that."""
    items = []
    for p in paths:
        item = (
            "<item>"
            f"<title><![CDATA[{p}]]></title>"
            f"<link>https://sourceforge.net/projects/x/files{p}/download</link>"
            "<pubDate>Sun, 24 May 2026 18:07:56 UT</pubDate>"
            "</item>"
        )
        items.append(item)
        if doubled:
            items.append(item)
    return f"<rss><channel>{''.join(items)}</channel></rss>"


def atom_feed(titles: list[str]) -> str:
    entries = "".join(
        f"<entry><title>{t}</title><updated>2026-07-08T00:00:00Z</updated></entry>" for t in titles
    )
    return f'<feed xmlns="http://www.w3.org/2005/Atom">{entries}</feed>'
