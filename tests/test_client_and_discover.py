"""The paths that only execute inside CI, pinned here so they are not first
exercised in production: the GitHub token, the retry/backoff loop, and the
discovery write-back that edits `sources.yaml` in place.
"""

from __future__ import annotations

import httpx
import pytest

from conftest import FakeClient
from distro_iso_feed import listers
from distro_iso_feed.client import Client
from distro_iso_feed.config import load_raw, yaml_rt
from distro_iso_feed.strategies import REGISTRY

RELEASES = (
    '[{"tag_name": "v1.0", "assets": [{"name": "a.iso", "browser_download_url": "u", "size": 1}]}]'
)


# ------------------------------------------------------------------------ gh token


def test_github_token_is_actually_sent():
    """Accepting a token and never sending it leaves the 60/hr limit in place."""
    client = FakeClient({"https://api.github.com/repos/o/r/releases": RELEASES})
    listers.gh_assets(client, "o/r", token="secret")
    headers = client.headers_seen[0]
    assert headers["Authorization"] == "Bearer secret"
    assert headers["Accept"] == "application/vnd.github+json"


def test_no_token_sends_no_authorization_header():
    client = FakeClient({"https://api.github.com/repos/o/r/releases": RELEASES})
    listers.gh_assets(client, "o/r", token=None)
    assert "Authorization" not in client.headers_seen[0]


def test_github_releases_strategy_forwards_the_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    seen: dict = {}

    def spy(client, repo, token=None):
        seen["token"] = token
        return []

    monkeypatch.setattr("distro_iso_feed.strategies.github_releases.gh_assets", spy)
    REGISTRY["github_releases"]().resolve(
        "d", "v", {"repo": "o/r", "match": r"\.iso$"}, FakeClient()
    )
    assert seen["token"] == "from-env"


# ------------------------------------------------------------------- retry / backoff


def _client_with(handler, **kw) -> Client:
    c = Client("ua", sleep=lambda _: None, **kw)
    c._http = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def test_retries_on_429_and_honours_retry_after():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, content=b"ok")

    assert _client_with(handler).text("https://x/") == "ok"
    assert len(calls) == 3


def test_gives_up_after_retries_and_returns_none_never_raises():
    handler = lambda r: httpx.Response(503)  # noqa: E731
    assert _client_with(handler, retries=2).get("https://x/") is None


def test_client_returns_none_on_404_without_retrying():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404)

    assert _client_with(handler).get("https://x/") is None
    assert len(calls) == 1  # a 404 is an answer, not a failure to retry


def test_network_error_is_swallowed():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns")

    assert _client_with(handler, retries=2).get("https://x/") is None


# ---------------------------------------------------------------- discovery write-back


SOURCES = """\
# A comment that must survive the round-trip.
defaults:
  arch: x86_64

distros:
  fedora:
    strategy: json_api  # inline comment
    variants:
      workstation: {}
"""


def test_discover_writeback_preserves_comments(tmp_path):
    """`run_discover` edits sources.yaml in place. A PR that strips every comment
    from the primary human interface is unmergeable, which is why it is ruamel."""
    p = tmp_path / "sources.yaml"
    p.write_text(SOURCES)

    yaml = yaml_rt()
    doc = load_raw(p)
    doc["distros"]["fedora"]["variants"]["kde"] = {"match": "TODO", "version_pattern": "TODO"}
    with p.open("w", encoding="utf-8") as fh:
        yaml.dump(doc, fh)

    body = p.read_text()
    assert "# A comment that must survive the round-trip." in body
    assert "# inline comment" in body
    assert "kde:" in body
    assert "workstation:" in body  # existing variants untouched


def test_discover_never_removes_a_variant(tmp_path):
    p = tmp_path / "sources.yaml"
    p.write_text(SOURCES)
    doc = load_raw(p)
    before = set(doc["distros"]["fedora"]["variants"])
    doc["distros"]["fedora"]["variants"]["kde"] = {}
    assert before <= set(doc["distros"]["fedora"]["variants"])


@pytest.mark.parametrize("group", [r"^Fedora-([A-Za-z]+)-"])
def test_discovery_applies_ignore_and_match_to_candidates(group):
    """`ignore` is written against the filename, not the variant key it produces."""
    from distro_iso_feed.listers import Candidate
    from distro_iso_feed.strategies.base import Strategy

    class Fake(Strategy):
        name = "fake"

        def resolve(self, *a, **k):
            return None

        def candidates(self, distro, params, client):
            return [
                Candidate(name="Fedora-Workstation-Live-44.iso"),
                Candidate(name="Fedora-Cloud-Base-44.qcow2"),  # dropped by `match`
                Candidate(name="Fedora-Cloud-Base-44.iso"),  # dropped by `ignore`
                Candidate(name="Fedora-KDE-Live-44-beta1.iso"),  # dropped as prerelease
            ]

    params = {"discover": {"match": r"\.iso$", "group": group, "ignore": ["Cloud"]}}
    found = Fake().discover_variants("fedora", params, FakeClient())
    assert [v.variant for v in found] == ["workstation"]


def test_real_sources_yaml_is_a_ruamel_fixed_point():
    """`run_discover` rewrites this file. If it is not already formatted the way
    ruamel emits, every discovery PR reflows hundreds of unrelated lines and buries
    the actual proposal. Keep the file a fixed point of its own formatter.
    """
    import io
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"
    buf = io.StringIO()
    yaml_rt().dump(load_raw(p), buf)
    assert buf.getvalue() == p.read_text(encoding="utf-8"), (
        "config/sources.yaml is not ruamel-normalized; a discovery PR would reflow it. "
        'Run: python -c "from pathlib import Path; from distro_iso_feed.config import '
        "load_raw, yaml_rt; p=Path('config/sources.yaml'); "
        "yaml_rt().dump(load_raw(p), p.open('w'))\""
    )
