"""The paths that only execute inside CI, pinned here so they are not first
exercised in production: the GitHub token, the retry/backoff loop, and the
discovery write-back that edits `sources.yaml` in place.
"""

from __future__ import annotations

import json

import httpx
import pytest

from conftest import FakeClient
from distro_iso_feed import escalate, listers
from distro_iso_feed.client import BUDGET_EXHAUSTED, Client
from distro_iso_feed.config import load_raw, yaml_rt
from distro_iso_feed.strategies import REGISTRY

RELEASES = (
    '[{"tag_name": "v1.0", "assets": [{"name": "a.iso", "browser_download_url": "u", "size": 1}]}]'
)

# ChimeraOS shape: newest release is GitHub-flagged prerelease:true, but its date-only tag carries no
# textual signal, and it ships one AGGREGATE `sha256sum.txt` asset (not a per-file sidecar).
CHIMERA_RELEASES = json.dumps(
    [
        {
            "tag_name": "2025-04-21_8a4f21f", "prerelease": True, "draft": False,
            "assets": [{"name": "chimeraos-2025.04.21-x86_64.iso",
                        "browser_download_url": "https://x/new.iso", "size": 9}],
        },
        {
            "tag_name": "2025-02-13_7e927cf", "prerelease": False, "draft": False,
            "assets": [
                {"name": "chimeraos-2025.02.13-x86_64.iso",
                 "browser_download_url": "https://x/stable.iso", "size": 8},
                {"name": "sha256sum.txt", "browser_download_url": "https://x/sums", "size": 1},
            ],
        },
    ]
)


def test_honor_prerelease_flag_skips_a_github_flagged_prerelease():
    """ChimeraOS's newest release is flagged prerelease:true, but its bare-date tag has no rc/beta
    text, so name-based is_prerelease can't see it. The opt-in flag makes gh_assets trust GitHub's
    boolean and fall through to the stable release; without it, the prerelease would win."""
    client = FakeClient({"https://api.github.com/repos/o/r/releases": CHIMERA_RELEASES})
    assert listers.gh_assets(client, "o/r")[0].name == "chimeraos-2025.04.21-x86_64.iso"  # prerelease
    stable = listers.gh_assets(client, "o/r", honor_prerelease_flag=True)
    assert [a.name for a in stable] == ["chimeraos-2025.02.13-x86_64.iso", "sha256sum.txt"]


def test_github_releases_sums_asset_reads_the_aggregate_checksum():
    """`sums_asset` names one aggregate checksum asset (vs `sums_suffix`'s per-file sidecar); the
    ISO is looked up inside it. Combined with the flag, resolve lands the stable ISO + its sha256."""
    sha = "a" * 64
    client = FakeClient(
        {
            "https://api.github.com/repos/o/r/releases": CHIMERA_RELEASES,
            "https://x/sums": f"{sha}  chimeraos-2025.02.13-x86_64.iso",
        }
    )
    rel = REGISTRY["github_releases"]().resolve(
        "chimeraos",
        "iso",
        {
            "repo": "o/r", "honor_prerelease_flag": True, "sums_asset": "sha256sum.txt",
            "match": r"^chimeraos-[0-9.]+-x86_64\.iso$",
            "version_pattern": r"chimeraos-([0-9.]+)-x86_64\.iso$",
        },
        client,
    )
    assert rel.version == "2025.02.13"
    assert rel.checksum == sha and rel.checksum_algo == "sha256"


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

    def spy(client, repo, token=None, **kw):
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


# ------------------------------------------------------- per-host failure budget
#
# A mirror read-timed out for 18 minutes and the run re-asked it 35 times, ~100% blocked on one
# sick host. The budget stops asking. What counts is the whole game: only a *transient* failure,
# and cumulatively -- not consecutively.


def _timeout_handler(calls: list) -> object:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        raise httpx.ReadTimeout("slow")

    return handler


def test_budget_stops_asking_a_host_that_keeps_failing_transiently():
    calls: list = []
    c = _client_with(_timeout_handler(calls), retries=1, host_budget=3)
    for _ in range(3):
        assert c.get("https://sick/f") is None
    assert len(calls) == 3  # budget spent, one wire call each

    assert c.get("https://sick/anything-else") is None
    assert len(calls) == 3, "the 4th fetch must not touch the wire"


def test_budget_short_circuit_records_a_transient_outcome_not_an_empty_trace():
    """`classify_outcomes([])` is STRUCTURAL by design, so a skipped fetch that recorded nothing
    would read as a content regression and file a bogus issue per skipped variant."""
    calls: list = []
    c = _client_with(_timeout_handler(calls), retries=1, host_budget=1)
    c.get("https://sick/f")

    mark = len(c.trace)
    assert c.get("https://sick/g") is None
    outcomes = [o for _, o in c.trace[mark:]]
    assert outcomes == [BUDGET_EXHAUSTED]
    assert escalate.classify_outcomes(outcomes) == escalate.TRANSIENT


def test_budget_is_per_host_so_a_healthy_mirror_is_untouched():
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "sick":
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200, content=b"fine")

    c = _client_with(handler, retries=1, host_budget=2)
    for _ in range(2):
        c.get("https://sick/f")
    c.get("https://sick/g")  # short-circuited

    assert c.get("https://healthy/f") is not None
    assert c.get("https://healthy/f").text == "fine"


def test_404s_never_consume_the_budget():
    """A 404 means the host is fine and the file is gone. Several sources carry optional per-file
    sidecars that legitimately 404 -- charging those would skip a perfectly healthy mirror."""
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(404)

    c = _client_with(handler, host_budget=2)
    for _ in range(6):
        assert c.get("https://healthy/missing") is None
    assert len(calls) == 6, "every 404 must still reach the wire; the budget must never open"


def test_non_consecutive_failures_still_exhaust_the_budget():
    """The shape that actually occurred: successes interleaved among the failures (an index here,
    a torrent there). A *consecutive* counter -- what every off-the-shelf circuit breaker uses --
    resets on those and never trips."""
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/ok":
            return httpx.Response(200, content=b"ok")
        raise httpx.ReadTimeout("slow")

    c = _client_with(handler, retries=1, host_budget=3)
    # fail, ok, fail, ok -- two failures, never two in a row.
    for _ in range(2):
        assert c.get("https://sick/fail") is None
        assert c.get("https://sick/ok") is not None  # would reset a consecutive counter

    assert c.get("https://sick/fail") is None  # the 3rd, still never adjacent to another
    before = len(calls)
    assert c.get("https://sick/ok") is None, "budget is cumulative, so even /ok is now skipped"
    assert len(calls) == before


# ------------------------------------------------------------------- get_cached


def test_get_cached_fetches_once_and_returns_the_same_bytes():
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"sha  file.iso")

    c = _client_with(handler)
    first = c.get_cached("https://x/SUMS")
    second = c.get_cached("https://x/SUMS")
    assert len(calls) == 1
    assert first is second, "the same Response, so signing gpg-verifies the exact published bytes"
    assert second.content == b"sha  file.iso"


def test_get_cached_does_not_cache_a_failure():
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(503)

    c = _client_with(handler, retries=2, host_budget=99)
    assert c.get_cached("https://x/SUMS") is None
    assert c.get_cached("https://x/SUMS") is None
    assert len(calls) == 4, "a failure stays retryable rather than being memoized as None"


def test_get_bypasses_the_cache_so_diagnose_still_sees_the_wire():
    """`diagnose` re-fetches on purpose to observe the *current* outcome; a cache hit would append
    nothing to `trace`, and an empty slice classifies STRUCTURAL."""
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=b"ok")

    c = _client_with(handler)
    c.get_cached("https://x/SUMS")
    c.get("https://x/SUMS")
    assert len(calls) == 2


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

    discover = {"match": r"\.iso$", "group": group, "ignore": ["Cloud"]}
    found = Fake().discover_all("fedora", [{}], discover, FakeClient())
    assert [v.variant for v in found] == ["workstation"]


def test_real_sources_yaml_is_a_ruamel_fixed_point():
    """`run_discover` rewrites this file. If it is not already formatted the way
    ruamel emits, every discovery PR reflows hundreds of unrelated lines and buries
    the actual proposal. Keep the file a fixed point of its own formatter.

    The content assertions below are load-bearing: a truncated or `null` file is
    trivially its own fixed point, so equality alone would pass on a destroyed
    config. (Ask me how I know.)
    """
    import io
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"
    text = p.read_text(encoding="utf-8")

    doc = load_raw(p)
    assert doc and "distros" in doc, "sources.yaml does not parse to a config"
    assert len(doc["distros"]) >= 20, "sources.yaml lost distros"

    buf = io.StringIO()
    yaml_rt().dump(doc, buf)
    assert buf.getvalue() == text, (
        "config/sources.yaml is not ruamel-normalized; a discovery PR would reflow it. "
        "Re-normalize by reading the file FULLY before opening it for write -- "
        "`with p.open('w') as fh: dump(load_raw(p), fh)` truncates it first."
    )


def test_gh_assets_returns_only_the_current_release():
    """Iterating every release resurrects dead artifacts.

    MiniOS still hosts `minios-bookworm-flux-minimum-...iso` from 2023, and
    discovery proposed `minimum`/`maximum` as brand-new variants because of it.
    """
    releases = json.dumps(
        [
            {
                "tag_name": "v5.1.1",
                "assets": [{"name": "current.iso", "browser_download_url": "u", "size": 1}],
            },
            {
                "tag_name": "v1.0.0",
                "assets": [{"name": "ancient-minimum.iso", "browser_download_url": "u", "size": 1}],
            },
        ]
    )
    client = FakeClient({"https://api.github.com/repos/o/r/releases": releases})
    names = [c.name for c in listers.gh_assets(client, "o/r")]
    assert names == ["current.iso"]


def test_gh_assets_skips_a_prerelease_at_the_head():
    releases = json.dumps(
        [
            {
                "tag_name": "9.0.0-rc1",
                "assets": [{"name": "rc.iso", "browser_download_url": "u", "size": 1}],
            },
            {
                "tag_name": "8.2.0",
                "assets": [{"name": "stable.iso", "browser_download_url": "u", "size": 1}],
            },
        ]
    )
    client = FakeClient({"https://api.github.com/repos/o/r/releases": releases})
    assert [c.name for c in listers.gh_assets(client, "o/r")] == ["stable.iso"]


def test_discover_groups_on_a_structured_field_when_configured():
    """Fedora's artifact is `Fedora-MATE_Compiz-Live-...` but its subvariant is `Mate`.

    Grouping on the filename proposes `mate_compiz` — a duplicate of a variant that
    already exists under its real name. `group_field` reads the JSON row instead.
    """
    from distro_iso_feed.listers import Candidate
    from distro_iso_feed.strategies.base import Strategy

    class Fake(Strategy):
        name = "fake"

        def resolve(self, *a, **k):
            return None

        def candidates(self, distro, params, client):
            return [
                Candidate(name="Fedora-MATE_Compiz-Live-44.iso", row={"subvariant": "Mate"}),
                Candidate(name="Fedora-i3-Live-44.iso", row={"subvariant": "i3"}),
            ]

    by_filename = {"match": r"\.iso$", "group": r"^Fedora-([A-Za-z0-9_]+)-"}
    got = Fake().discover_all("fedora", [{}], by_filename, FakeClient())
    assert "mate-compiz" in [v.variant for v in got]  # the wrong key

    by_field = {"match": r"\.iso$", "group_field": "subvariant", "group": r"^([A-Za-z0-9_-]+)$"}
    got = Fake().discover_all("fedora", [{}], by_field, FakeClient())
    assert sorted(v.variant for v in got) == ["i3", "mate"]
