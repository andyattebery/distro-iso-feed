"""The program, end to end: config in, feed out.

Everything else in this suite tests a component. This drives `run_refresh.main()`
against a fake network and then reads the artifacts back the way a subscriber
would -- with a real feed parser, not with the same ElementTree calls that wrote
them. A test that parses its own output with its own writer proves very little.
"""

from __future__ import annotations

import json
import logging

import feedparser
import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed import run_refresh
from distro_iso_feed.strategies import REGISTRY

SHA = "1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf"
MD5 = "0c365dc3c17b05a4b276c579168b01da"

# One json_api source (inline checksum, size), one directory_index source with a
# decoy, and one source that publishes an .img.gz with a bare md5 -- between them
# they exercise every verify shape and both enclosure types.
CONFIG = """\
defaults:
  arch: x86_64
  user_agent: test-agent

distros:
  fedora:
    strategy: json_api
    page_url: https://fedoraproject.org/
    params:
      url: https://fedoraproject.org/releases.json
      version_pattern: '(\\d+-\\d+\\.\\d+)(?:\\.[a-z0-9_]+)?\\.iso$'
    variants:
      workstation:
        label: Fedora Workstation
        select: {subvariant: Workstation, link_contains: Workstation-Live}
    discover: {enumerable: false, reason: fixture}

  debian:
    strategy: directory_index
    # A deliberately loose `match`, so `ignore` is what keeps `debian-edu` out. An
    # anchored match would reject the decoy on its own and this test would prove
    # nothing about `ignore` at all.
    params:
      index: https://cdimage.example/
      match: 'netinst\\.iso$'
      version_pattern: 'debian-(?:edu-)?([0-9.]+)-amd64'
      sums: SHA512SUMS
      sig: SHA512SUMS.sign
      ignore: [debian-edu-]
    variants:
      netinst: {label: Debian netinst}
    discover: {enumerable: false, reason: fixture}

  batocera:
    strategy: directory_index
    params:
      index: https://mirror.example/
      match: '^batocera-x86_64-[0-9.]+-\\d{8}\\.img\\.gz$'
      version_pattern: 'batocera-x86_64-([0-9.]+-\\d{8})\\.img\\.gz'
      sums: '{filename}.md5'
    variants:
      x86_64: {label: Batocera}
    discover: {enumerable: false, reason: fixture}
"""

RELEASES_JSON = json.dumps(
    [
        # An older release sits beside the newest: max-version must win, not row order.
        {
            "version": "43",
            "arch": "x86_64",
            "subvariant": "Workstation",
            "link": "https://dl.example/Fedora-Workstation-Live-43-1.2.x86_64.iso",
            "sha256": "a" * 64,
            "size": "111",
        },
        {
            "version": "44",
            "arch": "x86_64",
            "subvariant": "Workstation",
            "link": "https://dl.example/Fedora-Workstation-Live-44-1.7.x86_64.iso",
            "sha256": SHA,
            "size": "2851612672",
        },
        {  # wrong arch, must be filtered
            "version": "44",
            "arch": "aarch64",
            "subvariant": "Workstation",
            "link": "https://dl.example/Fedora-Workstation-Live-44-1.7.aarch64.iso",
            "sha256": "b" * 64,
            "size": "1",
        },
    ]
)

PAGES = {
    "https://fedoraproject.org/releases.json": RELEASES_JSON,
    "https://cdimage.example/": autoindex_html(
        ["debian-13.5.0-amd64-netinst.iso", "debian-edu-13.5.0-amd64-netinst.iso"]
    ),
    "https://cdimage.example/SHA512SUMS": f"{'b' * 128}  debian-13.5.0-amd64-netinst.iso",
    "https://mirror.example/": autoindex_html(["batocera-x86_64-43.1-20260529.img.gz"]),
    "https://mirror.example/batocera-x86_64-43.1-20260529.img.gz.md5": MD5,
}


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Point the program at a temp tree and a fake internet."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "sources.yaml").write_text(CONFIG)

    monkeypatch.setattr(run_refresh, "CONFIG", tmp_path / "config" / "sources.yaml")
    monkeypatch.setattr(run_refresh, "STATE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(run_refresh, "FEED_DIR", tmp_path / "feed")
    monkeypatch.setattr(run_refresh, "CATALOG", tmp_path / "docs" / "catalog.md")

    pages = dict(PAGES)

    class OneShot(FakeClient):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_refresh, "Client", lambda *a, **k: OneShot(pages))
    return tmp_path, pages


def read_feed(tmp_path):
    return feedparser.parse(str(tmp_path / "feed" / "feed.xml"))


# --------------------------------------------------------------------------- the run


def test_full_run_writes_every_artifact(project):
    tmp_path, _ = project
    assert run_refresh.main([]) == 0

    for rel in ("feed/feed.xml", "feed/feed.rss", "feed/latest.json", "feed/README.md"):
        assert (tmp_path / rel).exists(), rel
    assert (tmp_path / "state" / "state.json").exists()
    assert (tmp_path / "docs" / "catalog.md").exists()
    # one per distro
    assert sorted(p.stem for p in (tmp_path / "feed" / "by-distro").glob("*.xml")) == [
        "batocera",
        "debian",
        "fedora",
    ]


def test_output_parses_as_atom_for_a_real_subscriber(project):
    """Parsed by feedparser, not by the ElementTree calls that wrote it."""
    tmp_path, _ = project
    run_refresh.main([])

    d = read_feed(tmp_path)
    assert d.bozo is False
    assert d.version == "atom10"
    assert len(d.entries) == 3

    ids = {e.id for e in d.entries}
    assert "https://github.com/andyattebery/distro-iso-feed/id/fedora/workstation/44-1.7" in ids


def test_rss_also_parses_and_carries_the_raw_guid(project):
    tmp_path, _ = project
    run_refresh.main([])

    d = feedparser.parse(str(tmp_path / "feed" / "feed.rss"))
    assert d.bozo is False
    assert d.version == "rss20"
    guids = {e.id for e in d.entries}
    assert "fedora:workstation:44-1.7" in guids  # the bare guid, not the IRI


def test_json_api_selects_max_version_and_right_arch(project):
    """Row order in releases.json must not decide which release is published."""
    tmp_path, _ = project
    run_refresh.main([])

    data = json.loads((tmp_path / "feed" / "latest.json").read_text())["releases"]
    fed = data["fedora:workstation"]
    assert fed["version"] == "44-1.7"  # not 43-1.2, not row 0
    assert fed["arch"] == "x86_64"
    assert fed["checksum"] == SHA
    assert fed["size"] == 2851612672


def test_enclosures_carry_type_and_length_where_known(project):
    tmp_path, _ = project
    run_refresh.main([])

    d = read_feed(tmp_path)
    by_id = {e.id.rsplit("/id/", 1)[1]: e for e in d.entries}

    fedora = by_id["fedora/workstation/44-1.7"]
    encl = [ln for ln in fedora.links if ln.rel == "enclosure"][0]
    assert encl.type == "application/x-iso9660-image"
    assert encl.length == "2851612672"  # json_api gave us a size

    bato = by_id["batocera/x86_64/43.1-20260529"]
    encl = [ln for ln in bato.links if ln.rel == "enclosure"][0]
    assert encl.type == "application/gzip"  # NOT an ISO
    assert not encl.get("length")  # directory_index never HEADs for a size


def test_decoy_never_reaches_the_feed(project):
    """`match` here is loose enough to select `debian-edu`; only `ignore` stops it."""
    tmp_path, _ = project
    run_refresh.main([])

    xml = (tmp_path / "feed" / "feed.xml").read_text()
    assert "debian-edu" not in xml
    assert "debian-13.5.0-amd64-netinst.iso" in xml


def test_summary_lines_are_machine_readable_per_verify_shape(project):
    tmp_path, _ = project
    run_refresh.main([])

    d = read_feed(tmp_path)
    summaries = {e.id.rsplit("/id/", 1)[1].split("/")[0]: e.summary for e in d.entries}

    assert "sha256: " + SHA in summaries["fedora"]
    assert "Verify: checksum" in summaries["fedora"]

    assert "Signature: " in summaries["debian"]  # sums + sig -> gpg
    assert "Verify: gpg" in summaries["debian"]

    assert "md5: " + MD5 in summaries["batocera"]  # label is not hardcoded to sha256
    assert "WARNING" not in summaries["batocera"]


# ------------------------------------------------------------------------ idempotence


def test_second_run_changes_nothing_on_disk(project):
    """The property the daily commit depends on, driven through main()."""
    tmp_path, _ = project
    run_refresh.main([])
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    assert run_refresh.main([]) == 0
    after = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after


def test_dry_run_writes_nothing(project, capsys):
    tmp_path, _ = project
    assert run_refresh.main(["--dry-run"]) == 0

    assert not (tmp_path / "feed").exists()
    assert not (tmp_path / "state").exists()
    out = capsys.readouterr().out
    assert "fedora:workstation" in out
    assert "44-1.7" in out  # prints the artifact, never a status code


def test_only_restricts_to_one_variant(project, capsys):
    _, _ = project
    assert run_refresh.main(["--dry-run", "--only", "fedora:workstation"]) == 0
    out = capsys.readouterr().out
    assert "fedora:workstation" in out
    assert "debian" not in out


def test_unknown_only_target_is_an_error(project):
    assert run_refresh.main(["--only", "nosuchdistro"]) == 2


# --------------------------------------------------------------------- failure isolation


def test_one_dead_source_never_removes_an_entry_or_fails_the_run(project):
    """The whole point of failure isolation, exercised through main()."""
    tmp_path, pages = project
    run_refresh.main([])
    good_feed = (tmp_path / "feed" / "feed.xml").read_bytes()
    entries_before = len(read_feed(tmp_path).entries)

    del pages["https://cdimage.example/"]  # Debian's index goes dark
    assert run_refresh.main([]) == 0  # still green

    assert len(read_feed(tmp_path).entries) == entries_before  # stale, not empty
    assert (tmp_path / "feed" / "feed.xml").read_bytes() == good_feed


def test_every_source_failing_is_loud(project):
    """Individual failures are normal; total failure is a broken runner."""
    tmp_path, pages = project
    pages.clear()
    assert run_refresh.main([]) == 1


def test_summary_is_written_with_actionable_failures(project, tmp_path_factory):
    tmp_path, pages = project
    del pages["https://mirror.example/"]
    summary = tmp_path / "summary.md"

    run_refresh.main(["--summary", str(summary)])
    body = summary.read_text()

    assert "resolved: **2/3**" in body
    assert "batocera:x86_64" in body
    assert "https://mirror.example/" in body  # names the endpoint to open
    assert "--dry-run --only batocera:x86_64 -v" in body  # copy-pasteable repro


# ----------------------------------------------------------------------- run_discover

DISCOVER_CONFIG = """\
# Keep this comment.
defaults:
  arch: x86_64
  user_agent: test-agent

distros:
  fedora:
    strategy: json_api
    params:
      url: https://fedoraproject.org/releases.json
      version_pattern: '(\\d+-\\d+\\.\\d+)(?:\\.[a-z0-9_]+)?\\.iso$'
    variants:
      workstation:
        select: {subvariant: Workstation, link_contains: Workstation-Live}
    discover:
      match: '\\.iso$'
      group: '^Fedora-([A-Za-z]+)-'
      ignore: [Cloud]
"""

DISCOVER_JSON = json.dumps(
    [
        {
            "version": "44",
            "arch": "x86_64",
            "subvariant": "Workstation",
            "link": "https://dl.example/Fedora-Workstation-Live-44-1.7.x86_64.iso",
            "sha256": SHA,
        },
        {
            "version": "44",
            "arch": "x86_64",
            "subvariant": "KDE",
            "link": "https://dl.example/Fedora-KDE-Live-44-1.7.x86_64.iso",
            "sha256": SHA,
        },
        {
            "version": "44",
            "arch": "x86_64",
            "subvariant": "Cloud_Base",
            "link": "https://dl.example/Fedora-Cloud-Base-44-1.7.x86_64.iso",
            "sha256": SHA,
        },
        {
            "version": "44",
            "arch": "x86_64",
            "subvariant": "Cloud_Base",
            "link": "https://dl.example/Fedora-Cloud-Base-44-1.7.x86_64.qcow2",
            "sha256": SHA,
        },
    ]
)


@pytest.fixture
def discover_project(tmp_path, monkeypatch):
    from distro_iso_feed import run_discover

    (tmp_path / "config").mkdir()
    cfg = tmp_path / "config" / "sources.yaml"
    cfg.write_text(DISCOVER_CONFIG)
    monkeypatch.setattr(run_discover, "CONFIG", cfg)

    class OneShot(FakeClient):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(
        run_discover,
        "Client",
        lambda *a, **k: OneShot({"https://fedoraproject.org/releases.json": DISCOVER_JSON}),
    )
    return run_discover, cfg


def test_discover_dry_run_writes_nothing(discover_project, caplog):
    run_discover, cfg = discover_project
    before = cfg.read_text()
    with caplog.at_level(logging.INFO):
        assert run_discover.main(["--dry-run"]) == 0
    assert cfg.read_text() == before
    assert "propose fedora:kde" in caplog.text


def test_discover_proposes_only_new_non_ignored_iso_variants(discover_project, caplog):
    run_discover, _ = discover_project
    with caplog.at_level(logging.INFO):
        run_discover.main(["--dry-run"])
    out = caplog.text
    assert "fedora:kde" in out  # new
    assert "fedora:workstation" not in out  # already configured
    assert "cloud" not in out.lower()  # in `ignore`
    assert "qcow2" not in out  # dropped by `match`


def test_discover_writes_config_that_already_resolves(discover_project):
    """The proposal is not a name and not a `TODO`; it is a node that has been run.

    `match: TODO` made this PR a to-do list, and a to-do list is a thing you skim --
    which is how eight Fedora spins stayed missing while the PR sat open saying,
    accurately, that something was there.
    """
    run_discover, cfg = discover_project
    assert run_discover.main([]) == 0

    body = cfg.read_text()
    assert "# Keep this comment." in body
    assert "workstation:" in body  # never removes a variant
    assert "kde:" in body
    assert "TODO" not in body

    # Synthesized from the sibling by substituting `Workstation` -> `KDE`, everywhere.
    from distro_iso_feed.config import load

    _, sources = load(cfg, set(REGISTRY))
    kde = next(v for v in sources[0].variants if v.name == "kde")
    assert kde.params["select"] == {"subvariant": "KDE", "link_contains": "KDE-Live"}

    # And it resolves -- to the artifact that produced the key, not the sibling's.
    release = REGISTRY[kde.strategy]().resolve(
        "fedora",
        "kde",
        kde.params,
        FakeClient({"https://fedoraproject.org/releases.json": DISCOVER_JSON}),
    )
    assert release.filename == "Fedora-KDE-Live-44-1.7.x86_64.iso"
    assert release.checksum


def test_discover_pr_body_carries_the_resolved_evidence(discover_project, tmp_path):
    """The PR body is the artifact a reviewer reads. It names the sibling copied from
    and the ISO that was actually fetched, so review is checking evidence rather than
    trusting a variant name."""
    run_discover, _ = discover_project
    body = tmp_path / "pr.md"
    assert run_discover.main(["--dry-run", "--pr-body", str(body)]) == 0

    text = body.read_text()
    assert "| `fedora:kde` | `workstation` | `Fedora-KDE-Live-44-1.7.x86_64.iso` |" in text
    assert "TODO" not in text


def test_discover_placeholder_never_silently_publishes(discover_project):
    """A merged-but-unfilled PR must leave the variant unresolved, not wrong."""
    from distro_iso_feed import select

    assert select.choose(["Fedora-KDE-Live-44-1.7.x86_64.iso"], match="TODO") is None


# -------------------------------------------------------------------- github_releases


def test_github_releases_picks_the_asset_and_its_sha256_sidecar():
    releases = json.dumps(
        [
            {
                "tag_name": "v5.1.1",
                "assets": [
                    {
                        "name": "minios-trixie-xfce-standard-amd64-5.1.1.iso",
                        "browser_download_url": "https://dl/minios.iso",
                        "size": 42,
                    },
                    {
                        "name": "minios-trixie-xfce-standard-amd64-5.1.1.iso.sha256",
                        "browser_download_url": "https://dl/minios.iso.sha256",
                        "size": 1,
                    },
                    {
                        "name": "minios-5.1.1.torrent",
                        "browser_download_url": "https://dl/t.torrent",
                        "size": 1,
                    },
                ],
            }
        ]
    )
    client = FakeClient(
        {
            "https://api.github.com/repos/o/r/releases": releases,
            "https://dl/minios.iso.sha256": f"{SHA}  minios-trixie-xfce-standard-amd64-5.1.1.iso",
        }
    )
    rel = REGISTRY["github_releases"]().resolve(
        "minios",
        "standard",
        {
            "repo": "o/r",
            "match": r"^minios-\w+-xfce-standard-amd64-[0-9.]+\.iso$",
            "version_pattern": r"-([0-9.]+)\.iso$",
            "sums_suffix": ".sha256",
        },
        client,
    )
    assert rel.version == "5.1.1"
    assert rel.filename.endswith(".iso")  # never the .torrent
    assert rel.size == 42
    assert rel.checksum == SHA


def test_github_releases_yields_none_when_no_asset_matches():
    """elementary (zero assets) and AnduinOS (torrents only) both land here."""
    releases = json.dumps([{"tag_name": "8.1.0", "assets": []}])
    client = FakeClient({"https://api.github.com/repos/o/r/releases": releases})
    rel = REGISTRY["github_releases"]().resolve(
        "elementary", "default", {"repo": "o/r", "match": r"\.iso$"}, client
    )
    assert rel is None
