"""`run_discover.main` composition — one run that produces a variant, an arch, AND a family
proposal, driven end-to-end through `main()` so the three writeback shapes and the `pr_body`
assembly are integration-tested (the proposers themselves are unit-tested elsewhere). This guards
the Tier-2 proposer-contract change: if `main`'s collection, a writeback branch, or the `pr_body`
signature drifts, one of these assertions fails.
"""

from __future__ import annotations

import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed import run_discover
from distro_iso_feed.config import load_raw

H = "e" * 64

CONFIG = """\
families:
  fam:
    root: "https://fam/"
    member_match: '^[a-z]+$'
    model: modeldist
    ignore: []
distros:
  vd:
    strategy: directory_index
    params: {index: "https://vd/", version_pattern: 'vd-([0-9.]+)-', sums: "SUMS"}
    variants:
      a: {label: "VD A", params: {match: '^vd-[0-9.]+-a\\.iso$'}}
    discover: {match: '\\.iso$', group: '^vd-[0-9.]+-([a-z]+)\\.iso$'}
  ad:
    strategy: directory_index
    params: {version_dir: "https://ad/", index: "{version}/{token}/", sums: "SUMS"}
    variants:
      main: {label: "AD", arches: {x86_64: x86_64}, params: {match: '^ad\\.iso$'}}
    discover: {enumerable: false, reason: fixture}
  modeldist:
    strategy: directory_index
    page_url: "https://modeldist.example/"
    params:
      version_dir: "https://fam/modeldist/"
      index: "{version}/"
      version_pattern: 'modeldist-([0-9.]+)-'
      sums: "SUMS"
    variants:
      main: {label: "Modeldist", params: {match: '^modeldist-[0-9.]+-x\\.iso$'}}
    discover: {enumerable: false, reason: fixture}
"""


def _sums(name: str) -> str:
    return f"{H}  {name}\n"


def _pages() -> dict:
    return {
        # variant discovery: `a` configured, `b` new
        "https://vd/": autoindex_html(["vd-1.0-a.iso", "vd-1.0-b.iso", "SUMS"]),
        "https://vd/SUMS": _sums("vd-1.0-a.iso") + _sums("vd-1.0-b.iso"),
        # arch discovery: x86_64 configured, aarch64 new (path segment)
        "https://ad/": autoindex_html(["1.0/"]),
        "https://ad/1.0/": autoindex_html(["x86_64/", "aarch64/"]),
        "https://ad/1.0/x86_64/": autoindex_html(["ad.iso", "SUMS"]),
        "https://ad/1.0/x86_64/SUMS": _sums("ad.iso"),
        "https://ad/1.0/aarch64/": autoindex_html(["ad.iso", "SUMS"]),
        "https://ad/1.0/aarch64/SUMS": _sums("ad.iso"),
        # family discovery: modeldist configured, newmember new
        "https://fam/": autoindex_html(["modeldist/", "newmember/"]),
        "https://fam/newmember/": autoindex_html(["1.0/"]),
        "https://fam/newmember/1.0/": autoindex_html(["newmember-1.0-x.iso", "SUMS"]),
        "https://fam/newmember/1.0/SUMS": _sums("newmember-1.0-x.iso"),
    }


@pytest.fixture
def discover_env(tmp_path, monkeypatch):
    cfg = tmp_path / "sources.yaml"
    cfg.write_text(CONFIG)
    pages = _pages()

    class OneShot(FakeClient):
        def __init__(self, *a, **k):
            super().__init__(pages)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_discover, "Client", OneShot)
    return cfg


def test_main_writes_a_variant_an_arch_and_a_family_in_one_run(discover_env, tmp_path):
    pr = tmp_path / "pr.md"
    rc = run_discover.main(["--config", str(discover_env), "--pr-body", str(pr)])
    assert rc == 0

    doc = load_raw(discover_env)
    # variant: the new edition `b` landed as a variant of `vd`
    assert "b" in doc["distros"]["vd"]["variants"]
    # arch: aarch64 landed in the existing variant's `arches` map
    assert doc["distros"]["ad"]["variants"]["main"]["arches"]["aarch64"] == "aarch64"
    # family: a whole new distro block for the new member
    assert "newmember" in doc["distros"]

    body = pr.read_text()
    assert "## Proposed flavors" in body and "`newmember`" in body
    assert "## Proposed variants" in body and "vd:b" in body
    assert "## Proposed architectures" in body and "aarch64" in body


def test_dry_run_writes_nothing_but_still_reports(discover_env, tmp_path):
    before = discover_env.read_text()
    pr = tmp_path / "pr.md"
    assert run_discover.main(["--dry-run", "--config", str(discover_env), "--pr-body", str(pr)]) == 0
    assert discover_env.read_text() == before  # config untouched under --dry-run
    assert "newmember" in pr.read_text()  # but the evidence is still produced
