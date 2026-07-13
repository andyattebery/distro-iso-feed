"""Discovery extensions: family discovery (propose whole new distro blocks) and the openSUSE
two-surface spin discovery (`extra_index` + a family/edition group).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed.config import ConfigError, load, load_raw
from distro_iso_feed.propose_families import propose_families
from distro_iso_feed.strategies import REGISTRY
from distro_iso_feed.strategies.base import variant_key

REAL_CONFIG = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"

# A model distro + a family rooted at a fake cdimage. The model has no `channel`, so resolution is
# a plain max-version pick -- the family mechanism is what's under test, not the LTS rule.
FAMILY_CONFIG = (
    "families:\n"
    "  flavors:\n"
    "    root: \"https://cd/\"\n"
    "    member_match: '^[a-z]+$'\n"
    "    model: kubuntu\n"
    "    ignore: [streams]\n"
    "distros:\n"
    "  kubuntu:\n"
    "    strategy: directory_index\n"
    "    page_url: \"https://kubuntu.example/\"\n"
    "    params:\n"
    "      version_dir: \"https://cd/kubuntu/releases/\"\n"
    "      index: \"{version}/release/\"\n"
    "      sums: \"SHA256SUMS\"\n"
    "      version_pattern: 'kubuntu-([0-9.]+)-'\n"
    "    variants:\n"
    "      desktop: {label: \"Kubuntu Desktop\", params: {match: '^kubuntu-[0-9.]+-desktop-amd64\\.iso$'}}\n"
    "    discover: {enumerable: false, reason: fixture}\n"
)


def _family_client() -> FakeClient:
    rel = "https://cd/xubuntu/releases/26.04/release/"
    return FakeClient(
        {
            # The root lists a configured member (kubuntu), a new one (xubuntu), an ignored one
            # (streams), and an infra dir with no releases (empty -> resolves to nothing).
            "https://cd/": autoindex_html(["kubuntu/", "xubuntu/", "streams/", "empty/"]),
            "https://cd/xubuntu/releases/": autoindex_html(["26.04/"]),
            rel: autoindex_html(["xubuntu-26.04-desktop-amd64.iso", "SHA256SUMS"]),
            rel + "SHA256SUMS": f"{'a' * 64}  xubuntu-26.04-desktop-amd64.iso\n",
            "https://cd/empty/releases/": autoindex_html([]),
        }
    )


def test_family_discovery_clones_the_model_resolves_and_filters(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(FAMILY_CONFIG)
    _, sources = load(p, set(REGISTRY))
    props, rejected = propose_families(sources, load_raw(p), _family_client())

    # Only xubuntu: kubuntu is configured, streams is ignored, empty resolves to nothing (silently
    # -- a non-flavor that resolves to nothing is not a Rejected).
    assert rejected == []
    assert [f.distro for f in props] == ["xubuntu"]
    f = props[0]
    assert f.family == "flavors"
    assert f.release.filename == "xubuntu-26.04-desktop-amd64.iso" and f.release.version == "26.04"
    # The clone: lowercase name rewrote version_dir/match, the Capitalized name rewrote the label.
    assert f.node["params"]["version_dir"] == "https://cd/xubuntu/releases/"
    assert f.node["variants"]["desktop"]["params"]["match"] == r"^xubuntu-[0-9.]+-desktop-amd64\.iso$"
    assert f.node["variants"]["desktop"]["label"] == "Xubuntu Desktop"


def test_family_discovery_skips_a_member_added_to_ignore(tmp_path):
    """`ignore` is the sticky-decline: adding the would-be member silences it."""
    p = tmp_path / "s.yaml"
    p.write_text(FAMILY_CONFIG.replace("ignore: [streams]", "ignore: [streams, xubuntu]"))
    _, sources = load(p, set(REGISTRY))
    assert propose_families(sources, load_raw(p), _family_client()) == ([], [])


# ------------------------------------------------------------------ families validation

_DISTRO = (
    "distros:\n  kubuntu:\n    strategy: directory_index\n"
    "    discover: {enumerable: false, reason: fixture}\n"
    "    variants:\n      v: {params: {match: 'x'}}\n"
)


@pytest.mark.parametrize(
    "family_yaml, msg",
    [
        ("  f: {root: 'https://x/', member_match: '^a$', model: nope}\n", "not a configured distro"),
        ("  f: {root: 'https://x/', member_match: '[', model: kubuntu}\n", "member_match"),
        ("  f: {root: '', member_match: '^a$', model: kubuntu}\n", "root"),
        ("  f: {root: 'https://x/', member_match: '^a$', model: kubuntu, oops: 1}\n", "unknown key"),
    ],
)
def test_families_config_validation(tmp_path, family_yaml, msg):
    p = tmp_path / "s.yaml"
    p.write_text("families:\n" + family_yaml + _DISTRO)
    with pytest.raises(ConfigError, match=msg):
        load(p, set(REGISTRY))


def test_families_absent_is_fine(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(_DISTRO)
    load(p, set(REGISTRY))  # no `families:` -> no error


# ------------------------------------------------------------------ extra_index union

def test_enumerate_all_extra_index_unions_and_dedupes_by_name():
    di = REGISTRY["directory_index"]()
    a, b = "https://a/", "https://b/"
    client = FakeClient(
        {a: autoindex_html(["one.iso", "shared.iso"]), b: autoindex_html(["two.iso", "shared.iso"])}
    )
    names = {c.name for c in di.enumerate_all("d", [], {"index": a, "extra_index": b}, client)}
    assert names == {"one.iso", "two.iso", "shared.iso"}  # both surfaces, shared deduped once


# ------------------------------------------------------------------ openSUSE group keys

def test_opensuse_group_keys_family_and_edition_across_both_surfaces():
    group = re.compile(
        r"^openSUSE-(Leap|Tumbleweed|MicroOS)-(?:[0-9.]+-)?(.+?)-x86_64-(?:Build[0-9.]+-Media|Current)\.iso$"
    )
    cases = {
        "openSUSE-Leap-15.6-DVD-x86_64-Build710.3-Media.iso": "leap-dvd",
        "openSUSE-Leap-15.6-NET-x86_64-Build710.3-Media.iso": "leap-net",
        "openSUSE-Tumbleweed-GNOME-Live-x86_64-Current.iso": "tumbleweed-gnome-live",
        "openSUSE-Tumbleweed-Rescue-CD-x86_64-Current.iso": "tumbleweed-rescue-cd",
        "openSUSE-MicroOS-DVD-x86_64-Current.iso": "microos-dvd",
    }
    for filename, key in cases.items():
        m = group.search(filename)
        assert m and variant_key(m) == key, filename
    # A Snapshot-dated (non-Current) file is not an edition and must not match.
    assert not group.search("openSUSE-Tumbleweed-DVD-x86_64-Snapshot20260710-Media.iso")


def test_opensuse_config_carries_the_four_backfilled_spins():
    _, sources = load(REAL_CONFIG, set(REGISTRY))
    keys = {v.name for v in next(s for s in sources if s.name == "opensuse").variants}
    assert {
        "tumbleweed-gnome-live",
        "tumbleweed-kde-live",
        "tumbleweed-xfce-live",
        "tumbleweed-rescue-cd",
    } <= keys
