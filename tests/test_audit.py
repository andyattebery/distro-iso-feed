"""The two findings that are signal, and the config rule that forces an answer.

`PINNED` is the one no other check in this repo can see. A missing variant is
visible -- nothing appears in the feed. A pinned source resolves cleanly, publishes
a valid checksum, and serves a stale release forever while every check stays green.
Two of them shipped. So the pin check runs offline, over the real config, as a test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from distro_iso_feed.audit import Reason, pins, report
from distro_iso_feed.config import ConfigError, _validate_discover, load
from distro_iso_feed.models import Source, Variant
from distro_iso_feed.strategies import REGISTRY

CONFIG = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"


def _source(name: str, **params) -> Source:
    return Source(
        name=name, variants=(Variant(distro=name, name="v", strategy="s", params=params),)
    )


# --------------------------------------------------------------------------- pins


def test_the_real_config_pins_nothing():
    """The check that would have caught `builds/24.04/intel` and `antiX-26`."""
    _, sources = load(CONFIG, set(REGISTRY))
    found = [f"{f.distro}:{f.subject} -- {f.detail}" for s in sources for f in pins(s)]
    assert found == []


@pytest.mark.parametrize(
    "params",
    [
        {"url": "https://api.pop-os.org/builds/24.04/intel"},
        {"match": r"/antiX-26/antiX-26_x64-full\.iso$"},
        {"index": "https://cdimage.example/13.5/"},
    ],
    ids=["pop-os", "antix", "index"],
)
def test_a_release_literal_in_a_location_param_is_a_pin(params):
    assert [f.reason for f in pins(_source("d", **params))] == [Reason.PINNED]


@pytest.mark.parametrize(
    "params",
    [
        # EndeavourOS's date and Batocera's date both look release-shaped. They live
        # in `version_pattern` -- a token *extractor*, not a location -- so the scan
        # never sees them.
        {"match": r"\.iso$", "version_pattern": r"(\d{4}\.\d{2}\.\d{2})"},
        {"match": r"\.img\.gz$", "version_pattern": r"([0-9.]+-\d{8})"},
        # A word followed by a bare number is not a release. Mint's `match` reads
        # `cinnamon-64bit`, and it stayed invisible only because Mint takes its
        # release from `version_dir` and is skipped before the scan ever runs.
        {"match": r"^linuxmint-[0-9.]+-cinnamon-64bit\.iso$"},
        {"match": r"^archlinux-([a-z]+)-\d{4}\.\d{2}\.\d{2}-x86_64\.iso$"},
        # A literal is fine when the release is discovered some other way.
        {"index": "https://x/{version}/", "version_dir": {"template": "https://x/"}},
        {"url": "https://x/builds/24.04/intel", "probe_versions": {"generator": "ubuntu_style"}},
    ],
    ids=["endeavouros", "batocera", "mint-64bit", "arch-date", "version_dir", "probe_versions"],
)
def test_a_token_extractor_or_a_dynamic_lookup_is_not_a_pin(params):
    assert pins(_source("d", **params)) == []


# ------------------------------------------------------------------- discover shape


def test_a_distro_must_say_how_it_is_enumerated_or_why_it_cannot():
    with pytest.raises(ConfigError, match="no `discover:` block"):
        _validate_discover("d", None)


def test_not_enumerable_demands_a_reason():
    """The reason is the whole product: it separates a fact someone checked from a
    label someone reached for. Pop!_OS wore `enumerable: false` while pinned."""
    with pytest.raises(ConfigError, match="non-empty `reason:`"):
        _validate_discover("d", {"enumerable": False})


def test_not_enumerable_cannot_also_be_enumerated():
    with pytest.raises(ConfigError, match="contradicts"):
        _validate_discover("d", {"enumerable": False, "reason": "r", "group": "(x)"})


def test_a_typo_in_a_discover_key_is_a_load_error():
    with pytest.raises(ConfigError, match="unknown discover key"):
        _validate_discover("d", {"groups": "(x)"})


def test_a_broken_regex_is_caught_at_load_not_on_discovery_day():
    with pytest.raises(ConfigError, match="not a valid regex"):
        _validate_discover("d", {"group": "^([a-z]+$"})


def test_every_real_distro_answers_the_enumeration_question():
    """`load` enforces this, so it cannot be forgotten. Assert the reasons are real
    prose rather than a placeholder someone typed to get past the validator."""
    _, sources = load(CONFIG, set(REGISTRY))
    assert len(sources) >= 20
    for source in sources:
        assert source.discover, source.name
        if source.discover.get("enumerable") is False:
            assert len(source.discover["reason"]) > 20, source.name
        else:
            assert source.discover["group"], source.name


# -------------------------------------------------------------------------- report


def test_report_leads_with_signal_and_collapses_the_rest():
    from distro_iso_feed.audit import Finding

    text = report(
        [
            Finding("nobara", Reason.UNEXPLAINED, "steam-htpc", "`Nobara-43-Steam-HTPC.iso`"),
            Finding("nixos", Reason.NOT_ENUMERABLE, "-", "listing is client-side"),
        ]
    )
    assert text.index("UNEXPLAINED") < text.index("Not enumerable")
    assert "<details>" in text  # the quiet findings are folded away


def test_report_says_so_when_there_is_nothing_to_say():
    assert "No untracked editions, no pinned releases." in report([])
