"""The two findings that are signal, and the config rule that forces an answer.

`PINNED` is the one no other check in this repo can see. A missing variant is
visible -- nothing appears in the feed. A pinned source resolves cleanly, publishes
a valid checksum, and serves a stale release forever while every check keeps passing.
Two of them shipped. So the pin check runs offline, over the real config, as a test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed.audit import (
    Finding,
    Reason,
    audit_source,
    pins,
    report,
    resolve_findings,
    skipped_releases,
)
from distro_iso_feed.config import (
    ConfigError,
    _validate_discover,
    _validate_discovery_surface,
    _validate_signing_key,
    _validate_signing_surface,
    load,
)
from distro_iso_feed.models import Source, Variant
from distro_iso_feed.signing import COVERS
from distro_iso_feed.strategies import REGISTRY

CONFIG = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"


def _source(name: str, **params) -> Source:
    return Source(
        name=name, variants=(Variant(distro=name, name="v", strategy="s", params=params),)
    )


# ------------------------------------------------------------------- unresolvable
#
# The check the docs promised and nobody built: does a key we wrote down name something real?
# `ubuntu-unity:desktop-interim` asked for a non-LTS Ubuntu Unity, Unity ships LTS only, and it
# sat dead from the day it was added -- past every other check in this repo.

_DI = "directory_index"
_IDX = "https://mirror.example/current/"


def _di_source(name: str = "d", **over) -> Source:
    params = {
        "index": _IDX,
        "match": r"^thing-[0-9.]+-amd64\.iso$",
        "version_pattern": r"thing-([0-9.]+)-",
        **over,
    }
    return Source(
        name=name, variants=(Variant(distro=name, name="v", strategy=_DI, params=params),)
    )


def test_a_variant_that_names_nothing_real_is_unresolvable():
    """200 from the endpoint, but nothing it lists matches -- the config is wrong, not the mirror."""
    client = FakeClient({_IDX: autoindex_html(["other-9.9-amd64.iso"])})
    found = resolve_findings(_di_source(), client)
    assert [f.reason for f in found] == [Reason.UNRESOLVABLE]
    assert _IDX in found[0].detail


def test_a_resolving_variant_is_not_reported():
    client = FakeClient({_IDX: autoindex_html(["thing-1.2-amd64.iso"])})
    assert resolve_findings(_di_source(), client) == []


def test_a_timed_out_mirror_is_not_reported_as_unresolvable():
    """The guard that keeps a bad night at cdimage from becoming a wall of false findings.
    A transient failure means stale, not wrong -- it will be back tomorrow."""
    client = FakeClient(fail={_IDX: "ReadTimeout"})
    assert resolve_findings(_di_source(), client) == []


def test_a_host_over_its_failure_budget_is_not_reported_either():
    """The budget short-circuits with a synthetic transient trace entry; it must read as transient
    here too, or a sick host would file a finding per variant it skipped."""
    client = FakeClient(fail={_IDX: "ReadTimeout"}, host_budget=1)
    client.get(_IDX)  # burn the budget
    assert resolve_findings(_di_source(), client) == []


def test_unresolvable_still_runs_for_a_source_that_cannot_be_enumerated():
    """`enumerable: false` short-circuits `audit_source` before the upstream diff -- which is
    exactly where unity hid, and its declared reason was the channel mechanic that broke it.
    Pins already run before that gate; resolvability must too."""
    src = Source(
        name="d",
        variants=(Variant(distro="d", name="v", strategy=_DI, params={
            "index": _IDX, "match": r"^thing-[0-9.]+-amd64\.iso$",
            "version_pattern": r"thing-([0-9.]+)-",
        }),),
        discover={"enumerable": False, "reason": "fixture"},
    )  # fmt: skip
    client = FakeClient({_IDX: autoindex_html(["other-9.9-amd64.iso"])})
    reasons = [f.reason for f in audit_source(src, client)]
    assert Reason.UNRESOLVABLE in reasons
    assert Reason.NOT_ENUMERABLE in reasons  # the existing bookkeeping still happens


def test_unresolvable_is_signal_so_it_escapes_the_collapsed_fold():
    assert Reason.UNRESOLVABLE.is_signal
    assert not Reason.NOT_ENUMERABLE.is_signal


# ---------------------------------------------------------------------------- no checksum
#
# The push-time half of "a file the config names must arrive". The refresh raises it for a tracked
# variant; a variant that never resolved has no record to regress from, so this has to.

_ISO = "thing-1.2-amd64.iso"
_SIDECAR = f"{_IDX}{_ISO}.sha256"


@pytest.mark.parametrize("param", ["sums", "sums_suffix", "sums_asset"])
def test_a_configured_sidecar_that_404s_is_no_checksum(param):
    client = FakeClient({_IDX: autoindex_html([_ISO])})
    found = resolve_findings(_di_source(**{param: "{filename}.sha256"}), client)
    assert [(f.reason, f.subject) for f in found] == [(Reason.NO_CHECKSUM, "v")]
    assert _ISO in found[0].detail


def test_a_sidecar_that_omits_the_artifact_is_no_checksum():
    client = FakeClient({_IDX: autoindex_html([_ISO]), _SIDECAR: f"{'a' * 64}  other.iso"})
    found = resolve_findings(_di_source(sums="{filename}.sha256"), client)
    assert [f.reason for f in found] == [Reason.NO_CHECKSUM]


def test_a_sidecar_that_lists_the_artifact_is_not_reported():
    client = FakeClient({_IDX: autoindex_html([_ISO]), _SIDECAR: f"{'a' * 64}  {_ISO}"})
    assert resolve_findings(_di_source(sums="{filename}.sha256"), client) == []


def test_a_variant_configuring_no_checksum_is_not_reported():
    """The Tails shape: upstream ships a signature and no sidecar, and the config says so."""
    client = FakeClient({_IDX: autoindex_html([_ISO])})
    assert resolve_findings(_di_source(), client) == []


def test_a_timed_out_sidecar_is_not_no_checksum():
    """Stale, not wrong: the same line `UNRESOLVABLE` draws, and the refresh leaves it untouched."""
    client = FakeClient({_IDX: autoindex_html([_ISO])}, fail={_SIDECAR: "ReadTimeout"})
    assert resolve_findings(_di_source(sums="{filename}.sha256"), client) == []


def test_a_configured_torrent_that_404s_is_no_torrent():
    """The push-time check: a variant never resolved before has no record to regress from, so the
    refresh will not raise this, and `config-audit` has to."""
    client = FakeClient({_IDX: autoindex_html([_ISO])})
    found = resolve_findings(_di_source(torrent="{filename}.torrent"), client)
    assert [(f.reason, f.subject) for f in found] == [(Reason.NO_TORRENT, "v")]
    assert f"{_IDX}{_ISO}.torrent" in found[0].detail


def test_a_timed_out_torrent_is_not_no_torrent():
    client = FakeClient(
        {_IDX: autoindex_html([_ISO])}, fail={f"{_IDX}{_ISO}.torrent": "ReadTimeout"}
    )
    assert resolve_findings(_di_source(torrent="{filename}.torrent"), client) == []


def test_no_checksum_is_signal_and_reaches_the_report():
    assert Reason.NO_CHECKSUM.is_signal
    body = report([Finding("d", Reason.NO_CHECKSUM, "v", "`x.iso`")])
    assert "**NO_CHECKSUM**" in body


_GH_API = "https://api.github.com/repos/o/r/releases"
_GH_ISO = "thing-1.2-amd64.iso"


def _gh_source(**params) -> Source:
    base = {
        "repo": "o/r",
        "honor_prerelease_flag": True,
        "match": r"^thing-[0-9.]+-amd64\.iso$",
        "version_pattern": r"thing-([0-9.]+)-",
        **params,
    }
    return Source(
        name="d", variants=(Variant("d", "v", "github_releases", base),)
    )


def _gh_releases(*assets: str) -> str:
    rows = [{"name": a, "browser_download_url": f"https://x/{a}"} for a in (_GH_ISO, *assets)]
    return json.dumps(
        [{"tag_name": "v1.2", "prerelease": False, "published_at": "2026-01-01T00:00:00Z", "assets": rows}]
    )


@pytest.mark.parametrize(
    "params", [{"sums_suffix": ".sha256"}, {"sums_asset": "sha256sum.txt"}], ids=["suffix", "asset"]
)
def test_a_github_release_missing_its_checksum_asset_is_no_checksum(params):
    client = FakeClient({_GH_API: _gh_releases()})
    found = resolve_findings(_gh_source(**params), client)
    assert [f.reason for f in found] == [Reason.NO_CHECKSUM]


def test_a_timed_out_github_checksum_asset_is_not_no_checksum():
    client = FakeClient(
        {_GH_API: _gh_releases("sha256sum.txt")}, fail={"https://x/sha256sum.txt": "ReadTimeout"}
    )
    assert resolve_findings(_gh_source(sums_asset="sha256sum.txt"), client) == []


# ------------------------------------------------------------------------ skipped releases
#
# `version_dir` takes the highest dir holding an artifact, so a release upstream moved falls back
# to the last one that still fits, with no failure. Leap sat on 15.6 under a `16.1/` with no `iso/`.
# Tails walked back to 7.14 when 7.15.1 stopped serving.

_VD = "https://mirror.example/rel/"


def _vd_source(index: str = "{version}/", variants: tuple[str, ...] = ("v",), **over) -> Source:
    params = {
        "version_dir": _VD,
        "version_dir_match": r"^\d+\.\d+$",
        "index": index,
        "match": r"^thing-[0-9.]+-amd64\.iso$",
        "version_pattern": r"thing-([0-9.]+)-",
        **over,
    }
    return Source(
        name="d", variants=tuple(Variant("d", n, _DI, dict(params)) for n in variants)
    )


def _vd_pages(extra: dict | None = None, index: str = "1.0/") -> dict:
    return {
        _VD: autoindex_html(["1.0/", "2.0/"]),
        f"{_VD}{index}": autoindex_html(["thing-1.0-amd64.iso"]),
        **(extra or {}),
    }


def test_a_newer_dir_that_serves_nothing_is_skipped_release():
    found = skipped_releases(_vd_source(), FakeClient(_vd_pages()))
    assert [(f.reason, f.subject) for f in found] == [(Reason.SKIPPED_RELEASE, "v")]
    assert "2.0" in found[0].detail


def test_a_newer_release_that_moved_its_files_is_skipped_release():
    """The Leap shape: the version dir has real content, just not where the config looks."""
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["offline/", "repo/"])}, index="1.0/iso/")
    found = skipped_releases(_vd_source(index="{version}/iso/"), FakeClient(pages))
    assert [f.reason for f in found] == [Reason.SKIPPED_RELEASE]


def test_a_newer_dir_that_is_empty_is_not_reported():
    """FreeBSD's `15.2/` answered 200 with nothing in it while 15.2-BETA1 reached the CDN, and
    failed `config-audit` on an unrelated push. Nothing is published there yet, so nothing was
    skipped. A 404 is different: the release is listed and is not where we look."""
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html([])})
    assert skipped_releases(_vd_source(), FakeClient(pages)) == []


def test_a_newer_dir_holding_only_milestones_is_not_reported():
    """The Ubuntu development cycle: `27.04/release/` 404s for weeks, and that is expected."""
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["beta/", "snapshot-1/"])}, index="1.0/release/")
    assert skipped_releases(_vd_source(index="{version}/release/"), FakeClient(pages)) == []


def test_a_skipped_release_names_its_arch():
    """Same-dir `{token}` sources can lose one arch, and the finding carries only the variant."""
    params = _vd_source().variants[0].params
    source = Source(name="d", variants=(Variant("d", "v", _DI, params, arch="aarch64"),))
    found = skipped_releases(source, FakeClient(_vd_pages()))
    assert "aarch64" in found[0].detail


def test_a_newer_dir_with_renamed_files_is_skipped_release():
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["newname-2.0-amd64.iso"])})
    found = skipped_releases(_vd_source(), FakeClient(pages))
    assert [f.reason for f in found] == [Reason.SKIPPED_RELEASE]
    assert "2.0" in found[0].detail


def test_an_edition_dropped_from_a_newer_dir_is_skipped_release():
    """Gershwin's failure on a `version_dir` source: siblings move on, this one stays frozen."""
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["thing-2.0-other.iso"])})
    found = skipped_releases(_vd_source(), FakeClient(pages))
    assert [f.reason for f in found] == [Reason.SKIPPED_RELEASE]


def test_each_match_is_walked_separately():
    """Whether a dir was skipped depends on `match`, so sharing a listing is not enough to share a
    walk: here `amd` is fine and only `arm` is frozen."""
    base = _vd_source().variants[0].params
    pages = {
        _VD: autoindex_html(["1.0/", "2.0/"]),
        f"{_VD}1.0/": autoindex_html(["thing-1.0-amd64.iso", "thing-1.0-arm64.iso"]),
        f"{_VD}2.0/": autoindex_html(["thing-2.0-amd64.iso"]),
    }
    source = Source(
        name="d",
        variants=(
            Variant("d", "amd", _DI, {**base, "match": r"^thing-[0-9.]+-amd64\.iso$"}),
            Variant("d", "arm", _DI, {**base, "match": r"^thing-[0-9.]+-arm64\.iso$"}),
        ),
    )
    assert [f.subject for f in skipped_releases(source, FakeClient(pages))] == ["arm"]


def test_a_newer_dir_with_only_prerelease_artifacts_is_not_reported():
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["thing-2.0-beta-amd64.iso"])})
    assert skipped_releases(_vd_source(), FakeClient(pages)) == []


def test_a_newer_dir_with_only_ignored_artifacts_is_not_reported():
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["thing-2.0.r1-amd64.iso"])})
    source = _vd_source(ignore=[r"\.r\d+-"])
    assert skipped_releases(source, FakeClient(pages)) == []


def test_a_newer_dir_with_no_artifacts_at_all_is_not_reported():
    pages = _vd_pages({f"{_VD}2.0/": autoindex_html(["README", "SHA256SUMS", "x.iso.torrent"])})
    assert skipped_releases(_vd_source(), FakeClient(pages)) == []


def test_the_refresh_walk_fetches_nothing_extra():
    """The parent check costs a fetch, and belongs to the audit, never the daily walk."""
    pages = _vd_pages(index="1.0/release/")
    client = FakeClient(pages)
    params = dict(_vd_source(index="{version}/release/").variants[0].params)
    REGISTRY[_DI]()._index_url(params, client)
    assert client.requested == [_VD, f"{_VD}2.0/release/", f"{_VD}1.0/release/"]


def test_a_timed_out_newer_dir_is_not_skipped_release():
    client = FakeClient(_vd_pages(), fail={f"{_VD}2.0/": "ReadTimeout"})
    assert skipped_releases(_vd_source(), client) == []


def test_each_listing_is_walked_once():
    client = FakeClient(_vd_pages())
    found = skipped_releases(_vd_source(variants=("a", "b")), client)
    assert [f.subject for f in found] == ["a"]
    assert client.requested.count(_VD) == 1


def test_variants_on_different_channels_are_walked_separately():
    """Ubuntu lists `-lts` first, on the same listing as `-latest`. Keyed without `channel`, the
    `latest` variants were never walked and a moved 26.10 would have fallen back unseen."""
    pages = {
        _VD: autoindex_html(["24.04/", "26.10/"]),
        f"{_VD}24.04/": autoindex_html(["thing-24.04-amd64.iso"]),
    }
    source = Source(
        name="d",
        variants=(
            Variant("d", "lts", _DI, {**_vd_source().variants[0].params, "channel": "lts"}),
            Variant("d", "latest", _DI, {**_vd_source().variants[0].params, "channel": "latest"}),
        ),
    )
    found = skipped_releases(source, FakeClient(pages))
    assert [f.subject for f in found] == ["latest"]


def test_a_timed_out_parent_dir_is_not_skipped_release():
    """`release/` 404s and the check on its parent times out: nothing shows the dir is real."""
    pages = _vd_pages(index="1.0/release/")
    client = FakeClient(pages, fail={f"{_VD}2.0/": "ReadTimeout"})
    assert skipped_releases(_vd_source(index="{version}/release/"), client) == []


def test_a_variant_with_no_version_dir_has_nothing_to_skip():
    assert skipped_releases(_di_source(), FakeClient()) == []


def test_skipped_release_is_signal():
    assert Reason.SKIPPED_RELEASE.is_signal


def test_an_edition_tracked_under_another_name_is_not_unexplained():
    """neon moved `images/desktop/` to `images/desk/user/`. The `desktop` variant selects the
    `desk` row, so `desk` is tracked; only `big` is unexplained. Same test discovery applies, or
    `--strict` on the config push fails over a variant that resolves."""
    url = "https://nd/images/desk/user/current/nd-user-desk-current.iso"
    params = {"url": url, "sums": "{stem}.sha256sum",
              "token": {"from": "sidecar_filename", "pattern": r"(\d{8}-\d{4})"}}
    src = Source(
        name="nd",
        variants=(Variant(distro="nd", name="desktop", strategy="stable_symlink", params=params),),
        discover={"index": "https://nd/images/", "match": "^[a-z]+$", "group": "^([a-z]+)$"},
    )  # fmt: skip
    client = FakeClient({
        "https://nd/images/": autoindex_html(["big/", "desk/"]),
        url.replace(".iso", ".sha256sum"): "e" * 64 + "  nd-user-desk-20261018-1825.iso\n",
    })  # fmt: skip
    found = [f for f in audit_source(src, client) if f.reason is Reason.UNEXPLAINED]
    assert [f.subject for f in found] == ["big"]


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
        # A literal the scan DOES flag (an unescaped `24.04`), in a param `version_page` allows,
        # so dropping `version_page` from `_DYNAMIC` fails this case.
        {"match": "^distro-24.04-amd64.iso$", "version_page": "https://x/download/"},
    ],
    ids=[
        "endeavouros", "batocera", "mint-64bit", "arch-date", "version_dir", "probe_versions",
        "version_page",
    ],  # fmt: skip
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


# ------------------------------------------------------- fixed-URL discovery surface (E3)
#
# A pure stable_symlink distro lists one fixed URL, so a `group` with no `index`/`extra_index`
# would discover nothing forever -- a silent no-op that reads as "nothing to find". The shipped
# config is guarded by `load(CONFIG)` above; here the rule and its exemptions are pinned directly.

_FIXED = {"strategy": "stable_symlink", "variants": {"v": {"params": {"url": "https://x/a.iso"}}}}


def test_fixed_url_distro_with_a_group_needs_an_enumeration_surface():
    with pytest.raises(ConfigError, match="cannot enumerate new members"):
        _validate_discovery_surface("d", {**_FIXED, "discover": {"group": "(x)"}})


def test_fixed_url_distro_is_satisfied_by_index_extra_index_or_opt_out():
    for discover in (
        {"group": "(x)", "index": "https://x/"},
        {"group": "(x)", "extra_index": "https://x/"},
        {"enumerable": False, "reason": "r"},
    ):
        _validate_discovery_surface("d", {**_FIXED, "discover": discover})  # no raise


def test_mixed_strategy_distro_is_exempt_a_listing_variant_enumerates():
    """openSUSE: a directory_index Leap variant reads a listing, so the block has a real surface
    even though its Tumbleweed variants are fixed-URL."""
    block = {
        "strategy": "directory_index",
        "discover": {"group": "(x)"},
        "variants": {"leap": {}, "tw": {"strategy": "stable_symlink"}},
    }
    _validate_discovery_surface("d", block)  # no raise


# ------------------------------------------------------ signing `covers` set of truth (E2)


def test_covers_validation_is_driven_by_the_dispatch_set():
    """config validates `signing_key.covers` against `signing.COVERS` -- the very set the GPG
    dispatch reads -- so the validator and the policy can never name different modes across the two
    files. Every dispatched mode validates; anything outside the set is a load error."""
    for mode in COVERS:
        _validate_signing_key("d", {"url": "u", "fingerprint": "a" * 40, "covers": mode})
    with pytest.raises(ConfigError, match="covers"):
        _validate_signing_key("d", {"url": "u", "fingerprint": "a" * 40, "covers": "detached"})


def test_a_signing_key_with_nothing_to_verify_is_a_load_error():
    """`verify_signing_key` bails the moment `signature_url` is None -- for EVERY covers mode --
    so a pin without a `sig` can never publish and the entry silently serves `checksum` while the
    config implies `gpg`. The 8 `opensuse:leap-*` variants did exactly that until this check.

    Checked against every mode, because the rule is universal rather than a checksums quirk.
    """
    key = {"url": "u", "fingerprint": "a" * 40, "covers": "checksums"}
    for mode in COVERS:
        with pytest.raises(ConfigError, match="sig"):
            _validate_signing_surface("d", "v", {"signing_key": {**key, "covers": mode}})
    # either spelling satisfies it
    _validate_signing_surface("d", "v", {"signing_key": key, "sig": "{filename}.sha256.asc"})
    _validate_signing_surface("d", "v", {"signing_key": key, "sig_url": "https://x/SUMS.gpg"})
    # no signing_key at all -> nothing to check
    _validate_signing_surface("d", "v", {"sums": "SHA256SUMS"})


def test_the_real_config_has_no_inert_signing_key():
    """The regression test for the leap bug: every configured pin must have something to verify."""
    _, sources = load(CONFIG, set(REGISTRY))
    inert = [
        v.key
        for s in sources
        for v in s.variants
        if v.params.get("signing_key") and not (v.params.get("sig") or v.params.get("sig_url"))
    ]
    assert inert == []


# -------------------------------------------------------------------------- report


def test_report_leads_with_signal_and_collapses_the_rest():
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
