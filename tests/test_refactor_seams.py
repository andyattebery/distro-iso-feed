"""Seams introduced by the Tier 1/2 cleanup: the `build_release` factory, `choose_artifact`, the
unified `substitute`, and the honest `carries_integrity`. These pin the new shared surfaces so a
future change to any of them fails here rather than silently in seven resolve tails.
"""

from __future__ import annotations

from distro_iso_feed.arch import DEFAULT_ARCH
from distro_iso_feed.config import substitute, substitute_token
from distro_iso_feed.models import Release
from distro_iso_feed.propose_common import carries_integrity
from distro_iso_feed.strategies.build import build_release, choose_artifact


def test_build_release_fills_arch_title_page_url_and_passes_fields_through():
    r = build_release(
        "void",
        "base",
        "20250101",
        filename="void-base.iso",
        download_url="https://v/void-base.iso",
        params={"arch": "aarch64", "label": "Void base", "page_url": "https://v/"},
        checksum="abc",
        checksum_algo="sha256",
        size=99,
    )
    assert r.arch == "aarch64"  # from params
    assert r.title == "Void base 20250101 (aarch64)"  # label + version + arch
    assert r.page_url == "https://v/"  # from params
    assert (r.filename, r.download_url) == ("void-base.iso", "https://v/void-base.iso")
    assert (r.checksum, r.checksum_algo, r.size) == ("abc", "sha256", 99)  # **fields passthrough


def test_build_release_defaults_arch_to_the_one_default():
    r = build_release("d", "v", "1", filename="f.iso", download_url="u", params={})
    assert r.arch == DEFAULT_ARCH


def test_choose_artifact_reads_the_four_selection_params():
    names = ["x-1.0.iso", "x-1.0.iso.zsync", "x-2.0.iso"]
    params = {"match": r"^x-[0-9.]+\.iso$", "version_pattern": r"x-([0-9.]+)"}
    assert choose_artifact(names, params) == "x-2.0.iso"  # newest, zsync excluded by match
    assert choose_artifact(["y-1.iso"], params) is None  # nothing matches


def test_substitute_token_is_substitute_with_a_single_pair():
    params = {"index": "c/{token}/i", "sums": "SUM-{token}", "n": {"x": "{token}"}, "k": 3}
    assert substitute_token(params, "arm64") == substitute(params, [("{token}", "arm64")])
    assert substitute_token(params, "arm64")["index"] == "c/arm64/i"


def _bare_release(**kw) -> Release:
    return Release(distro="d", variant="v", version="1", title="t", filename="f.iso", **kw)


def test_carries_integrity_rejects_a_release_with_no_verifier():
    assert carries_integrity(_bare_release()) is not None  # no checksum/sig/infohash
    assert carries_integrity(_bare_release(checksum="abc")) is None
    assert carries_integrity(_bare_release(signature_url="https://s/f.sig")) is None
    assert carries_integrity(_bare_release(info_hash="deadbeef")) is None
