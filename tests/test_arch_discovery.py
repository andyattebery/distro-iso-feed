"""Arch discovery: enumerate upstream arches, verify each resolves, propose into the `arches` map.

Like variant discovery, and simpler -- a proposal is one `canonical: token` line, resolved live
before it is written. The runtime is untouched; discovery only edits config.
"""

from __future__ import annotations

from conftest import FakeClient, autoindex_html
from distro_iso_feed.arch import canonical
from distro_iso_feed.config import load, load_raw, substitute_token, yaml_rt
from distro_iso_feed.models import Release
from distro_iso_feed.propose_arches import propose_arches
from distro_iso_feed.propose_common import ArchProposal, pr_body
from distro_iso_feed.strategies import REGISTRY

SHA512 = "b" * 128


def test_canonical_maps_aliases_and_falls_back_to_identity():
    assert canonical("amd64") == "x86_64"
    assert canonical("arm64") == "aarch64"
    assert canonical("ppc64el") == "ppc64le"
    assert canonical("x64") == "x86_64"
    assert canonical("riscv64") == "riscv64"  # not an alias -> itself
    assert canonical("s390x") == "s390x"


def test_substitute_token_reaches_every_field_including_sums_and_nested():
    """Not just index/match/version_pattern -- a checksum-file name or a nested field too."""
    out = substitute_token(
        {"index": "c/{token}/i", "sums": "SUM-{token}", "n": {"x": "{token}"}}, "arm64"
    )
    assert out == {"index": "c/arm64/i", "sums": "SUM-arm64", "n": {"x": "arm64"}}


def test_directory_index_arch_tokens_lists_the_token_directory():
    client = FakeClient({"https://x/current/": autoindex_html(["amd64/", "arm64/", "source/"])})
    di = REGISTRY["directory_index"]()
    assert set(di.arch_tokens({"index": "https://x/current/{token}/iso-cd/"}, client)) == {
        "amd64",
        "arm64",
        "source",
    }
    assert di.arch_tokens({"index": "https://x/fixed/iso/"}, client) == []  # no {token} -> none


_DEBIAN = (
    "distros:\n  debian:\n    strategy: directory_index\n"
    "    discover: {enumerable: false, reason: fixture}\n"
    "    params: {sums: SHA512SUMS}\n"
    "    variants:\n"
    "      netinst:\n"
    "        arches: {x86_64: amd64}\n"
    "        params:\n"
    "          index: \"https://cd.example/current/{token}/iso-cd/\"\n"
    "          match: '^debian-[0-9.]+-{token}-netinst\\.iso$'\n"
    "          version_pattern: 'debian-([0-9.]+)-{token}'\n"
)


def _client() -> FakeClient:
    parent = "https://cd.example/current/"
    arm = parent + "arm64/iso-cd/"
    return FakeClient(
        {
            parent: autoindex_html(["amd64/", "arm64/", "source/"]),
            arm: autoindex_html(["debian-13.6.0-arm64-netinst.iso"]),
            arm + "SHA512SUMS": f"{SHA512}  debian-13.6.0-arm64-netinst.iso",
            # source/iso-cd/ is unmapped -> resolve returns None -> the dir is dropped
        }
    )


def test_propose_arches_proposes_the_new_arch_skips_known_and_drops_non_arch(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(_DEBIAN)
    _, sources = load(p, set(REGISTRY))
    props = propose_arches(sources[0], load_raw(p), _client())
    # amd64 is already in the map (skipped); `source/` doesn't resolve (dropped); only arm64 lands,
    # canonicalised to aarch64 and resolved live.
    assert [(a.variant, a.arch, a.token, a.release.filename) for a in props] == [
        ("netinst", "aarch64", "arm64", "debian-13.6.0-arm64-netinst.iso")
    ]
    assert props[0].release.checksum == SHA512  # verified against arm64's own SHA512SUMS


def test_writeback_adds_the_arch_preserving_comments_and_siblings(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(
        "distros:\n  d:\n    strategy: directory_index\n"
        "    discover: {enumerable: false, reason: x}\n"
        "    variants:\n"
        "      v:\n"
        "        # keep me\n"
        "        arches: {x86_64: amd64}\n"
        "        params: {index: 'a/{token}/b', match: 'm-{token}'}\n"
    )
    doc = load_raw(p)
    doc["distros"]["d"]["variants"]["v"]["arches"]["aarch64"] = "arm64"  # the run_discover writeback
    with p.open("w") as fh:
        yaml_rt().dump(doc, fh)
    text = p.read_text()
    assert "# keep me" in text  # comment survived the round-trip
    assert "aarch64: arm64" in text  # new arch written
    assert "x86_64: amd64" in text  # sibling untouched


def test_pr_body_renders_the_architectures_section():
    rel = Release(
        distro="debian",
        variant="netinst",
        version="13.6.0",
        title="t",
        filename="debian-13.6.0-arm64-netinst.iso",
        checksum="a" * 128,
        checksum_algo="sha512",
    )
    body = pr_body([], [ArchProposal("debian", "netinst", "aarch64", "arm64", rel)], [])
    assert "## Proposed architectures" in body
    assert "`debian:netinst`" in body and "`aarch64`" in body and "`arm64`" in body
    assert "debian-13.6.0-arm64-netinst.iso" in body
