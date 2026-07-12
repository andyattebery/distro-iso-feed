"""Arch discovery: enumerate upstream arches, verify each resolves, propose into the `arches` map.

Like variant discovery, and simpler -- a proposal is one `canonical: token` line, resolved live
before it is written. The runtime is untouched; discovery only edits config.
"""

from __future__ import annotations

import json

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


def test_directory_index_filename_capture_arch_tokens_ignores_musl():
    """Void shape: one flat dir, arch in the FILENAME. The capture regex enumerates arches, and
    `ignore` still drops the musl builds so `aarch64-musl` never becomes an arch of its own."""
    listing = autoindex_html(
        [
            "void-live-x86_64-20250202-base.iso",
            "void-live-aarch64-20250202-base.iso",
            "void-live-i686-20250202-base.iso",
            "void-live-aarch64-musl-20250202-base.iso",
        ]
    )
    client = FakeClient({"https://repo/live/current/": listing})
    di = REGISTRY["directory_index"]()
    params = {
        "index": "https://repo/live/current/",
        "match": r"^void-live-{token}-\d{8}-base\.iso$",
        "ignore": ["-musl-"],
    }
    assert di.arch_tokens(params, client) == ["aarch64", "i686", "x86_64"]  # musl excluded, sorted


def test_json_api_arch_tokens_are_per_variant_and_sparse():
    """Fedora shape: the arch is a JSON field, and the matrix is sparse. Each variant offers only
    the arches it actually publishes -- Server has s390x, Workstation does not."""
    doc = json.dumps(
        [
            {"version": "44", "arch": "x86_64", "subvariant": "Workstation",
             "link": "https://d/Fedora-Workstation-Live-44-x86_64.iso", "sha256": "a" * 64},
            {"version": "44", "arch": "aarch64", "subvariant": "Workstation",
             "link": "https://d/Fedora-Workstation-Live-44-aarch64.iso", "sha256": "a" * 64},
            {"version": "44", "arch": "x86_64", "subvariant": "Server",
             "link": "https://d/Fedora-Server-netinst-x86_64-44.iso", "sha256": "a" * 64},
            {"version": "44", "arch": "s390x", "subvariant": "Server",
             "link": "https://d/Fedora-Server-netinst-s390x-44.iso", "sha256": "a" * 64},
        ]
    )
    client = FakeClient({"https://f/releases.json": doc})
    ja = REGISTRY["json_api"]()
    ws = {"url": "https://f/releases.json", "select": {"subvariant": "Workstation"}}
    srv = {"url": "https://f/releases.json", "select": {"subvariant": "Server"}}
    assert ja.arch_tokens(ws, client) == ["aarch64", "x86_64"]  # no s390x for Workstation
    assert ja.arch_tokens(srv, client) == ["s390x", "x86_64"]  # Server has it


def test_stable_symlink_arch_tokens_offers_candidates_only_when_token_present():
    """A fixed URL has nothing to list, so it offers a candidate set that resolve-verify prunes --
    but only when the URL actually carries a `{token}` to substitute (NixOS does; ublue does not)."""
    ss = REGISTRY["stable_symlink"]()
    client = FakeClient({})
    assert ss.arch_tokens({"url": "https://ch/nixos-{version}/x-{token}-linux.iso"}, client) == [
        "x86_64",
        "aarch64",
    ]
    assert ss.arch_tokens({"url": "https://dl/bazzite-stable-amd64.iso"}, client) == []


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


def test_arch_ignore_silences_a_proposal_by_token_or_canonical(tmp_path):
    """`discover.arch_ignore` makes a declined arch stay declined. It matches the upstream token
    OR its canonical, so either spelling of Debian's arm64/aarch64 suppresses the proposal."""
    base = _DEBIAN.replace(
        "    discover: {enumerable: false, reason: fixture}\n",
        "    discover: {enumerable: false, reason: fixture, arch_ignore: [%s]}\n",
    )
    for entry in ("arm64", "aarch64"):  # token spelling and canonical spelling both work
        p = tmp_path / f"s-{entry}.yaml"
        p.write_text(base % entry)
        _, sources = load(p, set(REGISTRY))
        assert propose_arches(sources[0], load_raw(p), _client()) == []


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
