"""Novel source shapes and their shipped-config checks.

The BSDs and Parrot:
- OpenBSD: arch is a PATH segment (`7.9/{arch}/`) and the version is the DIRECTORY name (the
  filename `install79.iso` has no dotted version), so resolution leans on `version_dir` with no
  `version_pattern`.
- NetBSD: arch is a FILENAME token in one `images/` dir, and the version dir is prefixed
  (`NetBSD-10.1`), which `version_key` must still sort numerically.
- Parrot: one clearsigned `signed-hashes.txt` lists md5+sha256+sha512 for each ISO; the parser
  must publish the strongest (sha512).

GhostBSD/XCP-ng/Qubes/Gentoo/ChimeraOS (resolve the shipped config's own expanded params):
- XCP-ng: a two-group `version_pattern` so a re-hash refresh `…20250606.2` outsorts `…20250606`
  (a single group makes the older ISO parse as a higher `Version` tier and wrongly win).
- Qubes: a `<hash> *<name>` DIGESTS with both sha256 and sha512; the parser keeps sha512.
- Gentoo: the clearsigned `.sha256` (single 64-hex), NOT `.DIGESTS` whose SHA512/BLAKE2B both
  read as 128 hex; the datestamp is the change-token; arm64 via arches.
- ChimeraOS: `github_releases` with `honor_prerelease_flag` (bare-date tags carry no signal) and
  an aggregate `sums_asset` (see test_client_and_discover for the resolve).
"""

from __future__ import annotations

from pathlib import Path

from conftest import FakeClient, autoindex_html
from distro_iso_feed.config import load
from distro_iso_feed.strategies import REGISTRY

DI = REGISTRY["directory_index"]


# --------------------------------------------------------------- shipped config expands right

CONFIG = Path(__file__).resolve().parents[1] / "config" / "sources.yaml"


def _variants(distro: str) -> dict:
    _, sources = load(CONFIG, set(REGISTRY))
    return {v.key: v for v in next(s for s in sources if s.name == distro).variants}


def test_openbsd_config_expands_install_and_cd_over_two_arches():
    v = _variants("openbsd")
    assert set(v) == {"openbsd:install", "openbsd:install:aarch64", "openbsd:cd", "openbsd:cd:aarch64"}
    # aarch64 substitutes the path segment; x86_64 stays implicit in the key.
    assert "/amd64/" in v["openbsd:install"].params["index"]
    assert "/arm64/" in v["openbsd:install:aarch64"].params["index"]
    assert "version_pattern" not in v["openbsd:install"].params  # version comes from the dir


def test_netbsd_config_expands_one_install_over_amd64_and_evbarm_aarch64():
    v = _variants("netbsd")
    assert set(v) == {"netbsd:install", "netbsd:install:aarch64"}
    assert "-amd64\\.iso$" in v["netbsd:install"].params["match"]
    assert "-evbarm-aarch64\\.iso$" in v["netbsd:install:aarch64"].params["match"]


def test_parrot_config_is_clearsigned_with_six_editions():
    v = _variants("parrot")
    assert set(v) == {
        f"parrot:{e}"
        for e in ("home", "security", "spin-htb", "spin-mate", "spin-lxqt", "spin-enlightenment")
    }
    assert v["parrot:home"].params["signing_key"]["covers"] == "clearsigned"


# ------------------------------------------------------------------------ resolve mechanics

OB = "https://ob.example/pub/OpenBSD/"
OB_PARAMS = {"version_dir": OB, "version_dir_match": r"^\d+\.\d+$", "sums": "SHA256"}


def _openbsd_client() -> FakeClient:
    arch = OB + "7.9/amd64/"
    return FakeClient(
        {
            OB: autoindex_html(["7.8/", "7.9/", "packages/"]),  # packages/ excluded by the pattern
            arch: autoindex_html(["install79.iso", "cd79.iso", "install79.img", "SHA256"]),
            arch + "SHA256": f"SHA256 (install79.iso) = {'a' * 64}\nSHA256 (cd79.iso) = {'b' * 64}\n",
        }
    )


def test_openbsd_resolves_version_from_dir_and_bsd_checksum():
    params = {**OB_PARAMS, "index": "7.9/amd64/", "match": r"^install\d+\.iso$", "arch": "x86_64"}
    r = DI().resolve("openbsd", "install", params, _openbsd_client())
    assert r.filename == "install79.iso"
    assert r.version == "7.9"  # from the directory name, not the filename
    assert (r.checksum, r.checksum_algo) == ("a" * 64, "sha256")  # BSD-format SHA256


NB = "https://nb.example/pub/NetBSD/"
NB_PARAMS = {
    "version_dir": NB,
    "version_dir_match": r"^NetBSD-[0-9.]+$",
    "sums": "SHA512",
    "version_pattern": r"NetBSD-([0-9.]+)-",
}


def _netbsd_client() -> FakeClient:
    images = NB + "NetBSD-10.1/images/"
    sha = (
        f"SHA512 (NetBSD-10.1-amd64.iso) = {'a' * 128}\n"
        f"SHA512 (NetBSD-10.1-evbarm-aarch64.iso) = {'b' * 128}\n"
        f"SHA512 (NetBSD-10.1-evbarm-aarch64eb.iso) = {'c' * 128}\n"
    )
    return FakeClient(
        {
            NB: autoindex_html(["NetBSD-9.4/", "NetBSD-10.0/", "NetBSD-10.1/"]),
            images: autoindex_html(
                ["NetBSD-10.1-amd64.iso", "NetBSD-10.1-evbarm-aarch64.iso",
                 "NetBSD-10.1-evbarm-aarch64eb.iso", "SHA512"]
            ),
            images + "SHA512": sha,
        }
    )


def test_netbsd_sorts_prefixed_dirs_and_aarch64_excludes_the_eb_decoy():
    # aarch64 token is the literal `evbarm-aarch64`; the anchored match must NOT catch `aarch64eb`.
    params = {**NB_PARAMS, "index": "NetBSD-10.1/images/",
              "match": r"^NetBSD-[0-9.]+-evbarm-aarch64\.iso$", "arch": "aarch64"}
    r = DI().resolve("netbsd", "install", params, _netbsd_client())
    assert r.filename == "NetBSD-10.1-evbarm-aarch64.iso"  # not ...-aarch64eb.iso
    assert r.version == "10.1"  # newest prefixed dir sorted numerically
    assert (r.checksum, r.checksum_algo) == ("b" * 128, "sha512")


PA = "https://parrot.example/iso/"
# A clearsigned-shaped multi-algo hashes file (the wrapper lines are ignored by the parser).
PARROT_HASHES = (
    "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
    "Parrot OS 7.3\n\nmd5\n"
    f"{'a' * 32}  Parrot-home-7.3_amd64.iso\n\nsha256\n"
    f"{'b' * 64}  Parrot-home-7.3_amd64.iso\n\nsha512\n"
    f"{'c' * 128}  Parrot-home-7.3_amd64.iso\n"
    "-----BEGIN PGP SIGNATURE-----\n\niQIz...\n-----END PGP SIGNATURE-----\n"
)


def test_parrot_publishes_the_strongest_hash_from_the_multi_algo_file():
    params = {
        "version_dir": PA, "version_dir_match": r"^[0-9.]+$", "index": "{version}/",
        "sums": "signed-hashes.txt", "version_pattern": r"-([0-9.]+)_amd64",
        "match": r"^Parrot-home-[0-9.]+_amd64\.iso$",
    }
    client = FakeClient(
        {
            PA: autoindex_html(["7.2/", "7.3/"]),
            PA + "7.3/": autoindex_html(["Parrot-home-7.3_amd64.iso", "signed-hashes.txt"]),
            PA + "7.3/signed-hashes.txt": PARROT_HASHES,
        }
    )
    r = DI().resolve("parrot", "home", params, client)
    assert r.filename == "Parrot-home-7.3_amd64.iso" and r.version == "7.3"
    assert (r.checksum, r.checksum_algo) == ("c" * 128, "sha512")  # md5/sha256 present but sha512 wins


# ------------------------------------------------- GhostBSD / XCP-ng / Qubes / Gentoo / ChimeraOS
#
# Resolve tests drive the SHIPPED config's own expanded params against fixture bytes at the real
# URLs, so a regression in the block itself (not just a hand-built dict) fails here.


def test_ghostbsd_config_and_resolve_bare_iso_bsd_sidecar_no_signature():
    v = _variants("ghostbsd")
    assert set(v) == {"ghostbsd:mate", "ghostbsd:xfce", "ghostbsd:gershwin"}
    idx = "https://download.ghostbsd.org/releases/amd64/latest/"
    iso = "GhostBSD-26.1-R15.0p2.iso"
    client = FakeClient(
        {
            idx: autoindex_html([iso, "GhostBSD-26.1-R15.0p2-XFCE.iso", iso + ".sha256", iso + ".torrent"]),
            idx + iso + ".sha256": f"SHA256 ({iso}) = {'f' * 64}",
        }
    )
    r = DI().resolve("ghostbsd", "mate", dict(v["ghostbsd:mate"].params), client)
    assert r.filename == iso  # the bare (MATE) ISO, not -XFCE
    assert r.version == "26.1-R15.0p2"
    assert (r.checksum, r.checksum_algo) == ("f" * 64, "sha256")  # BSD-format sidecar
    assert r.verify == "checksum"  # no GPG signature published


def test_xcp_ng_resolves_the_dot2_refresh_not_the_older_decoy():
    """The review bug: with a single-group version_pattern the clean `…20250606` parses as a higher
    Version tier than `…20250606.2` and the STALE ISO wins. The shipped two-group pattern picks .2."""
    v = _variants("xcp-ng")
    assert set(v) == {"xcp-ng:install", "xcp-ng:netinstall"}
    base = "https://mirrors.xcp-ng.org/isos/"
    d = base + "8.3/"
    client = FakeClient(
        {
            base: autoindex_html(["8.2/", "8.3/", "drivers/"]),
            d: autoindex_html(
                ["xcp-ng-8.3.0-20250606.2.iso", "xcp-ng-8.3.0-20250606.iso",
                 "xcp-ng-8.3.0-20250606-netinstall.iso", "SHA256SUMS", "SHA256SUMS.asc"]
            ),
            d + "SHA256SUMS": f"{'a' * 64}  xcp-ng-8.3.0-20250606.2.iso\n{'b' * 64}  xcp-ng-8.3.0-20250606.iso\n",
        }
    )
    r = DI().resolve("xcp-ng", "install", dict(v["xcp-ng:install"].params), client)
    assert r.filename == "xcp-ng-8.3.0-20250606.2.iso"  # the refresh, NOT the older decoy
    assert r.version == "8.3.0-20250606.2"
    assert (r.checksum, r.checksum_algo) == ("a" * 64, "sha256")
    assert r.signature_url.endswith("SHA256SUMS.asc") and r.verify == "gpg"


def test_qubes_resolves_stable_over_rc_and_keeps_sha512_from_digests():
    v = _variants("qubes")
    assert set(v) == {"qubes:iso"}
    idx = "https://ftp.qubes-os.org/iso/"
    digests = f"{'a' * 64} *Qubes-R4.3.1-x86_64.iso\n{'b' * 128} *Qubes-R4.3.1-x86_64.iso\n"
    client = FakeClient(
        {
            idx: autoindex_html(
                ["Qubes-R4.3.1-x86_64.iso", "Qubes-R4.3.1-rc1-x86_64.iso",
                 "Qubes-R4.3.1-x86_64.iso.DIGESTS", "Qubes-R4.3.1-x86_64.iso.DIGESTS.asc"]
            ),
            idx + "Qubes-R4.3.1-x86_64.iso.DIGESTS": digests,
        }
    )
    r = DI().resolve("qubes", "iso", dict(v["qubes:iso"].params), client)
    assert r.filename == "Qubes-R4.3.1-x86_64.iso"  # not the co-located -rc1
    assert r.version == "4.3.1"
    assert (r.checksum, r.checksum_algo) == ("b" * 128, "sha512")  # sha512 beats the co-listed sha256; `*` marker parsed
    assert r.signature_url.endswith(".DIGESTS.asc") and r.verify == "gpg"


def test_gentoo_config_expands_two_arches_plus_livegui_and_resolves_datestamp():
    v = _variants("gentoo")
    assert set(v) == {"gentoo:minimal", "gentoo:minimal:aarch64", "gentoo:livegui"}
    assert "/amd64/" in v["gentoo:minimal"].params["index"]
    assert "/arm64/" in v["gentoo:minimal:aarch64"].params["index"]      # {token} -> arm64 in the path
    assert "current-livegui-amd64" in v["gentoo:livegui"].params["index"]  # override, no leftover {token}
    assert "{token}" not in v["gentoo:livegui"].params["index"]

    idx = "https://distfiles.gentoo.org/releases/amd64/autobuilds/current-install-amd64-minimal/"
    iso = "install-amd64-minimal-20260712T170110Z.iso"
    clearsigned = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n# SHA256 HASH\n"
        f"{'d' * 64}  {iso}\n-----BEGIN PGP SIGNATURE-----\niQIz\n-----END PGP SIGNATURE-----\n"
    )
    client = FakeClient(
        {
            idx: autoindex_html([iso, iso + ".sha256", iso + ".DIGESTS", iso + ".asc"]),
            idx + iso + ".sha256": clearsigned,
        }
    )
    r = DI().resolve("gentoo", "minimal", dict(v["gentoo:minimal"].params), client)
    assert r.filename == iso
    assert r.version == "20260712T170110Z"  # the datestamp is the change-token
    assert (r.checksum, r.checksum_algo) == ("d" * 64, "sha256")  # clearsigned .sha256, NOT the ambiguous .DIGESTS
    assert r.signature_url.endswith(".sha256") and r.verify == "gpg"


def test_chimeraos_config_uses_github_releases_with_the_new_knobs():
    _, sources = load(CONFIG, set(REGISTRY))
    c = next(s for s in sources if s.name == "chimeraos")
    p = c.variants[0].params
    assert c.variants[0].strategy == "github_releases"
    assert p["repo"] == "ChimeraOS/install-media"
    assert p["honor_prerelease_flag"] is True and p["sums_asset"] == "sha256sum.txt"
