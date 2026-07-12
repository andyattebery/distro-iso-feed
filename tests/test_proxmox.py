"""Proxmox: PVE + PBS from one flat /iso/ dir, over http, image-mode gpg.

The traps this locks: many co-listed versions (newest must win, the legacy hex-suffixed
VE names must not), four products sharing one directory (each variant isolates its own;
Mail Gateway and Datacenter Manager are ignored), a token that keeps the `-N` build
suffix so a respin re-notifies, and a co-located trust-on-first-use torrent whose
`info.name` carries the version.

The signing-key gate itself (image-mode issuer check against the pinned Trixie key, on a
signature that also carries the unpinned Bookworm key) is exercised generically in
test_signing_key.py; here `verify` is `gpg` straight from resolve because the signature is
present -- the build-time gate runs post-resolve.
"""

from __future__ import annotations

from conftest import FakeClient, autoindex_html
from distro_iso_feed.models import VERIFY_GPG
from distro_iso_feed.strategies import REGISTRY
from distro_iso_feed.strategies._common import attach_torrent
from test_torrents import benc

INDEX = "http://download.proxmox.com/iso/"

# The dir as upstream serves it: every product, every past version, including the legacy
# hex-suffixed VE names that predate the clean `X.Y-N` scheme.
NAMES = [
    "proxmox-ve_9.2-1.iso",
    "proxmox-ve_9.1-1.iso",
    "proxmox-ve_8.4-1.iso",
    "proxmox-ve_4.4-eb2d6f1e-2.iso",  # InvalidVersion -> must never win
    "proxmox-backup-server_4.2-1.iso",
    "proxmox-backup-server_3.4-1.iso",
    "proxmox-mail-gateway_9.1-1.iso",
    "proxmox-mailgateway_7.3-1.iso",  # old no-hyphen spelling
    "proxmox-datacenter-manager_1.1-1.iso",
]

VE_SHA = "4e" + "0" * 62
PBS_SHA = "11" + "0" * 62


def _sums_line(name: str) -> str:
    h = VE_SHA if name == "proxmox-ve_9.2-1.iso" else PBS_SHA if name == "proxmox-backup-server_4.2-1.iso" else "a" * 64
    return f"{h}  {name}"


# One aggregate SHA256SUMS covering every product+version -- looked up by filename.
SHA256SUMS = "\n".join(_sums_line(n) for n in NAMES) + "\n"

PARAMS = {
    "index": INDEX,
    "sums": "SHA256SUMS",
    "sig": "{filename}.asc",
    "version_pattern": r"_([0-9.]+-[0-9]+)\.iso$",
}
VE_MATCH = r"^proxmox-ve_[0-9.]+-[0-9]+\.iso$"
PBS_MATCH = r"^proxmox-backup-server_[0-9.]+-[0-9]+\.iso$"


def _client() -> FakeClient:
    return FakeClient({INDEX: autoindex_html(NAMES), INDEX + "SHA256SUMS": SHA256SUMS})


def _resolve(variant: str, match: str):
    return REGISTRY["directory_index"]().resolve(
        "proxmox", variant, {**PARAMS, "match": match}, _client()
    )


def test_ve_picks_newest_isolates_product_and_keeps_build_suffix():
    r = _resolve("ve", VE_MATCH)
    assert r.filename == "proxmox-ve_9.2-1.iso"
    assert r.version == "9.2-1"  # the -1 build stays in the token -> a respin gets a new guid
    assert (r.checksum, r.checksum_algo) == (VE_SHA, "sha256")  # from the aggregate, by name
    assert r.download_url == INDEX + "proxmox-ve_9.2-1.iso"  # http, first-party apex
    assert r.signature_url == INDEX + "proxmox-ve_9.2-1.iso.asc"
    assert r.verify == VERIFY_GPG  # signature present -> gpg (the pin gate runs post-resolve)


def test_pbs_isolates_its_own_product():
    r = _resolve("backup-server", PBS_MATCH)
    assert r.filename == "proxmox-backup-server_4.2-1.iso"
    assert r.version == "4.2-1"
    assert (r.checksum, r.checksum_algo) == (PBS_SHA, "sha256")


def test_legacy_hex_name_never_wins():
    """`proxmox-ve_4.4-eb2d6f1e-2.iso` is InvalidVersion; present in the dir, it must
    still lose to 9.2-1 rather than break max-version selection."""
    assert _resolve("ve", VE_MATCH).filename == "proxmox-ve_9.2-1.iso"


def test_colocated_torrent_attaches_trust_on_first_use():
    iso = "proxmox-ve_9.2-1.iso"
    tor = benc({"info": {"name": iso, "length": 9, "piece length": 1, "pieces": b"\0" * 20}})
    r = attach_torrent(
        FakeClient({INDEX + iso + ".torrent": tor}), _resolve("ve", VE_MATCH), {"torrent": "{filename}.torrent"}
    )
    assert r.torrent_url == INDEX + iso + ".torrent"
    assert r.torrent_checksum is None  # Proxmox publishes no torrent checksum -> TOFU
    assert r.info_hash and r.magnet_uri.startswith(f"magnet:?xt=urn:btih:{r.info_hash}")
    assert r.download_url == INDEX + iso  # the direct channel is intact
    assert r.verify == VERIFY_GPG  # an unsigned torrent never lowers the ISO's strength


def test_discover_yields_the_two_products_and_ignores_pmg_pdm():
    discover = {
        "match": r"\.iso$",
        "group": r"^proxmox-([a-z-]+)_",
        "ignore": ["mail-?gateway", "datacenter-manager"],
    }
    found = REGISTRY["directory_index"]().discover_all("proxmox", [PARAMS], discover, _client())
    assert {v.variant for v in found} == {"ve", "backup-server"}
