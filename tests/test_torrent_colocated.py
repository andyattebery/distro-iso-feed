"""Co-located torrents: an entry that carries a direct download AND a torrent.

Debian, Ubuntu, Arch and openSUSE publish `{filename}.torrent` beside the ISO. The
consumer picks a channel by field presence; the entry never loses its direct
download to a bad torrent. The interesting cases are all the ways a torrent is
*not* attached -- and the migration that adds these fields without re-notifying.
"""

from __future__ import annotations

import hashlib

from conftest import FakeClient
from distro_iso_feed import feed
from distro_iso_feed.models import VERIFY_GPG, Release
from distro_iso_feed.state import State
from distro_iso_feed.strategies.torrent import attach_torrent
from test_torrents import benc

# --- a debian-shaped source: ISO in iso-cd/, torrent + signed sums in bt-cd/ -------

ISO_DIR = "https://cdimage.example/debian-cd/current/amd64/iso-cd/"
BT_DIR = "https://cdimage.example/debian-cd/current/amd64/bt-cd/"
ISO = "debian-13.5.0-amd64-netinst.iso"
TORRENT = f"{ISO}.torrent"

TORRENT_BYTES = benc(
    {
        "announce": "http://bt.example/a",
        "info": {"name": ISO, "length": 700, "piece length": 1, "pieces": b"\0" * 20},
    }
)
TORRENT_SHA = hashlib.sha512(TORRENT_BYTES).hexdigest()


def _release(**kw) -> Release:
    base = dict(
        distro="debian",
        variant="netinst",
        version="13.5.0",
        title="Debian netinst 13.5.0 (x86_64)",
        filename=ISO,
        download_url=ISO_DIR + ISO,
        checksum="a" * 128,
        checksum_algo="sha512",
        signature_url=ISO_DIR + "SHA512SUMS.sign",
    )
    return Release(**{**base, **kw})


def _client(**over) -> FakeClient:
    pages = {
        BT_DIR + TORRENT: TORRENT_BYTES,
        BT_DIR + "SHA512SUMS": f"{TORRENT_SHA}  {TORRENT}\n",
    }
    pages.update(over)
    return FakeClient(pages)


DEBIAN_PARAMS = {"torrent": "../bt-cd/{filename}.torrent", "torrent_sums": "../bt-cd/SHA512SUMS"}
PLAIN_PARAMS = {"torrent": "{filename}.torrent"}  # ubuntu/arch/opensuse: no torrent sums


# --------------------------------------------------------------------- attach_torrent


def test_a_signed_torrent_is_attached_and_verified():
    r = attach_torrent(_client(), _release(), DEBIAN_PARAMS)
    assert r.download_url == ISO_DIR + ISO  # direct channel intact
    assert r.checksum == "a" * 128  # ISO checksum intact
    assert r.torrent_url == BT_DIR + TORRENT
    assert (r.torrent_checksum, r.torrent_checksum_algo) == (TORRENT_SHA, "sha512")
    assert len(r.info_hash) == 40
    assert r.magnet_uri.startswith(f"magnet:?xt=urn:btih:{r.info_hash}")
    assert r.verify == VERIFY_GPG  # the torrent never lowers the ISO's strength


def test_an_unsigned_torrent_is_attached_without_a_torrent_checksum():
    """Ubuntu/Arch/openSUSE publish no checksum for the torrent. It is still offered
    as a channel; the direct download's own signature carries the entry."""
    iso_url = "https://releases.example/26.04/ubuntu-26.04-desktop-amd64.iso"
    name = "ubuntu-26.04-desktop-amd64.iso"
    data = benc({"info": {"name": name, "length": 9, "piece length": 1, "pieces": b"\0" * 20}})
    rel = _release(
        distro="ubuntu", variant="desktop-lts", version="26.04", filename=name, download_url=iso_url
    )
    client = FakeClient({"https://releases.example/26.04/" + name + ".torrent": data})

    r = attach_torrent(client, rel, PLAIN_PARAMS)
    assert r.torrent_url.endswith(".torrent")
    assert r.torrent_checksum is None
    assert r.info_hash and r.magnet_uri
    assert r.verify == VERIFY_GPG


def test_a_missing_torrent_leaves_the_entry_a_pure_direct_download():
    r = attach_torrent(FakeClient({}), _release(), DEBIAN_PARAMS)  # nothing mapped -> 404
    assert r.torrent_url is None and r.info_hash is None and r.magnet_uri is None
    assert r.download_url == ISO_DIR + ISO  # untouched


def test_a_wrong_release_torrent_is_not_attached():
    """The `version in info.name` gate on its own: a torrent naming a different
    release is a stale mirror artifact, not this entry's torrent.

    Uses an *unsigned* source (no `torrent_sums`) so the version gate is the only
    thing that can reject it -- with sums present, the checksum mismatch would catch
    it too and this would not isolate the gate.
    """
    name = "somedistro-9.0.iso"
    iso = "https://x/9.1/somedistro-9.1.iso"  # entry is 9.1; the torrent names 9.0
    stale = benc({"info": {"name": name, "length": 1, "piece length": 1, "pieces": b"\0" * 20}})
    rel = _release(distro="somedistro", variant="main", version="9.1", filename="somedistro-9.1.iso", download_url=iso)
    client = FakeClient({"https://x/9.1/somedistro-9.1.iso.torrent": stale})

    r = attach_torrent(client, rel, PLAIN_PARAMS)
    assert r.torrent_url is None  # 9.1 not in "somedistro-9.0.iso"
    assert r.download_url == iso


def test_a_tampered_signed_torrent_is_not_attached_but_the_direct_download_survives():
    tampered = TORRENT_BYTES.replace(b"announce", b"annnunce")
    assert hashlib.sha512(tampered).hexdigest() != TORRENT_SHA
    r = attach_torrent(_client(**{BT_DIR + TORRENT: tampered}), _release(), DEBIAN_PARAMS)
    assert r.torrent_url is None  # signed-but-tampered -> omitted
    assert r.download_url == ISO_DIR + ISO and r.verify == VERIFY_GPG


def test_a_torrent_only_release_is_left_alone():
    """No `download_url` to hang a co-located torrent on; resolve_torrent_only owns it."""
    kali = Release(
        distro="kali",
        variant="live",
        version="2026.2",
        title="t",
        filename="x.iso",
        download_url=None,
        torrent_url="https://x/x.iso.torrent",
        info_hash="b" * 40,
    )
    assert attach_torrent(_client(), kali, DEBIAN_PARAMS) is kali


# ------------------------------------------------------------------- the feed shapes


def _colocated_state() -> State:
    r = attach_torrent(_client(), _release(), DEBIAN_PARAMS)
    s = State()
    s.update(r, r.checksum)
    return s


def test_atom_entry_carries_two_enclosures_rss_carries_one(tmp_path):
    feed.render(_colocated_state(), tmp_path)
    atom = (tmp_path / "feed.xml").read_text()
    entry = atom.split("<entry>")[1].split("</entry>")[0]
    assert entry.count('rel="enclosure"') == 2  # ISO + torrent
    assert 'type="application/x-iso9660-image"' in entry
    assert 'type="application/x-bittorrent"' in entry

    rss = (tmp_path / "feed.rss").read_text()
    item = rss.split("<item>")[1].split("</item>")[0]
    assert item.count("<enclosure") == 1  # RSS allows one; the ISO
    assert 'type="application/x-iso9660-image"' in item

    torrent_rss = (tmp_path / "torrent.rss").read_text()
    assert torrent_rss.count("<item>") == 1  # the co-located record appears here too
    assert 'type="application/x-bittorrent"' in torrent_rss


def test_render_is_byte_identical_across_runs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    s = _colocated_state()
    feed.render(s, a)
    feed.render(s, b)
    for name in ("feed.xml", "feed.rss", "torrent.xml", "torrent.rss", "latest.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


# --------------------------------------------------------------------- the magnet-only shape


MAGNET = "magnet:?xt=urn:btih:" + "c" * 40 + "&dn=distro.iso"


def _magnet_only() -> Release:
    return Release(
        distro="somedistro",
        variant="main",
        version="9.0",
        title="SomeDistro 9.0 (x86_64)",
        filename="somedistro-9.0.iso",
        download_url=None,
        torrent_url=None,  # a magnet with no .torrent file -- the wrinkle
        page_url="https://somedistro.example/download",
        magnet_uri=MAGNET,
        info_hash="c" * 40,
    )


def test_magnet_only_renders_consistently_across_every_surface(tmp_path):
    """The scenario the whole model must stay consistent under: magnet_uri set,
    torrent_url None. It must not vanish from any feed on a `not enclosures` check."""
    s = State()
    r = _magnet_only()
    s.update(r, r.info_hash)
    feed.render(s, tmp_path)

    rss = (tmp_path / "feed.rss").read_text()
    assert "<item>" in rss  # NOT dropped
    assert "<enclosure" not in rss  # a magnet cannot be an RSS enclosure
    assert "https://somedistro.example/download" in rss  # link = page_url
    assert "magnet:?xt=urn:btih:" + "c" * 40 in rss  # magnet rides in the description (& is escaped)

    assert "<entry>" in (tmp_path / "feed.xml").read_text()
    assert (tmp_path / "torrent.rss").read_text().count("<item>") == 0  # .torrent files only

    import json

    entry = json.loads((tmp_path / "latest.json").read_text())["releases"]["somedistro:main"]
    assert entry["magnet_uri"] == MAGNET and entry["torrent_url"] is None
    assert r.verify == "torrent"


def test_magnet_only_emits_no_empty_link_or_enclosure(tmp_path):
    s = State()
    r = _magnet_only()
    s.update(r, r.info_hash)
    feed.render(s, tmp_path)
    for name in ("feed.xml", "feed.rss", "torrent.xml", "torrent.rss"):
        body = (tmp_path / name).read_text()
        assert 'href=""' not in body and 'url=""' not in body and "<link></link>" not in body
