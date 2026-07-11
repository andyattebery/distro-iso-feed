"""Variants whose only artifact is a `.torrent`.

Kali lists three images in its signed `SHA256SUMS` whose `.iso` returns 404; every
AnduinOS release asset is a torrent. Both were excluded from this feed until the
resolver learned to read one.

The dangerous bug here is not a crash. `SHA256SUMS` lists a hash for the ISO *and*
for the `.torrent`, both valid sha256s, and looking one up under the other's name
produces a feed entry that parses, validates, and lies. That case leads.
"""

from __future__ import annotations

import hashlib

import pytest

from conftest import FakeClient, autoindex_html
from distro_iso_feed import feed
from distro_iso_feed.config import ConfigError, _validate_torrent_only
from distro_iso_feed.models import VERIFY_GPG, VERIFY_TORRENT
from distro_iso_feed.state import State
from distro_iso_feed.strategies import REGISTRY
from test_torrents import benc

INDEX = "https://cdimage.example/kali-2026.2/"
ISO = "kali-linux-2026.2-live-amd64.iso"
TORRENT = f"{ISO}.torrent"

TORRENT_BYTES = benc(
    {
        "announce": "http://bittorrent.example/announce",
        "info": {"name": ISO, "length": 5531987968, "piece length": 262144, "pieces": b"\x00" * 20},
    }
)
ISO_SHA = "49e90e694d1b3dedd47f94afbe99dfdd5afb41c8462b638bbd332929769c773a"
TORRENT_SHA = hashlib.sha256(TORRENT_BYTES).hexdigest()

# Both files are listed, exactly as Kali lists them.
SUMS = f"{ISO_SHA}  {ISO}\n{TORRENT_SHA}  {TORRENT}\n"

PARAMS = {
    "index": INDEX,
    "match": r"^kali-linux-[0-9.]+-live-amd64\.iso\.torrent$",
    "version_pattern": r"kali-linux-([0-9.]+)-",
    "sums": "SHA256SUMS",
    "sig": "SHA256SUMS.gpg",
    "torrent_only": True,
    "label": "Kali Live",
}


def pages(**over) -> dict:
    base = {
        INDEX: autoindex_html([TORRENT, "SHA256SUMS"]),
        INDEX + "SHA256SUMS": SUMS,
        INDEX + TORRENT: TORRENT_BYTES,
    }
    base.update(over)
    return base


def resolve(client=None):
    client = client or FakeClient(pages())
    return REGISTRY["directory_index"]().resolve("kali", "live", dict(PARAMS), client)


# ------------------------------------------------------------------ the two checksums


def test_checksum_is_the_isos_and_torrent_checksum_is_the_torrents():
    """The single most plausible silent bug: both hashes are valid, and swapping them
    yields a feed entry that parses, validates, and is wrong."""
    r = resolve()
    assert r.checksum == ISO_SHA
    assert r.torrent_checksum == TORRENT_SHA
    assert r.checksum != r.torrent_checksum


def test_the_iso_is_not_the_http_artifact():
    r = resolve()
    assert r.filename == ISO
    assert r.torrent_url == INDEX + TORRENT
    assert r.download_url is None


def test_filename_comes_from_info_name_not_from_the_torrents_own_name():
    """Kali happens to name its torrent `<iso>.torrent`, so stripping the suffix off
    the URL would look right there. Fedora does not: it serves
    `Fedora-Workstation-Live-x86_64-44.torrent` for
    `Fedora-Workstation-Live-44-1.7.x86_64.iso`. Only `info.name` survives that, and
    only a fixture where the two names differ can tell the difference.
    """
    iso = "Fedora-Workstation-Live-44-1.7.x86_64.iso"
    torrent = "Fedora-Workstation-Live-x86_64-44.torrent"  # note: NOT iso + ".torrent"
    data = benc({"info": {"name": iso, "length": 7, "piece length": 1, "pieces": b"\x00" * 20}})
    iso_sha, torrent_sha = "a" * 64, hashlib.sha256(data).hexdigest()

    client = FakeClient(
        {
            INDEX: autoindex_html([torrent]),
            INDEX + "SHA256SUMS": f"{iso_sha}  {iso}\n{torrent_sha}  {torrent}\n",
            INDEX + torrent: data,
        }
    )
    params = {
        **PARAMS,
        "match": r"^Fedora-.*\.torrent$",
        "version_pattern": r"Live-([0-9.]+-[0-9.]+)\.",
        "sig": None,
    }
    r = REGISTRY["directory_index"]().resolve("fedora", "workstation", params, client)

    assert r.filename == iso  # from info.name; `torrent.removesuffix()` would give the wrong name
    assert r.checksum == iso_sha  # and only that name finds the ISO's row
    assert r.torrent_checksum == torrent_sha


def test_version_pattern_runs_on_the_iso_name_so_the_guid_keeps_its_shape():
    assert resolve().guid() == "kali:live:2026.2"


def test_size_is_the_isos_and_torrent_size_is_the_torrent_files():
    r = resolve()
    assert r.size == 5531987968  # from info.length
    assert r.torrent_size == len(TORRENT_BYTES)


def test_a_signed_checksum_still_yields_gpg():
    """Losing the HTTP download costs nothing in integrity: SHA256SUMS is signed."""
    assert resolve().verify == VERIFY_GPG


def test_the_infohash_and_magnet_are_published():
    r = resolve()
    assert len(r.info_hash) == 40
    assert r.magnet_uri.startswith(f"magnet:?xt=urn:btih:{r.info_hash}")


# ------------------------------------------------------------------------ the teeth


def test_a_tampered_torrent_is_never_published():
    """A torrent's piece hashes prove it agrees with itself. Only the signed hash of
    the torrent catches bytes that were swapped in transit."""
    tampered = TORRENT_BYTES.replace(b"announce", b"annnunce")
    assert hashlib.sha256(tampered).hexdigest() != TORRENT_SHA

    assert resolve(FakeClient(pages(**{INDEX + TORRENT: tampered}))) is None


def test_a_torrent_that_is_not_bencode_is_rejected():
    html = b"<html><title>404 Not Found</title></html>"
    sums = f"{ISO_SHA}  {ISO}\n{hashlib.sha256(html).hexdigest()}  {TORRENT}\n"
    client = FakeClient(pages(**{INDEX + TORRENT: html, INDEX + "SHA256SUMS": sums}))
    assert resolve(client) is None


def test_an_unsigned_torrent_still_resolves_as_trust_on_first_use():
    """AnduinOS publishes no checksum at all. The infohash is real integrity, just
    unauthenticated -- `torrent`, not `checksum`, and not `none` either."""
    params = {k: v for k, v in PARAMS.items() if k not in ("sums", "sig")}
    client = FakeClient(pages())
    r = REGISTRY["directory_index"]().resolve("anduinos", "en-us", params, client)
    assert r.verify == VERIFY_TORRENT
    assert r.checksum is None
    assert r.torrent_checksum is None
    assert r.info_hash


# --------------------------------------------------------------------- config guard


def test_torrent_only_demands_a_match_on_the_torrent():
    """Point it at the `.iso` and resolution fetches gigabytes to learn what a regex
    could have said at load time."""
    with pytest.raises(ConfigError, match=r"ending in"):
        _validate_torrent_only("kali", "live", {"torrent_only": True, "match": r"^x\.iso$"})


def test_a_match_on_the_torrent_is_accepted():
    _validate_torrent_only("kali", "live", {"torrent_only": True, "match": r"^x\.iso\.torrent$"})


# --------------------------------------------------------------------------- the feed


def _state() -> State:
    state = State()
    r = resolve()
    state.update(r, r.checksum)
    return state


def test_summary_distinguishes_the_two_hashes_by_prefix():
    """A consumer greps `sha256:` for the ISO and `torrent-sha256:` for the torrent,
    and must never pick up the other."""
    text = feed.summary_for(resolve())
    assert f"\nsha256: {ISO_SHA}" in text
    assert f"\ntorrent-sha256: {TORRENT_SHA}" in text
    assert "Infohash: " in text
    assert "Magnet: magnet:?" in text
    assert feed.WARNING_NO_CHECKSUM not in text


def test_summary_says_an_unsigned_infohash_is_trust_on_first_use():
    params = {k: v for k, v in PARAMS.items() if k not in ("sums", "sig")}
    r = REGISTRY["directory_index"]().resolve("anduinos", "en-us", params, FakeClient(pages()))
    text = feed.summary_for(r)
    assert "Verify: torrent" in text
    assert feed.NOTE_UNSIGNED_TORRENT in text
    assert feed.WARNING_NO_CHECKSUM not in text  # an infohash is not "unverifiable"


def test_a_torrent_only_entry_never_emits_an_empty_link_or_enclosure(tmp_path):
    feed.render(_state(), tmp_path)
    for name in ("feed.xml", "feed.rss", "torrent.xml", "torrent.rss"):
        body = (tmp_path / name).read_text()
        assert 'href=""' not in body
        assert 'url=""' not in body
        assert "<link></link>" not in body


def test_the_enclosure_is_the_torrent_with_the_torrents_own_length(tmp_path):
    """RSS defines `length` as the size of the enclosure object, not of what it
    points at. The ISO is 5.5 GB; the `.torrent` is a few hundred bytes."""
    feed.render(_state(), tmp_path)
    rss = (tmp_path / "torrent.rss").read_text()
    assert 'type="application/x-bittorrent"' in rss
    assert f'length="{len(TORRENT_BYTES)}"' in rss
    assert "5531987968" not in rss.split("<enclosure")[1].split("/>")[0]


def test_the_torrent_feed_holds_exactly_the_records_with_a_torrent(tmp_path):
    feed.render(_state(), tmp_path)
    assert (tmp_path / "torrent.xml").read_text().count("<entry>") == 1
    assert (tmp_path / "torrent.rss").read_text().count("<item>") == 1


def test_torrent_feed_entries_reuse_the_main_feeds_ids(tmp_path):
    """A reader subscribed to both feeds must see one logical entry, not a duplicate."""
    feed.render(_state(), tmp_path)
    main = (tmp_path / "feed.xml").read_text()
    torrent = (tmp_path / "torrent.xml").read_text()
    entry_id = "/id/kali/live/2026.2"
    assert entry_id in main
    assert entry_id in torrent


def test_latest_json_carries_both_hashes_under_distinct_keys(tmp_path):
    import json

    feed.render(_state(), tmp_path)
    data = json.loads((tmp_path / "latest.json").read_text())
    entry = data["releases"]["kali:live"]
    assert data["schema"] == 3
    assert entry["checksum"] == ISO_SHA
    assert entry["torrent_checksum"] == TORRENT_SHA
    assert entry["download_url"] is None
    assert entry["magnet_uri"].startswith("magnet:?")


def test_render_is_byte_identical_across_runs(tmp_path):
    """The magnet's tracker order must be stable, or the feed diffs every day."""
    a, b = tmp_path / "a", tmp_path / "b"
    state = _state()
    feed.render(state, a)
    feed.render(state, b)
    for name in ("feed.xml", "feed.rss", "torrent.xml", "torrent.rss", "latest.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name
