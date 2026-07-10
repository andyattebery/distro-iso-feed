"""Bencode, and the two ways an infohash goes silently wrong.

Both regressions guarded here happened for real while this module was written:

* Slicing to the end of the file assumes `info` is the last key. Arch's torrent puts
  a 25 KB `url-list` after it, and the naive slice hashed all of it.
* Re-encoding a parsed `info` dict sorts its keys. A torrent whose keys were not
  already sorted then hashes to something no tracker has ever seen.

Both produce a well-formed 40-char hex digest, which is why neither is caught by
anything except a test that knows the right answer.
"""

from __future__ import annotations

import hashlib

import pytest

from distro_iso_feed import torrents


def benc(value) -> bytes:
    """Minimal encoder, for building fixtures. Preserves dict order, unlike the spec."""
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, str):
        return benc(value.encode())
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, list):
        return b"l" + b"".join(benc(v) for v in value) + b"e"
    if isinstance(value, dict):
        return b"d" + b"".join(benc(k) + benc(v) for k, v in value.items()) + b"e"
    raise TypeError(value)


# `name` before `length` is NOT bencode-sorted order. A re-encode would reorder it.
INFO = {"name": "a.iso", "length": 3, "piece length": 16384, "pieces": b"\x00" * 20}

# `url-list` sits AFTER `info`, exactly as Arch's torrent does.
TORRENT = benc(
    {
        "announce": "http://tracker.example/announce",
        "announce-list": [["http://tracker.example/announce"], ["udp://backup.example:80"]],
        "info": INFO,
        "url-list": ["https://mirror.example/a.iso"],
    }
)

INFO_RAW = benc(INFO)
EXPECTED = hashlib.sha1(INFO_RAW).hexdigest()  # noqa: S324


# ------------------------------------------------------------------------ info_hash


def test_info_hash_slices_the_published_bytes():
    assert torrents.info_hash(TORRENT) == EXPECTED


def test_info_hash_ignores_keys_that_follow_info():
    """Arch appends a 25 KB `url-list` after `info`. Hashing to end-of-file is wrong."""
    to_end = TORRENT[TORRENT.index(b"4:info") + 6 : -1]
    assert hashlib.sha1(to_end).hexdigest() != EXPECTED  # noqa: S324
    assert torrents.info_hash(TORRENT) == EXPECTED


def test_info_hash_is_not_a_reencode():
    """A re-encode sorts `info`'s keys, and this fixture's are deliberately unsorted."""
    reencoded = benc(dict(sorted(INFO.items())))
    assert reencoded != INFO_RAW
    assert hashlib.sha1(reencoded).hexdigest() != EXPECTED  # noqa: S324
    assert torrents.info_hash(TORRENT) == EXPECTED


# --------------------------------------------------------------------------- reading


def test_payload_name_is_the_file_the_torrent_serves():
    assert torrents.payload_name(TORRENT) == "a.iso"


def test_total_length_single_file():
    assert torrents.total_length(TORRENT) == 3


def test_total_length_sums_a_multi_file_torrent():
    data = benc({"info": {"name": "d", "files": [{"length": 2}, {"length": 5}]}})
    assert torrents.total_length(data) == 7


def test_total_length_is_none_when_unstated():
    assert torrents.total_length(benc({"info": {"name": "d"}})) is None


# ---------------------------------------------------------------------------- magnet


def test_magnet_carries_infohash_name_and_every_tracker_once():
    uri = torrents.magnet(TORRENT)
    assert uri.startswith(f"magnet:?xt=urn:btih:{EXPECTED}")
    assert "dn=a.iso" in uri
    assert uri.count("tr=") == 2  # `announce` deduplicated against `announce-list`
    assert "udp%3A%2F%2Fbackup.example%3A80" in uri


def test_magnet_is_stable_across_calls():
    """A magnet that reorders its trackers puts a diff in the feed every single day."""
    assert torrents.magnet(TORRENT) == torrents.magnet(TORRENT)


# --------------------------------------------------------------------------- rejects


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"<html><title>404 Not Found</title></html>",  # an error page served 200
        b"d",  # truncated
        b"l1:ae",  # a list, not a dict
        b"di1ei2ee",  # dict with a non-string key
    ],
    ids=["empty", "html", "truncated", "list", "int-key"],
)
def test_non_torrents_are_rejected(data):
    with pytest.raises(torrents.BencodeError):
        torrents.info_hash(data)


def test_a_dict_without_info_is_rejected():
    with pytest.raises(torrents.BencodeError):
        torrents.info_hash(benc({"announce": "http://x/"}))


def test_a_string_running_past_the_end_is_rejected():
    with pytest.raises(torrents.BencodeError):
        torrents.parse(b"d4:name99:short")
