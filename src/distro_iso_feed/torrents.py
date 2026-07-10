"""Bencode, far enough to read a `.torrent`.

A torrent names its own payload, and that is the whole reason this module exists.
For a torrent-only variant `info.name` **is** the artifact filename -- deriving it
by stripping `.torrent` off a URL is a guess, and it breaks the moment a project
names its torrent differently from what it serves. Fedora already does.

`info_hash` slices the **original bytes** of the `info` value. Re-encoding a parsed
dict would sort its keys, and a torrent whose keys were not already sorted would
then hash to something no tracker has ever heard of. The infohash is a hash of the
bytes upstream published, not of our idea of them.

Nothing here downloads or seeds anything. It reads a small metadata file.
"""

from __future__ import annotations

import hashlib
from urllib.parse import quote


class BencodeError(ValueError):
    """The bytes are not a bencoded value. An HTML error page served 200 lands here."""


def _decode(data: bytes, i: int) -> tuple[object, int]:
    char = data[i : i + 1]

    if char == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1 : end]), end + 1

    if char == b"l":
        i += 1
        items: list[object] = []
        while data[i : i + 1] != b"e":
            value, i = _decode(data, i)
            items.append(value)
        return items, i + 1

    if char == b"d":
        i += 1
        out: dict[bytes, object] = {}
        while data[i : i + 1] != b"e":
            key, i = _decode(data, i)
            value, i = _decode(data, i)
            if not isinstance(key, bytes):
                raise BencodeError("dict key is not a byte string")
            out[key] = value
        return out, i + 1

    if char.isdigit():
        colon = data.index(b":", i)
        length = int(data[i:colon])
        start = colon + 1
        if start + length > len(data):
            raise BencodeError("string runs past end of data")
        return data[start : start + length], start + length

    raise BencodeError(f"unexpected byte {char!r} at offset {i}")


def parse(data: bytes) -> dict:
    """Decode a bencoded dict. Raises `BencodeError` on anything else."""
    if not data or data[0:1] != b"d":
        raise BencodeError("not a bencoded dict")
    try:
        value, _ = _decode(data, 0)
    except BencodeError:
        raise
    except (ValueError, IndexError) as exc:
        raise BencodeError(str(exc)) from exc
    if not isinstance(value, dict):
        raise BencodeError("top level is not a dict")
    return value


def _info_span(data: bytes) -> tuple[int, int]:
    """Byte range of the `info` value, exactly as published."""
    if not data or data[0:1] != b"d":
        raise BencodeError("not a bencoded dict")
    i = 1
    while data[i : i + 1] != b"e":
        key, i = _decode(data, i)
        start = i
        _, i = _decode(data, i)
        if key == b"info":
            return start, i
    raise BencodeError("no `info` dict")


def info_hash(data: bytes) -> str:
    """SHA-1 of the raw `info` bytes. Never of a re-encoded dict."""
    start, end = _info_span(data)
    return hashlib.sha1(data[start:end]).hexdigest()  # noqa: S324 - the BitTorrent spec


def _info(data: bytes) -> dict:
    info = parse(data).get(b"info")
    if not isinstance(info, dict):
        raise BencodeError("no `info` dict")
    return info


def payload_name(data: bytes) -> str:
    """`info.name` -- the file this torrent serves."""
    name = _info(data).get(b"name")
    if not isinstance(name, bytes) or not name:
        raise BencodeError("no `info.name`")
    return name.decode("utf-8", errors="replace")


def total_length(data: bytes) -> int | None:
    """Size of the payload: `info.length`, or the sum of `info.files`."""
    info = _info(data)
    if isinstance(length := info.get(b"length"), int):
        return length
    files = info.get(b"files")
    if isinstance(files, list):
        sizes = [f.get(b"length") for f in files if isinstance(f, dict)]
        if sizes and all(isinstance(s, int) for s in sizes):
            return sum(sizes)  # type: ignore[arg-type]
    return None


def _trackers(doc: dict) -> list[str]:
    """`announce` first, then `announce-list`, in published order, deduplicated.

    Order is preserved rather than sorted: the magnet must be byte-stable across
    runs or the feed gains a diff every day.
    """
    out: list[str] = []

    def offer(value: object) -> None:
        if isinstance(value, bytes):
            url = value.decode("utf-8", errors="replace")
            if url and url not in out:
                out.append(url)

    offer(doc.get(b"announce"))
    tiers = doc.get(b"announce-list")
    if isinstance(tiers, list):
        for tier in tiers:
            if isinstance(tier, list):
                for url in tier:
                    offer(url)
            else:
                offer(tier)
    return out


def magnet(data: bytes) -> str:
    """`magnet:?xt=urn:btih:<infohash>&dn=<name>&tr=<tracker>...`

    Derived from the torrent we already fetched, so it costs nothing and cannot
    disagree with the infohash beside it. No page is scraped for this.
    """
    doc = parse(data)
    parts = [f"magnet:?xt=urn:btih:{info_hash(data)}", f"dn={quote(payload_name(data))}"]
    parts += [f"tr={quote(t, safe='')}" for t in _trackers(doc)]
    return "&".join(parts)
