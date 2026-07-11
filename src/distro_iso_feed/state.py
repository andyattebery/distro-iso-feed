"""`state/state.json`: change detection *and* the thing the feed renders from.

Keyed by ``distro:variant`` -- the guid *prefix*, not the guid. Keying by guid
would make a new version write a new key instead of replacing the old one, and the
feed would grow without bound; N=1 exists to avoid exactly that.

A resolver returning None leaves a record untouched, so a transient upstream
failure degrades the feed to *stale*, never to *empty*.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .models import Release


class Record:
    __slots__ = ("version", "hash", "seen", "release")

    def __init__(self, version: str, hash: str, seen: str, release: Release) -> None:
        self.version = version
        self.hash = hash
        self.seen = seen
        self.release = release

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "hash": self.hash,
            "seen": self.seen,
            "release": self.release.to_json(),
        }

    @classmethod
    def from_json(cls, data: dict) -> Record:
        return cls(
            version=data["version"],
            hash=data["hash"],
            seen=data["seen"],
            release=Release.from_json(data["release"]),
        )

    @property
    def seen_dt(self) -> datetime:
        return datetime.fromisoformat(self.seen)


class State:
    def __init__(self, records: dict[str, Record] | None = None) -> None:
        self.records: dict[str, Record] = records or {}

    @classmethod
    def load(cls, path: Path) -> State:
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls({k: Record.from_json(v) for k, v in data.items()})

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: v.to_json() for k, v in self.records.items()}
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
        path.write_text(text + "\n", encoding="utf-8")

    def is_new(self, release: Release, payload_hash: str) -> bool:
        current = self.records.get(release.state_key)
        if current is None:
            return True
        return current.version != release.version or current.hash != payload_hash

    def update(self, release: Release, payload_hash: str, *, now: datetime | None = None) -> bool:
        """Replace the variant's record if it moved. Returns True when it did."""
        if not self.is_new(release, payload_hash):
            return False
        seen = (now or datetime.now(UTC)).isoformat(timespec="seconds")
        self.records[release.state_key] = Record(release.version, payload_hash, seen, release)
        return True

    def enrich(self, release: Release) -> bool:
        """Same artifact, richer metadata. Rewrite in place, preserving `seen`.

        Adding a field to `Release` -- a torrent URL beside an existing ISO -- moves
        neither `version` nor the change-hash, so `update()` sees no change and the
        new data would never land. This writes it while keeping `version`, `hash`,
        and `seen` exactly as they were.

        Preserving `seen` is the whole point: it feeds every feed timestamp, so an
        enriched entry gains its new enclosure without a single `<updated>` moving,
        and no subscriber re-notifies. Returns True only when it actually rewrote.
        """
        current = self.records.get(release.state_key)
        if current is None or current.version != release.version:
            return False  # a genuinely new or moved release is `update()`'s job
        if current.release.to_json() == release.to_json():
            return False  # nothing new to record
        self.records[release.state_key] = Record(
            current.version, current.hash, current.seen, release
        )
        return True

    def entries(self) -> list[Record]:
        """Newest first, ties broken by guid so ordering is total and stable."""
        return sorted(
            self.records.values(),
            key=lambda r: (r.release.published or r.seen_dt, r.release.guid()),
            reverse=True,
        )


def payload_hash(checksum: str | None, fallback: str) -> str:
    """`hash` is the published checksum when there is one, else the payload's sha256.

    §12 asks for a hash but never says of what; this is that definition, and it is
    what catches a respin whose `version` failed to move.
    """
    return checksum or fallback
