"""Core data model.

`Release` extends the spec's §5 shape: `arch`, `size`, `page_url` and a derived
`content_type` are all required by real upstreams (Kali co-lists arm64; Fedora and
Pop!_OS hand over sizes; Batocera ships a gzipped disk image, not an ISO).

**Two checksums, for two different files.** `checksum` always describes `filename`
-- the ISO. `torrent_checksum` always describes `torrent_url` -- the `.torrent`.
Kali's `SHA256SUMS` lists both, so conflating them publishes the torrent's hash
under the ISO's name: well-formed, plausible, and wrong.

`download_url` is optional because some sources publish no HTTP artifact at all.
AnduinOS ships 22 assets and every one is a `.torrent`; three of Kali's images are
listed in `SHA256SUMS` but 404 as direct downloads.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

# Extension -> enclosure MIME type. Batocera is the reason this is not a constant.
CONTENT_TYPES: dict[str, str] = {
    ".iso": "application/x-iso9660-image",
    ".img": "application/octet-stream",
    ".img.gz": "application/gzip",
    ".img.xz": "application/x-xz",
    ".raw.xz": "application/x-xz",
    ".iso.bz2": "application/x-bzip2",  # OPNsense ships bzip2-compressed images
    ".img.bz2": "application/x-bzip2",
    ".iso.zip": "application/zip",  # Memtest86+ wraps its ISO in a zip
}

TORRENT_TYPE = "application/x-bittorrent"

VERIFY_CHECKSUM = "checksum"
VERIFY_GPG = "gpg"
# The infohash covers every piece, but nothing signs the torrent: trust on first
# use. Weaker than a signed checksum, stronger than nothing, and a lie to call either.
VERIFY_TORRENT = "torrent"
VERIFY_NONE = "none"


def content_type_for(filename: str) -> str:
    """Longest matching extension wins, so `.img.gz` beats `.gz`."""
    lowered = filename.lower()
    best = ""
    for ext in CONTENT_TYPES:
        if lowered.endswith(ext) and len(ext) > len(best):
            best = ext
    return CONTENT_TYPES.get(best, "application/octet-stream")


@dataclass(frozen=True, slots=True)
class Release:
    distro: str
    variant: str
    version: str
    title: str
    filename: str
    download_url: str | None = None
    arch: str = "x86_64"
    published: datetime | None = None
    size: int | None = None
    checksum: str | None = None
    checksum_algo: str | None = None
    signature_url: str | None = None
    signing_key_url: str | None = None
    signing_key_fingerprint: str | None = None
    signature_target: str | None = None  # what signature_url signs: "checksums" | "image"
    torrent_url: str | None = None
    torrent_size: int | None = None
    torrent_checksum: str | None = None
    torrent_checksum_algo: str | None = None
    info_hash: str | None = None
    magnet_uri: str | None = None
    page_url: str | None = None
    notes: str | None = None

    def guid(self) -> str:
        """Identifies an *artifact*. Moves whenever the bytes move."""
        return f"{self.distro}:{self.variant}:{self.version}"

    @property
    def state_key(self) -> str:
        """Identifies a *variant*. The `state.json` key; one current record each."""
        return f"{self.distro}:{self.variant}"

    @property
    def primary_url(self) -> str:
        """What the feed links. A torrent-only release has no HTTP artifact."""
        return self.download_url or self.torrent_url or self.page_url or ""

    @property
    def verify(self) -> str:
        if self.signature_url:
            return VERIFY_GPG
        if self.checksum:
            return VERIFY_CHECKSUM
        if self.info_hash:
            return VERIFY_TORRENT
        return VERIFY_NONE

    @property
    def content_type(self) -> str:
        return content_type_for(self.filename)

    def to_json(self) -> dict:
        data = asdict(self)
        data["published"] = self.published.isoformat() if self.published else None
        return data

    @classmethod
    def from_json(cls, data: dict) -> Release:
        data = dict(data)
        published = data.get("published")
        data["published"] = datetime.fromisoformat(published) if published else None
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass(frozen=True, slots=True)
class VariantSpec:
    """A variant proposed by `discover_all`, not yet in the config."""

    distro: str
    variant: str
    params: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Variant:
    distro: str
    name: str
    strategy: str
    params: dict
    label: str | None = None
    mirror: bool = False

    @property
    def key(self) -> str:
        return f"{self.distro}:{self.name}"


@dataclass(frozen=True, slots=True)
class Source:
    """One distro block, already merged and validated."""

    name: str
    variants: tuple[Variant, ...]
    page_url: str | None = None
    discover: dict = field(default_factory=dict)
