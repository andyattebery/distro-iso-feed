"""Core data model.

`Release` extends the spec's §5 shape: `arch`, `size`, `page_url` and a derived
`content_type` are all required by real upstreams (Kali co-lists arm64; Fedora and
Pop!_OS hand over sizes; Batocera ships a gzipped disk image, not an ISO).
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
}

VERIFY_CHECKSUM = "checksum"
VERIFY_GPG = "gpg"
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
    download_url: str
    filename: str
    arch: str = "x86_64"
    published: datetime | None = None
    size: int | None = None
    checksum: str | None = None
    checksum_algo: str | None = None
    signature_url: str | None = None
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
    def verify(self) -> str:
        if self.signature_url:
            return VERIFY_GPG
        if self.checksum:
            return VERIFY_CHECKSUM
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
