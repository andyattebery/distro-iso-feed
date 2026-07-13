"""Turn resolved facts into a `Release` -- the tail every strategy's `resolve()` shares.

`build_release` fills the three fields that came out the same way in all seven builders (`arch`
from params with the default fallback, the `title`, and `page_url`) and passes everything
strategy-specific through as `**fields`. A wrong field name fails loudly at `Release(...)` rather
than silently, so the factory is safe to fan out across strategies.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..arch import DEFAULT_ARCH
from ..models import Release
from ..select import choose


def choose_artifact(names: Iterable[str], params: dict) -> str | None:
    """The `choose` call every listing strategy makes, reading the same four selection params.

    The version/torrent/path handling that follows genuinely differs per strategy (SourceForge
    selects on paths, directory_index/github interleave a torrent branch), so only this identical
    front half is shared -- one home for the four-param `choose` contract.
    """
    return choose(
        names,
        match=params["match"],
        ignore=params.get("ignore", ()),
        version_pattern=params.get("version_pattern"),
        sort_pattern=params.get("sort_pattern"),
    )


def title_for(distro: str, variant: str, version: str, arch: str, label: str | None) -> str:
    """Human text comes from `label`; the variant key is a permanent identifier."""
    name = label or f"{distro.replace('-', ' ').title()} {variant.replace('-', ' ').title()}"
    return f"{name} {version} ({arch})"


def build_release(
    distro: str,
    variant: str,
    version: str,
    *,
    filename: str,
    download_url: str | None,
    params: dict,
    **fields,
) -> Release:
    """Build a `Release`, deriving `arch`/`title`/`page_url` from `params` once.

    `**fields` are the strategy-specific columns (`size`, `published`, `checksum`,
    `checksum_algo`, `signature_url`, and the `torrent_*` set) passed straight into `Release`.
    """
    arch = params.get("arch", DEFAULT_ARCH)
    return Release(
        distro=distro,
        variant=variant,
        version=version,
        title=title_for(distro, variant, version, arch, params.get("label")),
        download_url=download_url,
        filename=filename,
        arch=arch,
        page_url=params.get("page_url"),
        **fields,
    )
