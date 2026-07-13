"""GitHub *assets*. MiniOS and AnduinOS.

The three ublue projects were once filed here; they belong to `stable_symlink`,
because GitHub supplies only their version string. Reserving this name for
"the artifact is a release asset" is what makes that distinction visible.

AnduinOS publishes 22 assets and every one is a `.torrent` -- no ISO exists. It is
why `torrent_only` reaches this strategy at all. elementary stays excluded because
its releases carry no assets whatsoever.
"""

from __future__ import annotations

import os

from ..client import Client
from ..listers import Candidate, gh_assets
from ..models import Release
from ..tokens import from_filename
from .base import Strategy
from .build import build_release, choose_artifact
from .integrity import fetch_integrity
from .torrent import resolve_torrent_only


class GithubReleases(Strategy):
    name = "github_releases"

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        return gh_assets(client, params["repo"], os.environ.get("GITHUB_TOKEN"))

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        assets = gh_assets(client, params["repo"], os.environ.get("GITHUB_TOKEN"))
        if not assets:
            return None

        by_name = {a.name: a for a in assets}
        filename = choose_artifact(by_name.keys(), params)
        if not filename:
            return None

        best = by_name[filename]

        # AnduinOS: the asset IS the torrent, and the torrent names the ISO.
        if params.get("torrent_only"):
            if not best.url:
                return None
            return resolve_torrent_only(
                client, distro=distro, variant=variant, params=params, torrent_url=best.url
            )

        version = from_filename(filename, params["version_pattern"])
        if not version:
            return None

        # The checksum sidecar is a sibling ASSET (its own URL), not a `urljoin`-relative
        # path, so `fetch_integrity` fetches+parses it via the absolute `sums_url` override.
        checksum = algo = None
        if suffix := params.get("sums_suffix"):
            sidecar = by_name.get(filename + suffix)
            if sidecar and sidecar.url:
                checksum, algo, _ = fetch_integrity(
                    client, base="", filename=filename, version=version, sums_url=sidecar.url
                )

        return build_release(
            distro,
            variant,
            version,
            filename=filename,
            download_url=best.url or "",
            params=params,
            size=best.size,
            checksum=checksum,
            checksum_algo=algo,
        )
