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
from ..select import choose
from ..tokens import from_filename
from ._common import resolve_torrent_only
from .base import Strategy, title_for


class GithubReleases(Strategy):
    name = "github_releases"

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        return gh_assets(client, params["repo"], os.environ.get("GITHUB_TOKEN"))

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        assets = gh_assets(client, params["repo"], os.environ.get("GITHUB_TOKEN"))
        if not assets:
            return None

        by_name = {a.name: a for a in assets}
        filename = choose(
            by_name.keys(),
            match=params["match"],
            ignore=params.get("ignore", ()),
            version_pattern=params.get("version_pattern"),
            sort_pattern=params.get("sort_pattern"),
        )
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

        checksum = algo = None
        if suffix := params.get("sums_suffix"):
            sidecar = by_name.get(filename + suffix)
            if sidecar and sidecar.url and (text := client.text(sidecar.url)):
                from .. import checksums

                if found := checksums.lookup(text, filename):
                    algo, checksum = found

        arch = params.get("arch", "x86_64")
        return Release(
            distro=distro,
            variant=variant,
            version=version,
            title=title_for(distro, variant, version, arch, params.get("label")),
            download_url=best.url or "",
            filename=filename,
            arch=arch,
            size=best.size,
            checksum=checksum,
            checksum_algo=algo,
            page_url=params.get("page_url"),
        )
