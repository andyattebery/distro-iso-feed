"""Autoindex-backed sources: the largest family.

Three capabilities §7 never mentions, all forced by real upstreams:

* a **version-dir listing** (FreeBSD, Leap, Tails, Batocera, Ubuntu, Mint)
* a **templated `sums`** -- FreeBSD's is ``CHECKSUM.SHA256-FreeBSD-{version}-RELEASE-amd64``
* **torrent-only artifacts** -- Kali's `live` images are in its signed `SHA256SUMS`
  but 404 as direct downloads; the index offers only the `.torrent`
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..client import Client
from ..listers import Candidate, autoindex, version_dir
from ..models import Release
from ..select import by_channel, choose, matching, version_key
from ..tokens import from_filename
from ._common import fetch_integrity, resolve_torrent_only
from .base import Strategy, title_for


class DirectoryIndex(Strategy):
    name = "directory_index"

    def _index_url(self, params: dict, client: Client) -> tuple[str, str]:
        """Resolve ``(index_url, version)``, probing version dirs when configured."""
        parent = params.get("version_dir")
        if not parent:
            return params["index"], params.get("version", "")

        versions = version_dir(client, parent, params.get("version_dir_match", r"^\d+(\.\d+)*$"))
        if channel := params.get("channel"):
            versions = by_channel(versions, channel)
        if not versions:
            return "", ""

        # Highest dir that actually contains a *matching* artifact, not merely the highest
        # number. A dir with content but nothing matching `match` is a release-candidate-only
        # dir -- OPNsense ships `26.7/` holding only `-26.7.r1-` files while 26.7 is in RC;
        # skipping it falls through to the newest stable dir (26.1.6).
        template = params.get("index", "{version}/")
        match = params.get("match")
        for version in sorted(versions, key=version_key, reverse=True):
            url = urljoin(parent, template.format(version=version))
            names = [c.name for c in autoindex(client, url)]
            if not names:
                continue
            if match and not matching(names, match):
                continue
            return url, version
        return "", ""

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        index, _ = self._index_url(params, client)
        return autoindex(client, index) if index else []

    def arch_tokens(self, params: dict, client: Client) -> list[str]:
        """Path-segment arches: `index` templates `{token}` as a directory (Debian
        `current/{token}/iso-cd/`). List the parent of `{token}` and return the subdir names;
        non-arch dirs (`source/`, `trace/`) survive here but fail arch-verify's resolve."""
        index = params.get("index", "")
        if "{token}" not in index:
            return []
        prefix = index.split("{token}", 1)[0]
        return version_dir(client, prefix, r"^[a-z0-9_]+$")

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        index, version_dirname = self._index_url(params, client)
        if not index:
            return None

        names = [c.name for c in autoindex(client, index)]
        filename = choose(
            names,
            match=params["match"],
            ignore=params.get("ignore", ()),
            version_pattern=params.get("version_pattern"),
            sort_pattern=params.get("sort_pattern"),
        )
        if not filename:
            return None

        # `filename` here is a `.torrent`; the ISO it names is not in this index.
        if params.get("torrent_only"):
            return resolve_torrent_only(
                client,
                distro=distro,
                variant=variant,
                params=params,
                torrent_url=urljoin(index, filename),
                base=index,
                version_dirname=version_dirname,
            )

        version = (
            from_filename(filename, params["version_pattern"])
            if params.get("version_pattern")
            else version_dirname
        )
        if not version:
            return None

        # `sums` templating usually wants the version-DIR name (FreeBSD's
        # `CHECKSUM.SHA256-FreeBSD-{version}-RELEASE-amd64`). OPNsense inverts this: the
        # `26.7/` dir holds `OPNsense-26.7.r1-…`, so its checksums file is named from the
        # FILENAME token, not the dir. `sums_from_filename` opts into that.
        sums_version = version if params.get("sums_from_filename") else (version_dirname or version)
        checksum, algo, signature_url = fetch_integrity(
            client,
            base=index,
            filename=filename,
            version=sums_version,
            sums=params.get("sums"),
            sig=params.get("sig"),
        )

        arch = params.get("arch", "x86_64")
        return Release(
            distro=distro,
            variant=variant,
            version=version,
            title=title_for(distro, variant, version, arch, params.get("label")),
            download_url=urljoin(index, filename),
            filename=filename,
            arch=arch,
            checksum=checksum,
            checksum_algo=algo,
            signature_url=signature_url,
            page_url=params.get("page_url"),
        )
