"""Autoindex-backed sources: the largest family.

Four capabilities §7 never mentions, all forced by real upstreams:

* a **version-dir listing** (FreeBSD, Leap, Tails, Batocera, Ubuntu, Mint)
* an **announced release** instead (`version_page`, Parrot): the release the project's own
  download page links, because the newest version dir can be a staged, unannounced one
* a **templated `sums`** -- FreeBSD's is ``CHECKSUM.SHA256-FreeBSD-{version}-RELEASE-amd64``
* **torrent-only artifacts** -- Kali's `live` images are in its signed `SHA256SUMS`
  but 404 as direct downloads; the index offers only the `.torrent`
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..client import Client
from ..listers import Candidate, autoindex, page_index, version_dir
from ..models import Release
from ..select import by_channel, matching, version_key
from ..tokens import from_filename
from .base import Strategy
from .build import build_release, choose_artifact
from .integrity import fetch_integrity
from .torrent import resolve_torrent_only


class DirectoryIndex(Strategy):
    name = "directory_index"

    def _index_url(self, params: dict, client: Client) -> tuple[str, str]:
        """Resolve ``(index_url, version)``, probing version dirs when configured."""
        if page := params.get("version_page"):
            return self._announced_index(page, params, client)
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

    def _announced_index(self, page: str, params: dict, client: Client) -> tuple[str, str]:
        """The directory of the newest release a product page links: the release the project has
        *announced*, which the newest version dir need not be. Parrot staged 7.4 in `iso/7.4/` with
        an unsigned, md5-only hashes file while its download page still offered 7.3, and a
        `version_dir` listing published the staged release.

        Reuses `listers.page_index`. The page may link one edition only (Parrot links just its
        Security ISO), which is enough: that ISO's directory holds every edition, and each variant
        then selects its own there exactly as from a plain `index`. The link's *own* directory is
        used, so the dir name never has to equal the filename's version token. Unlike
        `version_dir` there is no fall-back to an older, unlinked dir -- a release the page doesn't
        offer is not announced.
        """
        pattern = params["version_pattern"]
        dirs: dict[str, str] = {}  # the dir of each linked release -> its version token
        for link in page_index(client, page):
            if link.url and (token := from_filename(link.name, pattern)):
                dirs.setdefault(link.url.rsplit("/", 1)[0] + "/", token)
        match = params.get("match")
        for url, _ in sorted(dirs.items(), key=lambda d: version_key(d[1]), reverse=True):
            names = [c.name for c in autoindex(client, url)]
            if names and (not match or matching(names, match)):
                return url, url.rstrip("/").rsplit("/", 1)[-1]
        return "", ""

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        index, _ = self._index_url(params, client)
        return autoindex(client, index) if index else []

    def arch_tokens(self, params: dict, client: Client) -> list[str]:
        """Enumerate a variant's arch tokens for discovery. Two shapes:

        * `{token}` in `index` (a **path segment**, Debian `current/{token}/iso-cd/`, RHEL
          `{version}/isos/{token}/`): resolve `{version}` first if a `version_dir` is set, then list
          the dir that holds the arch subdirs. Non-arch dirs (`source/`) survive here but fail the
          resolve in arch-verify.
        * `{token}` in `match` only (a **filename token**, Void/Leap/Kali in one flat dir): resolve
          the index and capture the arch from each filename. The match-aware `_index_url` needs a
          real regex, so `{token}` becomes a capture group before resolving, not left literal.
        """
        index = params.get("index", "")
        if "{token}" in index:
            resolved = index
            parent = params.get("version_dir")
            if parent and "{version}" in index:
                vmatch = params.get("version_dir_match", r"^\d+(\.\d+)*$")
                versions = version_dir(client, parent, vmatch)
                if not versions:
                    return []
                newest = max(versions, key=version_key)
                resolved = urljoin(parent, index.replace("{version}", newest))
            return version_dir(client, resolved.split("{token}", 1)[0], r"^[a-z0-9_]+$")

        match = params.get("match", "")
        if "{token}" in match:
            capture = match.replace("{token}", "([a-z0-9_]+)")
            idx, _ = self._index_url({**params, "match": capture}, client)
            if not idx:
                return []
            rx = re.compile(capture)
            ignore = [re.compile(p) for p in params.get("ignore", ())]
            toks = {
                m.group(1)
                for c in autoindex(client, idx)
                if not any(r.search(c.name) for r in ignore) and (m := rx.search(c.name))
            }
            return sorted(toks)

        return []

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        index, version_dirname = self._index_url(params, client)
        if not index:
            return None

        names = [c.name for c in autoindex(client, index)]
        filename = choose_artifact(names, params)
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

        return build_release(
            distro,
            variant,
            version,
            filename=filename,
            download_url=urljoin(index, filename),
            params=params,
            checksum=checksum,
            checksum_algo=algo,
            signature_url=signature_url,
        )
