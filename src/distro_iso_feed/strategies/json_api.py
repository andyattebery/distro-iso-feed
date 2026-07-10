"""JSON metadata documents. Checksums are inline, so no second fetch is needed.

Fedora's `releases.json` lists v42, v43 and v44 side by side for every subvariant.
Returning the first matching row would pin the feed to whatever order upstream
happens to serialize -- so filter by `select`, then take the max version.
"""

from __future__ import annotations

from ..client import Client
from ..listers import Candidate, json_doc
from ..models import Release
from ..select import version_key
from ..tokens import from_filename, from_json_field
from .base import Strategy, title_for


class JsonApi(Strategy):
    name = "json_api"

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        return json_doc(client, params["url"])

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        rows = json_doc(client, params["url"])
        if not rows:
            return None

        select = params.get("select") or {}
        matches = []
        exact = {k: v for k, v in select.items() if k != "link_contains"}
        for cand in rows:
            row = cand.row or {}
            if any(str(row.get(k, "")) != str(v) for k, v in exact.items()):
                continue
            if (needle := select.get("link_contains")) and needle not in (cand.url or ""):
                continue
            if (arch := params.get("arch")) and row.get("arch") and row["arch"] != arch:
                continue
            matches.append(cand)

        if not matches:
            return None

        # Max version, never the first row.
        best = max(matches, key=lambda c: version_key(str((c.row or {}).get("version", ""))))
        row = best.row or {}

        if pattern := params.get("version_pattern"):
            version = from_filename(best.name, pattern)
        else:
            version = from_json_field(row, params.get("version_fields", ["version"]))
        if not version:
            return None

        arch = params.get("arch", "x86_64")
        return Release(
            distro=distro,
            variant=variant,
            version=version,
            title=title_for(distro, variant, version, arch, params.get("label")),
            download_url=best.url or "",
            filename=best.name,
            arch=arch,
            size=best.size,
            checksum=best.checksum,
            checksum_algo="sha256" if best.checksum else None,
            page_url=params.get("page_url"),
        )
