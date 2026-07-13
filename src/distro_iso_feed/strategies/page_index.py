"""ISO links on a product page. Formerly `html_scrape`.

Renamed because it is a *lister* choice, not a parallel universe: once a candidate
list exists, selection, tokens and checksums are identical to every other strategy.
Only the listing step is fragile, and it lives in `listers.page_index`.

Nobara exposes ``data-iso``/``data-url`` attributes -- far stabler anchors than
link markup -- and its checksum sidecar is ``<iso>.sha256sum`` (``.sha256`` 404s),
which only reading its `script.js` revealed.

Manjaro's ``/download/`` is a 95-byte ``<meta refresh>`` stub; the real page is
``/products/download/x86``.
"""

from __future__ import annotations

from ..client import Client
from ..listers import Candidate, page_index
from ..models import Release
from ..tokens import from_filename
from .base import Strategy
from .build import build_release, choose_artifact
from .integrity import fetch_integrity


class PageIndex(Strategy):
    name = "page_index"

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        return page_index(client, params["url"], params.get("attr"))

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        links = page_index(client, params["url"], params.get("attr"))
        if not links:
            return None

        by_name = {c.name: c for c in links}
        filename = choose_artifact(by_name.keys(), params)
        if not filename:
            return None

        best = by_name[filename]
        version = from_filename(filename, params["version_pattern"])
        if not version or not best.url:
            return None

        base = best.url.rsplit("/", 1)[0] + "/"
        checksum, algo, signature_url = fetch_integrity(
            client,
            base=base,
            filename=filename,
            version=version,
            sums=params.get("sums"),
            sig=params.get("sig"),
        )

        return build_release(
            distro,
            variant,
            version,
            filename=filename,
            download_url=best.url,
            params=params,
            checksum=checksum,
            checksum_algo=algo,
            signature_url=signature_url,
        )
