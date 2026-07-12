"""SourceForge per-project file RSS.

Three hazards, all confirmed live:

* ``<title>`` is a CDATA **full path** (``/Final/Xfce/MX-25.2_Xfce_x64.iso``), and
  the feed interleaves `.iso`, `.zsync`, `.sig` and `README.txt`.
* **Every item appears twice.**
* The directory name can disagree with the filename -- CachyOS lists
  ``/gui-installer/handheld/250626/cachyos-handheld-linux-260426.iso``. The token
  must come from the filename.
"""

from __future__ import annotations

from ..client import Client
from ..listers import Candidate, rss
from ..models import Release
from ..select import choose
from ..tokens import from_filename
from ._common import fetch_integrity
from .base import Strategy, title_for


def _feed_url(params: dict) -> str:
    project, path = params["project"], params.get("path", "/")
    return f"https://sourceforge.net/projects/{project}/rss?path={path}"


def _download_url(project: str, path: str) -> str:
    return f"https://sourceforge.net/projects/{project}/files{path}/download"


def _sidecar_url(project: str, template: str, fmt: dict) -> str:
    """A checksum/signature URL. Usually a SourceForge file derived from the artifact's
    path, but Clonezilla keeps its signed `CHECKSUMS.TXT` off-site, so an absolute URL in
    the config is used verbatim rather than wrapped in the SourceForge download template.
    """
    value = template.format(**fmt)
    return value if value.startswith(("http://", "https://")) else _download_url(project, value)


class SourceForge(Strategy):
    name = "sourceforge"

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        return rss(client, _feed_url(params))

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        items = rss(client, _feed_url(params))
        if not items:
            return None

        by_path = {c.name: c for c in items}  # dedupes the doubled items
        path = choose(
            by_path.keys(),
            match=params["match"],
            ignore=params.get("ignore", ()),
            version_pattern=params.get("version_pattern"),
            sort_pattern=params.get("sort_pattern"),
        )
        if not path:
            return None

        best = by_path[path]
        filename = path.rsplit("/", 1)[-1]
        version = from_filename(filename, params["version_pattern"])
        if not version:
            return None

        project = params["project"]
        # Bluestar drops the `.iso` before `.md5`, so templates get a `{stem}` too.
        stem = path.rsplit(".", 1)[0]
        fmt = {"path": path, "stem": stem, "filename": filename, "version": version}

        sums_url = None
        if sums := params.get("sums"):
            sums_url = _sidecar_url(project, sums, fmt)

        checksum, algo, _ = fetch_integrity(
            client,
            base="",
            filename=filename,
            version=version,
            sums=None,
            sig=None,
            sums_url=sums_url,
        )

        signature_url = None
        if sig := params.get("sig"):
            signature_url = _sidecar_url(project, sig, fmt)

        arch = params.get("arch", "x86_64")
        return Release(
            distro=distro,
            variant=variant,
            version=version,
            title=title_for(distro, variant, version, arch, params.get("label")),
            download_url=best.url or _download_url(project, path),
            filename=filename,
            arch=arch,
            published=best.published,
            checksum=checksum,
            checksum_algo=algo,
            signature_url=signature_url,
            page_url=params.get("page_url"),
        )
