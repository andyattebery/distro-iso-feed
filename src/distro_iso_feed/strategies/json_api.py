"""JSON metadata documents. Checksums are inline, so no second fetch is needed.

Fedora's `releases.json` lists v42, v43 and v44 side by side for every subvariant.
Returning the first matching row would pin the feed to whatever order upstream
happens to serialize -- so filter by `select`, then take the max version.

Pop!_OS needs the opposite thing. Its API exposes exactly one endpoint,
`builds/{version}/{channel}`, with no index, so the *release* is discovered by
probing rather than by reading. Without that, `url` carries a literal release and
the feed serves it forever: a pinned source resolves cleanly, publishes a valid
checksum, and is wrong.
"""

from __future__ import annotations

from ..client import Client
from ..listers import Candidate, candidate_probe, json_doc, json_has
from ..models import Release
from ..releases import candidates_for
from ..select import version_key
from ..tokens import from_filename, from_json_field
from .base import Strategy
from .build import build_release


class JsonApi(Strategy):
    name = "json_api"

    def _url(self, params: dict, client: Client) -> str | None:
        """Resolve `url`, probing for the release when `probe_versions` is set."""
        url = params["url"]
        probe = params.get("probe_versions")
        if not probe:
            return url

        # A 200 is not a build document -- validate the body. See listers.json_has.
        found = candidate_probe(
            client,
            candidates_for(probe),
            probe["template"],
            validate=json_has(probe.get("requires", "url")),
        )
        return url.format(version=found) if found else None

    def claims(self, candidate: Candidate, params: dict) -> bool:
        """Does this variant cover this row?

        `json_api` variants have no `match` regex -- they have `select`. Anything
        that assumes a regex concludes that no Fedora variant selects anything, and
        `resolve()` and `propose.py` would then disagree about what is already
        tracked. Both go through here.
        """
        select = params.get("select") or {}
        row = candidate.row or {}
        exact = {k: v for k, v in select.items() if k != "link_contains"}
        if any(str(row.get(k, "")) != str(v) for k, v in exact.items()):
            return False
        if (needle := select.get("link_contains")) and needle not in (candidate.url or ""):
            return False
        arch = params.get("arch")
        return not (arch and row.get("arch") and row["arch"] != arch)

    def arch_tokens(self, params: dict, client: Client) -> list[str]:
        """Fedora: the arch is a JSON `arch` field. Return the distinct arches over the rows this
        variant selects with the arch filter dropped (`claims` with `arch=None`), so a variant only
        offers arches it actually publishes -- Fedora's sparse matrix (s390x Server but no s390x
        Workstation) falls out per-variant."""
        url = self._url(params, client)
        if not url:
            return []
        no_arch = {**params, "arch": None}
        arches = {
            str((c.row or {}).get("arch"))
            for c in json_doc(client, url)
            if (c.row or {}).get("arch") and self.claims(c, no_arch)
        }
        return sorted(arches)

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        url = self._url(params, client)
        return json_doc(client, url) if url else []

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        url = self._url(params, client)
        if not url:
            return None
        rows = json_doc(client, url)
        if not rows:
            return None

        matches = [c for c in rows if self.claims(c, params)]
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

        return build_release(
            distro,
            variant,
            version,
            filename=best.name,
            download_url=best.url or "",
            params=params,
            size=best.size,
            checksum=best.checksum,
            checksum_algo="sha256" if best.checksum else None,
        )
