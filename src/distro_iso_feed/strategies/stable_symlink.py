"""Fixed, version-less download URL + a pluggable token source.

This strategy absorbs the ublue projects (Bazzite, Bluefin, Aurora). They use
GitHub for *nothing but the version string* -- the URL is fixed on a different
host and integrity is a sidecar beside it. That is this shape, one parameter apart
from KDE neon.

Token sources:
  sidecar_filename -- the sidecar names a dated artifact behind a version-less URL
                      (neon, Tumbleweed, NixOS). The mismatch IS the mechanism.
  atom_tag         -- the sidecar carries no token at all (ublue's `-CHECKSUM`
                      names `bazzite-stable-amd64.iso`), so GitHub supplies it.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..client import Client
from ..listers import Candidate, atom, candidate_probe, fixed
from ..models import Release
from ..releases import candidates_for
from ..select import is_prerelease
from ..tokens import from_atom_tag, from_sidecar_filename
from ._common import _expand, fetch_integrity
from .base import Strategy, title_for


class StableSymlink(Strategy):
    name = "stable_symlink"

    def arch_tokens(self, params: dict, client: Client) -> list[str]:
        """A fixed URL has nothing to list, so offer the plausible arches and let arch-verify keep
        only the ones that actually resolve (NixOS publishes `...-{arch}-linux.iso` + `.sha256`)."""
        return ["x86_64", "aarch64"] if "{token}" in str(params.get("url", "")) else []

    def candidates(self, distro: str, params: dict, client: Client) -> list[Candidate]:
        if repo := (params.get("token") or {}).get("repo"):
            return atom(client, repo)
        return fixed(params["url"]) if params.get("url") else []

    def claims(self, candidate: Candidate, params: dict) -> bool:
        """This strategy has no `match` regex -- it has one fixed URL.

        A discovered candidate is either the artifact itself (Aurora enumerates
        `dl.getaurora.dev/`, whose rows are ISOs) or the directory holding it (neon
        enumerates `images/`, whose rows are editions). Both are named inside the
        variant's own URL, so both are recognizable from it, and the audit can tell
        which editions a `stable_symlink` distro already tracks.
        """
        url, name = params.get("url") or "", candidate.name
        if not url or not name:
            return False
        return url.endswith(f"/{name}") or f"/{name}/" in url

    def _version(self, params: dict, client: Client, sidecar_text: str | None) -> str | None:
        token = params.get("token") or {}
        source = token.get("from", "sidecar_filename")

        if source == "atom_tag":
            # Strip the title's trailing prose BEFORE the prerelease check: the entry
            # reads `stable-20260708: Stable (F44...)`, and elementary's `8.1.0-rc3: RC`
            # must be rejected on the tag, never on GitHub's `prerelease` flag.
            tags = [e.name.split(":", 1)[0].strip() for e in atom(client, token["repo"])]
            tags = [t for t in tags if t and not is_prerelease(t)]
            if not tags:
                return None  # a 200 with zero entries is not a release (Nobara)
            return from_atom_tag(tags[0], token.get("pattern"))

        if sidecar_text:
            return from_sidecar_filename(sidecar_text, token["pattern"])
        return None

    def resolve(self, distro: str, variant: str, params: dict, client: Client) -> Release | None:
        url = params["url"]

        if probe := params.get("probe_versions"):
            found = candidate_probe(client, candidates_for(probe), probe["template"])
            if not found:
                return None
            url = url.format(version=found)

        base = url.rsplit("/", 1)[0] + "/"
        filename = url.rsplit("/", 1)[-1]

        sidecar_text = None
        if sums := params.get("sums"):
            sidecar_text = client.text(urljoin(base, _expand(sums, filename=filename, version="")))

        version = self._version(params, client, sidecar_text)
        if not version:
            return None

        checksum, algo, signature_url = fetch_integrity(
            client,
            base=base,
            filename=filename,
            version=version,
            sums=params.get("sums"),
            sig=params.get("sig"),
            # The sidecar names the dated artifact, not the version-less URL we fetch.
            sole_entry=True,
        )

        arch = params.get("arch", "x86_64")
        return Release(
            distro=distro,
            variant=variant,
            version=version,
            title=title_for(distro, variant, version, arch, params.get("label")),
            download_url=url,
            filename=filename,
            arch=arch,
            checksum=checksum,
            checksum_algo=algo,
            signature_url=signature_url,
            page_url=params.get("page_url"),
        )
