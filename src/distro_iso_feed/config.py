"""Load and validate `config/sources.yaml`.

The config is the primary human interface, so `run_discover` writes back to it and
must not destroy comments -- hence ruamel round-trip mode rather than PyYAML.

Validation is load-time and loud. A typo must not silently drop a distro from the
feed; a missing entry is indistinguishable from an upstream outage otherwise.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .arch import DEFAULT_ARCH
from .models import Source, Variant

DEFAULT_UA = "distro-iso-feed/1.0 (+https://github.com/andyattebery/distro-iso-feed)"

_DISCOVER_KEYS = {
    "group",
    "group_field",
    "index",
    "extra_index",
    "match",
    "ignore",
    "arch_ignore",
    "enumerable",
    "reason",
}
_DISCOVER_REGEX_KEYS = ("group", "match")


class ConfigError(ValueError):
    pass


def _validate_discover(distro: str, discover: Any) -> None:
    """A distro either says how to enumerate itself, or says why it cannot.

    Twenty-one of twenty-seven distros once had no `discover:` block at all, so
    nothing ever enumerated them and their completeness rested on a hand audit.
    Silence was indistinguishable from "nothing to find". It is now a load error,
    which is the only version of this rule that cannot be forgotten.

    `enumerable: false` demands a `reason` because the reason is the whole product:
    it is the difference between a fact someone checked and a label someone reached
    for. Pop!_OS wore `enumerable: false` while its release sat pinned at 24.04.
    """
    if discover is None:
        raise ConfigError(
            f"{distro}: no `discover:` block. Give it `group:`, or `enumerable: false` "
            f"with a `reason:` saying what you checked."
        )
    if not isinstance(discover, dict):
        raise ConfigError(f"{distro}: `discover:` must be a mapping")

    if unknown := set(discover) - _DISCOVER_KEYS:
        raise ConfigError(
            f"{distro}: unknown discover key(s) {', '.join(sorted(unknown))}; "
            f"known: {', '.join(sorted(_DISCOVER_KEYS))}"
        )

    # `arch_ignore` is the arch analog of `ignore`, but exact arch names -- a token
    # (`i686`, `x86_64_v2`) or a canonical (`ppc64le`) -- not filename regexes, because the
    # arch space is a small closed set. It makes declining a proposed arch STICKY: without it,
    # every arch left out of a variant's `arches` map is re-proposed on every discovery run.
    # Validated even under `enumerable: false`, since arch discovery runs off the `arches` map
    # independently of variant enumeration (Ubuntu discovers arches while `enumerable: false`).
    arch_ignore = discover.get("arch_ignore")
    if arch_ignore is not None and (
        not isinstance(arch_ignore, list) or not all(str(a).strip() for a in arch_ignore)
    ):
        raise ConfigError(f"{distro}: discover.arch_ignore must be a list of non-empty arch names")

    if discover.get("enumerable") is False:
        if not str(discover.get("reason") or "").strip():
            raise ConfigError(f"{distro}: `enumerable: false` needs a non-empty `reason:`")
        # Both would be true of no source: a listing you can read and cannot read.
        if extra := {"group", "index"} & set(discover):
            raise ConfigError(
                f"{distro}: `enumerable: false` contradicts {', '.join(sorted(extra))}"
            )
        return

    if not str(discover.get("group") or "").strip():
        raise ConfigError(f"{distro}: `discover:` needs `group:`, or `enumerable: false`")

    # A broken regex here would otherwise surface only in the weekly discovery run,
    # as a distro that silently proposes nothing.
    for key in _DISCOVER_REGEX_KEYS:
        if pattern := discover.get(key):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{distro}: discover.{key} is not a valid regex: {exc}") from exc
    for pattern in discover.get("ignore") or []:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"{distro}: discover.ignore {pattern!r}: {exc}") from exc


def yaml_rt() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def load_raw(path: Path) -> Any:
    return yaml_rt().load(path.read_text(encoding="utf-8"))


def _merge(*layers: dict | None) -> dict:
    out: dict = {}
    for layer in layers:
        if layer:
            out.update(layer)
    return out


_FPR_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def _validate_signing_key(distro: str, sk: Any) -> None:
    """A `signing_key` pins the GPG key the build verifies against. A malformed pin
    is worse than none -- it makes a consumer reject a valid key -- so it is a load
    error, not a runtime surprise.
    """
    if sk is None:
        return
    if not isinstance(sk, dict):
        raise ConfigError(f"{distro}: `signing_key` must be a mapping")
    if unknown := set(sk) - {"url", "fingerprint", "covers"}:
        raise ConfigError(f"{distro}: unknown signing_key key(s) {', '.join(sorted(unknown))}")
    if not str(sk.get("url") or "").strip():
        raise ConfigError(f"{distro}: signing_key needs a `url`")
    if not _FPR_RE.match(str(sk.get("fingerprint") or "")):
        raise ConfigError(f"{distro}: signing_key `fingerprint` must be 40 hex chars")
    if sk.get("covers") not in ("checksums", "image", "clearsigned"):
        raise ConfigError(
            f"{distro}: signing_key `covers` must be `checksums`, `image`, or `clearsigned`"
        )


def _validate_torrent_only(distro: str, variant: str, params: dict) -> None:
    """A torrent-only variant selects the `.torrent`, because no ISO exists to select.

    Its `match` runs against the listing, where the artifact is `x.iso.torrent`. Point
    it at `x.iso` and resolution fetches an ISO and tries to bencode it -- gigabytes
    down the wire to learn what a regex could have said at load time.
    """
    if not params.get("torrent_only"):
        return
    match = str(params.get("match") or "")
    if not match.endswith(r"\.torrent$"):
        raise ConfigError(
            f"{distro}:{variant}: `torrent_only` needs a `match` ending in "
            rf"`\.torrent$`; got {match!r}"
        )


def substitute(node: dict, tokens: list[tuple[str, str]]) -> dict:
    """Rewrite every string leaf of `node`, applying each `(old, new)` replacement in order.

    Recursive rather than a fixed field list so it reaches wherever an author put a token -- a
    path segment (`index`), a filename regex (`match`), a checksum-file name (`sums`), a label.
    Deep-copies, so the source is untouched. This is the one substitution primitive: config-load
    arch expansion, arch discovery, variant discovery (token-diff synthesis), and family discovery
    (clone-a-model) all go through it, so they substitute identically.
    """

    def walk(value):
        if isinstance(value, str):
            for old, new in tokens:
                value = value.replace(old, new)
            return value
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return walk(copy.deepcopy(node))


def substitute_token(params: dict, token: str) -> dict:
    """The single-token `{token}` -> upstream-token specialization used by config-load expansion
    and arch discovery (`{token}` appears only where the author wrote it)."""
    return substitute(params, [("{token}", token)])


def _validate_arches(distro: str, variant: str, arches: Any) -> None:
    """`arches` is a `{canonical: value}` map -- e.g. `{x86_64: amd64, aarch64: arm64}`.

    The canonical name is the identity/display (x86_64 stays implicit in the key). The value is
    either a **token** string substituted into `{token}` across the params, or an **override dict**
    `{token: <tok>, <param>: <override>, ...}` for an arch that lives on a different host/tree
    (Ubuntu's cdimage, Tumbleweed's `/ports/`, FreeBSD's spellings) -- the token defaults to the
    canonical name and the rest are params merged in for that arch.
    """
    if not isinstance(arches, dict) or not arches:
        raise ConfigError(f"{distro}:{variant}: `arches` must be a non-empty map")
    for canonical, value in arches.items():
        if not str(canonical).strip():
            raise ConfigError(f"{distro}:{variant}: `arches` has an empty arch name")
        if isinstance(value, dict):
            if not str(value.get("token", canonical)).strip():
                raise ConfigError(f"{distro}:{variant}:{canonical}: override `token` is empty")
        elif not str(value).strip():
            raise ConfigError(f"{distro}:{variant}:{canonical}: `arches` token is empty")


_FAMILY_KEYS = {"root", "member_match", "model", "ignore"}


def _validate_families(families: Any, distro_names: set[str]) -> None:
    """A `families:` entry lets discovery propose a whole new distro block for a new member of a
    listable root, cloned from a `model` sibling. Validated loudly at load time (a typo must not
    silently disable family discovery), but NOT returned -- only `run_discover` consumes it, off the
    raw doc, so `load()`'s signature is unchanged and refresh/audit are untouched.
    """
    if families is None:
        return
    if not isinstance(families, dict):
        raise ConfigError("`families:` must be a mapping")
    for name, fam in families.items():
        if not isinstance(fam, dict):
            raise ConfigError(f"family {name}: must be a mapping")
        if unknown := set(fam) - _FAMILY_KEYS:
            raise ConfigError(
                f"family {name}: unknown key(s) {', '.join(sorted(unknown))}; "
                f"known: {', '.join(sorted(_FAMILY_KEYS))}"
            )
        if not str(fam.get("root") or "").strip():
            raise ConfigError(f"family {name}: needs a `root:` URL")
        pattern = str(fam.get("member_match") or "")
        if not pattern.strip():
            raise ConfigError(f"family {name}: needs a `member_match:` regex")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"family {name}: member_match is not a valid regex: {exc}") from exc
        if fam.get("model") not in distro_names:
            raise ConfigError(
                f"family {name}: `model` {fam.get('model')!r} is not a configured distro"
            )
        if not isinstance(fam.get("ignore") or [], list):
            raise ConfigError(f"family {name}: `ignore` must be a list")


def load(path: Path, known_strategies: set[str]) -> tuple[dict, list[Source]]:
    raw = load_raw(path)
    if not raw or "distros" not in raw:
        raise ConfigError(f"{path}: no `distros:` block")

    defaults = dict(raw.get("defaults") or {})
    defaults.setdefault("user_agent", DEFAULT_UA)
    defaults.setdefault("arch", DEFAULT_ARCH)
    default_params = dict(defaults.get("params") or {})

    sources: list[Source] = []
    for distro, block in (raw["distros"] or {}).items():
        if not isinstance(block, dict):
            raise ConfigError(f"{distro}: block must be a mapping")

        _validate_discover(distro, block.get("discover"))
        _validate_signing_key(distro, (block.get("params") or {}).get("signing_key"))

        distro_strategy = block.get("strategy")
        distro_params = dict(block.get("params") or {})
        variants_raw = block.get("variants") or {}
        if not variants_raw:
            raise ConfigError(f"{distro}: no variants")

        variants: list[Variant] = []
        for name, vraw in variants_raw.items():
            vraw = dict(vraw or {})
            # §6, as amended: exactly one strategy resolvable *per variant*.
            # openSUSE is the reason -- Leap lists a directory, Tumbleweed is a
            # fixed URL, and nobody thinks openSUSE is two projects.
            strategy = vraw.pop("strategy", None) or distro_strategy
            if not strategy:
                raise ConfigError(
                    f"{distro}:{name}: no strategy (set one on the distro or the variant)"
                )
            if strategy not in known_strategies:
                raise ConfigError(
                    f"{distro}:{name}: unknown strategy {strategy!r}; "
                    f"known: {', '.join(sorted(known_strategies))}"
                )

            label = vraw.pop("label", None)
            mirror = bool(vraw.pop("mirror", block.get("mirror", False)))
            arches = vraw.pop("arches", None)
            params = _merge(default_params, distro_params, vraw.pop("params", None), vraw)
            _validate_torrent_only(distro, name, params)

            if arches is not None:
                # One Variant per architecture. The map is {canonical: upstream-token}: the
                # canonical name (x86_64/aarch64/...) drives the key/display, the token
                # (amd64/arm64/...) is substituted into the URL/filename fields. x86_64 keeps
                # the bare key (see models.arch_tag), so adding arches never moves an existing id.
                _validate_arches(distro, name, arches)
                for canonical, value in arches.items():
                    if isinstance(value, dict):
                        token = str(value.get("token", canonical))
                        overrides = {k: v for k, v in value.items() if k != "token"}
                        per = substitute_token({**params, **overrides}, token)
                    else:
                        per = substitute_token(params, str(value))
                    per["arch"] = canonical
                    variants.append(
                        Variant(distro, name, strategy, per, label, mirror, arch=canonical)
                    )
            else:
                params.setdefault("arch", defaults["arch"])
                variants.append(
                    Variant(distro, name, strategy, params, label, mirror, arch=params["arch"])
                )

        sources.append(
            Source(
                name=distro,
                variants=tuple(variants),
                page_url=block.get("page_url"),
                discover=dict(block.get("discover") or {}),
            )
        )

    _validate_families(raw.get("families"), {s.name for s in sources})
    return defaults, sources
