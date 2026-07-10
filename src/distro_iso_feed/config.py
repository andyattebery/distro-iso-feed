"""Load and validate `config/sources.yaml`.

The config is the primary human interface, so `run_discover` writes back to it and
must not destroy comments -- hence ruamel round-trip mode rather than PyYAML.

Validation is load-time and loud. A typo must not silently drop a distro from the
feed; a missing entry is indistinguishable from an upstream outage otherwise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .models import Source, Variant

DEFAULT_UA = "distro-iso-feed/1.0 (+https://github.com/andyattebery/distro-iso-feed)"


class ConfigError(ValueError):
    pass


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


def load(path: Path, known_strategies: set[str]) -> tuple[dict, list[Source]]:
    raw = load_raw(path)
    if not raw or "distros" not in raw:
        raise ConfigError(f"{path}: no `distros:` block")

    defaults = dict(raw.get("defaults") or {})
    defaults.setdefault("user_agent", DEFAULT_UA)
    defaults.setdefault("arch", "x86_64")
    default_params = dict(defaults.get("params") or {})

    sources: list[Source] = []
    for distro, block in (raw["distros"] or {}).items():
        if not isinstance(block, dict):
            raise ConfigError(f"{distro}: block must be a mapping")

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
            params = _merge(default_params, distro_params, vraw.pop("params", None), vraw)
            params.setdefault("arch", defaults["arch"])
            variants.append(
                Variant(
                    distro=distro,
                    name=name,
                    strategy=strategy,
                    params=params,
                    label=label,
                    mirror=mirror,
                )
            )

        sources.append(
            Source(
                name=distro,
                variants=tuple(variants),
                page_url=block.get("page_url"),
                discover=dict(block.get("discover") or {}),
            )
        )

    return defaults, sources
