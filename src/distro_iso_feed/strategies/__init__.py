"""Strategy registry. `strategy:` in sources.yaml names one of these keys."""

from __future__ import annotations

from .base import Strategy
from .directory_index import DirectoryIndex
from .github_releases import GithubReleases
from .json_api import JsonApi
from .page_index import PageIndex
from .sourceforge import SourceForge
from .stable_symlink import StableSymlink

REGISTRY: dict[str, type[Strategy]] = {
    cls.name: cls
    for cls in (DirectoryIndex, StableSymlink, JsonApi, SourceForge, GithubReleases, PageIndex)
}

__all__ = ["REGISTRY", "Strategy"]
