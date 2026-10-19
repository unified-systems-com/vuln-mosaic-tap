"""Operator settings: one file on the operator's filesystem, validated at load (req-vuln-mosaic-settings).

Deliberately free of any grid or Django import (req-vuln-mosaic-settings-3).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

import jsonschema

from tap_plugin.vuln_mosaic.home import resolve_home

SOURCES = ("cvelist", "kev", "epss", "nvd", "osv", "ghsa")
DEFAULT_MAX_AGE_DAYS = 3
_DEFAULT_ENABLED = {"cvelist": True, "kev": True, "epss": True, "nvd": False, "osv": False, "ghsa": False}


class SettingsError(ValueError):
    """The settings file is unreadable or violates its schema; the run must not start."""


@dataclass(frozen=True)
class SourceSettings:
    enabled: bool
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    mode: str = "wanted"
    ecosystems: tuple[str, ...] = ()


@dataclass(frozen=True)
class Settings:
    sources: Mapping[str, SourceSettings]
    immediate_fetch: bool = False
    mirror: Mapping[str, Path] = field(default_factory=lambda: MappingProxyType({}))


def load_schema(name: str) -> dict[str, Any]:
    text = resources.files("tap_plugin.vuln_mosaic").joinpath("schemas", name).read_text()
    return json.loads(text)


def _defaults() -> dict[str, SourceSettings]:
    return {name: SourceSettings(enabled=_DEFAULT_ENABLED[name]) for name in SOURCES}


def parse_settings(data: Mapping[str, Any]) -> Settings:
    try:
        jsonschema.validate(dict(data), load_schema("settings.schema.json"))
    except jsonschema.ValidationError as exc:
        where = ".".join(str(p) for p in exc.absolute_path) or "(top level)"
        raise SettingsError(f"settings invalid at {where}: {exc.message}") from None
    sources = _defaults()
    for name, given in (data.get("sources") or {}).items():
        base = sources[name]
        sources[name] = SourceSettings(
            enabled=given.get("enabled", base.enabled),
            max_age_days=given.get("max_age_days", base.max_age_days),
            mode=given.get("mode", base.mode),
            ecosystems=tuple(given.get("ecosystems", base.ecosystems)),
        )
    mirror = {name: Path(path) for name, path in (data.get("mirror") or {}).items()}
    return Settings(
        sources=MappingProxyType(sources),
        immediate_fetch=bool(data.get("immediate_fetch", False)),
        mirror=MappingProxyType(mirror),
    )


def load_settings(home: str | Path | None = None) -> Settings:
    """Load ``<home>/settings.json``; absent means the documented defaults."""
    path = resolve_home(home) / "settings.json"
    if path.is_symlink():
        raise SettingsError("settings.json is a symlink")
    try:
        text = path.read_text()
    except FileNotFoundError:
        return parse_settings({})
    except OSError as exc:
        raise SettingsError(f"settings.json unreadable: {exc}") from None
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SettingsError(f"settings.json is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise SettingsError("settings.json must be a JSON object")
    return parse_settings(data)
