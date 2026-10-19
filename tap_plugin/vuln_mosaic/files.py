"""Whole-file datasets: staged swap under ``files/<source>/`` (req-vuln-mosaic-store-2)."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import BinaryIO

from tap_plugin.vuln_mosaic.staleness import DatasetFacts

KEEP_BUILDS = 2


def source_dir(home: Path, source: str) -> Path:
    # `source` may be "kev", "epss" or "osv/<ecosystem>"; callers validate the ecosystem name.
    base = home / "files"
    path = base.joinpath(*source.split("/"))
    if base.resolve() not in path.resolve().parents:
        raise ValueError(f"source escapes the files directory: {source!r}")
    return path


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True))
    os.replace(tmp, path)


def new_staging(home: Path, source: str, build: str) -> Path:
    """An empty staging directory beside the live copy; the caller fills and validates it."""
    root = source_dir(home, source)
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".staging-{build}-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    return staging


def discard(staging: Path) -> None:
    shutil.rmtree(staging, ignore_errors=True)


def current_build(home: Path, source: str) -> str | None:
    link = source_dir(home, source) / "current"
    if not link.is_symlink():
        return None
    return os.readlink(link)


def publish(home: Path, source: str, build: str, staging: Path, facts: DatasetFacts) -> Path:
    """Move a validated staging directory into ``<build>`` and atomically repoint ``current``."""
    root = source_dir(home, source)
    target = root / build
    if target.exists():
        shutil.rmtree(staging, ignore_errors=True)
        raise FileExistsError(f"build {build!r} already published")
    _atomic_write_json(staging / "index.json", asdict(facts))
    os.rename(staging, target)
    tmp = root / f".current.{os.getpid()}.tmp"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(build, tmp)
    os.replace(tmp, root / "current")
    _atomic_write_json(root / "checked.json", {"build": build, "checked_at": facts.checked_at})
    _prune(root, keep=build)
    return target


def _prune(root: Path, keep: str) -> None:
    builds = sorted(
        (p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".") and not p.is_symlink()),
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    )
    survivors = {p.name for p in builds[:KEEP_BUILDS]} | {keep}
    for build in builds:
        if build.name not in survivors:
            shutil.rmtree(build, ignore_errors=True)


def touch_checked(home: Path, source: str, checked_at: str) -> None:
    """An unchanged source: advance ``checked_at`` only (req-vuln-mosaic-staleness-2)."""
    root = source_dir(home, source)
    build = current_build(home, source)
    if build is None:
        raise FileNotFoundError(f"no current build for {source!r}")
    _atomic_write_json(root / "checked.json", {"build": build, "checked_at": checked_at})


def read_facts(home: Path, source: str) -> DatasetFacts:
    """The facts of the current build, with ``checked_at`` from the overlay; empty when absent."""
    root = source_dir(home, source)
    build = current_build(home, source)
    if build is None:
        return DatasetFacts()
    try:
        facts = json.loads((root / build / "index.json").read_text())
    except (OSError, ValueError):
        return DatasetFacts()
    try:
        overlay = json.loads((root / "checked.json").read_text())
    except (OSError, ValueError):
        overlay = {}
    if overlay.get("build") == build and isinstance(overlay.get("checked_at"), str):
        facts["checked_at"] = overlay["checked_at"]
    return DatasetFacts(**{k: facts.get(k) for k in ("as_of", "checked_at", "source_version", "fetched_at")})


def open_current(home: Path, source: str, artifact: str) -> BinaryIO:
    """Open the current build's artifact and return the descriptor-holding file object.

    The caller reads through the returned file, so a later publication that prunes the build
    cannot take it away mid-read; the path is never resolved a second time.
    """
    root = source_dir(home, source)
    build = current_build(home, source)
    if build is None:
        raise FileNotFoundError(f"no current build for {source!r}")
    return open(root / build / artifact, "rb")
