"""The operator mirror: an artifact plus a sha256 manifest, verified before use (req-vuln-mosaic-mirror).

Trust boundary: anyone who can write the mirror directory (artifact and manifest together) or
``settings.json`` can substitute a dataset. The digest catches accident and half-substitution only.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tap_plugin.vuln_mosaic.staleness import parse_time, utcnow

MAX_MANIFEST_BYTES = 64 * 1024


class MirrorError(ValueError):
    """The mirror artifact or manifest was refused; the installed dataset keeps serving."""


@dataclass(frozen=True)
class MirrorArtifact:
    path: Path
    built: str
    source: str
    sha256: str


def _no_symlink(path: Path) -> None:
    if path.is_symlink():
        raise MirrorError(f"{path.name} is a symlink")


def load_artifact(
    directory: Path, source: str, installed_built: str | None, now: datetime | None = None
) -> MirrorArtifact:
    manifest_path = directory / "manifest.json"
    _no_symlink(manifest_path)
    try:
        with open(manifest_path, "rb") as handle:
            manifest = json.loads(handle.read(MAX_MANIFEST_BYTES + 1)[:MAX_MANIFEST_BYTES])
    except (OSError, ValueError) as exc:
        raise MirrorError(f"manifest unreadable: {exc}") from None
    if not isinstance(manifest, dict):
        raise MirrorError("manifest is not a JSON object")
    try:
        archive, digest, built, named = manifest["archive"], manifest["sha256"], manifest["built"], manifest["source"]
    except KeyError as exc:
        raise MirrorError(f"manifest lacks {exc.args[0]!r}") from None
    if not all(isinstance(v, str) for v in (archive, digest, built, named)):
        raise MirrorError("manifest fields must be strings")
    if named != source:
        raise MirrorError(f"manifest is for {named!r}, not {source!r}")
    if "/" in archive or archive.startswith("."):
        raise MirrorError("manifest archive must be a plain file name")
    artifact = directory / archive
    _no_symlink(artifact)
    try:
        fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise MirrorError(f"artifact unreadable: {exc}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise MirrorError("artifact is not a regular file")
        sha = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as handle:
            while chunk := handle.read(1 << 20):
                sha.update(chunk)
    finally:
        os.close(fd)
    if sha.hexdigest() != digest.lower():
        raise MirrorError("artifact digest differs from its manifest")
    built_at = parse_time(built)
    if built_at is None or built_at > (now or utcnow()):
        raise MirrorError(f"built {built!r} is in the future or unparseable")
    installed = parse_time(installed_built)
    if installed is not None and built_at < installed:
        raise MirrorError(f"built {built} is older than the installed dataset ({installed_built})")
    return MirrorArtifact(artifact, built, source, digest.lower())
