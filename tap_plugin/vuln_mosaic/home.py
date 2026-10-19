"""Where the stores live (req-vuln-mosaic-settings, req-vuln-mosaic-store)."""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "VULN_MOSAIC_HOME"
# Observed 2026-10-19 in the tap-web image: /var/lib/tap does not exist and its parent is
# root-owned, while HOME (/home/nonroot) is declared by the Dockerfile and writable by the runtime
# user. The default therefore lives under HOME, in the container's own filesystem.
DEFAULT_SUBPATH = ".local/share/tap/vuln-mosaic"


def resolve_home(home: str | os.PathLike[str] | None = None) -> Path:
    if home is not None:
        return Path(home)
    configured = os.environ.get(HOME_ENV)
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_SUBPATH
