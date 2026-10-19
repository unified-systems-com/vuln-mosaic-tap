"""TAP Vuln Mosaic plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name) — nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The refresh collector is registered in ``ready()`` once it exists (req-vuln-mosaic-refresh).
"""

from tap_plugins.base import TapPluginConfig


class VulnMosaicConfig(TapPluginConfig):
    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models/edges.
        super().ready()
