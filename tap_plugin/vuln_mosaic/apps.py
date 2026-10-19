"""TAP Vuln Mosaic plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name) — nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The refresh collector is registered in ``ready()`` (req-vuln-mosaic-refresh).
"""

from tap_plugins.base import TapPluginConfig


class VulnMosaicConfig(TapPluginConfig):
    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models/edges.
        super().ready()

        # Imported inside ready(), not at module top, so the app-loading graph stays light.
        from tap_plugin.vuln_mosaic.collectors.refresh.collector import VulnMosaicRefreshCollector

        from tap_cares.registry import register_collector

        register_collector(
            key="refresh",
            # Stable scope (the plugin slug), never inferred from the module path: the derived
            # entity id is a durable grid key and the schedule bundle's hardcoded target
            # (req-vuln-mosaic-refresh-4).
            scope="vuln_mosaic",
            cls=VulnMosaicRefreshCollector,
            name="vuln_mosaic Refresh Collector",
            description=(
                "Keeps local copies of public vulnerability data (CVE records, CISA KEV, EPSS, NVD, "
                "OSV) current in the instance's own stores. Lands no GRIFT batch; the collection job "
                "record carries each source's outcome and staleness."
            ),
        )
