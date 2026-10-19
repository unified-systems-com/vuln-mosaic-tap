"""The CISA KEV catalog as a whole file (req-vuln-mosaic-kev)."""

from __future__ import annotations

import shutil
from pathlib import Path

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.integrity import check_kev
from tap_plugin.vuln_mosaic.mirror import load_artifact
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.staleness import DatasetFacts, is_stale, to_iso

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HOSTS = frozenset({"www.cisa.gov"})
ARTIFACT = "known_exploited_vulnerabilities.json"
MAX_BYTES = 64 * 1024 * 1024


def refresh(ctx: RunContext) -> SourceOutcome:
    cfg = ctx.settings.sources[SOURCE]
    outcome = SourceOutcome(SOURCE)
    now = to_iso(ctx.now())
    installed = files.read_facts(ctx.home, SOURCE)
    mirror_dir = ctx.settings.mirror.get(SOURCE)
    staging = files.new_staging(ctx.home, SOURCE, "incoming")
    try:
        target = staging / ARTIFACT
        if mirror_dir:
            artifact = load_artifact(mirror_dir, SOURCE, installed.checked_at, ctx.now())
            shutil.copyfile(artifact.path, target)
            checked_at = artifact.built
        else:
            ctx.fetcher_factory(HOSTS).download(URL, target, max_bytes=MAX_BYTES)
            checked_at = now
        catalog = check_kev(target.read_bytes(), installed.source_version, ctx.now())
        if installed.source_version == catalog.catalog_version:
            files.discard(staging)
            files.touch_checked(ctx.home, SOURCE, checked_at)
            outcome.notes.append("catalog unchanged; checked_at advanced")
        else:
            facts = DatasetFacts(
                as_of=catalog.date_released, checked_at=checked_at,
                source_version=catalog.catalog_version, fetched_at=now,
            )
            files.publish(ctx.home, SOURCE, f"v{catalog.catalog_version}-{ctx.now():%Y%m%dT%H%M%S}", staging, facts)
        outcome.counts["entries"] = catalog.count
    except BaseException:
        files.discard(staging)
        raise
    outcome.facts = files.read_facts(ctx.home, SOURCE)
    outcome.source_version = outcome.facts.source_version
    outcome.stale = is_stale(outcome.facts.checked_at, cfg.max_age_days, ctx.now())
    return outcome


def catalog_path(home: Path) -> Path:
    return files.source_dir(home, SOURCE) / "current" / ARTIFACT
