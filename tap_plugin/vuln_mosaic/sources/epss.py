"""FIRST EPSS daily scores as a whole file (req-vuln-mosaic-epss)."""

from __future__ import annotations

import shutil
from pathlib import Path

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.integrity import check_epss
from tap_plugin.vuln_mosaic.mirror import load_artifact
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.staleness import DatasetFacts, is_stale, parse_time, to_iso

SOURCE = "epss"
URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
HOSTS = frozenset({"epss.empiricalsecurity.com"})
ARTIFACT = "epss_scores.csv.gz"
MAX_BYTES = 256 * 1024 * 1024


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
        scores = check_epss(target, installed.as_of, ctx.now())
        if installed.as_of is not None and parse_time(installed.as_of) == parse_time(scores.score_date):
            files.discard(staging)
            files.touch_checked(ctx.home, SOURCE, checked_at)
            outcome.notes.append("scores unchanged; checked_at advanced")
        else:
            facts = DatasetFacts(
                as_of=scores.score_date, checked_at=checked_at,
                source_version=scores.model_version, fetched_at=now,
            )
            files.publish(ctx.home, SOURCE, f"{parse_time(scores.score_date):%Y%m%dT%H%M%SZ}", staging, facts)
        outcome.counts["rows"] = scores.rows
    except BaseException:
        files.discard(staging)
        raise
    outcome.facts = files.read_facts(ctx.home, SOURCE)
    outcome.source_version = outcome.facts.source_version
    outcome.stale = is_stale(outcome.facts.checked_at, cfg.max_age_days, ctx.now())
    return outcome


def scores_path(home: Path) -> Path:
    return files.source_dir(home, SOURCE) / "current" / ARTIFACT
