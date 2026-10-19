"""The refresh orchestration, Django-free so the collector and the tests share it (req-vuln-mosaic-refresh)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from tap_plugin.vuln_mosaic.fetch import Fetcher
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.locking import writer_lock
from tap_plugin.vuln_mosaic.outcome import RunContext, RunReport, SourceOutcome
from tap_plugin.vuln_mosaic.settings import Settings, load_settings
from tap_plugin.vuln_mosaic.sources import cvelist, epss, kev, nvd, osv
from tap_plugin.vuln_mosaic.staleness import utcnow
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import ingest_spool

ORDER = ("cvelist", "kev", "epss", "nvd", "osv")


def run_refresh(
    home: str | Path | None = None,
    *,
    settings: Settings | None = None,
    now: Callable[[], datetime] = utcnow,
    fetcher_factory: Callable[[frozenset[str]], Fetcher] = Fetcher,
    git_factory: Callable[[Path, Path], Git] = Git,
    sleep: Callable[[float], None] | None = None,
) -> RunReport:
    """Run every enabled source once under the writer lock. One source failing never skips the rest."""
    root = resolve_home(home)
    settings = settings or load_settings(root)
    ctx = RunContext(root, settings, now, fetcher_factory, git_factory)
    report = RunReport()
    with writer_lock(root):
        for name in ORDER:
            if not settings.sources[name].enabled:
                continue
            try:
                report.outcomes.append(_run_source(name, ctx, report, sleep))
            except Exception as exc:
                report.outcomes.append(SourceOutcome(name, ok=False, error=f"{type(exc).__name__}: {exc}"[:500]))
    return report


def _run_source(name: str, ctx: RunContext, report: RunReport, sleep: Callable[[float], None] | None) -> SourceOutcome:
    if name in ("cvelist", "nvd"):
        store = RecordStore.open_writer(ctx.home, name)
        try:
            if name == "cvelist":
                report.spooled = ingest_spool(ctx.home, store)
                outcome = cvelist.refresh(ctx, store)
                report.wanted_problems = [n for n in outcome.notes if n.startswith("wanted/")]
                return outcome
            return nvd.refresh(ctx, store, sleep) if sleep else nvd.refresh(ctx, store)
        finally:
            store.close()
    return {"kev": kev, "epss": epss, "osv": osv}[name].refresh(ctx)
