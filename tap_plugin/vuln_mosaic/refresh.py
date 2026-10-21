"""The refresh orchestration, Django-free so the collector and the tests share it (req-vuln-mosaic-refresh)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from tap_plugin.vuln_mosaic.fetch import Fetcher
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.locking import writer_lock
from tap_plugin.vuln_mosaic.outcome import GridRead, RunContext, RunReport, SourceOutcome
from tap_plugin.vuln_mosaic.settings import Settings, load_settings
from tap_plugin.vuln_mosaic.sources import cvelist, epss, ghsa, kev, nvd, osv
from tap_plugin.vuln_mosaic.staleness import utcnow
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import ingest_grid, ingest_spool

# ghsa runs before cvelist so the CVE ids it aliases are wanted by cvelist in the same run.
ORDER = ("ghsa", "cvelist", "kev", "epss", "nvd", "osv")


def run_refresh(
    home: str | Path | None = None,
    *,
    settings: Settings | None = None,
    now: Callable[[], datetime] = utcnow,
    fetcher_factory: Callable[[frozenset[str]], Fetcher] = Fetcher,
    git_factory: Callable[..., Git] = Git,
    sleep: Callable[[float], None] | None = None,
    grid_reader: Callable[[Settings], GridRead] | None = None,
) -> RunReport:
    """Run every enabled source once under the writer lock. One source failing never skips the rest."""
    root = resolve_home(home)
    settings = settings or load_settings(root)
    report = RunReport()
    grid_ids = _read_grid(settings, grid_reader, report)
    ctx = RunContext(root, settings, now, fetcher_factory, git_factory, grid_ids)
    with writer_lock(root):
        for name in ORDER:
            if not settings.sources[name].enabled:
                continue
            try:
                report.outcomes.append(_run_source(name, ctx, report, sleep))
            except Exception as exc:
                report.outcomes.append(SourceOutcome(name, ok=False, error=f"{type(exc).__name__}: {exc}"[:500]))
    return report


def _read_grid(settings: Settings, reader: Callable[[Settings], GridRead] | None, report: RunReport) -> tuple[str, ...]:
    """Ask the grid which vulnerabilities it holds. Any failure is reported and the run carries on without."""
    if not settings.grid.enabled or reader is None:
        return ()
    try:
        read = reader(settings)
    except Exception as exc:  # the grid being unreadable must never stop the sources refreshing
        report.grid_problems.append(f"grid: {type(exc).__name__}: {exc}"[:300])
        return ()
    report.grid_problems.extend(read.problems)
    report.grid_ids = len(read.ids)
    return tuple(read.ids)


def _run_source(name: str, ctx: RunContext, report: RunReport, sleep: Callable[[float], None] | None) -> SourceOutcome:
    if name in ("cvelist", "nvd", "ghsa"):
        store = RecordStore.open_writer(ctx.home, name)
        try:
            if name == "ghsa":
                report.spooled += ingest_spool(ctx.home, store, kind="ghsa")
                _take_grid(ctx, store, "ghsa", report)
                outcome = ghsa.refresh(ctx, store)
                cvelist_store = RecordStore.open_writer(ctx.home, "cvelist")
                try:
                    with cvelist_store.transaction():
                        outcome.counts["aliases_wanted"] = ghsa.want_aliases(store, cvelist_store)
                finally:
                    cvelist_store.close()
                return outcome
            if name == "cvelist":
                report.spooled += ingest_spool(ctx.home, store)
                _take_grid(ctx, store, "cve", report)
                outcome = cvelist.refresh(ctx, store)
                report.wanted_problems = [n for n in outcome.notes if n.startswith("wanted/")]
                return outcome
            _take_grid(ctx, store, "cve", report)
            return nvd.refresh(ctx, store, sleep) if sleep else nvd.refresh(ctx, store)
        finally:
            store.close()
    return {"kev": kev, "epss": epss, "osv": osv}[name].refresh(ctx)


def _take_grid(ctx: RunContext, store: RecordStore, kind: str, report: RunReport) -> None:
    if not ctx.grid_ids:
        return
    with store.transaction():
        _, bad = ingest_grid(store, ctx.grid_ids, kind=kind)
    for value in bad:
        note = f"grid: not a CVE or GHSA id: {value}"
        if note not in report.grid_problems:
            report.grid_problems.append(note)
