"""VulnMosaicRefreshCollector: keep the local vulnerability datasets current (req-vuln-mosaic-refresh).

Registered as ``vuln_mosaic:refresh``. It writes the stores under the vuln_mosaic home and lands NO
GRIFT batch: its only grid footprint is the collection job record, which carries each source's
outcome. A run in which any source failed or is stale ends as a failed job naming those sources,
never clean.
"""

from __future__ import annotations

import shutil
from typing import Any

from tap_plugin.vuln_mosaic.collectors.refresh.gridread import read_grid_ids
from tap_plugin.vuln_mosaic.collectors.refresh.gridwrite import enrich_grid
from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.locking import LockBusy
from tap_plugin.vuln_mosaic.outcome import RunReport, SourceOutcome
from tap_plugin.vuln_mosaic.refresh import run_refresh
from tap_plugin.vuln_mosaic.settings import SettingsError, load_settings
from tap_plugin.vuln_mosaic.sources import cvelist, epss, ghsa, kev, nvd, osv

from tap_cares.collectors.base import CollectorBase
from tap_cares.collectors.readiness import (
    CollectorReadinessStatus,
    CollectorSelfTestResult,
    check_fail,
    check_pass,
    check_skip,
)

# record_* call-site tokens (minted via scripts/log-site-id; unique within this file).
_SITE_STARTED = "3bd9"
_SITE_SOURCE_OK = "db95"
_SITE_SOURCE_STALE = "f009"
_SITE_SOURCE_FAILED = "e326"
_SITE_SETTINGS = "5431"
_SITE_BUSY = "c2f7"
_SITE_WANTED_PROBLEM = "5f67"
_SITE_FINISHED = "f2d3"
_SITE_GRID_PROBLEM = "b3eb"
_SITE_GRID_WRITE_PROBLEM = "a576"

_HOSTS = {
    "cvelist": cvelist.HOSTS,
    "kev": kev.HOSTS,
    "epss": epss.HOSTS,
    "nvd": nvd.HOSTS,
    "osv": osv.HOSTS,
    "ghsa": ghsa.HOSTS,
}


class VulnMosaicRefreshError(RuntimeError):
    """The run finished with a failed or stale source; ``str(exc)`` names them."""


class VulnMosaicRefreshCollector(CollectorBase):
    def run(self) -> None:
        self.declare_no_surfaces()
        self.record_info(_SITE_STARTED, "RUN_STARTED", "Refreshing the local vulnerability datasets.")
        try:
            report = run_refresh(grid_reader=read_grid_ids, grid_writer=enrich_grid)
        except SettingsError as exc:
            self.summary = f"Settings invalid; no source was fetched: {exc}"[:400]
            self.record_error(_SITE_SETTINGS, "SETTINGS_INVALID", str(exc))
            raise VulnMosaicRefreshError(self.summary) from None
        except LockBusy:
            self.summary = "Another refresh holds the writer lock; this run did nothing."
            self.record_error(_SITE_BUSY, "REFRESH_ALREADY_RUNNING", self.summary)
            raise VulnMosaicRefreshError(self.summary) from None

        for note in report.wanted_problems:
            self.record_warn(_SITE_WANTED_PROBLEM, "WANTED_FILE_PROBLEM", note)
        for note in report.grid_problems:
            self.record_warn(_SITE_GRID_PROBLEM, "GRID_READ_PROBLEM", note)
        if report.enrich is not None:
            for note in report.enrich.problems:
                self.record_warn(_SITE_GRID_WRITE_PROBLEM, "GRID_WRITE_PROBLEM", note)
        for outcome in report.outcomes:
            self._record_outcome(outcome)
        self.summary = report.summary()[:400]
        self.record_info(_SITE_FINISHED, "RUN_FINISHED", self.summary, message_data=_report_data(report))
        if not report.clean:
            raise VulnMosaicRefreshError(self.summary)

    def _record_outcome(self, outcome: SourceOutcome) -> None:
        data: dict[str, Any] = {
            "source": outcome.source,
            "source_version": outcome.source_version,
            "stale": outcome.stale,
            "counts": outcome.counts,
            "notes": outcome.notes,
            "as_of": outcome.facts.as_of,
            "checked_at": outcome.facts.checked_at,
        }
        if not outcome.ok:
            data["reason"] = outcome.error
            self.record_error(_SITE_SOURCE_FAILED, "SOURCE_FAILED", outcome.line(), message_data=data)
        elif outcome.stale:
            self.record_warn(_SITE_SOURCE_STALE, "SOURCE_STALE", outcome.line(), message_data=data)
        else:
            self.record_info(_SITE_SOURCE_OK, "SOURCE_REFRESHED", outcome.line(), message_data=data)

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        checks = []
        home = resolve_home()
        try:
            home.mkdir(parents=True, exist_ok=True)
            probe = home / ".self-test"
            probe.write_text("ok")
            probe.unlink()
            checks.append(check_pass("HOME_WRITABLE", f"{home} is writable."))
        except OSError as exc:
            checks.append(
                check_fail("HOME_UNWRITABLE", f"{home} is not writable: {exc}", readiness_status=CollectorReadinessStatus.MISCONFIGURED)
            )
        settings = None
        try:
            settings = load_settings(home)
            checks.append(check_pass("SETTINGS_VALID", "settings.json is valid (or absent: defaults apply)."))
        except SettingsError as exc:
            checks.append(check_fail("SETTINGS_INVALID", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        if shutil.which("git"):
            checks.append(check_pass("GIT_PRESENT", "git is on PATH."))
        else:
            checks.append(
                check_fail("GIT_MISSING", "git is not on PATH.", readiness_status=CollectorReadinessStatus.MISCONFIGURED)
            )
        if settings is not None:
            for name, cfg in settings.sources.items():
                if not cfg.enabled:
                    checks.append(check_skip(f"SOURCE_{name.upper()}_DISABLED", f"{name} is disabled."))
                elif name in settings.mirror:
                    checks.append(check_pass(f"SOURCE_{name.upper()}_MIRROR", f"{name} imports from {settings.mirror[name]}; no egress."))
                else:
                    checks.append(
                        check_pass(f"SOURCE_{name.upper()}_HOST", f"{name} egress host: {', '.join(sorted(_HOSTS[name]))}.")
                    )
        return CollectorSelfTestResult.from_checks(checks, summary="vuln_mosaic self-test")


def _report_data(report: RunReport) -> dict[str, Any]:
    return {
        "failed": report.failed_sources,
        "stale": report.stale_sources,
        "spooled": report.spooled,
        "grid_ids": report.grid_ids,
        "enrich": (
            None
            if report.enrich is None
            else {
                "patched": report.enrich.patched,
                "unchanged": report.enrich.unchanged,
                "failed": report.enrich.failed,
                "lists_deferred": report.enrich.lists_deferred,
                "stopped_early": report.enrich.stopped_early,
                "fields": report.enrich.fields,
            }
        ),
        "sources": [o.line() for o in report.outcomes],
    }
