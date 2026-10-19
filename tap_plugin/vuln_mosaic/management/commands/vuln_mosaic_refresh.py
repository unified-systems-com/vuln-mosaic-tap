"""Run one refresh now, in this process (req-vuln-mosaic-refresh): manage.py vuln_mosaic_refresh.

The scheduled collector does the same work hourly; this is for priming a stack after writing a wanted
file. It takes the same writer lock, so it refuses while a scheduled run holds it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from tap_plugin.vuln_mosaic.locking import LockBusy
from tap_plugin.vuln_mosaic.refresh import run_refresh
from tap_plugin.vuln_mosaic.settings import SettingsError


class Command(BaseCommand):
    help = "Refresh every enabled vuln_mosaic source once and print each source's outcome."

    def handle(self, *args, **options) -> None:  # type: ignore[no-untyped-def]
        try:
            report = run_refresh()
        except SettingsError as exc:
            raise CommandError(f"settings invalid: {exc}") from None
        except LockBusy:
            raise CommandError("another refresh holds the writer lock; try again shortly") from None
        for outcome in report.outcomes:
            self.stdout.write(outcome.line())
        for note in report.wanted_problems:
            self.stderr.write(note)
        self.stdout.write(report.summary())
        if not report.clean:
            raise CommandError(report.summary())
