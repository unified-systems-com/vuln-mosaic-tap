"""NVD API 2.0 records for the wanted ids (req-vuln-mosaic-nvd).

GATED. NVD's own documentation pages render only through JavaScript and could not be read here
(2026-10-19); the limits below come from secondary sources (nvd-api on PyPI, nvdlib) and are used
conservatively: unauthenticated, one request per 6.5 s (documented as 5 per rolling 30 s), windows
of at most 120 days. The source is off by default and ``req-vuln-mosaic-nvd-1`` stays Proposed
until the official terms are read. No API key is used.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from urllib.parse import urlencode

from tap_plugin.vuln_mosaic.fetch import FetchError
from tap_plugin.vuln_mosaic.ids import validate_cve_id
from tap_plugin.vuln_mosaic.integrity import IntegrityError, check_nvd_object
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.staleness import is_stale, parse_time, to_iso
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import scan_wanted_files, wanted_set

SOURCE = "nvd"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HOSTS = frozenset({"services.nvd.nist.gov"})
MIN_INTERVAL = 6.5
MAX_WINDOW = timedelta(days=119)
PAGE = 2000
MAX_BODY = 64 * 1024 * 1024
MAX_PAGES = 50
BACKOFF = (30.0, 60.0, 120.0)


class _Throttle:
    def __init__(self, sleep: Callable[[float], None]) -> None:
        self._sleep, self._last = sleep, 0.0

    def wait(self) -> None:
        gap = MIN_INTERVAL - (time.monotonic() - self._last)
        if gap > 0:
            self._sleep(gap)
        self._last = time.monotonic()


def _query(ctx: RunContext, throttle: _Throttle, params: dict[str, str], sleep: Callable[[float], None]) -> dict:
    url = f"{BASE}?{urlencode(params)}"
    for delay in (*BACKOFF, None):
        throttle.wait()
        try:
            body, _ = ctx.fetcher_factory(HOSTS).get_bytes(url, max_bytes=MAX_BODY)
            return json.loads(body)
        except FetchError as exc:
            if exc.status in (403, 429) and delay is not None:
                sleep(delay)
                continue
            raise
        except ValueError as exc:
            raise IntegrityError(f"NVD answered non-JSON: {exc}") from None
    raise FetchError("NVD kept refusing after backoff")  # pragma: no cover


def _store(store: RecordStore, items: list[dict], wanted: set[str] | None) -> tuple[int, int]:
    stored = bad = 0
    with store.transaction():
        for item in items:
            cve_id = (item.get("cve") or {}).get("id")
            if wanted is not None and cve_id not in wanted:
                continue
            raw = json.dumps(item, sort_keys=True).encode()
            try:
                checked = check_nvd_object(raw, str(cve_id))
            except IntegrityError as exc:
                store.quarantine(str(cve_id), str(exc))
                bad += 1
                continue
            store.put(cve_id, checked.state, checked.date_updated, raw)
            stored += 1
    return stored, bad


def refresh(ctx: RunContext, store: RecordStore, sleep: Callable[[float], None] = time.sleep) -> SourceOutcome:
    cfg = ctx.settings.sources[SOURCE]
    outcome = SourceOutcome(SOURCE)
    now_dt = ctx.now()
    now = to_iso(now_dt)
    if ctx.settings.mirror.get(SOURCE):
        outcome.ok = False
        outcome.error = "an NVD mirror import is not implemented in v0"
        return outcome
    throttle = _Throttle(sleep)
    scan = scan_wanted_files(ctx.home)
    wanted = wanted_set(scan, store)
    held = store.held_ids()
    stored = bad = 0
    for cve_id in sorted(wanted - held):
        data = _query(ctx, throttle, {"cveId": validate_cve_id(cve_id)}, sleep)
        s, b = _store(store, data.get("vulnerabilities", []), {cve_id})
        stored, bad = stored + s, bad + b
    last_end = store.get_meta("last_mod_end")
    if last_end and held:
        start = parse_time(last_end)
        while start is not None and start < now_dt:
            end = min(start + MAX_WINDOW, now_dt)
            index = 0
            for _ in range(MAX_PAGES):
                data = _query(
                    ctx, throttle,
                    {
                        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "resultsPerPage": str(PAGE), "startIndex": str(index),
                    },
                    sleep,
                )
                s, b = _store(store, data.get("vulnerabilities", []), held | wanted)
                stored, bad = stored + s, bad + b
                index += int(data.get("resultsPerPage", PAGE))
                if index >= int(data.get("totalResults", 0)):
                    break
            else:
                raise FetchError("NVD window exceeded the page bound")
            start = end
    with store.transaction():
        store.set_meta("last_mod_end", now)
        store.set_facts(as_of=now, checked_at=now, source_version=now, fetched_at=now)
    outcome.counts.update(stored=stored, quarantined=bad)
    outcome.facts = store.facts()
    outcome.source_version = outcome.facts.source_version
    outcome.stale = is_stale(outcome.facts.checked_at, cfg.max_age_days, now_dt)
    if bad:
        outcome.ok, outcome.error = False, f"{bad} NVD object(s) failed verification"
    return outcome


__all__ = ["HOSTS", "SOURCE", "datetime", "refresh"]
