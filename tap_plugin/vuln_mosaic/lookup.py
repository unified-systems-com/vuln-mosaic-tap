"""The read function other modules call (req-vuln-mosaic-lookup). Plain Python, no Django import."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.ids import validate_cve_id
from tap_plugin.vuln_mosaic.locking import LockBusy, writer_lock
from tap_plugin.vuln_mosaic.settings import SettingsError, load_settings
from tap_plugin.vuln_mosaic.staleness import DatasetFacts, is_stale
from tap_plugin.vuln_mosaic.store import RecordStore, fetch_record
from tap_plugin.vuln_mosaic.wanted import request_id

FOUND, NOT_FETCHED, REJECTED = "found", "not-fetched", "rejected"
IMMEDIATE_BUDGET = 10.0


@dataclass(frozen=True)
class DatasetInfo:
    as_of: str | None
    checked_at: str | None
    source_version: str | None
    stale: bool | None  # None is unobserved, never "fresh"


@dataclass(frozen=True)
class LookupResult:
    state: str
    record: dict[str, Any] | None
    dataset: DatasetInfo
    reason: str | None = None


def _info(facts: DatasetFacts, max_age_days: int) -> DatasetInfo:
    return DatasetInfo(facts.as_of, facts.checked_at, facts.source_version, is_stale(facts.checked_at, max_age_days))


def _max_age(home: Path) -> int:
    try:
        return load_settings(home).sources["cvelist"].max_age_days
    except SettingsError:
        return 3


def get_cve(cve_id: str, *, home: Path | None = None) -> LookupResult:
    """Return found, rejected or not-fetched. Raises ``ValueError`` for a malformed id before any I/O."""
    validate_cve_id(cve_id)
    root = resolve_home(home)
    age = _max_age(root)
    stored, facts = fetch_record(root, "cvelist", cve_id)
    if stored is not None:
        dataset = _info(facts, age)
        if stored.state == "REJECTED":
            return LookupResult(REJECTED, None, dataset)
        return LookupResult(FOUND, json.loads(stored.raw), dataset)
    request_id(root, cve_id)
    reason = "queued for the next refresh"
    try:
        settings = load_settings(root)
    except SettingsError as exc:
        return LookupResult(NOT_FETCHED, None, _info(facts, age), f"settings invalid: {exc}")
    if settings.immediate_fetch:
        fetched = _immediate(root, cve_id)
        if isinstance(fetched, LookupResult):
            return fetched
        reason = fetched
    return LookupResult(NOT_FETCHED, None, _info(facts, age), reason)


def _immediate(root: Path, cve_id: str) -> LookupResult | str:
    """Fetch inside the call through the collector's own fetch function, under the writer lock."""
    from tap_plugin.vuln_mosaic.gitops import Git, GitError
    from tap_plugin.vuln_mosaic.sources import cvelist

    try:
        with writer_lock(root, wait_seconds=1.0):
            git = Git(cvelist.repo_path(root), root, timeout=IMMEDIATE_BUDGET)
            git.ensure_repo()
            store = RecordStore.open_writer(root, "cvelist")
            try:
                store.add_wanted(cve_id, "immediate")
                stored, bad, _ = cvelist.fetch_ids(git, store, [cve_id])
            finally:
                store.close()
    except LockBusy:
        return "a refresh is running; queued for it"
    except GitError as exc:
        return f"immediate fetch failed: {exc}"
    if not stored:
        return "quarantined by verification" if bad else "not present upstream"
    stored_rec, facts = fetch_record(root, "cvelist", cve_id)
    if stored_rec is None:  # pragma: no cover - just written
        return "stored record not readable"
    dataset = _info(facts, _max_age(root))
    if stored_rec.state == "REJECTED":
        return LookupResult(REJECTED, None, dataset)
    return LookupResult(FOUND, json.loads(stored_rec.raw), dataset)
