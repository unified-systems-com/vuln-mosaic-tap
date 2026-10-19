"""The read function other modules call (req-vuln-mosaic-lookup). Plain Python, no Django import."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.advisories import ParsedAdvisory, extract_advisory
from tap_plugin.vuln_mosaic.ids import validate_cve_id, validate_ghsa_id
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


def _max_age(home: Path, source: str = "cvelist") -> int:
    try:
        return load_settings(home).sources[source].max_age_days
    except SettingsError:
        return 3


def get_cve(cve_id: str, *, home: Path | None = None, queue: bool = True) -> LookupResult:
    """Return found, rejected or not-fetched. Raises ``ValueError`` for a malformed id before any I/O.

    ``queue=False`` makes a miss a pure read: nothing is written and the immediate fetch is not tried.
    """
    validate_cve_id(cve_id)
    root = resolve_home(home)
    age = _max_age(root)
    stored, facts = fetch_record(root, "cvelist", cve_id)
    if stored is not None:
        dataset = _info(facts, age)
        if stored.state == "REJECTED":
            return LookupResult(REJECTED, None, dataset)
        return LookupResult(FOUND, json.loads(stored.raw), dataset)
    if not queue:
        return LookupResult(NOT_FETCHED, None, _info(facts, age), "not held; not queued")
    queued = request_id(root, cve_id)
    reason = "queued for the next refresh" if queued else "already queued, or the queue is full"
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


# ---------------------------------------------------------------------------------------------
# GitHub Security Advisories (req-vuln-mosaic-ghsa)
# ---------------------------------------------------------------------------------------------

WITHDRAWN = "withdrawn"


@dataclass(frozen=True)
class GhsaResult:
    """``state`` is ``found``, ``withdrawn`` or ``not-fetched``.

    ``advisory`` is set for ``found`` and ``withdrawn`` (a withdrawn advisory is kept so its
    aliases and withdrawal date can be read; it is never presented as live). Its ``cve_ids`` are
    the CVEs it aliases: read their CNA records with ``get_cve``.
    """

    state: str
    advisory: ParsedAdvisory | None
    dataset: DatasetInfo
    reason: str | None = None


def get_ghsa(ghsa_id: str, *, home: Path | None = None, queue: bool = True) -> GhsaResult:
    """Return found, withdrawn or not-fetched. Raises ``ValueError`` for a malformed id before any I/O.

    ``queue=False`` makes a miss a pure read: nothing is written and the immediate fetch is not tried.
    """
    validate_ghsa_id(ghsa_id)
    root = resolve_home(home)
    age = _max_age(root, "ghsa")
    stored, facts = fetch_record(root, "ghsa", ghsa_id)
    if stored is not None:
        return _ghsa_result(stored.state, stored.raw, _info(facts, age))
    if not queue:
        return GhsaResult(NOT_FETCHED, None, _info(facts, age), "not held; not queued")
    queued = request_id(root, ghsa_id)
    reason = "queued for the next refresh" if queued else "already queued, or the queue is full"
    try:
        settings = load_settings(root)
    except SettingsError as exc:
        return GhsaResult(NOT_FETCHED, None, _info(facts, age), f"settings invalid: {exc}")
    if not settings.sources["ghsa"].enabled:
        reason += "; the ghsa source is not enabled, so nothing will fetch it"
    elif settings.immediate_fetch:
        fetched = _immediate_ghsa(root, ghsa_id)
        if isinstance(fetched, GhsaResult):
            return fetched
        reason = fetched
    return GhsaResult(NOT_FETCHED, None, _info(facts, age), reason)


def _ghsa_result(state: str, raw: bytes, dataset: DatasetInfo) -> GhsaResult:
    advisory = extract_advisory(json.loads(raw))
    return GhsaResult(WITHDRAWN if state == "WITHDRAWN" else FOUND, advisory, dataset)


def _immediate_ghsa(root: Path, ghsa_id: str) -> GhsaResult | str:
    from tap_plugin.vuln_mosaic.gitops import Git, GitError
    from tap_plugin.vuln_mosaic.sources import ghsa

    try:
        with writer_lock(root, wait_seconds=1.0):
            git = Git(ghsa.repo_path(root), root, remote=ghsa.REMOTE, timeout=IMMEDIATE_BUDGET)
            git.ensure_repo()
            store = RecordStore.open_writer(root, "ghsa")
            try:
                store.add_wanted(ghsa_id, "immediate")
                stored, bad, _ = ghsa.fetch_ids(git, store, [ghsa_id])
            finally:
                store.close()
    except LockBusy:
        return "a refresh is running; queued for it"
    except GitError as exc:
        return f"immediate fetch failed: {exc}"
    if not stored:
        return "quarantined by verification" if bad else "not present upstream"
    record, facts = fetch_record(root, "ghsa", ghsa_id)
    if record is None:  # pragma: no cover - just written
        return "stored record not readable"
    return _ghsa_result(record.state, record.raw, _info(facts, _max_age(root, "ghsa")))


# ---------------------------------------------------------------------------------------------
# Whole-file datasets: KEV and EPSS (req-vuln-mosaic-kev, req-vuln-mosaic-epss)
# ---------------------------------------------------------------------------------------------

LISTED, NOT_LISTED = "listed", "not-listed"
SCORED, NOT_SCORED = "scored", "not-scored"


@dataclass(frozen=True)
class KevResult:
    """``state`` is ``listed``, ``not-listed`` or ``not-fetched`` (no catalog is held yet).

    ``entry`` is the catalog entry as published (cveID, vendorProject, product, vulnerabilityName,
    dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes
    where present); ``not-listed`` is a statement about the catalog held, not about the CVE.
    """

    state: str
    entry: dict[str, Any] | None
    dataset: DatasetInfo


@dataclass(frozen=True)
class EpssResult:
    """``state`` is ``scored``, ``not-scored`` or ``not-fetched``. Only the current day is held."""

    state: str
    epss: float | None
    percentile: float | None
    model_version: str | None
    score_date: str | None
    dataset: DatasetInfo


def _file_info(root: Path, source: str) -> DatasetInfo:
    try:
        age = load_settings(root).sources[source].max_age_days
    except SettingsError:
        age = 3
    return _info(files.read_facts(root, source), age)


def get_kev(cve_id: str, *, home: Path | None = None) -> KevResult:
    """Look an id up in the held CISA KEV catalog. Raises ``ValueError`` for a malformed id."""
    validate_cve_id(cve_id)
    root = resolve_home(home)
    info = _file_info(root, "kev")
    try:
        handle = files.open_current(root, "kev", "known_exploited_vulnerabilities.json")
    except FileNotFoundError:
        return KevResult(NOT_FETCHED, None, info)
    with handle:
        try:
            catalog = json.load(handle)
        except ValueError:
            return KevResult(NOT_FETCHED, None, info)
    for entry in catalog.get("vulnerabilities", []):
        if isinstance(entry, dict) and entry.get("cveID") == cve_id:
            return KevResult(LISTED, entry, info)
    return KevResult(NOT_LISTED, None, info)


def get_epss(cve_id: str, *, home: Path | None = None) -> EpssResult:
    """Look an id up in the held EPSS scores (current day only). Raises ``ValueError`` for a malformed id."""
    import gzip

    validate_cve_id(cve_id)
    root = resolve_home(home)
    info = _file_info(root, "epss")
    try:
        handle = files.open_current(root, "epss", "epss_scores.csv.gz")
    except FileNotFoundError:
        return EpssResult(NOT_FETCHED, None, None, None, None, info)
    prefix = f"{cve_id},".encode()
    with handle, gzip.open(handle, "rb") as rows:
        first = rows.readline().decode().strip()
        model_version = score_date = None
        if first.startswith("#"):
            parts = dict(p.split(":", 1) for p in first[1:].split(",") if ":" in p)
            model_version, score_date = parts.get("model_version"), parts.get("score_date")
        for line in rows:
            if line.startswith(prefix):
                _, epss, percentile = line.decode().strip().split(",")
                return EpssResult(SCORED, float(epss), float(percentile), model_version, score_date, info)
    return EpssResult(NOT_SCORED, None, None, model_version, score_date, info)
