"""GitHub Security Advisories from github/advisory-database via a blobless shallow clone (req-vuln-mosaic-ghsa).

The same fetch shape as cvelist, with one difference: an advisory's path carries its publication
year and month, which its id does not, so the path of a wanted id is found by listing the tree
(trees are in a blobless clone) instead of being derived.
"""

from __future__ import annotations

import json
from pathlib import Path

from tap_plugin.vuln_mosaic.advisories import extract_advisory
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.ids import id_from_advisory_path, is_reviewed_path
from tap_plugin.vuln_mosaic.integrity import check_ghsa_advisory
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.sources.cvelist import apply_shas
from tap_plugin.vuln_mosaic.staleness import is_stale, to_iso
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import scan_wanted_files, wanted_set

SOURCE = "ghsa"
HOSTS = frozenset({"github.com"})
REMOTE = "https://github.com/github/advisory-database.git"
TREE = "advisories/"


def repo_path(home: Path) -> Path:
    return home / "git" / "advisory-database.git"


def advisory_index(git: Git, tip: str) -> dict[str, str]:
    """Blob id of every advisory at ``tip``, by id. A reviewed copy wins over an unreviewed one."""
    index: dict[str, str] = {}
    reviewed: set[str] = set()
    for path, sha in git.list_records(tip, TREE):
        ghsa_id = id_from_advisory_path(path)
        if ghsa_id is None:
            continue
        if is_reviewed_path(path):
            reviewed.add(ghsa_id)
        elif ghsa_id in reviewed:
            continue
        index[ghsa_id] = sha
    return index


def fetch_ids(git: Git, store: RecordStore, ids: list[str]) -> tuple[int, int, int]:
    """Fetch specific ids at the current tip (the immediate lookup). Returns (stored, quarantined, absent)."""
    tip = git.fetch_tip()
    index = advisory_index(git, tip)
    shas = {i: index[i] for i in ids if i in index}
    stored, bad = apply_shas(git, store, shas, prefetch=True, check=check_ghsa_advisory) if shas else (0, 0)
    return stored, bad, len(ids) - len(shas)


def want_aliases(ghsa_store: RecordStore, cvelist_store: RecordStore) -> int:
    """Ask cvelist for the CVE each held advisory aliases, so its CNA record is there when a consumer reads it."""
    added = 0
    known = cvelist_store.wanted_ids() | cvelist_store.held_ids()
    for _, raw in ghsa_store.iter_raw():
        for cve_id in extract_advisory(json.loads(raw)).cve_ids:
            if cve_id not in known:
                cvelist_store.add_wanted(cve_id, "ghsa-alias")
                known.add(cve_id)
                added += 1
    return added


def refresh(ctx: RunContext, store: RecordStore) -> SourceOutcome:
    cfg = ctx.settings.sources[SOURCE]
    outcome = SourceOutcome(SOURCE)
    outcome.counts["absent_upstream"] = 0
    now = to_iso(ctx.now())
    git = ctx.git_factory(repo_path(ctx.home), ctx.home, remote=REMOTE)
    git.ensure_repo(blobless=True)
    tip = git.fetch_tip(blobless=True)
    last = git.applied()
    wanted = wanted_set(scan_wanted_files(ctx.home), store, kind="ghsa")
    held = store.held_ids()

    to_put: dict[str, str] = {}
    to_delete: list[str] = []
    ignored = 0
    if last is not None and last != tip:
        by_id: dict[str, list] = {}
        for change in git.diff(last, tip):
            ghsa_id = id_from_advisory_path(change.path)
            if ghsa_id is None:
                ignored += 1
            elif ghsa_id in wanted:
                by_id.setdefault(ghsa_id, []).append(change)
        for ghsa_id, changes in by_id.items():
            # An advisory promoted from unreviewed to reviewed is a delete and an add of one id.
            live = [c for c in changes if c.status != "D" and c.new_sha]
            if live:
                to_put[ghsa_id] = max(live, key=lambda c: is_reviewed_path(c.path)).new_sha  # type: ignore[assignment]
            else:
                to_delete.append(ghsa_id)
    missing = [i for i in wanted if i not in held and i not in to_put and i not in to_delete]
    if missing:
        index = advisory_index(git, tip)
        for ghsa_id in missing:
            if ghsa_id in index:
                to_put[ghsa_id] = index[ghsa_id]
            else:
                outcome.counts["absent_upstream"] = outcome.counts.get("absent_upstream", 0) + 1

    stored, bad = apply_shas(git, store, to_put, prefetch=True, check=check_ghsa_advisory) if to_put else (0, 0)
    with store.transaction():
        for ghsa_id in to_delete:
            store.delete(ghsa_id)
        if not bad:
            store.set_facts(as_of=git.commit_time(tip), checked_at=now, source_version=tip, fetched_at=now)
    if not bad:
        git.mark_applied(tip)

    outcome.counts.update(stored=stored, quarantined=bad, deleted=len(to_delete), ignored_paths=ignored)
    outcome.source_version = tip if not bad else store.facts().source_version
    outcome.facts = store.facts()
    outcome.stale = is_stale(outcome.facts.checked_at, cfg.max_age_days, ctx.now())
    if bad:
        outcome.ok = False
        outcome.error = f"{bad} record(s) failed verification and were quarantined"
    return outcome
