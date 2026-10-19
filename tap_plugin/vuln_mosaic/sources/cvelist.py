"""CVE records from cvelistV5 via a blobless shallow clone (req-vuln-mosaic-cvelist)."""

from __future__ import annotations

from pathlib import Path

from tap_plugin.vuln_mosaic.gitops import Git, GitError
from tap_plugin.vuln_mosaic.ids import id_from_record_path, record_path
from tap_plugin.vuln_mosaic.integrity import IntegrityError, check_cve_record
from tap_plugin.vuln_mosaic.mirror import MirrorError, load_artifact
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.staleness import is_stale, to_iso
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import scan_wanted_files, wanted_set

SOURCE = "cvelist"
HOSTS = frozenset({"github.com"})


def repo_path(home: Path) -> Path:
    return home / "git" / "cvelistV5.git"


def apply_shas(
    git: Git, store: RecordStore, wanted_shas: dict[str, str], *, prefetch: bool
) -> tuple[int, int]:
    """Read, verify and write records by blob id. Returns (stored, quarantined).

    A record that fails verification is quarantined and the previous good copy stays
    (req-vuln-mosaic-integrity-1). The good records of the batch are applied together.
    """
    if prefetch:
        git.prefetch_blobs(list(wanted_shas.values()))
    blobs = git.read_blobs(list(wanted_shas.values()))
    good: list[tuple[str, str, str | None, bytes]] = []
    bad: list[tuple[str, str]] = []
    for cve_id, sha in wanted_shas.items():
        raw = blobs[sha]
        try:
            checked = check_cve_record(raw, cve_id)
        except IntegrityError as exc:
            bad.append((cve_id, str(exc)))
            continue
        good.append((cve_id, checked.state, checked.date_updated, raw))
    with store.transaction():
        for cve_id, state, updated, raw in good:
            store.put(cve_id, state, updated, raw)
        for cve_id, reason in bad:
            store.quarantine(cve_id, reason)
    return len(good), len(bad)


def fetch_ids(git: Git, store: RecordStore, ids: list[str]) -> tuple[int, int, int]:
    """Fetch specific ids at the current tip: the one fetch path shared by the collector and
    the immediate lookup, so the two cannot drift. Returns (stored, quarantined, absent)."""
    tip = git.fetch_tip()
    paths = {record_path(i): i for i in ids}
    located = git.blob_ids(tip, list(paths))
    shas = {paths[p]: sha for p, sha in located.items() if sha}
    absent = len(ids) - len(shas)
    stored, bad = apply_shas(git, store, shas, prefetch=True) if shas else (0, 0)
    return stored, bad, absent


def refresh(ctx: RunContext, store: RecordStore) -> SourceOutcome:
    cfg = ctx.settings.sources[SOURCE]
    outcome = SourceOutcome(SOURCE)
    now = to_iso(ctx.now())
    full = cfg.mode == "full"
    mirror_dir = ctx.settings.mirror.get(SOURCE)
    allow = "file" if mirror_dir else "https"
    git = ctx.git_factory(repo_path(ctx.home), ctx.home) if not mirror_dir else Git(
        repo_path(ctx.home), ctx.home, allow_protocol=allow
    )
    git.ensure_repo(blobless=not full and not mirror_dir)

    built = None
    if mirror_dir:
        installed = store.facts().checked_at
        artifact = load_artifact(mirror_dir, SOURCE, installed, ctx.now())
        tip, built = git.import_bundle(artifact.path), artifact.built
    else:
        tip = git.fetch_tip(blobless=not full)

    last = git.applied()
    scan = scan_wanted_files(ctx.home)
    outcome.notes.extend(scan.problems)
    wanted = None if full else wanted_set(scan, store)
    held = store.held_ids()

    to_put: dict[str, str] = {}
    to_delete: list[str] = []
    ignored = 0
    if last is not None and last != tip:
        for change in git.diff(last, tip):
            cve_id = id_from_record_path(change.path)
            if cve_id is None:
                ignored += 1
                continue
            if wanted is not None and cve_id not in wanted:
                continue
            if change.status == "D":
                to_delete.append(cve_id)
            elif change.new_sha:
                to_put[cve_id] = change.new_sha
    if full and last is None:
        for path, sha in git.list_records(tip):
            cve_id = id_from_record_path(path)
            if cve_id:
                to_put[cve_id] = sha
    if wanted is not None:
        missing = [i for i in wanted if i not in held and i not in to_put and i not in to_delete]
        if missing:
            located = git.blob_ids(tip, [record_path(i) for i in missing])
            for cve_id in missing:
                sha = located.get(record_path(cve_id))
                if sha:
                    to_put[cve_id] = sha
                else:
                    outcome.counts["absent_upstream"] = outcome.counts.get("absent_upstream", 0) + 1

    stored, bad = apply_shas(git, store, to_put, prefetch=not full and not mirror_dir) if to_put else (0, 0)
    with store.transaction():
        for cve_id in to_delete:
            store.delete(cve_id)
        store.set_facts(
            as_of=git.commit_time(tip),
            checked_at=built or now,
            source_version=tip,
            fetched_at=now,
        )
    git.mark_applied(tip)
    if full or last is not None:
        _housekeeping(git, stored)

    outcome.counts.update(stored=stored, quarantined=bad, deleted=len(to_delete), ignored_paths=ignored)
    outcome.source_version = tip
    outcome.facts = store.facts()
    outcome.stale = is_stale(outcome.facts.checked_at, cfg.max_age_days, ctx.now())
    if bad:
        outcome.ok = False
        outcome.error = f"{bad} record(s) failed verification and were quarantined"
    return outcome


def _housekeeping(git: Git, stored: int) -> None:
    # Lazy blob fetches leave small packs; compact them after a run that stored records.
    if stored > 50:
        try:
            git.run("gc", "--auto", "--quiet", check=False)
        except GitError:
            pass


__all__ = ["HOSTS", "SOURCE", "MirrorError", "fetch_ids", "refresh", "repo_path"]
