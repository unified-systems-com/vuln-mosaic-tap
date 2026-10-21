"""Write the facts the local datasets hold onto vulnerability nodes already on the grid (req-vuln-mosaic-enrich).

Patches only: a node is never created or deleted here. Each patch carries the node's version as it was
read (optimistic concurrency), so a node someone else changed in between is left for the next run
instead of being overwritten. What may be written is decided by ``enrich.plan_patch``; this module reads
the nodes, calls it, and writes the result in small atomic batches.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from tap_plugin.vuln_mosaic.enrich import FIELDS, facts_for, plan_patch
from tap_plugin.vuln_mosaic.ids import validate_vuln_id
from tap_plugin.vuln_mosaic.outcome import EnrichResult
from tap_plugin.vuln_mosaic.settings import Settings

PAGE = 500  # nodes per read: each carries every enrichable field
CHUNK = 50  # patches per atomic batch
MAX_ROWS = 1_000_000
LIST_FIELDS = frozenset({"cwes"})  # facts that are JSON lists
# What tap core's PATCH raises for a list value: it deep-merges every JSON field as if it were an object.
LIST_PATCH_BUG = "has no attribute 'items'"
LIST_NOTE = "grid write: cwes were not written, this grid's patch cannot take list values yet (needs the tap core fix); every other fact was"
BATCH_NAME = "vuln_mosaic enrichment"
BATCH_DESCRIPTION = "Filled unobserved vulnerability facts from the local copies of public vulnerability data."

Execute = Callable[..., dict[str, Any]]


def _query(entity_type: str, limit: int) -> str:
    # The slug is schema-checked in settings; it is query text, not a command.
    columns = ", ".join(f"v.data.{name} AS {name}" for name in FIELDS)
    return (
        f"MATCH (v:{entity_type}) WHERE v.data.vuln_id > $after "
        f"RETURN v.entity_id AS eid, v.version AS ver, v.data.vuln_id AS vuln_id, {columns} "
        f"ORDER BY vuln_id ASC LIMIT {limit}"
    )


def iter_nodes(settings: Settings, execute: Execute, out: EnrichResult) -> Iterator[dict[str, Any]]:
    """Nodes of the configured types, one page in memory at a time. A type that cannot be read is named.

    When no configured type can be read at all, the write phase has nothing to work on and is marked ``raised``."""
    scanned = 0
    unreadable = 0
    for entity_type in settings.grid.vulnerability_types:
        after = ""
        try:
            while scanned < MAX_ROWS:
                rows = execute(_query(entity_type, PAGE), {"after": after}).get("rows") or []
                scanned += len(rows)
                for row in rows:
                    if isinstance(row, dict) and isinstance(row.get("eid"), str) and isinstance(row.get("vuln_id"), str):
                        row["type"] = entity_type
                        yield row
                last = rows[-1].get("vuln_id") if rows and isinstance(rows[-1], dict) else None
                if len(rows) < PAGE or not isinstance(last, str) or last <= after:
                    break
                after = last
        except Exception as exc:
            unreadable += 1
            out.problems.append(f"grid write: {entity_type}: {type(exc).__name__}: {str(exc)[:160]}")
    if settings.grid.vulnerability_types and unreadable == len(settings.grid.vulnerability_types):
        out.raised = True


def _error_text(result: Any) -> str:
    errors = list(getattr(result, "errors", None) or [])
    return "; ".join(str(getattr(e, "message", e)) for e in errors)[:200] or "refused"


def _write(chunk: list[tuple[str, int, dict[str, Any]]], batch: Callable[..., Any], out: EnrichResult) -> None:
    from tap_grid.service_types import WriteOperation

    if out.lists_deferred:  # this grid already refused a list patch in this run: do not provoke it again per node
        stripped = []
        for eid, version, patch in chunk:
            rest = {k: v for k, v in patch.items() if k not in LIST_FIELDS}
            out.lists_deferred += len(rest) != len(patch)
            if rest:
                stripped.append((eid, version, rest))
        if not stripped:
            return
        chunk = stripped
    ops = [WriteOperation(verb="patch_node", target=eid, payload=patch, entity_expected_version=ver) for eid, ver, patch in chunk]
    result = batch(ops, batch_name=BATCH_NAME, batch_description=BATCH_DESCRIPTION)
    if result.success:
        out.patched += len(chunk)
        out.fields += sum(len(patch) for _, _, patch in chunk)
        return
    if len(chunk) > 1:  # one refused patch rolls its batch back: retry the nodes one at a time
        for single in chunk:
            _write([single], batch, out)
        return
    eid, version, patch = chunk[0]
    text = _error_text(result.results[0] if result.results else result)
    if LIST_PATCH_BUG in text and LIST_FIELDS & patch.keys():
        # The refused patch rolled back, so the node is as read: write what the grid can take.
        out.lists_deferred += 1
        if LIST_NOTE not in out.problems:
            out.problems.append(LIST_NOTE)
        rest = {k: v for k, v in patch.items() if k not in LIST_FIELDS}
        if rest:
            _write([(eid, version, rest)], batch, out)
        return
    out.failed += 1
    if len(out.problems) < 20:
        out.problems.append(f"grid write: node {eid}: {text}")


def enrich_grid(
    settings: Settings,
    home: Path,
    *,
    execute: Execute | None = None,
    batch: Callable[..., Any] | None = None,
    facts: Callable[[str, Path | None], Any] = facts_for,
) -> EnrichResult:
    """Fill unobserved facts on existing vulnerability nodes; return what happened."""
    if execute is None:
        from tap_grid.gryphon import execute_gryphon_raw as execute
    if batch is None:
        from tap_grid.services import write_batch as batch
    out = EnrichResult()
    budget = settings.grid.max_nodes_per_run
    attempt_cap = budget * 5  # nodes the grid keeps refusing must not make a run try the whole grid
    attempted = 0
    chunk: list[tuple[str, int, dict[str, Any]]] = []
    for node in iter_nodes(settings, execute, out):
        try:
            validate_vuln_id(node["vuln_id"])
        except ValueError:
            continue  # reported once by the id read; nothing is looked up for it
        patch = plan_patch({name: node.get(name) for name in FIELDS}, facts(node["vuln_id"], home).values)
        if not patch:
            out.unchanged += 1
            continue
        if out.lists_deferred and patch.keys() <= LIST_FIELDS:
            out.lists_deferred += 1  # only a list fact, and this grid has refused lists this run: not an attempt
            continue
        version = node.get("ver")
        if not isinstance(version, int):
            out.failed += 1
            continue
        chunk.append((node["eid"], version, patch))
        attempted += 1
        if len(chunk) >= CHUNK or out.patched + len(chunk) >= budget:
            _write(chunk, batch, out)
            chunk = []
        if out.patched >= budget or attempted >= attempt_cap:
            out.stopped_early = True
            break
    if chunk:
        _write(chunk, batch, out)
    return out
