"""Read the vulnerability ids the grid already holds (req-vuln-mosaic-wanted-7).

Read-only: one Gryphon query per configured entity type, paged by id so no type is read in one gulp.
The grid is untrusted input here, so this module only collects strings; ``wanted.ingest_grid``
decides which of them are ids. It needs the ``grid.read`` capability the collector's actor holds.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tap_plugin.vuln_mosaic.ids import validate_vuln_id
from tap_plugin.vuln_mosaic.outcome import GridRead
from tap_plugin.vuln_mosaic.settings import Settings

PAGE = 2000
MAX_IDS = 200_000  # valid ids kept per run, so a runaway type cannot grow the wanted table without limit
MAX_ROWS = 1_000_000  # rows scanned per run, valid or not, so malformed values cannot keep the pager walking

Execute = Callable[..., dict[str, Any]]


def _query(entity_type: str) -> str:
    # The slug is schema-checked in settings (lowercase, digits, underscores, one `__`); it is query text, not a command.
    return (
        f"MATCH (v:{entity_type}) WHERE v.data.vuln_id > $after "
        "RETURN v.data.vuln_id AS id ORDER BY id ASC LIMIT " + str(PAGE)
    )


def read_grid_ids(settings: Settings, execute: Execute | None = None) -> GridRead:
    """Every ``vuln_id`` on nodes of the configured types; a type that cannot be read is reported and skipped.

    A value that is not exactly a CVE or GHSA id is dropped here and named (at most twenty), and does not
    count toward ``MAX_IDS``: malformed values must not squeeze real ids out of the bound."""
    if execute is None:
        from tap_grid.gryphon import execute_gryphon_raw as execute  # imported late: the refresh core stays Django-free
    result = GridRead()
    seen: set[str] = set()
    scanned = 0
    refused = 0
    stop = ""
    for entity_type in settings.grid.vulnerability_types:
        after = ""
        try:
            while not stop:
                rows = execute(_query(entity_type), {"after": after}).get("rows") or []
                values = [r.get("id") for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)]
                scanned += len(rows)
                for value in values:
                    try:
                        validate_vuln_id(value)
                    except ValueError:
                        refused += 1
                        if refused <= 20:
                            result.problems.append(f"grid: not a CVE or GHSA id: {value[:80]!r}")
                        continue
                    if value not in seen:
                        if len(seen) >= MAX_IDS:
                            stop = f"grid: stopped at {MAX_IDS} ids"
                            break
                        seen.add(value)
                        result.ids.append(value)
                if scanned >= MAX_ROWS and not stop:
                    stop = f"grid: stopped after scanning {MAX_ROWS} rows"
                if stop or len(rows) < PAGE or not values or values[-1] <= after:
                    break
                after = values[-1]
        except Exception as exc:  # a type that is not installed raises; the other types and the sources go on
            result.problems.append(f"grid: {entity_type}: {type(exc).__name__}: {str(exc)[:160]}")
        if stop:
            result.problems.append(stop)
            break
    if refused > 20:
        result.problems.append(f"grid: {refused - 20} more values were not CVE or GHSA ids")
    return result
