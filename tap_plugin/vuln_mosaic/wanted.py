"""The wanted-ids contract: consumer files and the request spool (req-vuln-mosaic-wanted)."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema

from tap_plugin.vuln_mosaic.ids import GHSA_ID_RE, validate_vuln_id
from tap_plugin.vuln_mosaic.settings import load_schema
from tap_plugin.vuln_mosaic.store import RecordStore

CONSUMER_FILE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\.json$")
MAX_WANTED_FILE_BYTES = 8 * 1024 * 1024


@dataclass
class WantedScan:
    ids: set[str] = field(default_factory=set)  # CVE ids
    ghsa_ids: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)


def _read_regular(path: Path, limit: int) -> bytes:
    """Read a regular file without following a symlink in the final component."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError(f"larger than {limit} bytes")
    return data


def scan_wanted_files(home: Path) -> WantedScan:
    """Union of every valid ``wanted/<consumer>.json``; each bad entry is named, none aborts the scan."""
    scan = WantedScan()
    directory = home / "wanted"
    if directory.is_symlink():
        scan.problems.append("wanted/: the directory is a symlink, ignored")
        return scan
    try:
        entries = sorted(os.scandir(directory), key=lambda e: e.name)
    except FileNotFoundError:
        return scan
    schema = load_schema("wanted.schema.json")
    for entry in entries:
        name = entry.name
        if not CONSUMER_FILE_RE.fullmatch(name):
            scan.problems.append(f"wanted/{name!r}: name is not a valid consumer file name")
            continue
        if entry.is_symlink():
            scan.problems.append(f"wanted/{name}: is a symlink, ignored")
            continue
        try:
            document = json.loads(_read_regular(Path(entry.path), MAX_WANTED_FILE_BYTES))
            jsonschema.validate(document, schema)
        except (OSError, ValueError, jsonschema.ValidationError) as exc:
            scan.problems.append(f"wanted/{name}: invalid ({str(exc).splitlines()[0][:160]})")
            continue
        for value in document["ids"]:
            (scan.ghsa_ids if GHSA_ID_RE.fullmatch(value) else scan.ids).add(value)
    return scan


MAX_SPOOL = 5000


def request_id(home: Path, vuln_id: str) -> bool:
    """Queue an id for the next refresh. ``O_EXCL`` makes concurrent requests one file.

    The spool is bounded (``MAX_SPOOL`` entries): a read-triggered write must not let a viewer grow
    the directory, or the next refresh's fetch set, without limit. At the cap nothing is created and
    ``False`` is returned; the id is simply not queued.
    """
    validate_vuln_id(vuln_id)
    spool = home / "spool"
    spool.mkdir(parents=True, exist_ok=True)
    try:
        queued = sum(1 for _ in os.scandir(spool))
    except OSError:
        queued = 0
    if queued >= MAX_SPOOL:
        return False
    try:
        fd = os.open(spool / vuln_id, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return False
    os.close(fd)
    return True


def ingest_spool(home: Path, store: RecordStore, *, kind: str = "cve") -> list[str]:
    """Move spooled ids of ``kind`` (``cve`` or ``ghsa``) into the ``wanted`` table and remove their files.

    Bad names, and ids of the other kind, are left alone for the store that owns them."""
    spool = home / "spool"
    taken: list[str] = []
    try:
        names = sorted(e.name for e in os.scandir(spool) if e.is_file(follow_symlinks=False))
    except FileNotFoundError:
        return taken
    for name in names:
        try:
            vuln_id = validate_vuln_id(name)
        except ValueError:
            continue
        if bool(GHSA_ID_RE.fullmatch(vuln_id)) != (kind == "ghsa"):
            continue
        store.add_wanted(vuln_id, "spool")
        os.unlink(spool / name)
        taken.append(vuln_id)
    return taken


MAX_GRID_WANTED = 200_000  # grid-origin rows one store may hold in total, across every run


def ingest_grid(store: RecordStore, ids: Iterable[str], *, kind: str = "cve") -> tuple[int, list[str]]:
    """Add grid-supplied ids of ``kind`` to the ``wanted`` table; return (taken, problems).

    The grid is outside the trust boundary: a value that is not exactly a CVE or GHSA id is refused and
    named, never stored, and nothing here places an id on a command line. Grid-origin rows are bounded
    in total (``MAX_GRID_WANTED``), so ids rotated between runs cannot ratchet the table without limit."""
    taken, problems = 0, []
    room = MAX_GRID_WANTED - store.wanted_count("grid")
    full = False
    for value in ids:
        try:
            vuln_id = validate_vuln_id(value)
        except ValueError:
            if len(problems) < 20:
                problems.append(f"grid: not a CVE or GHSA id: {value!r:.80}")
            continue
        if bool(GHSA_ID_RE.fullmatch(vuln_id)) != (kind == "ghsa"):
            continue
        if store.is_wanted(vuln_id):
            continue
        if room <= 0:
            full = True
            continue
        store.add_wanted(vuln_id, "grid")
        room -= 1
        taken += 1
    if full:
        problems.append(f"grid: not all ids were added, {MAX_GRID_WANTED} grid-origin wanted ids is the bound")
    return taken, problems


def wanted_set(scan: WantedScan, store: RecordStore, *, kind: str = "cve") -> set[str]:
    """Consumer files, the wanted table and every id already held (req-vuln-mosaic-wanted-5)."""
    return (scan.ghsa_ids if kind == "ghsa" else scan.ids) | store.wanted_ids() | store.held_ids()
