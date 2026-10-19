"""The SQLite record stores for ``cvelist`` and ``nvd`` (req-vuln-mosaic-store).

One file per source, one writer (the holder of ``writer_lock``), readers need no lock.
Records are kept exactly as received, gzipped (req-vuln-mosaic-store-1).
"""

from __future__ import annotations

import gzip
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from tap_plugin.vuln_mosaic.staleness import DatasetFacts, to_iso, utcnow

RECORD_SOURCES = ("cvelist", "nvd")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records(
    id TEXT PRIMARY KEY, state TEXT NOT NULL, date_updated TEXT, record_gz BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wanted(
    id TEXT PRIMARY KEY, first_wanted TEXT NOT NULL, origin TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quarantine(
    id TEXT NOT NULL, seen_at TEXT NOT NULL, reason TEXT NOT NULL);
"""

_FACT_KEYS = ("as_of", "checked_at", "source_version", "fetched_at")


def store_path(home: Path, source: str) -> Path:
    if source not in RECORD_SOURCES:
        raise ValueError(f"not a record source: {source!r}")
    return home / "stores" / f"{source}.sqlite"


def compress(raw: bytes) -> bytes:
    # mtime=0 keeps the stored bytes a function of the record alone.
    return gzip.compress(raw, compresslevel=6, mtime=0)


@dataclass(frozen=True)
class StoredRecord:
    id: str
    state: str
    date_updated: str | None
    raw: bytes


class RecordStore:
    """A connection to one source's store. Use ``open_writer`` or ``open_reader``."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @classmethod
    def open_writer(cls, home: Path, source: str) -> RecordStore:
        path = store_path(home, source)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return cls(conn)

    @classmethod
    def open_reader(cls, home: Path, source: str) -> RecordStore | None:
        """Open read-only, or ``None`` when no store exists yet (a fresh or recreated container)."""
        path = store_path(home, source)
        if not path.is_file():
            return None
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10, isolation_level=None)
            conn.execute("SELECT 1 FROM records LIMIT 1")
        except sqlite3.Error:
            return None
        return cls(conn)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> RecordStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """All-or-nothing: an exception rolls the whole batch back (req-vuln-mosaic-integrity)."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    # records
    def get(self, cve_id: str) -> StoredRecord | None:
        row = self._conn.execute(
            "SELECT id, state, date_updated, record_gz FROM records WHERE id = ?", (cve_id,)
        ).fetchone()
        if row is None:
            return None
        return StoredRecord(row[0], row[1], row[2], gzip.decompress(row[3]))

    def put(self, cve_id: str, state: str, date_updated: str | None, raw: bytes) -> None:
        self._conn.execute(
            "INSERT INTO records(id, state, date_updated, record_gz) VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET state=excluded.state, "
            "date_updated=excluded.date_updated, record_gz=excluded.record_gz",
            (cve_id, state, date_updated, compress(raw)),
        )

    def delete(self, cve_id: str) -> None:
        self._conn.execute("DELETE FROM records WHERE id = ?", (cve_id,))

    def held_ids(self) -> set[str]:
        return {r[0] for r in self._conn.execute("SELECT id FROM records")}

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    # meta
    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def facts(self) -> DatasetFacts:
        return DatasetFacts(**{k: self.get_meta(k) for k in _FACT_KEYS})

    def set_facts(self, **facts: str | None) -> None:
        for key, value in facts.items():
            if key not in _FACT_KEYS:
                raise ValueError(f"unknown dataset fact {key!r}")
            if value is not None:
                self.set_meta(key, value)

    # wanted
    def add_wanted(self, cve_id: str, origin: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO wanted(id, first_wanted, origin) VALUES(?,?,?)",
            (cve_id, to_iso(utcnow()), origin),
        )

    def wanted_ids(self) -> set[str]:
        return {r[0] for r in self._conn.execute("SELECT id FROM wanted")}

    # quarantine
    def quarantine(self, cve_id: str, reason: str) -> None:
        """Record a refusal once per (id, reason): a retried failure does not grow the table."""
        self._conn.execute(
            "INSERT INTO quarantine(id, seen_at, reason) SELECT ?,?,? "
            "WHERE NOT EXISTS (SELECT 1 FROM quarantine WHERE id = ? AND reason = ?)",
            (cve_id, to_iso(utcnow()), reason, cve_id, reason),
        )

    def quarantined(self) -> list[tuple[str, str]]:
        return [(r[0], r[2]) for r in self._conn.execute("SELECT id, seen_at, reason FROM quarantine")]


def fetch_record(home: Path, source: str, cve_id: str) -> tuple[StoredRecord | None, DatasetFacts]:
    """Read one record and the dataset facts; an absent store reads as not fetched, never raises."""
    reader = RecordStore.open_reader(home, source)
    if reader is None:
        return None, DatasetFacts()
    with closing(reader):
        return reader.get(cve_id), reader.facts()
