"""Verify before apply, fail closed (req-vuln-mosaic-integrity).

Nothing upstream is signed, so these checks prove shape and transport integrity, never the
publisher's identity. Every validator raises ``IntegrityError`` with a reason and has no side
effect, so a caller can quarantine or refuse without having applied anything.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from tap_plugin.vuln_mosaic.ids import CVE_ID_RE
from tap_plugin.vuln_mosaic.staleness import parse_time, utcnow

MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_ZIP_MEMBERS = 1_000_000
MAX_ZIP_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
MAX_EPSS_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
ZIP_MEMBER_RE = re.compile(r"^[A-Za-z0-9_.-]+\.json$")
CVE_STATES = frozenset({"PUBLISHED", "REJECTED"})


class IntegrityError(ValueError):
    """A fetched item failed verification; ``str(exc)`` is the reason."""


@dataclass(frozen=True)
class CheckedRecord:
    cve_id: str
    state: str
    date_updated: str | None


def _loads_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RECORD_BYTES:
        raise IntegrityError(f"record larger than {MAX_RECORD_BYTES} bytes")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise IntegrityError(f"not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise IntegrityError("record is not a JSON object")
    return value


def check_cve_record(raw: bytes, expected_id: str) -> CheckedRecord:
    """CVE Record v5 shape: type, major version, id, state (req-vuln-mosaic-integrity-1)."""
    record = _loads_object(raw)
    if record.get("dataType") != "CVE_RECORD":
        raise IntegrityError(f"dataType is {record.get('dataType')!r}, not CVE_RECORD")
    version = str(record.get("dataVersion", ""))
    if version.split(".")[0] != "5":
        raise IntegrityError(f"dataVersion {version!r} is not major 5")
    meta = record.get("cveMetadata")
    if not isinstance(meta, dict):
        raise IntegrityError("cveMetadata missing")
    cve_id = meta.get("cveId")
    if cve_id != expected_id:
        raise IntegrityError(f"cveId {cve_id!r} does not match the requested key {expected_id!r}")
    state = meta.get("state")
    if state not in CVE_STATES:
        raise IntegrityError(f"state {state!r} is not PUBLISHED or REJECTED")
    updated = meta.get("dateUpdated")
    return CheckedRecord(expected_id, state, updated if isinstance(updated, str) else None)


def check_nvd_object(raw: bytes, expected_id: str) -> CheckedRecord:
    """NVD API 2.0 vulnerability object: its own rules, not CVE Record v5 (req-vuln-mosaic-integrity-5)."""
    item = _loads_object(raw)
    cve = item.get("cve")
    if not isinstance(cve, dict):
        raise IntegrityError("NVD object has no 'cve' member")
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
        raise IntegrityError(f"NVD id {cve_id!r} is not a CVE id")
    if cve_id != expected_id:
        raise IntegrityError(f"NVD id {cve_id!r} does not match the requested key {expected_id!r}")
    status = cve.get("vulnStatus")
    if not isinstance(status, str):
        raise IntegrityError("NVD vulnStatus is not a string")
    modified = cve.get("lastModified")
    return CheckedRecord(expected_id, status, modified if isinstance(modified, str) else None)


def version_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        raise IntegrityError(f"version {value!r} is not dotted integers") from None


@dataclass(frozen=True)
class KevCatalog:
    catalog_version: str
    date_released: str
    count: int


def check_kev(raw: bytes, installed_version: str | None, now: datetime | None = None) -> KevCatalog:
    """KEV catalog: shape, count, ids, no rollback, no future release (req-vuln-mosaic-kev-2)."""
    catalog = _loads_object_large(raw)
    try:
        version, released, count = catalog["catalogVersion"], catalog["dateReleased"], catalog["count"]
        vulns = catalog["vulnerabilities"]
    except KeyError as exc:
        raise IntegrityError(f"catalog lacks {exc.args[0]!r}") from None
    if not isinstance(vulns, list) or not isinstance(count, int) or len(vulns) != count:
        raise IntegrityError("catalog count does not equal the number of vulnerabilities")
    for entry in vulns:
        cve_id = entry.get("cveID") if isinstance(entry, dict) else None
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            raise IntegrityError(f"catalog entry has a bad cveID {cve_id!r}")
    incoming = version_tuple(str(version))  # dotted integers only: the value later becomes a directory name
    if installed_version is not None and incoming < version_tuple(installed_version):
        raise IntegrityError(f"catalogVersion {version} is lower than installed {installed_version}")
    released_at = parse_time(str(released))
    if released_at is None or released_at > (now or utcnow()):
        raise IntegrityError(f"dateReleased {released!r} is in the future or unparseable")
    return KevCatalog(str(version), str(released), count)


def _loads_object_large(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise IntegrityError(f"not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise IntegrityError("document is not a JSON object")
    return value


@dataclass(frozen=True)
class EpssFile:
    model_version: str
    score_date: str
    rows: int


_EPSS_HEADER = ["cve", "epss", "percentile"]
_EPSS_FIRST = re.compile(r"^#model_version:([^,]+),score_date:(\S+)$")


def check_epss(gz_path: Path, installed_score_date: str | None, now: datetime | None = None) -> EpssFile:
    """EPSS scores: read in full, streamed (req-vuln-mosaic-epss-2)."""
    try:
        with gzip.open(gz_path, "rb") as raw:
            bounded = _BoundedReader(raw, MAX_EPSS_UNCOMPRESSED_BYTES)
            text = io.TextIOWrapper(bounded, encoding="utf-8", newline="")
            first = text.readline().strip()
            match = _EPSS_FIRST.match(first)
            if not match:
                raise IntegrityError("EPSS first line is not '#model_version:…,score_date:…'")
            model_version, score_date = match.group(1), match.group(2)
            reader = csv.reader(text)
            if next(reader, None) != _EPSS_HEADER:
                raise IntegrityError("EPSS header is not cve,epss,percentile")
            rows = _check_epss_rows(reader)
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise IntegrityError(f"EPSS file unreadable: {exc}") from None
    scored = parse_time(score_date)
    if scored is None or scored > (now or utcnow()):
        raise IntegrityError(f"score_date {score_date!r} is in the future or unparseable")
    installed = parse_time(installed_score_date)
    if installed is not None and scored < installed:
        raise IntegrityError(f"score_date {score_date} is earlier than installed {installed_score_date}")
    return EpssFile(model_version, score_date, rows)


def _check_epss_rows(reader: Iterable[list[str]]) -> int:
    count = 0
    for row in reader:
        if len(row) != 3 or not CVE_ID_RE.fullmatch(row[0]):
            raise IntegrityError(f"EPSS row {count + 1} is malformed")
        try:
            epss, percentile = float(row[1]), float(row[2])
        except ValueError:
            raise IntegrityError(f"EPSS row {count + 1} has a non-numeric score") from None
        if not (0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0):
            raise IntegrityError(f"EPSS row {count + 1} has a score outside [0, 1]")
        count += 1
    return count


class _BoundedReader(io.RawIOBase):
    """Refuse a decompression bomb: stop after ``limit`` uncompressed bytes."""

    def __init__(self, inner: IO[bytes], limit: int) -> None:
        self._inner, self._left = inner, limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._inner.read(min(len(buffer), 1 << 20))
        self._left -= len(data)
        if self._left < 0:
            raise IntegrityError("decompressed size exceeds the bound")
        buffer[: len(data)] = data
        return len(data)


def check_osv_zip(path: Path) -> int:
    """OSV ecosystem zip: caps, member names, every member parsed in a stream (req-vuln-mosaic-integrity-3)."""
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise IntegrityError(f"zip has {len(infos)} members, more than {MAX_ZIP_MEMBERS}")
            if sum(i.file_size for i in infos) > MAX_ZIP_TOTAL_BYTES:
                raise IntegrityError("zip expands past the total size bound")
            for info in infos:
                if info.is_dir() or not ZIP_MEMBER_RE.fullmatch(info.filename) or ".." in info.filename:
                    raise IntegrityError(f"zip member name {info.filename!r} is not allowed")
                if info.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise IntegrityError(f"zip member {info.filename!r} is larger than the per-member bound")
            for info in infos:
                with archive.open(info) as member:
                    body = member.read(MAX_ZIP_MEMBER_BYTES + 1)
                if len(body) > MAX_ZIP_MEMBER_BYTES:
                    raise IntegrityError(f"zip member {info.filename!r} expands past the per-member bound")
                try:
                    json.loads(body)
                except ValueError:
                    raise IntegrityError(f"zip member {info.filename!r} is not valid JSON") from None
            return len(infos)
    except zipfile.BadZipFile as exc:
        raise IntegrityError(f"not a valid zip: {exc}") from None
    except OSError as exc:
        raise IntegrityError(f"zip unreadable: {exc}") from None
