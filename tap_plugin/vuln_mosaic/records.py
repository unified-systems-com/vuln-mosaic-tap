"""Parse a stored CVE Record v5 into the facts consumers want (req-vuln-mosaic-records).

Standard library only (req-vuln-mosaic-records-4). Parsing happens at read time over the stored
record; nothing here changes what is kept. ``None`` is unobserved (the container or field is
not in the record); an empty list is observed-empty.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CISA_ADP = "CISA-ADP"
# Newest first: within one container the most recent scoring version is preferred as primary.
_CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))


@dataclass(frozen=True)
class CvssMetric:
    container: str
    version: str
    base_score: float | None
    severity: str | None
    vector: str | None
    primary: bool = False


@dataclass(frozen=True)
class Ssvc:
    exploitation: str | None
    automatable: str | None
    technical_impact: str | None
    version: str | None
    timestamp: str | None


@dataclass(frozen=True)
class ParsedRecord:
    cve_id: str | None
    state: str | None
    date_published: str | None
    date_updated: str | None
    cvss: tuple[CvssMetric, ...] | None
    cwes: tuple[str, ...] | None
    ssvc: Ssvc | None
    affected: tuple[dict[str, Any], ...] | None
    references: tuple[str, ...] | None


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _adp_containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    adp = _as_dict(record.get("containers")).get("adp")
    return [c for c in adp if isinstance(c, dict)] if isinstance(adp, list) else []


def _cisa_adp(record: dict[str, Any]) -> dict[str, Any] | None:
    for container in _adp_containers(record):
        if _as_dict(container.get("providerMetadata")).get("shortName") == CISA_ADP:
            return container
    return None


def _cvss_from(container: dict[str, Any] | None, name: str) -> list[CvssMetric] | None:
    if container is None:
        return None
    metrics = container.get("metrics")
    if not isinstance(metrics, list):
        return None
    found: list[CvssMetric] = []
    for entry in metrics:
        if not isinstance(entry, dict):
            continue
        for key, version in _CVSS_KEYS:
            block = entry.get(key)
            if isinstance(block, dict):
                found.append(
                    CvssMetric(
                        container=name,
                        version=str(block.get("version", version)),
                        base_score=block.get("baseScore"),
                        severity=block.get("baseSeverity"),
                        vector=block.get("vectorString"),
                    )
                )
    return found


def _cwes_from(container: dict[str, Any] | None) -> list[str] | None:
    if container is None:
        return None
    problem_types = container.get("problemTypes")
    if not isinstance(problem_types, list):
        return None
    cwes: list[str] = []
    for problem in problem_types:
        for description in _as_dict(problem).get("descriptions", []) or []:
            cwe = _as_dict(description).get("cweId")
            if isinstance(cwe, str) and cwe not in cwes:
                cwes.append(cwe)
    return cwes


def _ssvc(container: dict[str, Any] | None) -> Ssvc | None:
    if container is None:
        return None
    for metric in container.get("metrics", []) or []:
        other = _as_dict(_as_dict(metric).get("other"))
        if other.get("type") != "ssvc":
            continue
        content = _as_dict(other.get("content"))
        points: dict[str, str] = {}
        for option in content.get("options", []) or []:
            if isinstance(option, dict):
                for key, value in option.items():
                    if isinstance(value, str):
                        points[key] = value
        return Ssvc(
            exploitation=points.get("Exploitation"),
            automatable=points.get("Automatable"),
            technical_impact=points.get("Technical Impact"),
            version=content.get("version"),
            timestamp=content.get("timestamp"),
        )
    return None


def extract_record(record: dict[str, Any]) -> ParsedRecord:
    meta = _as_dict(record.get("cveMetadata"))
    containers = _as_dict(record.get("containers"))
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else None
    adp = _cisa_adp(record)

    cna_cvss = _cvss_from(cna, "cna")
    adp_cvss = _cvss_from(adp, CISA_ADP)
    cvss: tuple[CvssMetric, ...] | None
    if cna_cvss is None and adp_cvss is None:
        cvss = None
    else:
        combined = [*(cna_cvss or []), *(adp_cvss or [])]
        cvss = tuple(
            CvssMetric(m.container, m.version, m.base_score, m.severity, m.vector, primary=(i == 0))
            for i, m in enumerate(combined)
        )

    cna_cwes, adp_cwes = _cwes_from(cna), _cwes_from(adp)
    if cna_cwes is None and adp_cwes is None:
        cwes = None
    elif cna_cwes:
        cwes = tuple(cna_cwes)
    else:
        cwes = tuple(adp_cwes or [])

    affected = cna.get("affected") if cna else None
    refs = cna.get("references") if cna else None
    return ParsedRecord(
        cve_id=meta.get("cveId"),
        state=meta.get("state"),
        date_published=meta.get("datePublished"),
        date_updated=meta.get("dateUpdated"),
        cvss=cvss,
        cwes=cwes,
        ssvc=_ssvc(adp),
        affected=tuple(a for a in affected if isinstance(a, dict)) if isinstance(affected, list) else None,
        references=(
            tuple(r["url"] for r in refs if isinstance(r, dict) and isinstance(r.get("url"), str))
            if isinstance(refs, list)
            else None
        ),
    )
