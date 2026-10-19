"""Parse a stored GitHub advisory (OSV format) into the facts consumers want (req-vuln-mosaic-ghsa-4).

Standard library only. Parsing happens at read time over the stored record. ``None`` is unobserved
(the field is not in the record); an empty tuple is observed-empty. A CVSS metric whose vector is
not v3.0 or v3.1 keeps its vector and reports ``base_score = None``: the score is never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tap_plugin.vuln_mosaic import cvss
from tap_plugin.vuln_mosaic.ids import CVE_ID_RE
from tap_plugin.vuln_mosaic.records import CvssMetric, Reference

_TYPE_VERSION = {"CVSS_V2": "2.0", "CVSS_V3": None, "CVSS_V4": "4.0"}
_PREFERRED = ("3.1", "3.0")


@dataclass(frozen=True)
class AdvisoryPackage:
    ecosystem: str | None
    name: str | None
    introduced: tuple[str, ...]
    fixed: tuple[str, ...]  # range ends only (OSV ``fixed`` events); never ``last_affected``


@dataclass(frozen=True)
class ParsedAdvisory:
    ghsa_id: str
    aliases: tuple[str, ...]
    cve_ids: tuple[str, ...]  # the aliases that are CVE ids, in the order the advisory lists them
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    withdrawn: str | None
    reviewed: bool | None  # database_specific.github_reviewed; None when the record does not say
    severity_label: str | None  # GitHub's own rating (LOW, MODERATE, HIGH, CRITICAL)
    cwe_ids: tuple[str, ...]
    cvss: tuple[CvssMetric, ...]
    references: tuple[Reference, ...]
    packages: tuple[AdvisoryPackage, ...]

    @property
    def best_cvss(self) -> CvssMetric | None:
        """The metric a chart should show: a scored v3.1, then a scored v3.0, else ``None``.

        A v4 or v2 vector never stands in for a v3 score; it stays in ``cvss`` for a consumer that
        wants it, and this returns ``None`` when only those exist.
        """
        for version in _PREFERRED:
            for metric in self.cvss:
                if metric.version == version and metric.base_score is not None:
                    return metric
        return None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _metric(entry: object) -> CvssMetric | None:
    if not isinstance(entry, dict):
        return None
    vector = _text(entry.get("score"))
    kind = entry.get("type")
    if vector is None or kind not in _TYPE_VERSION:
        return None
    if vector.startswith("CVSS:3."):
        version = vector.split("/", 1)[0][5:]
    else:
        version = _TYPE_VERSION[kind]
    score = cvss.base_score(vector)
    return CvssMetric(
        container="ghsa",
        version=version or "3.x",
        base_score=score,
        severity=cvss.severity(score) if score is not None else None,
        vector=vector,
    )


def _packages(value: object) -> tuple[AdvisoryPackage, ...]:
    out: list[AdvisoryPackage] = []
    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        introduced: list[str] = []
        fixed: list[str] = []
        for rng in entry.get("ranges") if isinstance(entry.get("ranges"), list) else []:
            for event in rng.get("events", []) if isinstance(rng, dict) else []:
                if not isinstance(event, dict):
                    continue
                if isinstance(event.get("introduced"), str):
                    introduced.append(event["introduced"])
                if isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"])
        out.append(AdvisoryPackage(_text(package.get("ecosystem")), _text(package.get("name")),
                                   tuple(introduced), tuple(fixed)))
    return tuple(out)


def extract_advisory(record: dict[str, Any]) -> ParsedAdvisory:
    """The facts of one OSV-format advisory; tolerant of absent fields, strict about none."""
    aliases = _strings(record.get("aliases"))
    severity = record.get("severity") if isinstance(record.get("severity"), list) else []
    metrics = tuple(m for m in (_metric(e) for e in severity) if m)
    meta = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
    refs: list[Reference] = []
    for ref in record.get("references", []) if isinstance(record.get("references"), list) else []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            kind = _text(ref.get("type"))
            refs.append(Reference(ref["url"], (kind.lower(),) if kind else ()))
    reviewed = meta.get("github_reviewed")
    return ParsedAdvisory(
        ghsa_id=str(record.get("id", "")),
        aliases=aliases,
        cve_ids=tuple(a for a in aliases if CVE_ID_RE.fullmatch(a)),
        summary=_text(record.get("summary")),
        details=_text(record.get("details")),
        published=_text(record.get("published")),
        modified=_text(record.get("modified")),
        withdrawn=_text(record.get("withdrawn")),
        reviewed=reviewed if isinstance(reviewed, bool) else None,
        severity_label=_text(meta.get("severity")),
        cwe_ids=_strings(meta.get("cwe_ids")),
        cvss=metrics,
        references=tuple(refs),
        packages=_packages(record.get("affected")),
    )
