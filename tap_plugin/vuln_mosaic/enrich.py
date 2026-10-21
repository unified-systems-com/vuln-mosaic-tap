"""What the local datasets can add to a vulnerability node already on the grid (req-vuln-mosaic-enrich).

Django-free and pure apart from reading the local stores: ``facts_for`` gathers candidate values for
one id, ``plan_patch`` decides which of them may be written onto a node that already has the values in
``current``. Nothing here touches the grid; ``collectors/refresh/gridwrite.py`` does the reading and writing.

The rules, in one place:

- A fact the node does not have yet (``None``) is filled. A fact the node has is left alone, whoever
  wrote it: another producer's value is not this plugin's to overwrite.
- The CVSS fields are one group (they describe a single metric) and are written together or not at all.
- KEV and EPSS change daily, so each is a group that is rewritten only when the local dataset is newer
  than the one the node's values came from, never because the values merely differ.
- A KEV or EPSS dataset past its staleness limit, or never checked, adds nothing: "not listed" read from an
  old catalog would be a false statement about today.
- Withdrawn advisories and rejected records add nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tap_plugin.vuln_mosaic.advisories import ParsedAdvisory
from tap_plugin.vuln_mosaic.ids import CVE_ID_RE, GHSA_ID_RE
from tap_plugin.vuln_mosaic.integrity import version_tuple
from tap_plugin.vuln_mosaic.lookup import (
    FOUND,
    LISTED,
    NOT_LISTED,
    SCORED,
    get_cve,
    get_epss,
    get_ghsa,
    get_kev,
)
from tap_plugin.vuln_mosaic.records import CvssMetric, extract_record

# Every node field this module may write. A node is read for exactly these.
FIELDS = (
    "title", "description", "published_at", "cvss_score", "cvss_vector", "cvss_version", "cvss_source",
    "cwes", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "ssvc_assessed_at",
    "kev", "kev_added", "kev_catalog_version", "kev_due_date", "kev_required_action", "kev_ransomware_use",
    "epss_score", "epss_percentile", "epss_date", "record_url", "record_updated_at",
)  # fmt: skip

CVSS_GROUP = ("cvss_score", "cvss_vector", "cvss_version", "cvss_source")
KEV_GROUP = ("kev", "kev_added", "kev_catalog_version", "kev_due_date", "kev_required_action", "kev_ransomware_use")
EPSS_GROUP = ("epss_score", "epss_percentile", "epss_date")
_GROUPED = {*CVSS_GROUP, *KEV_GROUP, *EPSS_GROUP}
MAX_TEXT = 20_000


@dataclass
class Facts:
    """Candidate values by node field name, with the dataset stamps the recency rules compare."""

    values: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _clip(value: object) -> str | None:
    return value.strip()[:MAX_TEXT] if isinstance(value, str) and value.strip() else None


def _day(value: object) -> str | None:
    """``YYYY-MM-DD`` from a date or timestamp string, else ``None``."""
    if isinstance(value, str) and len(value) >= 10 and value[4] == "-" and value[7] == "-":
        return value[:10]
    return None


def _cna_text(record: dict[str, Any]) -> tuple[str | None, str | None]:
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        return None, None
    description = None
    for entry in cna.get("descriptions") or []:
        if isinstance(entry, dict) and str(entry.get("lang", "")).lower().startswith("en"):
            description = _clip(entry.get("value"))
            break
    return _clip(cna.get("title")), description


def _score(metric: CvssMetric | None, source: str) -> dict[str, Any]:
    if metric is None or metric.base_score is None or not 0 <= metric.base_score <= 10:
        return {}
    out: dict[str, Any] = {"cvss_score": float(metric.base_score), "cvss_version": metric.version, "cvss_source": source}
    if metric.vector:
        out["cvss_vector"] = metric.vector
    return out


def _cve_facts(cve_id: str, home: Path | None, facts: Facts) -> None:
    result = get_cve(cve_id, home=home, queue=False)
    if result.state != FOUND or result.record is None:
        return
    parsed = extract_record(result.record)
    title, description = _cna_text(result.record)
    values: dict[str, Any] = {"title": title, "description": description}
    values["published_at"] = _clip(parsed.date_published)
    values["record_updated_at"] = _clip(parsed.date_updated)
    values["record_url"] = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    if parsed.cwes is not None:
        values["cwes"] = list(parsed.cwes)
    primary = next((m for m in parsed.cvss or () if m.primary), None)
    if primary is not None:
        source = "CNA" if primary.container == "cna" else primary.container
        values.update(_score(primary, source))
    if parsed.ssvc is not None:
        values["ssvc_exploitation"] = parsed.ssvc.exploitation
        values["ssvc_automatable"] = parsed.ssvc.automatable
        values["ssvc_technical_impact"] = parsed.ssvc.technical_impact
        values["ssvc_assessed_at"] = parsed.ssvc.timestamp
    facts.values.update({k: v for k, v in values.items() if v is not None})


def _kev_facts(cve_id: str, home: Path | None, facts: Facts) -> None:
    kev = get_kev(cve_id, home=home)
    if kev.state not in (LISTED, NOT_LISTED) or kev.dataset.stale is not False:
        return  # never read, never checked, or past its limit: say nothing
    version = kev.dataset.source_version
    values: dict[str, Any] = {"kev": kev.state == LISTED}
    if version:
        values["kev_catalog_version"] = version
    if kev.entry:
        values.update(
            kev_added=_day(kev.entry.get("dateAdded")),
            kev_due_date=_day(kev.entry.get("dueDate")),
            kev_required_action=_clip(kev.entry.get("requiredAction")),
            kev_ransomware_use=_clip(kev.entry.get("knownRansomwareCampaignUse")),
        )
    facts.values.update({k: v for k, v in values.items() if v is not None})


def _epss_facts(cve_id: str, home: Path | None, facts: Facts) -> None:
    epss = get_epss(cve_id, home=home)
    if epss.state != SCORED or epss.dataset.stale is not False or epss.epss is None or epss.percentile is None:
        return  # the group is written whole: a score without its percentile would leave a mixed observation
    day = _day(epss.score_date)
    if day is None:
        return  # an undated score cannot be compared with the node's, so it is not written
    facts.values.update({"epss_score": epss.epss, "epss_percentile": epss.percentile, "epss_date": day})


def _advisory_facts(ghsa_id: str, home: Path | None, facts: Facts) -> None:
    result = get_ghsa(ghsa_id, home=home, queue=False)
    advisory: ParsedAdvisory | None = result.advisory
    if result.state != FOUND or advisory is None:
        return  # not held, or withdrawn: a withdrawn advisory is not presented as live
    values: dict[str, Any] = {
        "title": _clip(advisory.summary),
        "description": _clip(advisory.details),
        "published_at": _clip(advisory.published),
        "record_updated_at": _clip(advisory.modified),
        "record_url": f"https://github.com/advisories/{ghsa_id}",
        "cwes": list(advisory.cwe_ids),
    }
    values.update(_score(advisory.best_cvss, "GitHub advisory"))
    facts.values.update({k: v for k, v in values.items() if v is not None})


def facts_for(vuln_id: str, home: Path | None = None) -> Facts:
    """Everything the local datasets hold about ``vuln_id`` that a node could carry. Reads, never writes."""
    facts = Facts()
    if CVE_ID_RE.fullmatch(vuln_id):
        _cve_facts(vuln_id, home, facts)
        _kev_facts(vuln_id, home, facts)
        _epss_facts(vuln_id, home, facts)
    elif GHSA_ID_RE.fullmatch(vuln_id):
        _advisory_facts(vuln_id, home, facts)
    return facts


def _newer(ours: object, theirs: object) -> bool:
    """True when ``ours`` sorts after ``theirs``. Versions and ISO dates compare as strings; either missing is False."""
    return isinstance(ours, str) and isinstance(theirs, str) and ours > theirs


def _newer_version(ours: object, theirs: object) -> bool:
    """True when dotted-integer version ``ours`` is above ``theirs``, compared as the KEV refresh compares them.

    A version that is not dotted integers is never newer: it cannot be ordered, so it moves nothing."""
    try:
        return version_tuple(str(ours)) > version_tuple(str(theirs))
    except (ValueError, TypeError):
        return False


def _group_may_move(
    current: Mapping[str, Any], group: tuple[str, ...], stamp: str, ours: object, newer: Callable[[object, object], bool] = _newer
) -> bool:
    """A KEV or EPSS group is written when the node has none of it, or when ours is stamped newer than theirs.

    A node with part of a group but no stamp is another writer's and is left, and a node stamped newer than
    our dataset is never moved back, whatever else it lacks."""
    theirs = current.get(stamp)
    if theirs is not None:
        return newer(ours, theirs)
    return all(current.get(name) is None for name in group)


def plan_patch(current: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    """The fields to write onto a node whose present values are ``current``; empty when there is nothing to add."""
    patch: dict[str, Any] = {}
    for name in FIELDS:
        if name in _GROUPED or name not in facts or facts[name] is None:
            continue
        if current.get(name) is None:
            patch[name] = facts[name]
    if all(name in facts for name in CVSS_GROUP) and all(current.get(name) is None for name in CVSS_GROUP):
        patch.update({name: facts[name] for name in CVSS_GROUP if name in facts})
    if "kev" in facts and _group_may_move(current, KEV_GROUP, "kev_catalog_version", facts.get("kev_catalog_version"), _newer_version):
        group = {name: facts[name] for name in KEV_GROUP if name in facts}
        # The group is one observation of one catalog: a detail this catalog does not carry (a delisting,
        # or a listing without a due date) is cleared, never left from an earlier catalog's entry.
        group.update({name: None for name in KEV_GROUP if name != "kev" and name not in group and current.get(name) is not None})
        if any(current.get(name) != value for name, value in group.items()):
            patch.update(group)
    if all(name in facts for name in EPSS_GROUP) and _group_may_move(current, EPSS_GROUP, "epss_date", facts.get("epss_date")):
        group = {name: facts[name] for name in EPSS_GROUP if name in facts}
        if any(current.get(name) != value for name, value in group.items()):
            patch.update(group)
    return patch
