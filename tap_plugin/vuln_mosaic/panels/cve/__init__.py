"""vuln-mosaic-cve — one CVE, everything the local datasets hold about it (req-vuln-mosaic-panel-cve).

Reads ``get_cve``, ``get_kev`` and ``get_epss`` inside the request: the stores are local files, so no
network call is made while the page renders. The panel states facts in structured sections and
writes no narrative.

Disciplines this panel keeps:

- **Unobserved is not fresh.** A dataset with no ``checked_at`` reads "unobserved", never "fresh".
- **Absence is rendered, never blanked.** ``not-fetched`` shows a placeholder and the id is queued for
  the next refresh (``get_cve`` does that); ``not-listed`` in KEV says the catalog held does not list it.
- **Range ends are not remediation advice.** Only ``fixed_versions`` is shown; ``unaffected_versions``
  (which can predate the vulnerable range) is never presented as a fix.
- **Links only for ids the source owns.** A link is built for an id of the matching shape; an
  untrusted reference URL is linked only if it is http or https.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlsplit

import jsonschema

from tap_plugin.vuln_mosaic.ids import CVE_ID_RE
from tap_plugin.vuln_mosaic.lookup import get_cve, get_epss, get_kev
from tap_plugin.vuln_mosaic.panels.cve.cvss_text import AFFECTED_NOTE, explain_vector
from tap_plugin.vuln_mosaic.records import extract_record

if TYPE_CHECKING:
    from django.http import HttpRequest

    from tap_web.models import Panel

logger = logging.getLogger(__name__)

DEFAULT_VULN_VAR = "vuln_id"
# Render order is fixed; the ``sections`` config chooses which of these appear. Absent means all of them.
SECTIONS = ("header", "cards", "cvss", "cvss_breakdown", "affected", "references", "freshness")
DEFAULT_SECTIONS = ("header", "cards", "cvss", "affected", "references", "freshness")
GHSA_RE = re.compile(r"^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$")

CVE_PANEL_CONFIG_SCHEMA: dict[str, Any] = {
    "description": (
        "Config of a vuln-mosaic-cve panel: which query parameter carries the vulnerability id and how much "
        "of each list to show. Everything else the panel shows comes from the local datasets."
    ),
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "vuln_id_var": {
            "description": "Name of the page query parameter that holds the CVE or GHSA id. Default vuln_id.",
            "type": "string",
            "minLength": 1,
        },
        "hide_header": {
            "description": "True hides the panel header bar.",
            "type": "boolean",
        },
        "queue_misses": {
            "description": (
                "True (the default) queues an id the stores do not hold for the next refresh, which writes one "
                "small file per distinct id (bounded). False makes the panel purely read-only."
            ),
            "type": "boolean",
        },
        "sections": {
            "description": (
                "Which sections render, from header, cards, cvss, cvss_breakdown, affected, references and "
                "freshness. The page order is fixed, not the order given. Absent means header, cards, cvss, "
                "affected, references and freshness (cvss_breakdown, the plain-English table of the primary "
                "CVSS metric, is opt-in)."
            ),
            "type": "array",
            "items": {"description": "One section name.", "enum": list(SECTIONS)},
            "uniqueItems": True,
            "minItems": 1,
        },
        "max_references_per_tag": {
            "description": "How many reference links to list under each tag before the rest are counted. Default 8.",
            "type": "integer",
            "minimum": 1,
        },
    },
}

#: Metric names for the CVSS vector keys, so a chip reads "Attack Vector N" and not a bare "AV:N".
METRIC_NAMES = {
    "AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required", "UI": "User Interaction",
    "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability", "AT": "Attack Requirements",
    "VC": "Vulnerable Confidentiality", "VI": "Vulnerable Integrity", "VA": "Vulnerable Availability",
    "SC": "Subsequent Confidentiality", "SI": "Subsequent Integrity", "SA": "Subsequent Availability",
    "Au": "Authentication",
}

#: Tone per CVSS severity: red for the loud ones, yellow for medium, grey for the rest (the stat-card palette).
SEVERITY_TONE = {"CRITICAL": "bad", "HIGH": "bad", "MEDIUM": "warn", "LOW": "neutral", "NONE": "neutral"}

LINKS = {
    "kev_catalog": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "epss": "https://www.first.org/epss/",
}


def classify(vuln_id: str) -> str:
    """``cve``, ``ghsa`` or ``other``: which source family owns this id's shape."""
    if CVE_ID_RE.fullmatch(vuln_id):
        return "cve"
    if GHSA_RE.fullmatch(vuln_id):
        return "ghsa"
    return "other"


def external_links(vuln_id: str, kind: str) -> list[dict[str, str]]:
    """Outside links, only for the sources that own this kind of id."""
    if kind == "cve":
        return [
            {"label": "CVE.org", "url": f"https://www.cve.org/CVERecord?id={vuln_id}"},
            {"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"},
            {"label": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"},
        ]
    if kind == "ghsa":
        return [
            {"label": "GitHub advisory", "url": f"https://github.com/advisories/{vuln_id}"},
            {"label": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"},
        ]
    return []


def safe_url(url: str) -> str | None:
    """Return ``url`` only if it is http(s); a reference in a CVE record is untrusted text."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return url if parts.scheme in ("http", "https") and parts.netloc else None


def vector_chips(vector: str | None) -> list[dict[str, str]]:
    """Split a CVSS vector into metric chips; the leading ``CVSS:x.y`` is the version, not a metric."""
    if not vector:
        return []
    chips = []
    for part in vector.split("/"):
        key, _, value = part.partition(":")
        if not value or key == "CVSS":
            continue
        chips.append({"key": key, "name": METRIC_NAMES.get(key, key), "value": value})
    return chips


def dataset_row(label: str, info: Any) -> dict[str, Any]:
    stale = info.stale
    return {
        "label": label,
        "as_of": info.as_of,
        "checked_at": info.checked_at,
        "source_version": (info.source_version or "")[:14] or None,
        # Three states: None is unobserved and is never shown as fresh.
        "freshness": "unobserved" if stale is None else ("stale" if stale else "within limit"),
        "tone": "warn" if stale is None or stale else "good",
    }


def _cvss_rows(parsed: Any) -> list[dict[str, Any]]:
    rows = []
    for metric in parsed.cvss or ():
        severity = (metric.severity or "").upper()
        rows.append(
            {
                "container": "CNA" if metric.container == "cna" else metric.container,
                "version": metric.version,
                "score": metric.base_score,
                "severity": metric.severity,
                "tone": SEVERITY_TONE.get(severity, "neutral"),
                "primary": metric.primary,
                "vector": metric.vector,
                "chips": vector_chips(metric.vector),
            }
        )
    return rows


def _breakdown(cvss_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The plain-English table for the primary CVSS metric (the first one when none is marked primary)."""
    if not cvss_rows:
        return None
    row = next((r for r in cvss_rows if r["primary"]), cvss_rows[0])
    rows = explain_vector(row["vector"], row["version"])
    if not rows:
        return None
    try:
        score = "unscored" if row["score"] is None else f"{float(row['score']):.1f}" + (f" {str(row['severity']).title()}" if row["severity"] else "")
    except (TypeError, ValueError):  # a stored score that is not a number reads as unscored, never as an error
        score = "unscored"
    return {"source": f"Scored by {row['container']}, CVSS {row['version']} \u00b7 {score}", "rows": rows}


def _references(parsed: Any, per_tag: int) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for ref in parsed.reference_details or ():
        url = safe_url(ref.url)
        if url is None:
            continue
        for tag in ref.tags or ("untagged",):
            groups.setdefault(tag, []).append(url)
    ordered = sorted(groups.items(), key=lambda kv: (kv[0] == "untagged", kv[0]))
    return [{"tag": tag, "links": urls[:per_tag], "more": max(0, len(urls) - per_tag), "total": len(urls)} for tag, urls in ordered]


def _products(parsed: Any) -> list[dict[str, Any]]:
    return [
        {
            "vendor": p.vendor,
            "product": p.package_name or p.product,
            "fixed_versions": list(p.fixed_versions),
            "ranges": [
                " ".join(x for x in (v.version, f"< {v.less_than}" if v.less_than else "", f"<= {v.less_than_or_equal}" if v.less_than_or_equal else "") if x)
                for v in p.versions
                if v.status == "affected"
            ][:4],
        }
        for p in (parsed.affected_products or ())
    ]


class VulnMosaicCvePanelType:
    slug: ClassVar[str] = "vuln-mosaic-cve"
    label: ClassVar[str] = "Vuln Mosaic CVE"
    view: ClassVar[str] = "vuln_mosaic/panels/cve.html"
    css: ClassVar[list[str]] = ["vuln_mosaic/css/cve.css"]
    js: ClassVar[list[str]] = []
    editor_view: ClassVar[str] = ""
    config_defaults: ClassVar[dict[str, Any]] = {}

    @classmethod
    def get_view_context(cls, panel: Panel, request: HttpRequest) -> dict[str, Any]:
        config = dict(getattr(panel, "config", None) or {})
        try:
            jsonschema.validate(config, CVE_PANEL_CONFIG_SCHEMA)
        except jsonschema.ValidationError as exc:
            return {"state": "bad_config", "detail": exc.message, "requested": ""}
        chosen = config.get("sections") or DEFAULT_SECTIONS
        show = {name: name in chosen for name in SECTIONS}
        var = config.get("vuln_id_var") or DEFAULT_VULN_VAR
        requested = (request.GET.get(var) or "").strip() if request else ""
        if not requested:
            return {"state": "no_selection", "requested": "", "show": show}
        kind = classify(requested)
        context: dict[str, Any] = {
            "show": show,
            "affected_note": AFFECTED_NOTE,
            "requested": requested,
            "kind": kind,
            "links": external_links(requested, kind),
            "kev_catalog_url": LINKS["kev_catalog"],
            "epss_url": LINKS["epss"],
        }
        if kind == "ghsa":
            return {**context, "state": "ghsa_only"}
        if kind == "other":
            return {**context, "state": "unrecognised"}
        return {
            **context,
            "state": "cve",
            **cls._cve_sections(requested, int(config.get("max_references_per_tag") or 8), config.get("queue_misses", True)),
        }

    @classmethod
    def _cve_sections(cls, cve_id: str, per_tag: int, queue: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {"datasets": []}
        try:
            record = get_cve(cve_id, queue=queue)
        except Exception:  # a failed read must not take the page down
            logger.exception("[a5d7] vuln_mosaic get_cve failed for %s", cve_id)
            record = None
        out["record_state"] = record.state if record else "error"
        if record is not None:
            out["datasets"].append(dataset_row("CVE record", record.dataset))
            out["queued"] = record.state == "not-fetched" and queue
            if record.state == "found" and record.record is not None:
                parsed = extract_record(record.record)
                ssvc = parsed.ssvc
                cvss_rows = _cvss_rows(parsed)
                out.update(
                    cvss=cvss_rows,
                    breakdown=_breakdown(cvss_rows),
                    cwes=list(parsed.cwes) if parsed.cwes is not None else None,
                    ssvc=ssvc,
                    published=parsed.date_published,
                    updated=parsed.date_updated,
                    products=_products(parsed),
                    references=_references(parsed, per_tag),
                )
        try:
            kev = get_kev(cve_id)
            out["kev"] = {"state": kev.state, "entry": kev.entry}
            out["datasets"].append(dataset_row("CISA KEV", kev.dataset))
        except Exception:
            logger.exception("[4d17] vuln_mosaic get_kev failed for %s", cve_id)
            out["kev"] = {"state": "error", "entry": None}
        try:
            epss = get_epss(cve_id)
            out["epss"] = epss
            out["datasets"].append(dataset_row("FIRST EPSS", epss.dataset))
        except Exception:
            logger.exception("[32bc] vuln_mosaic get_epss failed for %s", cve_id)
            out["epss"] = None
        return out
