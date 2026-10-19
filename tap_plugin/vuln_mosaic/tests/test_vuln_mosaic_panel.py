"""The CVE panel: context, links and rendering (req-vuln-mosaic-panel-cve). Local datasets only; no network."""

from __future__ import annotations

import gzip
import json
from types import SimpleNamespace

import pytest
from django.template.loader import render_to_string
from django.test import RequestFactory

from tap_plugin.vuln_mosaic import files, lookup
from tap_plugin.vuln_mosaic.panels.cve import (
    CVE_PANEL_CONFIG_SCHEMA,
    VulnMosaicCvePanelType,
    classify,
    external_links,
    safe_url,
    vector_chips,
)
from tap_plugin.vuln_mosaic.staleness import DatasetFacts
from tap_plugin.vuln_mosaic.store import RecordStore

from .conftest import LOG4SHELL, corpus

GHSA = "GHSA-jfh8-c2jp-5v3q"


@pytest.fixture
def vm_home(home, monkeypatch):
    monkeypatch.setenv("VULN_MOSAIC_HOME", str(home))
    return home


def render(query: str = "", config: dict | None = None) -> tuple[dict, str]:
    config = {"hide_header": True, **(config or {})}
    request = RequestFactory().get(f"/page/?{query}" if query else "/page/")
    panel = SimpleNamespace(config=config, name="CVE", slug="cve")
    context = VulnMosaicCvePanelType.get_view_context(panel, request)
    html = render_to_string(VulnMosaicCvePanelType.view, {**context, "panel": panel, "request": request})
    return context, html


def seed(home, cve_id=LOG4SHELL, raw=None, checked="2099-01-01T00:00:00Z") -> None:
    with RecordStore.open_writer(home, "cvelist") as store:
        store.put(cve_id, "PUBLISHED", None, raw or corpus(cve_id))
        store.set_facts(as_of=checked, checked_at=checked, source_version="abcdef1234567890", fetched_at=checked)
    kev = {"catalogVersion": "2026.10.15", "dateReleased": "2026-10-15T00:00:00Z", "count": 1, "vulnerabilities": [{
        "cveID": cve_id, "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "requiredAction": "Apply updates <b>now</b>.",
        "knownRansomwareCampaignUse": "Known"}]}
    stage = files.new_staging(home, "kev", "b1")
    (stage / "known_exploited_vulnerabilities.json").write_text(json.dumps(kev))
    files.publish(home, "kev", "b1", stage, DatasetFacts(as_of="2026-10-15T00:00:00Z", checked_at=checked, source_version="2026.10.15"))
    stage = files.new_staging(home, "epss", "b1")
    (stage / "epss_scores.csv.gz").write_bytes(gzip.compress(
        f"#model_version:v2026.06.15,score_date:2026-10-16T12:02:51Z\ncve,epss,percentile\n{cve_id},0.97,0.99\n".encode()))
    files.publish(home, "epss", "b1", stage, DatasetFacts(as_of="2026-10-16T12:02:51Z", checked_at=checked, source_version="v2026.06.15"))


def test_panel_type_shape() -> None:
    t = VulnMosaicCvePanelType
    assert t.slug == "vuln-mosaic-cve" and t.view == "vuln_mosaic/panels/cve.html" and t.css == ["vuln_mosaic/css/cve.css"]
    assert t.config_defaults == {} and t.editor_view == ""


def test_config_schema_describes_itself() -> None:
    assert CVE_PANEL_CONFIG_SCHEMA["description"]
    assert all(p["description"] for p in CVE_PANEL_CONFIG_SCHEMA["properties"].values())


def test_registered_on_the_panel_registry() -> None:
    from tap_web.registry import panel_type_registry

    assert panel_type_registry.get("vuln-mosaic-cve") is VulnMosaicCvePanelType


def test_classify_and_links_only_for_owned_ids() -> None:
    assert classify("CVE-2021-44228") == "cve" and classify(GHSA) == "ghsa" and classify("PYSEC-2021-1") == "other"
    assert classify("CVE-2021-44228 ") == "other" and classify("GHSA-AAAA-bbbb-cccc") == "other"
    assert [l["label"] for l in external_links("CVE-2021-44228", "cve")] == ["CVE.org", "NVD", "OSV"]
    urls = {l["label"]: l["url"] for l in external_links("CVE-2021-44228", "cve")}
    assert urls["CVE.org"] == "https://www.cve.org/CVERecord?id=CVE-2021-44228"
    assert urls["NVD"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert urls["OSV"] == "https://osv.dev/vulnerability/CVE-2021-44228"
    ghsa = {l["label"]: l["url"] for l in external_links(GHSA, "ghsa")}
    assert ghsa == {"GitHub advisory": f"https://github.com/advisories/{GHSA}", "OSV": f"https://osv.dev/vulnerability/{GHSA}"}
    assert external_links("PYSEC-2021-1", "other") == []


def test_safe_url_allows_only_http_and_https() -> None:
    assert safe_url("https://example.org/a") and safe_url("http://example.org/a")
    for bad in ("javascript:alert(1)", "data:text/html,x", "ftp://example.org", "//example.org", "https:///nohost"):
        assert safe_url(bad) is None


def test_vector_chips_v3_and_v4() -> None:
    chips = vector_chips("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert [c["key"] for c in chips] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert chips[0] == {"key": "AV", "name": "Attack Vector", "value": "N"}
    assert [c["key"] for c in vector_chips("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")][:3] == ["AV", "AC", "AT"]
    assert vector_chips(None) == [] and vector_chips("garbage") == []


def test_no_selection_and_bad_config(vm_home) -> None:
    ctx, html = render("")
    assert ctx["state"] == "no_selection" and "No vulnerability id selected" in html
    ctx, html = render("vuln_id=CVE-2021-44228", {"unknown_key": 1})
    assert ctx["state"] == "bad_config" and "Panel config invalid" in html


def test_custom_param_name(vm_home) -> None:
    seed(vm_home)
    ctx, _ = render("cve=CVE-2021-44228", {"vuln_id_var": "cve"})
    assert ctx["state"] == "cve"


def test_full_render_of_a_held_cve(vm_home) -> None:
    seed(vm_home)
    ctx, html = render(f"vuln_id={LOG4SHELL}")
    assert ctx["record_state"] == "found" and ctx["state"] == "cve"
    for expected in ("CISA KEV", "Listed", "2021-12-10", "2021-12-24", "Known", "Apply updates", "EPSS", "0.97000", "v2026.06.15",
                     "2026-10-16T12:02:51Z", "2.15.0", "2.12.2", "2.3.1", "vendor-advisory", "Affected products", "CWE"):
        assert expected in html, expected
    assert "&lt;b&gt;now&lt;/b&gt;" in html and "<b>now</b>" not in html  # record-supplied text is escaped
    assert "https://www.cve.org/CVERecord?id=CVE-2021-44228" in html and "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in html
    assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in html and "https://www.first.org/epss/" in html
    assert "within limit" in html and "unobserved" not in html


def test_cvss_chips_render_for_a_record_with_metrics(vm_home) -> None:
    seed(vm_home, "CVE-2022-0179", corpus("CVE-2022-0179"))
    ctx, html = render("vuln_id=CVE-2022-0179")
    assert ctx["cvss"] and ctx["cvss"][0]["primary"] and "vmcve-chip" in html
    assert ctx["cvss"][0]["tone"] in {"bad", "warn", "neutral"}


def test_ssvc_section(vm_home) -> None:
    seed(vm_home, "CVE-2022-0001", corpus("CVE-2022-0001"))
    _, html = render("vuln_id=CVE-2022-0001")
    assert "SSVC" in html and "Exploitation" in html and "Technical impact" in html


def test_unobserved_dataset_is_never_shown_as_fresh(vm_home) -> None:
    with RecordStore.open_writer(vm_home, "cvelist") as store:
        store.put(LOG4SHELL, "PUBLISHED", None, corpus(LOG4SHELL))  # no dataset facts at all
    ctx, html = render(f"vuln_id={LOG4SHELL}")
    assert ctx["datasets"][0]["freshness"] == "unobserved" and "within limit" not in html
    assert "unobserved" in html


def test_stale_dataset_is_labelled_stale(vm_home) -> None:
    seed(vm_home, checked="2026-01-01T00:00:00Z")
    _, html = render(f"vuln_id={LOG4SHELL}")
    assert "stale" in html and "within limit" not in html


def test_not_fetched_shows_a_placeholder_and_queues(vm_home) -> None:
    ctx, html = render("vuln_id=CVE-2022-7777")
    assert ctx["record_state"] == "not-fetched" and ctx["queued"] is True
    assert "Queued for the next refresh" in html and "Not observed" in html
    assert (vm_home / "spool" / "CVE-2022-7777").exists()
    assert "Record not fetched" in html


def test_queue_misses_false_is_purely_read_only(vm_home) -> None:
    ctx, html = render("vuln_id=CVE-2022-7778", {"queue_misses": False})
    assert ctx["record_state"] == "not-fetched" and ctx["queued"] is False
    assert "Queued for the next refresh" not in html and "Not observed" in html
    assert not (vm_home / "spool").exists()


def test_spool_is_bounded(vm_home, monkeypatch) -> None:
    from tap_plugin.vuln_mosaic import wanted

    monkeypatch.setattr(wanted, "MAX_SPOOL", 2)
    for n in range(5):
        lookup.get_cve(f"CVE-2022-90{n:02d}", home=vm_home)
    assert len(list((vm_home / "spool").iterdir())) == 2
    assert lookup.get_cve("CVE-2022-9099", home=vm_home).state == "not-fetched"


def test_ghsa_only_renders_a_note_without_touching_the_cve_datasets(vm_home, monkeypatch) -> None:
    import tap_plugin.vuln_mosaic.panels.cve as mod

    for name in ("get_cve", "get_kev", "get_epss"):
        monkeypatch.setattr(mod, name, lambda *a, **k: pytest.fail("a GHSA id must not be looked up as a CVE"))
    ctx, html = render(f"vuln_id={GHSA}")
    assert ctx["state"] == "ghsa_only" and "GitHub advisory only" in html
    assert f"https://github.com/advisories/{GHSA}" in html and f"https://osv.dev/vulnerability/{GHSA}" in html
    assert "cve.org" not in html and "nvd.nist.gov" not in html and "CISA KEV" not in html


def test_unrecognised_id_has_no_links(vm_home) -> None:
    ctx, html = render("vuln_id=not-an-id")
    assert ctx["state"] == "unrecognised" and "Not a CVE or GitHub advisory id" in html and "href=" not in html


def test_unaffected_versions_are_never_shown_as_fixes(vm_home) -> None:
    doc = json.loads(corpus(LOG4SHELL))
    doc["containers"]["cna"]["affected"] = [{"vendor": "v", "product": "p", "versions": [
        {"version": "0.0.9-unaff", "status": "unaffected"}, {"version": "2.0", "status": "affected", "lessThan": "3.0"}]}]
    seed(vm_home, raw=json.dumps(doc).encode())
    _, html = render(f"vuln_id={LOG4SHELL}")
    assert "0.0.9-unaff" not in html and "3.0" in html


def test_hostile_reference_urls_are_not_linked(vm_home) -> None:
    doc = json.loads(corpus(LOG4SHELL))
    doc["containers"]["cna"]["references"] = [
        {"url": "javascript:alert(1)", "tags": ["exploit"]},
        {"url": "https://example.org/x?a=1&b=<script>", "tags": ["<img src=x>"]},
        {"url": "https://example.org/ok"},
    ]
    seed(vm_home, raw=json.dumps(doc).encode())
    ctx, html = render(f"vuln_id={LOG4SHELL}")
    assert "javascript:" not in html and "<script>" not in html and "<img src=x>" not in html
    assert "https://example.org/ok" in html and any(g["tag"] == "untagged" for g in ctx["references"])


def test_reference_overflow_is_counted(vm_home) -> None:
    doc = json.loads(corpus(LOG4SHELL))
    doc["containers"]["cna"]["references"] = [{"url": f"https://example.org/{n}", "tags": ["patch"]} for n in range(12)]
    seed(vm_home, raw=json.dumps(doc).encode())
    ctx, html = render(f"vuln_id={LOG4SHELL}", {"max_references_per_tag": 5})
    assert ctx["references"][0]["total"] == 12 and len(ctx["references"][0]["links"]) == 5 and "+7 more" in html


def test_a_failing_dataset_read_does_not_break_the_page(vm_home, monkeypatch) -> None:
    import tap_plugin.vuln_mosaic.panels.cve as mod

    seed(vm_home)
    monkeypatch.setattr(mod, "get_kev", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ctx, html = render(f"vuln_id={LOG4SHELL}")
    assert ctx["kev"]["state"] == "error" and "Not observed" in html and LOG4SHELL in html


def test_panel_module_makes_no_network_call() -> None:
    import tap_plugin.vuln_mosaic.panels.cve as mod

    src = open(mod.__file__).read()
    for banned in ("urllib.request", "requests", "http.client", "socket", "subprocess"):
        assert banned not in src


def test_lookup_module_still_free_of_django() -> None:
    assert "django" not in open(lookup.__file__).read()


def test_stylesheet_is_theme_aware_with_the_stat_card_palette() -> None:  # panel-cve-7
    from pathlib import Path

    import tap_plugin.vuln_mosaic.panels.cve as mod

    css = (Path(mod.__file__).parents[2] / "static" / "vuln_mosaic" / "css" / "cve.css").read_text()
    assert ':root[data-theme="dark"] .tap-panel--vmcve' in css and "prefers-color-scheme: dark" in css
    assert ':root:not([data-theme="light"]) .tap-panel--vmcve' in css
    for token, light, dark in (("--vmcve-bad", "#b91c1c", "#f87171"), ("--vmcve-warn", "#b45309", "#fbbf24"), ("--vmcve-neutral", "#94a3b8", "#64748b")):
        assert f"{token}: {light}" in css and f"{token}: {dark}" in css
