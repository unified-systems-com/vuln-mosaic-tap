"""CVE panel sections and the CVSS plain-English table (req-vuln-mosaic-panel-cve-9, -9). Local datasets only."""

from __future__ import annotations

import json

import pytest

from tap_plugin.vuln_mosaic.panels.cve import DEFAULT_SECTIONS, SECTIONS
from tap_plugin.vuln_mosaic.panels.cve.cvss_text import AFFECTED_NOTE, TABLES, explain_vector, vector_version

from .conftest import LOG4SHELL, corpus
from .test_vuln_mosaic_panel import render, seed, vm_home  # noqa: F401  (fixture)

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
V4 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MSI:X"


def by_key(rows):
    return {r["key"]: r for r in rows}


# --- the constants ---------------------------------------------------------------------------------


def test_v3_vector_is_spelled_out_in_the_vectors_own_order() -> None:  # panel-cve-10
    rows = explain_vector(V31)
    assert [r["key"] for r in rows] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    got = by_key(rows)
    assert (got["AV"]["name"], got["AV"]["label"]) == ("Attack vector", "Network")
    assert "remotely over the network" in got["AV"]["meaning"]
    assert (got["PR"]["label"], got["UI"]["label"], got["S"]["label"]) == ("None", "None", "Changed")
    assert got["C"]["name"] == "Confidentiality impact" and got["C"]["label"] == "High"
    assert all(r["known"] and r["meaning"] for r in rows)


def test_version_comes_from_the_vector_then_from_the_declared_version() -> None:  # panel-cve-10
    assert vector_version(V31) == "3.1" and vector_version("CVSS:3.0/AV:N") == "3.0" and vector_version(V4) == "4.0"
    assert vector_version(V2) == "2.0"
    assert vector_version("AV:N/AC:L", "2") == "2.0"


def test_v2_and_v4_vectors_are_spelled_out() -> None:  # panel-cve-10
    v2 = by_key(explain_vector(V2))
    assert (v2["Au"]["name"], v2["Au"]["label"]) == ("Authentication", "None")
    assert (v2["C"]["label"], v2["A"]["label"]) == ("Partial", "Partial")
    v4 = by_key(explain_vector(V4))
    assert (v4["AT"]["label"], v4["UI"]["label"]) == ("Present", "Active")
    assert v4["VI"]["name"] == "Integrity impact (vulnerable system)" and v4["VI"]["label"] == "High"
    assert v4["SC"]["name"] == "Confidentiality impact (other systems)"


def test_v4_threat_and_environmental_metrics_that_are_not_defined_are_skipped() -> None:  # panel-cve-10
    keys = [r["key"] for r in explain_vector(V4)]
    assert keys == ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def test_unknown_metric_or_value_shows_the_raw_code_and_never_throws() -> None:  # panel-cve-10
    rows = by_key(explain_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:9"))
    assert (rows["AV"]["label"], rows["AV"]["known"]) == ("Z", False) and rows["AV"]["meaning"]
    assert (rows["ZZ"]["name"], rows["ZZ"]["label"], rows["ZZ"]["known"]) == ("ZZ", "9", False)
    assert rows["AC"]["known"] is True


def test_x_is_skipped_only_for_optional_metrics_and_defined_optional_values_show_raw() -> None:  # panel-cve-10
    got = by_key(explain_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:X/E:X/RL:O"))
    assert "ZZ" in got and got["ZZ"]["label"] == "X" and "E" not in got
    assert got["RL"]["label"] == "O" and got["RL"]["known"] is False
    v4 = by_key(explain_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:X/MAV:N"))
    assert v4["E"]["label"] == "A" and v4["MAV"]["label"] == "N" and "CR" not in v4


def test_a_non_numeric_stored_score_reads_as_unscored_not_an_error(vm_home) -> None:  # panel-cve-10
    record = json.loads(corpus(LOG4SHELL))
    for container in [record["containers"]["cna"], *record["containers"].get("adp", [])]:
        for metric in container.get("metrics", []):
            for body in metric.values():
                if isinstance(body, dict) and "baseScore" in body:
                    body["baseScore"] = "not-a-number"
    seed(vm_home, LOG4SHELL, json.dumps(record).encode())
    ctx, html = render(f"vuln_id={LOG4SHELL}")  # the default layout must not regress either
    assert ctx["state"] == "cve" and "<h4>CVSS</h4>" in html
    assert "unscored" in render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown"]})[1]


@pytest.mark.parametrize("vector", [None, "", "   ", "not a vector", "CVSS:", "CVSS:9.9/AV:N", "/", ":::", "AV:", "CVSS:3.1/", "\x00:\x00", "A" * 5000])
def test_garbage_never_raises_and_never_returns_a_blank_row(vector) -> None:  # panel-cve-10
    for row in explain_vector(vector):
        assert row["key"] and row["code"] and row["label"] and row["meaning"]


def test_every_table_entry_has_a_name_and_text_for_every_value() -> None:  # panel-cve-10
    for table in TABLES.values():
        for name, values in table.values():
            assert name and values
            assert all(label and meaning for label, meaning in values.values())


# --- the sections config ---------------------------------------------------------------------------


def test_default_layout_is_unchanged_and_the_breakdown_is_opt_in(vm_home) -> None:  # panel-cve-9
    assert "cvss_breakdown" not in DEFAULT_SECTIONS and set(DEFAULT_SECTIONS) < set(SECTIONS)
    seed(vm_home)
    ctx, html = render(f"vuln_id={LOG4SHELL}")
    assert ctx["show"] == {s: s in DEFAULT_SECTIONS for s in SECTIONS}
    for text in ('class="vmcve__id"', "<h4>CISA KEV</h4>", "<h4>CVSS</h4>", "Affected products", "References", "vmcve-datasets", AFFECTED_NOTE):
        assert text in html, text
    assert "How it can be attacked" not in html


def test_only_the_chosen_sections_render(vm_home) -> None:  # panel-cve-9
    seed(vm_home)
    _, html = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown", "affected", "references", "freshness"]})
    assert "How it can be attacked" in html and "Affected products" in html and "References" in html and "vmcve-datasets" in html
    assert 'class="vmcve__id"' not in html and "<h4>CISA KEV</h4>" not in html and "<h4>CVSS</h4>" not in html
    _, only = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown"]})
    assert "How it can be attacked" in only and "Affected products" not in only and "References" not in only
    assert "vmcve-datasets" not in only


def test_the_array_order_does_not_change_the_page_order(vm_home) -> None:  # panel-cve-9
    seed(vm_home)
    _, a = render(f"vuln_id={LOG4SHELL}", {"sections": ["freshness", "affected", "cvss_breakdown"]})
    _, b = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown", "affected", "freshness"]})
    assert a == b
    assert a.index("How it can be attacked") < a.index("Affected products") < a.index("vmcve-datasets")


@pytest.mark.parametrize("sections", [["nope"], [], ["cvss", "cvss"], "cvss", [1]])
def test_a_bad_sections_value_is_a_bad_config_not_a_crash(sections) -> None:  # panel-cve-9
    ctx, html = render(f"vuln_id={LOG4SHELL}", {"sections": sections})
    assert ctx["state"] == "bad_config" and "Panel config invalid" in html


# --- the breakdown --------------------------------------------------------------------------------


def test_breakdown_has_the_source_line_and_one_row_per_metric(vm_home) -> None:  # panel-cve-10
    seed(vm_home)
    ctx, html = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown"]})
    breakdown = ctx["breakdown"]
    assert breakdown["source"].startswith("Scored by ") and "CVSS 3.1" in breakdown["source"] and "10.0" in breakdown["source"]
    assert [r["key"] for r in breakdown["rows"]] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert breakdown["source"] in html and "can be exploited remotely over the network".replace("can be", "Can be") in html
    assert html.count("<tr><td>") == 8


def test_breakdown_says_so_when_the_record_has_no_cvss(vm_home) -> None:  # panel-cve-10
    record = json.loads(corpus(LOG4SHELL))
    for container in [record["containers"]["cna"], *record["containers"].get("adp", [])]:
        container.pop("metrics", None)
    seed(vm_home, LOG4SHELL, json.dumps(record).encode())
    ctx, html = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown"]})
    assert ctx["breakdown"] is None and "None in the record" in html and "<tr><td>" not in html


def test_the_affected_note_is_one_plain_line(vm_home) -> None:  # panel-cve-9
    assert AFFECTED_NOTE == "Versions in these ranges are affected; upgrade to a fixed-in version."
    seed(vm_home)
    _, html = render(f"vuln_id={LOG4SHELL}", {"sections": ["affected"]})
    assert f'<p class="vmcve-note">{AFFECTED_NOTE}</p>' in html


def test_meaning_text_is_escaped_not_trusted(vm_home) -> None:  # panel-cve-10
    record = json.loads(corpus(LOG4SHELL))
    for container in [record["containers"]["cna"], *record["containers"].get("adp", [])]:
        for metric in container.get("metrics", []):
            for body in metric.values():
                if isinstance(body, dict) and "vectorString" in body:
                    body["vectorString"] = "CVSS:3.1/AV:<script>x</script>/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    seed(vm_home, LOG4SHELL, json.dumps(record).encode())
    _, html = render(f"vuln_id={LOG4SHELL}", {"sections": ["cvss_breakdown"]})
    assert "<script>x" not in html and "&lt;script&gt;" in html
