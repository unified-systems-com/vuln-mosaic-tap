"""Parser tests over real committed records (req-vuln-mosaic-records, req-vuln-mosaic-corpus-1)."""

from __future__ import annotations

import json
import subprocess
import sys

from tap_plugin.vuln_mosaic.records import extract_record

from .conftest import CNA_ONLY, LOG4SHELL, NO_ADP_NO_CPE, PUBLISHED_SSVC, REJECTED, corpus


def parsed(cve_id: str):
    return extract_record(json.loads(corpus(cve_id)))


def test_ssvc_from_cisa_adp() -> None:  # req-vuln-mosaic-records-2
    record = parsed(PUBLISHED_SSVC)
    assert record.ssvc is not None
    assert record.ssvc.exploitation in {"none", "poc", "active"}
    assert record.ssvc.automatable in {"yes", "no"}
    assert record.ssvc.technical_impact in {"partial", "total"}
    assert record.ssvc.version and record.ssvc.timestamp


def test_no_adp_yields_none_ssvc() -> None:
    assert parsed(NO_ADP_NO_CPE).ssvc is None
    assert parsed(CNA_ONLY).ssvc is None


def test_cna_cvss_is_primary_when_alone() -> None:  # req-vuln-mosaic-records-1
    record = parsed(CNA_ONLY)
    assert record.cvss and record.cvss[0].container == "cna" and record.cvss[0].primary
    assert all(not m.primary for m in record.cvss[1:])


def test_cna_first_then_adp_fallback() -> None:
    base = json.loads(corpus(CNA_ONLY))
    adp = {"providerMetadata": {"shortName": "CISA-ADP"},
           "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V"}}]}
    both = {**base, "containers": {**base["containers"], "adp": [adp]}}
    record = extract_record(both)
    assert [m.container for m in record.cvss][-1] == "CISA-ADP"
    assert record.cvss[0].container == "cna" and record.cvss[0].primary
    cna_less = json.loads(json.dumps(both))
    cna_less["containers"]["cna"].pop("metrics", None)
    only_adp = extract_record(cna_less)
    assert only_adp.cvss[0].container == "CISA-ADP" and only_adp.cvss[0].primary


def test_three_states_for_cwes() -> None:  # req-vuln-mosaic-records-3
    base = json.loads(corpus(CNA_ONLY))
    absent = json.loads(json.dumps(base))
    absent["containers"]["cna"].pop("problemTypes", None)
    assert extract_record(absent).cwes is None
    empty = json.loads(json.dumps(base))
    empty["containers"]["cna"]["problemTypes"] = []
    assert extract_record(empty).cwes == ()


def test_rejected_record_state() -> None:
    assert parsed(REJECTED).state == "REJECTED"


def test_log4shell_has_cwes_and_references() -> None:
    record = parsed(LOG4SHELL)
    assert record.cve_id == LOG4SHELL
    assert record.cwes and record.references


def test_records_module_imports_only_the_standard_library() -> None:  # req-vuln-mosaic-records-4
    code = (
        "import sys; import tap_plugin.vuln_mosaic.records as r;"
        "allowed=set(sys.stdlib_module_names)|{'tap_plugin'};"
        "bad=sorted(m for m in sys.modules if m.split('.')[0] not in allowed and not m.startswith('_'));"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]", out.stdout


def test_reference_tags_are_parsed() -> None:  # records-5
    record = parsed(LOG4SHELL)
    tags = {t for ref in record.reference_details for t in ref.tags}
    assert {"vendor-advisory", "mailing-list", "third-party-advisory"} <= tags
    assert [r.url for r in record.reference_details] == list(record.references)
    assert all(isinstance(r.tags, tuple) for r in record.reference_details)
    assert parsed(CNA_ONLY).reference_details and all(r.tags == () for r in parsed(CNA_ONLY).reference_details)


def test_reference_details_absent_is_none() -> None:
    doc = json.loads(corpus(CNA_ONLY))
    doc["containers"]["cna"].pop("references")
    assert extract_record(doc).reference_details is None


def test_fixed_versions_from_changes_and_less_than() -> None:  # records-6
    log4j = parsed(LOG4SHELL).affected_products[0]
    assert log4j.vendor == "Apache Software Foundation" and log4j.product == "Apache Log4j2"
    assert log4j.fixed_versions == ("2.3.1", "2.12.2", "2.15.0")  # 'log4j-core*' is a package name, not a bound
    snipe = parsed(CNA_ONLY).affected_products[0]
    assert snipe.fixed_versions == ("5.3.6",) and snipe.versions[0].less_than == "5.3.6"


def test_no_fix_named_gives_an_empty_tuple_not_none() -> None:
    intel = parsed(PUBLISHED_SSVC).affected_products[0]
    assert intel.fixed_versions == () and intel.versions[0].version == "See references"


def test_explicit_unaffected_entry_is_a_fixed_version() -> None:
    doc = {"containers": {"cna": {"affected": [{"vendor": "v", "product": "p", "versions": [
        {"version": "1.0", "status": "affected"}, {"version": "1.1", "status": "unaffected"}]}]}}}
    assert extract_record(doc).affected_products[0].fixed_versions == ("1.1",)
    assert extract_record({"containers": {"cna": {}}}).affected_products is None
