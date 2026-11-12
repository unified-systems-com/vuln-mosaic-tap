"""Tests for req-vuln-mosaic-osv-mal: malicious-package advisories read from the held OSV zips."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.enrich import MALWARE_CWE, facts_for, plan_patch
from tap_plugin.vuln_mosaic.ids import id_kind, validate_mal_id, validate_vuln_id
from tap_plugin.vuln_mosaic.lookup import FOUND, NOT_FETCHED, WITHDRAWN, get_osv
from tap_plugin.vuln_mosaic.staleness import DatasetFacts
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import ingest_grid, ingest_spool

MAL = "MAL-2023-4242"


def mal_record(osv_id: str = MAL, **over) -> dict:
    record = {
        "id": osv_id,
        "summary": "Malicious code in evil-pkg (PyPI)",
        "details": "The package reads ~/.ssh and posts it to a remote host.",
        "published": "2023-06-01T10:00:00Z",
        "modified": "2023-06-02T10:00:00Z",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "evil-pkg"}, "versions": ["1.0.0"]}],
        "references": [{"type": "ADVISORY", "url": "https://example.test/evil-pkg"}],
    }
    record.update(over)
    return record


def hold(home: Path, ecosystem: str, members: dict[str, object]) -> None:
    """Publish a real zip as the current build of ``osv/<ecosystem>``, as a refresh would."""
    key = f"osv/{ecosystem}"
    staging = files.new_staging(home, key, "incoming")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, body in members.items():
            archive.writestr(name, body if isinstance(body, (str, bytes)) else json.dumps(body))
    (staging / "all.zip").write_bytes(buf.getvalue())
    facts = DatasetFacts(as_of="2026-10-20T00:00:00Z", checked_at="2026-10-20T00:00:00Z", source_version="v1", fetched_at="2026-10-20T00:00:00Z")
    files.publish(home, key, "20261020T000000", staging, facts)


# --- ids ---------------------------------------------------------------------------------------


@pytest.mark.spec("req-vuln-mosaic-osv-mal-1")
@pytest.mark.parametrize("good", ["MAL-2023-4242", "MAL-2025-1", "MAL-0000-123456"])
def test_a_mal_id_is_accepted(good) -> None:
    assert validate_mal_id(good) == good
    assert validate_vuln_id(good) == good
    assert id_kind(good) == "osv"


@pytest.mark.spec("req-vuln-mosaic-osv-mal-1")
@pytest.mark.parametrize("bad", ["MAL-23-4242", "mal-2023-4242", "MAL-2023-", "MAL-2023-4242\n", "MAL-2023-4242/../x", "PYSEC-2023-1", "MAL-2023-1234567890", b"MAL-2023-1", None])
def test_anything_else_is_refused(bad) -> None:
    with pytest.raises(ValueError):
        validate_mal_id(bad)
    with pytest.raises(ValueError):
        validate_vuln_id(bad)


@pytest.mark.spec("req-vuln-mosaic-osv-mal-1")
def test_a_mal_id_is_neither_cve_nor_ghsa_wanted(home) -> None:
    store = RecordStore.open_writer(home, "cvelist")
    try:
        taken, problems = ingest_grid(store, [MAL, "CVE-2021-44228"], kind="cve")
        assert (taken, problems) == (1, [])  # the CVE only; the MAL id is not a cvelist id and is not a problem
        assert not store.is_wanted(MAL)
    finally:
        store.close()


@pytest.mark.spec("req-vuln-mosaic-osv-mal-1")
def test_a_spooled_mal_id_is_left_alone(home) -> None:
    (home / "spool").mkdir(parents=True)
    (home / "spool" / MAL).write_text("")
    store = RecordStore.open_writer(home, "cvelist")
    try:
        assert ingest_spool(home, store, kind="cve") == []
    finally:
        store.close()
    assert (home / "spool" / MAL).exists()


# --- reading -----------------------------------------------------------------------------------


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_held_advisory_is_found_with_its_ecosystem_and_dataset(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    got = get_osv(MAL, home=home)
    assert got.state == FOUND and got.malware is True and got.ecosystem == "PyPI"
    assert got.advisory.summary == "Malicious code in evil-pkg (PyPI)"
    assert got.advisory.packages[0].name == "evil-pkg"
    assert got.dataset.as_of == "2026-10-20T00:00:00Z"


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_the_id_is_found_in_whichever_held_ecosystem_has_it(home) -> None:
    hold(home, "Go", {"GO-1.json": {"id": "GO-1"}})
    hold(home, "npm", {f"{MAL}.json": mal_record(summary="Malicious code in evil (npm)")})
    got = get_osv(MAL, home=home)
    assert got.ecosystem == "npm" and got.advisory.summary.endswith("(npm)")


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_an_ecosystem_name_with_a_space_is_searched(home) -> None:
    hold(home, "Rocky Linux", {f"{MAL}.json": mal_record()})
    assert get_osv(MAL, home=home).ecosystem == "Rocky Linux"


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_withdrawn_advisory_is_kept_but_not_live(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record(withdrawn="2023-07-01T00:00:00Z")})
    got = get_osv(MAL, home=home)
    assert got.state == WITHDRAWN and got.advisory.withdrawn == "2023-07-01T00:00:00Z"


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_miss_is_not_fetched_never_absent(home) -> None:
    assert get_osv(MAL, home=home).reason == "no OSV ecosystem is held"
    hold(home, "PyPI", {"MAL-2020-1.json": mal_record("MAL-2020-1")})
    got = get_osv(MAL, home=home)
    assert got.state == NOT_FETCHED and got.advisory is None and "held OSV ecosystem" in got.reason
    assert list((home).glob("spool/*")) == []  # a read queues nothing


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_member_whose_id_differs_from_its_name_is_not_served(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record("MAL-2099-1")})
    assert get_osv(MAL, home=home).state == NOT_FETCHED


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_broken_zip_or_member_is_skipped_not_raised(home) -> None:
    hold(home, "Alpine", {f"{MAL}.json": "not json"})
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    assert get_osv(MAL, home=home).ecosystem == "PyPI"
    (files.source_dir(home, "osv/Debian")).mkdir(parents=True)  # a directory with no build
    assert get_osv(MAL, home=home).state == FOUND


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_member_that_is_not_valid_utf8_is_skipped_not_raised(home) -> None:
    """``json.loads`` on undecodable bytes raises UnicodeDecodeError, a ValueError, which ``get_osv`` already
    treats as a member it cannot read (an AI review of PR 19 asked whether it escapes; this pins that it does not)."""
    hold(home, "Alpine", {f"{MAL}.json": b"\xff\xfe not utf-8 \x80"})
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    got = get_osv(MAL, home=home)  # must not raise, and must reach the valid ecosystem
    assert got.state == FOUND and got.ecosystem == "PyPI"


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_an_oversize_member_is_not_read(home, monkeypatch) -> None:
    from tap_plugin.vuln_mosaic import lookup

    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    monkeypatch.setattr(lookup, "MAX_OSV_MEMBER_BYTES", 10)
    assert get_osv(MAL, home=home).state == NOT_FETCHED


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
def test_a_malformed_id_raises_before_any_io(home) -> None:
    with pytest.raises(ValueError):
        get_osv("../../etc/passwd", home=home)


# --- enrichment --------------------------------------------------------------------------------


@pytest.mark.spec("req-vuln-mosaic-osv-mal-3")
def test_a_malware_node_gets_the_record_and_cwe_506(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    values = facts_for(MAL, home).values
    assert values["cwes"] == [MALWARE_CWE] == ["CWE-506"]
    assert values["title"].startswith("Malicious code in evil-pkg")
    assert values["record_url"] == f"https://osv.dev/vulnerability/{MAL}"
    assert values["published_at"] == "2023-06-01T10:00:00Z"
    assert not {"kev", "epss_score", "cvss_score"} & values.keys()  # nothing is said about daily data


@pytest.mark.spec("req-vuln-mosaic-osv-mal-3")
def test_a_cwe_the_record_carries_is_used_instead_of_ours(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record(database_specific={"cwe_ids": ["CWE-912"]})})
    assert facts_for(MAL, home).values["cwes"] == ["CWE-912"]


@pytest.mark.spec("req-vuln-mosaic-osv-mal-3")
def test_a_withdrawn_or_unheld_advisory_adds_nothing(home) -> None:
    assert facts_for(MAL, home).values == {}
    hold(home, "PyPI", {f"{MAL}.json": mal_record(withdrawn="2023-07-01T00:00:00Z")})
    assert facts_for(MAL, home).values == {}


@pytest.mark.spec("req-vuln-mosaic-osv-mal-3")
def test_a_cwe_list_the_node_already_has_is_not_replaced(home) -> None:
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    facts = facts_for(MAL, home).values
    assert "cwes" in plan_patch({"cwes": None}, facts)
    assert "cwes" not in plan_patch({"cwes": ["CWE-1104"]}, facts)
    assert "cwes" not in plan_patch({"cwes": []}, facts)  # observed-empty is an observation


@pytest.mark.spec("req-vuln-mosaic-osv-mal-2")
@pytest.mark.parametrize(
    "junk",
    [
        {"affected": 1},
        {"affected": [1, None, {"package": 5, "ranges": "x"}, {"package": {}, "ranges": [1, {"events": 7}]}]},
        {"aliases": 5, "references": "x", "severity": "high", "database_specific": [1], "summary": 9, "published": []},
        {"references": [1, {"url": 3}], "severity": [{"type": "CVSS_V3", "score": 5}, 4], "withdrawn": 0},
    ],
)
def test_a_malformed_member_never_stops_the_search(home, junk) -> None:
    """The first ecosystem holds a member with the right id and nonsense fields; the next holds a good one."""
    hold(home, "Alpine", {f"{MAL}.json": mal_record(**junk)})
    hold(home, "PyPI", {f"{MAL}.json": mal_record()})
    got = get_osv(MAL, home=home)  # must not raise
    assert got.state in (FOUND, WITHDRAWN)
    facts_for(MAL, home)  # nor may the enrichment's read of it
