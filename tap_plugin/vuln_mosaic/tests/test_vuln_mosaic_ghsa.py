"""GitHub advisories: fetch, verify, score, look up (req-vuln-mosaic-ghsa). Real advisories, local git, no network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import cvss
from tap_plugin.vuln_mosaic.advisories import extract_advisory
from tap_plugin.vuln_mosaic.ids import id_from_advisory_path, validate_ghsa_id, validate_vuln_id
from tap_plugin.vuln_mosaic.integrity import IntegrityError, check_ghsa_advisory
from tap_plugin.vuln_mosaic.lookup import FOUND, NOT_FETCHED, WITHDRAWN, get_cve, get_ghsa
from tap_plugin.vuln_mosaic.settings import parse_settings
from tap_plugin.vuln_mosaic.sources import ghsa
from tap_plugin.vuln_mosaic.store import RecordStore, fetch_record
from tap_plugin.vuln_mosaic.wanted import ingest_spool, request_id, scan_wanted_files

from .conftest import CORPUS, Upstream, make_context

TARBALL = "GHSA-rj44-3777-mh5x"  # unreviewed; CVSS v4 only
TOCTOU = "GHSA-fmf4-pr35-46c2"  # unreviewed; CVSS v3.1 (6.3 on GitHub's API)
RESOLVER = "GHSA-qghr-qhfc-4hxp"  # unreviewed; CVSS v3.1 (5.3)
GITPYTHON = "GHSA-239g-whfq-7xj9"  # reviewed; PyPI package with a fixed version
ENABLED = {"sources": {"ghsa": {"enabled": True}}}


def advisory(ghsa_id: str) -> bytes:
    return (CORPUS / f"{ghsa_id}.json").read_bytes()


def path_for(ghsa_id: str, *, reviewed: bool = False, ym: str = "2026/09") -> str:
    return f"advisories/{'github-reviewed' if reviewed else 'unreviewed'}/{ym}/{ghsa_id}/{ghsa_id}.json"


def seed(up: Upstream) -> str:
    return up.commit({
        path_for(TARBALL): advisory(TARBALL),
        path_for(TOCTOU): advisory(TOCTOU),
        path_for(RESOLVER): advisory(RESOLVER),
        path_for(GITPYTHON, reviewed=True): advisory(GITPYTHON),
        "README.md": b"x",
    }, "seed")


def want(home: Path, *ids: str) -> None:
    (home / "wanted").mkdir(parents=True, exist_ok=True)
    (home / "wanted" / "rampart_pg.json").write_text(json.dumps({"ids": list(ids)}))


@pytest.fixture
def adb(tmp_path: Path) -> Upstream:
    return Upstream(tmp_path / "advisory-database")


def run(home, adb, clock, settings=None):
    ctx = make_context(home, None, clock, parse_settings(settings or ENABLED), ghsa_upstream=adb)
    with RecordStore.open_writer(home, "ghsa") as store:
        return ghsa.refresh(ctx, store)


def held(home: Path) -> set[str]:
    with RecordStore.open_writer(home, "ghsa") as store:
        return store.held_ids()


# --- ids and paths --------------------------------------------------------------------------

def test_ghsa_id_validation() -> None:
    assert validate_ghsa_id(TOCTOU) == TOCTOU
    for bad in ("GHSA-fmf4-pr35-46c2\n", "ghsa-fmf4-pr35-46c2", "GHSA-fmf4-pr35", "GHSA-aaaa-aaaa-aaaa", "CVE-2022-0001", None, b"x"):
        with pytest.raises(ValueError):
            validate_ghsa_id(bad)
    assert validate_vuln_id("CVE-2022-0001") == "CVE-2022-0001" and validate_vuln_id(TOCTOU) == TOCTOU
    with pytest.raises(ValueError):
        validate_vuln_id("../x")


def test_advisory_paths() -> None:
    assert id_from_advisory_path(path_for(TOCTOU)) == TOCTOU
    assert id_from_advisory_path(path_for(GITPYTHON, reviewed=True)) == GITPYTHON
    for bad in ("advisories/unreviewed/2026/09/GHSA-fmf4-pr35-46c2/other.json", "advisories/other/2026/09/x/x.json",
                f"advisories/unreviewed/2026/9/{TOCTOU}/{TOCTOU}.json", "README.md",
                f"advisories/unreviewed/2026/09/{TOCTOU}/{TOCTOU}.json.bak"):
        assert id_from_advisory_path(bad) is None


# --- CVSS ------------------------------------------------------------------------------------

@pytest.mark.parametrize(("vector", "score"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", 3.6),  # GHSA-h8x4-734c-9753, GitHub API 3.6
    ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.3),  # GHSA-qghr-qhfc-4hxp, 5.3
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L", 6.3),  # GHSA-fmf4-pr35-46c2, 6.3
    ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", 4.2),  # GHSA-gwqp-9qgw-c5pv, 4.2
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C", 9.8),  # temporal metrics are ignored
    # Scope changed, not capped at 10: reviewed advisories whose scores GitHub's API returned (the 3.1 base formula).
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),  # GHSA-269c-h76q-8cxw
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7),  # GHSA-275h-v5h9-vr82
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 9.6),  # GHSA-2h44-8472-frjj
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),  # GHSA-26vp-8gxg-v4pg
])
def test_cvss_v3_base_scores(vector: str, score: float) -> None:  # ghsa-4
    assert cvss.base_score(vector) == score


@pytest.mark.parametrize("vector", [
    "", "CVSS:3.1/AV:N", "CVSS:2.0/AV:N", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X", "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/BOGUS:X",  # a key outside the 3.x vocabulary
])
def test_cvss_refuses_what_it_cannot_compute(vector: str) -> None:  # ghsa-4: never guess
    assert cvss.base_score(vector) is None


def test_severity_bands() -> None:
    assert [cvss.severity(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == [
        "NONE", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"]


def test_parser_scores_v3_and_leaves_v4_unscored() -> None:  # ghsa-4
    toctou = extract_advisory(json.loads(advisory(TOCTOU)))
    assert toctou.cve_ids == ("CVE-2026-86805",) and toctou.reviewed is False
    assert toctou.best_cvss is not None
    assert (toctou.best_cvss.base_score, toctou.best_cvss.version, toctou.best_cvss.severity) == (6.3, "3.1", "MEDIUM")
    assert toctou.severity_label == "MODERATE" and toctou.cwe_ids == ("CWE-367",)
    tar = extract_advisory(json.loads(advisory(TARBALL)))
    assert [(m.version, m.base_score) for m in tar.cvss] == [("4.0", None)]
    assert tar.best_cvss is None  # a v4 vector is never presented as a v3 score
    assert tar.cvss[0].vector.startswith("CVSS:4.0/")


def test_parser_reads_packages_and_references() -> None:
    gp = extract_advisory(json.loads(advisory(GITPYTHON)))
    assert gp.reviewed is True
    (pkg,) = gp.packages
    assert (pkg.ecosystem, pkg.name, pkg.introduced, pkg.fixed) == ("PyPI", "gitpython", ("0",), ("3.1.60",))
    assert gp.references and all(r.url and len(r.tags) == 1 for r in gp.references)


def test_parser_tolerates_a_bare_record() -> None:
    bare = extract_advisory({"id": TOCTOU})
    assert bare.aliases == () and bare.cvss == () and bare.packages == () and bare.reviewed is None and bare.best_cvss is None


# --- integrity ---------------------------------------------------------------------------------

def test_integrity_accepts_real_advisory_and_marks_withdrawn() -> None:  # ghsa-3
    checked = check_ghsa_advisory(advisory(TOCTOU), TOCTOU)
    assert (checked.state, checked.date_updated) == ("PUBLISHED", "2026-09-22T18:33:29Z")
    withdrawn = json.loads(advisory(TOCTOU))
    withdrawn["withdrawn"] = "2026-10-01T00:00:00Z"
    assert check_ghsa_advisory(json.dumps(withdrawn).encode(), TOCTOU).state == "WITHDRAWN"


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(id="GHSA-aaaa-bbbb-cccc"),
    lambda d: d.update(schema_version="2.0.0"),
    lambda d: d.pop("schema_version"),
    lambda d: d.pop("modified"),
    lambda d: d.update(aliases="CVE-2026-86805"),
    lambda d: d.update(severity={"type": "CVSS_V3"}),
])
def test_integrity_refuses_malformed(mutate) -> None:  # ghsa-3
    doc = json.loads(advisory(TOCTOU))
    mutate(doc)
    with pytest.raises(IntegrityError):
        check_ghsa_advisory(json.dumps(doc).encode(), TOCTOU)
    with pytest.raises(IntegrityError):
        check_ghsa_advisory(b"[]", TOCTOU)
    with pytest.raises(IntegrityError):
        check_ghsa_advisory(b"{not json", TOCTOU)


# --- fetch -------------------------------------------------------------------------------------

def test_bootstrap_stores_only_wanted_found_by_listing(home, adb, clock) -> None:  # ghsa-1, -2
    seed(adb)
    want(home, TOCTOU, GITPYTHON, "CVE-2022-0001")
    out = run(home, adb, clock)
    assert out.ok and out.counts["stored"] == 2 and out.counts["absent_upstream"] == 0
    assert held(home) == {TOCTOU, GITPYTHON}
    stored, facts = fetch_record(home, "ghsa", TOCTOU)
    assert stored.raw == advisory(TOCTOU) and stored.state == "PUBLISHED"
    assert facts.source_version and facts.checked_at


def test_absent_upstream_is_counted_not_a_failure(home, adb, clock) -> None:  # ghsa-2
    seed(adb)
    want(home, TOCTOU, "GHSA-2222-3333-4444")
    out = run(home, adb, clock)
    assert out.ok and out.counts["absent_upstream"] == 1 and held(home) == {TOCTOU}


def test_increment_updates_held_and_follows_a_promotion(home, adb, clock) -> None:  # ghsa-2
    seed(adb)
    want(home, TOCTOU, GITPYTHON)
    run(home, adb, clock)
    edited = json.loads(advisory(TOCTOU))
    edited["modified"] = "2030-01-01T00:00:00Z"
    adb.commit({path_for(TOCTOU): json.dumps(edited).encode()})
    run(home, adb, clock)
    assert json.loads(fetch_record(home, "ghsa", TOCTOU)[0].raw)["modified"] == "2030-01-01T00:00:00Z"
    # Promoted: the unreviewed path disappears and a reviewed one appears for the same id, in one commit.
    adb.commit({path_for(TOCTOU): None, path_for(TOCTOU, reviewed=True, ym="2026/10"): json.dumps(edited).encode()})
    out = run(home, adb, clock)
    assert out.ok and out.counts["deleted"] == 0 and TOCTOU in held(home)


def test_deleted_upstream_removes_the_row(home, adb, clock) -> None:  # ghsa-2
    seed(adb)
    want(home, TOCTOU)
    run(home, adb, clock)
    adb.commit({path_for(TOCTOU): None})
    out = run(home, adb, clock)
    assert out.counts["deleted"] == 1 and held(home) == set()


def test_reviewed_copy_wins_in_the_index(adb) -> None:  # ghsa-1
    adb.commit({path_for(TOCTOU): advisory(TOCTOU), path_for(TOCTOU, reviewed=True): advisory(RESOLVER)})
    ctx = make_context(Path("/nonexistent"), None, lambda: None, ghsa_upstream=adb)  # type: ignore[arg-type]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        git = ctx.git_factory(Path(tmp) / "r.git", Path(tmp), remote=ghsa.REMOTE)
        git.ensure_repo()
        tip = git.fetch_tip()
        reviewed_sha = dict(git.list_records(tip, "advisories/"))[path_for(TOCTOU, reviewed=True)]
        assert ghsa.advisory_index(git, tip)[TOCTOU] == reviewed_sha


def test_a_bad_advisory_is_quarantined_and_blocks_the_ref(home, adb, clock) -> None:  # ghsa-3
    seed(adb)
    wrong = json.loads(advisory(TOCTOU))
    wrong["id"] = RESOLVER
    adb.commit({path_for(TOCTOU): json.dumps(wrong).encode()})
    want(home, TOCTOU, GITPYTHON)
    out = run(home, adb, clock)
    assert not out.ok and out.counts["quarantined"] == 1
    assert held(home) == {GITPYTHON}  # the good record of the batch is kept, the bad one is not
    with RecordStore.open_writer(home, "ghsa") as store:
        assert store.quarantined()[0][0] == TOCTOU
        assert store.facts().checked_at is None  # facts did not advance, so it ages toward stale


def test_default_install_does_not_fetch_ghsa() -> None:  # ghsa-7
    assert parse_settings({}).sources["ghsa"].enabled is False


# --- wanted ids, aliases, spool ----------------------------------------------------------------

def test_wanted_files_carry_both_kinds_and_each_source_sees_its_own(home) -> None:  # ghsa-5
    want(home, "CVE-2022-0001", TOCTOU)
    scan = scan_wanted_files(home)
    assert scan.ids == {"CVE-2022-0001"} and scan.ghsa_ids == {TOCTOU} and not scan.problems


def test_wanted_file_rejects_a_malformed_ghsa_id(home) -> None:
    want(home, "GHSA-fmf4-pr35")
    assert scan_wanted_files(home).problems


def test_spool_routes_by_kind(home) -> None:  # ghsa-5
    assert request_id(home, TOCTOU) is True and request_id(home, "CVE-2022-0001") is True
    with RecordStore.open_writer(home, "ghsa") as store:
        assert ingest_spool(home, store, kind="ghsa") == [TOCTOU]
        assert store.wanted_ids() == {TOCTOU}
    assert (home / "spool" / "CVE-2022-0001").exists() and not (home / "spool" / TOCTOU).exists()
    with RecordStore.open_writer(home, "cvelist") as store:
        assert ingest_spool(home, store) == ["CVE-2022-0001"]


def test_held_advisory_makes_its_alias_wanted_by_cvelist(home, adb, clock) -> None:  # ghsa-5
    seed(adb)
    want(home, TOCTOU)
    run(home, adb, clock)
    with RecordStore.open_writer(home, "ghsa") as g, RecordStore.open_writer(home, "cvelist") as c:
        assert ghsa.want_aliases(g, c) == 1
        assert c.wanted_ids() == {"CVE-2026-86805"}
        assert ghsa.want_aliases(g, c) == 0  # idempotent


# --- the read function ---------------------------------------------------------------------------

def test_get_ghsa_found_with_scored_cvss_and_aliases(home, adb, clock) -> None:  # ghsa-6
    seed(adb)
    want(home, TOCTOU)
    run(home, adb, clock)
    result = get_ghsa(TOCTOU, home=home, queue=False)
    assert result.state == FOUND and result.advisory.cve_ids == ("CVE-2026-86805",)
    assert result.advisory.best_cvss.base_score == 6.3
    assert result.dataset.as_of and result.dataset.stale is False


def test_get_ghsa_withdrawn_is_never_live(home, adb, clock) -> None:  # ghsa-6
    seed(adb)
    doc = json.loads(advisory(TOCTOU))
    doc["withdrawn"] = "2026-10-01T00:00:00Z"
    adb.commit({path_for(TOCTOU): json.dumps(doc).encode()})
    want(home, TOCTOU)
    run(home, adb, clock)
    result = get_ghsa(TOCTOU, home=home, queue=False)
    assert result.state == WITHDRAWN and result.advisory.withdrawn == "2026-10-01T00:00:00Z"


def test_get_ghsa_not_fetched_queues_and_says_when_the_source_is_off(home) -> None:  # ghsa-6
    first = get_ghsa(TOCTOU, home=home)
    assert first.state == NOT_FETCHED and (home / "spool" / TOCTOU).exists()
    assert "not enabled" in first.reason
    assert first.dataset.stale is None  # unobserved, never fresh
    assert get_ghsa(RESOLVER, home=home, queue=False).reason == "not held; not queued"
    assert not (home / "spool" / RESOLVER).exists()


def test_get_ghsa_and_get_cve_refuse_each_others_ids(home) -> None:  # ghsa-6
    with pytest.raises(ValueError):
        get_ghsa("CVE-2022-0001", home=home)
    with pytest.raises(ValueError):
        get_cve(TOCTOU, home=home)
    with pytest.raises(ValueError):
        get_ghsa("../../etc/passwd", home=home)


# --- through the whole refresh -------------------------------------------------------------------

def test_full_refresh_runs_ghsa_before_cvelist_and_wants_the_alias(home, adb, upstream, clock) -> None:  # ghsa-5
    from tap_plugin.vuln_mosaic import refresh as refresh_mod

    from .conftest import FakeOpener
    from .test_vuln_mosaic_cvelist import seed as seed_cves
    from .test_vuln_mosaic_files_sources import EPSS_URL, KEV_URL, epss_body, kev_body

    seed(adb)
    seed_cves(upstream)
    want(home, TOCTOU)
    request_id(home, GITPYTHON)  # asked for by a read, not by a file
    report = refresh_mod.run_refresh(
        home,
        settings=parse_settings(ENABLED),
        now=clock,
        fetcher_factory=lambda hosts: __import__("tap_plugin.vuln_mosaic.fetch", fromlist=["Fetcher"]).Fetcher(
            hosts, FakeOpener({KEV_URL: (kev_body(), {}), EPSS_URL: (epss_body(), {})})),
        git_factory=lambda repo, h, remote=None: __import__("tap_plugin.vuln_mosaic.gitops", fromlist=["Git"]).Git(
            repo, h, remote=(adb if remote else upstream).url, allow_protocol="file"),
    )
    assert [o.source for o in report.outcomes] == ["ghsa", "cvelist", "kev", "epss"]
    assert report.clean, report.summary()
    assert held(home) == {TOCTOU, GITPYTHON}
    assert report.outcomes[0].counts["aliases_wanted"] == 2
    with RecordStore.open_writer(home, "cvelist") as c:
        assert {"CVE-2026-86805", "CVE-2026-87817"} <= c.wanted_ids()


def test_unreviewed_change_does_not_displace_a_reviewed_copy(home, adb, clock) -> None:  # ghsa-1, -2
    reviewed = json.loads(advisory(TOCTOU))
    reviewed["summary"] = "reviewed copy"
    unreviewed = json.loads(advisory(TOCTOU))
    unreviewed["summary"] = "unreviewed copy"
    adb.commit({path_for(TOCTOU, reviewed=True): json.dumps(reviewed).encode(),
                path_for(TOCTOU): json.dumps(unreviewed).encode()})
    want(home, TOCTOU)
    run(home, adb, clock)
    assert json.loads(fetch_record(home, "ghsa", TOCTOU)[0].raw)["summary"] == "reviewed copy"
    unreviewed["modified"] = "2030-01-01T00:00:00Z"
    unreviewed["summary"] = "unreviewed copy, edited"
    adb.commit({path_for(TOCTOU): json.dumps(unreviewed).encode()})  # only the unreviewed path changes
    out = run(home, adb, clock)
    assert out.ok
    assert json.loads(fetch_record(home, "ghsa", TOCTOU)[0].raw)["summary"] == "reviewed copy"


def test_no_mirror_for_ghsa_is_refused_at_settings() -> None:  # the spec's "no mirror in this version"
    from tap_plugin.vuln_mosaic.settings import SettingsError

    with pytest.raises(SettingsError, match="mirror"):
        parse_settings({"mirror": {"ghsa": "/tmp/x"}})


def test_deleting_one_duplicate_path_keeps_the_other_copy(home, adb, clock) -> None:  # ghsa-2
    reviewed = json.loads(advisory(TOCTOU))
    reviewed["summary"] = "reviewed copy"
    unreviewed = json.loads(advisory(TOCTOU))
    unreviewed["summary"] = "unreviewed copy"
    adb.commit({path_for(TOCTOU, reviewed=True): json.dumps(reviewed).encode(),
                path_for(TOCTOU): json.dumps(unreviewed).encode()})
    want(home, TOCTOU)
    run(home, adb, clock)
    adb.commit({path_for(TOCTOU, reviewed=True): None})  # the reviewed copy goes; the unreviewed one remains
    out = run(home, adb, clock)
    assert out.ok and out.counts["deleted"] == 0
    assert json.loads(fetch_record(home, "ghsa", TOCTOU)[0].raw)["summary"] == "unreviewed copy"
    adb.commit({path_for(TOCTOU): None})  # now the last copy goes
    assert run(home, adb, clock).counts["deleted"] == 1 and held(home) == set()
