"""Filling unobserved facts on vulnerability nodes from the local datasets (req-vuln-mosaic-enrich)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tap_plugin.vuln_mosaic import enrich as enrich_mod
from tap_plugin.vuln_mosaic import refresh as refresh_mod
from tap_plugin.vuln_mosaic.collectors.refresh import gridwrite
from tap_plugin.vuln_mosaic.enrich import FIELDS, facts_for, plan_patch
from tap_plugin.vuln_mosaic.outcome import EnrichResult
from tap_plugin.vuln_mosaic.settings import SettingsError, parse_settings
from tap_plugin.vuln_mosaic.store import RecordStore

from .conftest import LOG4SHELL, FakeOpener, fetcher_for
from .test_vuln_mosaic_panel import seed

EMPTY = {name: None for name in FIELDS}
TOCTOU = "GHSA-fmf4-pr35-46c2"


# --- what the datasets say ---------------------------------------------------------------------


def test_facts_for_a_cve_carry_record_kev_and_epss(home) -> None:  # enrich-1
    seed(home)
    v = facts_for(LOG4SHELL, home).values
    assert v["cvss_score"] == 10.0 and v["cvss_version"] == "3.1" and v["cvss_source"] == "CISA-ADP"
    assert v["cvss_vector"].startswith("CVSS:3.1/") and v["cwes"] == ["CWE-502", "CWE-400", "CWE-20"]
    assert (v["ssvc_exploitation"], v["ssvc_automatable"], v["ssvc_technical_impact"]) == ("active", "yes", "total")
    assert v["kev"] is True and v["kev_catalog_version"] == "2026.10.15" and v["kev_added"] == "2021-12-10"
    assert v["kev_due_date"] == "2021-12-24" and v["kev_ransomware_use"] == "Known"
    assert (v["epss_score"], v["epss_percentile"], v["epss_date"]) == (0.97, 0.99, "2026-10-16")
    assert v["record_url"] == f"https://cveawg.mitre.org/api/cve/{LOG4SHELL}"
    assert v["title"] and v["description"] and v["published_at"].startswith("2021-12-10")
    assert set(v) <= set(FIELDS)


def test_nothing_held_means_no_facts(home) -> None:  # enrich-1
    assert facts_for(LOG4SHELL, home).values == {}
    assert facts_for("not an id", home).values == {}


def test_a_stale_or_unchecked_kev_and_epss_say_nothing(home) -> None:  # enrich-3
    seed(home, checked="2020-01-01T00:00:00Z")  # far past the three-day limit
    v = facts_for(LOG4SHELL, home).values
    assert "kev" not in v and "epss_score" not in v and v["cvss_score"] == 10.0, "the record itself still counts"


def test_not_listed_is_a_fact_only_from_a_fresh_catalog(home) -> None:  # enrich-3
    seed(home, cve_id="CVE-2022-0001")
    v = facts_for("CVE-2022-0001", home).values
    assert v["kev"] is True  # the seed lists its own id; use a different id for not-listed
    other = facts_for(LOG4SHELL, home).values  # held nowhere: no record, but the catalogs are fresh
    assert other["kev"] is False and other["kev_catalog_version"] == "2026.10.15" and "kev_added" not in other


def test_a_rejected_record_adds_nothing(home) -> None:  # enrich-4
    with RecordStore.open_writer(home, "cvelist") as store:
        store.put(LOG4SHELL, "REJECTED", None, b"{}")
        store.set_facts(as_of="2099-01-01T00:00:00Z", checked_at="2099-01-01T00:00:00Z", source_version="x", fetched_at="2099-01-01T00:00:00Z")
    assert "cvss_score" not in facts_for(LOG4SHELL, home).values


def _advisory(**over) -> bytes:
    record = {
        "id": TOCTOU, "summary": "A summary", "details": "The details.", "published": "2026-09-01T00:00:00Z",
        "modified": "2026-09-02T00:00:00Z", "aliases": [],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"cwe_ids": ["CWE-506"], "github_reviewed": True}, **over,
    }
    return json.dumps(record).encode()


def _seed_ghsa(home, state="PUBLISHED", raw=None) -> None:
    with RecordStore.open_writer(home, "ghsa") as store:
        store.put(TOCTOU, state, None, raw or _advisory())
        store.set_facts(as_of="2099-01-01T00:00:00Z", checked_at="2099-01-01T00:00:00Z", source_version="x", fetched_at="2099-01-01T00:00:00Z")


def test_facts_for_a_ghsa_only_node(home) -> None:  # enrich-1
    _seed_ghsa(home)
    v = facts_for(TOCTOU, home).values
    assert v["cwes"] == ["CWE-506"] and v["cvss_score"] == 9.8 and v["cvss_source"] == "GitHub advisory"
    assert v["title"] == "A summary" and v["record_url"] == f"https://github.com/advisories/{TOCTOU}"
    assert "kev" not in v and "epss_score" not in v, "KEV and EPSS are keyed by CVE id"


def test_a_withdrawn_advisory_adds_nothing(home) -> None:  # enrich-4
    _seed_ghsa(home, state="WITHDRAWN", raw=_advisory(withdrawn="2026-09-03T00:00:00Z"))
    assert facts_for(TOCTOU, home).values == {}


def test_a_v4_only_advisory_leaves_the_score_unwritten(home) -> None:  # enrich-1: never a guessed number
    _seed_ghsa(home, raw=_advisory(severity=[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]))
    v = facts_for(TOCTOU, home).values
    assert "cvss_score" not in v and v["cwes"] == ["CWE-506"]


# --- what may be written -----------------------------------------------------------------------


FACTS = {
    "title": "T", "description": "D", "cwes": ["CWE-79"], "cvss_score": 7.5, "cvss_vector": "V", "cvss_version": "3.1",
    "cvss_source": "CNA", "kev": True, "kev_catalog_version": "2026.10.15", "kev_added": "2026-01-01",
    "epss_score": 0.5, "epss_percentile": 0.9, "epss_date": "2026-10-16", "record_url": "U",
}  # fmt: skip


def test_a_partly_filled_group_is_never_rolled_back_or_clobbered() -> None:  # enrich-3
    newer_kev = {**EMPTY, "kev": None, "kev_catalog_version": "2027.01.01"}
    assert not {k for k in plan_patch(newer_kev, FACTS) if k.startswith("kev")}, "stamped newer than our catalog"
    sibling = {**EMPTY, "kev": None, "kev_added": "2021-12-10"}
    assert not {k for k in plan_patch(sibling, FACTS) if k.startswith("kev")}, "part of a group, no stamp: another writer's"
    newer_epss = {**EMPTY, "epss_score": None, "epss_date": "2027-01-01"}
    assert not {k for k in plan_patch(newer_epss, FACTS) if k.startswith("epss")}
    older_epss = {**EMPTY, "epss_score": None, "epss_date": "2026-01-01"}
    assert plan_patch(older_epss, FACTS)["epss_score"] == 0.5, "stamped older: ours moves it forward"


def test_an_unobserved_node_gets_everything(home) -> None:  # enrich-2
    assert plan_patch(EMPTY, FACTS) == FACTS


def test_what_the_node_has_is_never_overwritten(home) -> None:  # enrich-2
    current = {**EMPTY, "title": "scanner title", "cwes": [], "record_url": "theirs"}
    patch = plan_patch(current, FACTS)
    assert "title" not in patch and "cwes" not in patch and "record_url" not in patch
    assert patch["description"] == "D", "an empty list is an observed fact too, but a missing one is filled"


def test_an_observed_empty_cwe_list_is_not_replaced() -> None:  # enrich-2
    assert "cwes" not in plan_patch({**EMPTY, "cwes": []}, FACTS)


def test_the_cvss_group_is_written_whole_or_not_at_all() -> None:  # enrich-2
    assert "cvss_score" not in plan_patch({**EMPTY, "cvss_source": "Vendor"}, FACTS)
    assert "cvss_vector" not in plan_patch({**EMPTY, "cvss_score": 5.0}, FACTS)
    group = {k: plan_patch(EMPTY, FACTS)[k] for k in ("cvss_score", "cvss_vector", "cvss_version", "cvss_source")}
    assert group == {"cvss_score": 7.5, "cvss_vector": "V", "cvss_version": "3.1", "cvss_source": "CNA"}


def test_kev_versions_compare_as_numbers_not_as_text() -> None:  # enrich-3
    held = {**EMPTY, "kev": True, "kev_catalog_version": "2026.9.1"}
    newer = {**FACTS, "kev_catalog_version": "2026.10.15"}
    assert plan_patch(held, newer)["kev_catalog_version"] == "2026.10.15", "10 is above 9 although '10' sorts below '9'"
    held = {**EMPTY, "kev": True, "kev_catalog_version": "2026.10.15"}
    assert "kev" not in plan_patch(held, {**FACTS, "kev_catalog_version": "2026.9.1"})
    assert "kev" not in plan_patch({**held, "kev_catalog_version": "weird"}, FACTS), "an unorderable stamp moves nothing"


def test_a_cvss_metric_without_a_vector_writes_no_cvss_at_all() -> None:  # enrich-2
    partial = {"cvss_score": 7.5, "cvss_version": "3.1", "cvss_source": "CNA"}
    assert not {k for k in plan_patch(EMPTY, partial) if k.startswith("cvss")}


def test_kev_is_rewritten_only_for_a_newer_catalog() -> None:  # enrich-3
    held = {**EMPTY, "kev": True, "kev_catalog_version": "2026.10.15", "kev_added": "2026-01-01"}
    assert not {k for k in plan_patch(held, FACTS) if k.startswith("kev")}, "the same catalog: nothing to say"
    older = {**held, "kev_catalog_version": "2026.09.01", "kev": False}
    assert plan_patch(older, FACTS)["kev"] is True, "a newer catalog corrects an older answer"
    newer = {**held, "kev_catalog_version": "2026.11.01", "kev": False}
    assert "kev" not in plan_patch(newer, FACTS), "never move a node back to an older catalog"
    unversioned = {**EMPTY, "kev": False}
    assert "kev" not in plan_patch(unversioned, FACTS), "a value with no catalog version is another writer's"


def test_delisting_withdraws_the_old_kev_details() -> None:  # enrich-3
    held = {**EMPTY, "kev": True, "kev_catalog_version": "2026.09.01", "kev_added": "2020-01-01", "kev_due_date": "2020-02-01"}
    patch = plan_patch(held, {"kev": False, "kev_catalog_version": "2026.10.15"})
    assert patch["kev"] is False and patch["kev_added"] is None and patch["kev_due_date"] is None
    assert patch["kev_catalog_version"] == "2026.10.15"


def test_a_newer_listing_without_a_detail_clears_the_old_one() -> None:  # enrich-3
    held = {**EMPTY, "kev": True, "kev_catalog_version": "2026.09.01", "kev_due_date": "2020-02-01", "kev_required_action": "old"}
    facts = {"kev": True, "kev_catalog_version": "2026.10.15", "kev_added": "2026-01-01"}
    patch = plan_patch(held, facts)
    assert patch["kev_due_date"] is None and patch["kev_required_action"] is None and patch["kev_added"] == "2026-01-01"


def test_epss_is_rewritten_only_for_a_newer_day() -> None:  # enrich-3
    held = {**EMPTY, "epss_score": 0.1, "epss_percentile": 0.2, "epss_date": "2026-10-16"}
    assert not {k for k in plan_patch(held, FACTS) if k.startswith("epss")}, "same day: nothing to say"
    assert plan_patch({**held, "epss_date": "2026-10-01"}, FACTS)["epss_score"] == 0.5
    assert "epss_score" not in plan_patch({**held, "epss_date": "2026-10-30"}, FACTS)
    assert "epss_score" not in plan_patch({**EMPTY, "epss_score": 0.3}, FACTS), "undated: another writer's"


def test_a_node_that_already_has_it_all_needs_no_patch() -> None:  # enrich-2
    assert plan_patch(dict(FACTS), FACTS) == {}


# --- writing to the grid -----------------------------------------------------------------------


def _row(n: int, vuln_id: str | None = None, **over) -> dict:
    return {"eid": f"eid-{n}", "ver": 1, "vuln_id": vuln_id or f"CVE-2026-{n:05d}", **EMPTY, **over}


class Grid:
    """A stand-in for the grid's read and write paths."""

    def __init__(self, rows, fail_eids=(), list_bug=False):
        self.rows, self.fail, self.list_bug, self.batches = rows, set(fail_eids), list_bug, []

    def execute(self, query, inputs):
        window = [r for r in sorted(self.rows, key=lambda r: r["vuln_id"]) if r["vuln_id"] > inputs["after"]]
        return {"rows": window[: gridwrite.PAGE]}

    def batch(self, ops, **kw):
        self.batches.append((ops, kw))
        bad = [i for i, op in enumerate(ops) if op.target in self.fail or (self.list_bug and "cwes" in op.payload)]
        why = ["'list' object has no attribute 'items'" if self.list_bug and "cwes" in ops[i].payload else "entity_version_conflict" for i in range(len(ops))]
        results = [SimpleNamespace(success=i not in bad, errors=[SimpleNamespace(message=why[i])] if i in bad else []) for i in range(len(ops))]
        return SimpleNamespace(success=not bad, results=results, errors=[])


def _facts(_id, _home):
    return SimpleNamespace(values={"cwes": ["CWE-506"], "title": "T"})


def run_write(grid, home, settings=None, facts=_facts):
    return gridwrite.enrich_grid(parse_settings(settings or {}), home, execute=grid.execute, batch=grid.batch, facts=facts)


def test_only_nodes_with_something_to_add_are_patched_with_their_version(home) -> None:  # enrich-5
    grid = Grid([_row(1), _row(2, ver=7, title="kept", cwes=[])])
    out = run_write(grid, home)
    ops = [op for batch, _ in grid.batches for op in batch]
    assert len(ops) == 1 and ops[0].verb == "patch_node", "a patch, never a create; a node with nothing to add is not touched"
    assert ops[0].target == "eid-1" and ops[0].entity_expected_version == 1
    assert ops[0].payload == {"cwes": ["CWE-506"], "title": "T"}
    assert (out.patched, out.unchanged, out.failed, out.fields) == (1, 1, 0, 2)
    assert grid.batches[0][1]["batch_name"] == "vuln_mosaic enrichment" and grid.batches[0][1]["batch_description"]


def test_patches_go_in_batches_of_fifty(home) -> None:  # enrich-5
    grid = Grid([_row(n) for n in range(1, 121)])
    out = run_write(grid, home)
    assert [len(ops) for ops, _ in grid.batches] == [50, 50, 20] and out.patched == 120


def test_one_refused_patch_costs_only_its_own_node(home) -> None:  # enrich-6
    grid = Grid([_row(n) for n in range(1, 6)], fail_eids={"eid-3"})
    out = run_write(grid, home)
    assert (out.patched, out.failed) == (4, 1)
    assert len(out.problems) == 1 and "eid-3" in out.problems[0] and "entity_version_conflict" in out.problems[0]


def test_a_grid_that_cannot_patch_lists_still_gets_every_other_fact(home) -> None:  # enrich-6
    grid = Grid([_row(1), _row(2)], list_bug=True)
    out = run_write(grid, home)
    written = [op.payload for ops, _ in grid.batches for op in ops if not (grid.list_bug and "cwes" in op.payload)]
    assert written == [{"title": "T"}, {"title": "T"}], "the retry drops only the list fact, at the version it was read"
    assert (out.patched, out.failed, out.lists_deferred) == (2, 0, 2)
    refused = [op for ops, _ in grid.batches for op in ops if "cwes" in op.payload]
    assert len(refused) == 3, "the two in the first batch, then the first alone; the second is retried without cwes"
    assert out.problems == [gridwrite.LIST_NOTE], "named once, not once per node"


def test_a_node_with_only_a_list_fact_is_deferred_not_failed(home) -> None:  # enrich-6
    grid = Grid([_row(1, title="kept")], list_bug=True)
    out = run_write(grid, home)
    assert (out.patched, out.failed, out.lists_deferred) == (0, 0, 1)


def test_the_per_run_bound_leaves_the_rest_for_the_next_run(home) -> None:  # enrich-6
    grid = Grid([_row(n) for n in range(1, 6)])
    out = run_write(grid, home, {"grid": {"enrich": {"max_nodes_per_run": 2}}})
    assert (out.patched, out.stopped_early) == (2, True)
    assert not run_write(Grid([_row(1)]), home).stopped_early


def test_a_node_whose_id_is_not_an_id_is_never_looked_up(home) -> None:  # enrich-6
    asked: list[str] = []

    def facts(vuln_id, h):
        asked.append(vuln_id)
        return _facts(vuln_id, h)

    out = run_write(Grid([_row(1, vuln_id="not an id"), _row(2, vuln_id="../etc")]), home, facts=facts)
    assert asked == [] and out.patched == 0 and not Grid([]).batches


def test_unwritable_nodes_do_not_starve_the_ones_after_them(home) -> None:  # enrich-6
    def facts(vuln_id, h):
        # the first three nodes can only ever be given a list fact; the later ones can be given a title
        return SimpleNamespace(values={"cwes": ["CWE-506"]} if vuln_id < "CVE-2026-00004" else {"title": "T"})

    grid = Grid([_row(n) for n in range(1, 9)], list_bug=True)
    out = run_write(grid, home, {"grid": {"enrich": {"max_nodes_per_run": 2}}}, facts=facts)
    assert out.patched == 2 and out.lists_deferred == 3 and out.stopped_early, out
    titled = [op.target for ops, _ in grid.batches for op in ops if op.payload == {"title": "T"}]
    assert titled == ["eid-4", "eid-5"]


def test_the_grid_is_read_lazily_not_all_at_once(home, monkeypatch) -> None:  # enrich-6
    monkeypatch.setattr(gridwrite, "PAGE", 2)
    pages: list[str] = []
    grid = Grid([_row(n) for n in range(1, 9)])

    def execute(query, inputs):
        pages.append(inputs["after"])
        return grid.execute(query, inputs)

    out = gridwrite.enrich_grid(
        parse_settings({"grid": {"enrich": {"max_nodes_per_run": 1}}}), home, execute=execute, batch=grid.batch, facts=_facts
    )
    assert out.patched == 1 and len(pages) == 1, "stopped at the bound without reading the rest of the grid"


def test_a_node_with_no_version_is_not_written_blind(home) -> None:  # enrich-5
    grid = Grid([_row(1, ver=None)])
    out = run_write(grid, home)
    assert out.failed == 1 and grid.batches == []


def test_the_grid_is_read_in_pages(home, monkeypatch) -> None:
    monkeypatch.setattr(gridwrite, "PAGE", 2)
    grid = Grid([_row(n) for n in range(1, 8)])
    assert run_write(grid, home).patched == 7


def test_an_unreadable_type_is_named_and_nothing_is_written(home) -> None:  # enrich-6
    def execute(query, inputs):
        raise LookupError("unknown entity type")

    out = gridwrite.enrich_grid(parse_settings({}), home, execute=execute, batch=lambda *a, **k: pytest.fail("wrote"))
    assert out.patched == 0 and out.problems and "LookupError" in out.problems[0]
    assert out.broken, "no configured type could be read: the run is not clean"


def test_one_unreadable_type_among_readable_ones_is_only_a_warning(home) -> None:  # enrich-6
    grid = Grid([_row(1)])

    def execute(query, inputs):
        if "bad__type" in query:
            raise LookupError("unknown entity type")
        return grid.execute(query, inputs)

    settings = parse_settings({"grid": {"vulnerability_types": ["bad__type", "compliance_core__compliance_vulnerability"]}})
    out = gridwrite.enrich_grid(settings, home, execute=execute, batch=grid.batch, facts=_facts)
    assert out.patched == 1 and out.problems and not out.broken


# --- the run -------------------------------------------------------------------------------------


def _run(home, upstream, clock, writer, settings=None):
    from tap_plugin.vuln_mosaic.gitops import Git

    return refresh_mod.run_refresh(
        home,
        settings=parse_settings({"sources": {"kev": {"enabled": False}, "epss": {"enabled": False}, "cvelist": {"enabled": False}}, **(settings or {})}),
        now=clock,
        fetcher_factory=fetcher_for(FakeOpener({})),
        git_factory=lambda repo, h, remote=None: Git(repo, h, remote=upstream.url, allow_protocol="file"),
        grid_writer=writer,
    )


def test_the_write_runs_once_after_the_sources(home, upstream, clock) -> None:  # enrich-7
    calls: list[str] = []
    report = _run(home, upstream, clock, lambda s, h: calls.append("write") or EnrichResult(patched=3))
    assert calls == ["write"] and report.enrich.patched == 3


@pytest.mark.parametrize("grid", [{"enrich": {"enabled": False}}, {"enabled": False}])
def test_the_write_can_be_switched_off(home, upstream, clock, grid) -> None:  # enrich-7
    calls: list[int] = []
    report = _run(home, upstream, clock, lambda s, h: calls.append(1) or EnrichResult(), {"grid": grid})
    assert calls == [] and report.enrich is None


def test_a_write_phase_that_fails_outright_makes_the_run_not_clean(home, upstream, clock) -> None:  # enrich-7
    def boom(settings, h):
        raise RuntimeError("grid said no")

    report = _run(home, upstream, clock, boom)
    assert report.enrich.problems == ["grid write: RuntimeError: grid said no"]
    assert not report.clean and report.failed_sources == [] and "grid write failed" in report.summary()


def test_a_broken_write_phase_fails_the_collector_job(monkeypatch) -> None:  # enrich-7
    from tap_plugin.vuln_mosaic.collectors.refresh import collector as mod
    from tap_plugin.vuln_mosaic.outcome import RunReport

    report = RunReport(enrich=EnrichResult(raised=True, problems=["grid write: RuntimeError: no"]))
    monkeypatch.setattr(mod, "run_refresh", lambda **_: report)
    instance = mod.VulnMosaicRefreshCollector.__new__(mod.VulnMosaicRefreshCollector)
    instance.results = {"info": [], "warn": [], "error": []}
    instance._produced_batches, instance._surfaces, instance._surfaces_declared, instance.summary = [], [], False, ""
    with pytest.raises(mod.VulnMosaicRefreshError, match="grid write failed"):
        instance.run()
    assert any(e["message_code"] == "GRID_WRITE_FAILED" for e in instance.results["error"])


def test_a_newer_epss_score_without_a_percentile_is_not_written_as_a_mixed_group(home) -> None:  # enrich-3
    held = {**EMPTY, "epss_score": 0.1, "epss_percentile": 0.9, "epss_date": "2026-01-01"}
    assert plan_patch(held, {"epss_score": 0.2, "epss_date": "2026-02-01"}) == {}


def test_one_refused_node_is_not_a_broken_write_phase() -> None:  # enrich-6
    assert not EnrichResult(patched=4, failed=1).broken
    assert not EnrichResult(lists_deferred=3).broken, "a known limit of the grid is a warning, not a failure"
    assert EnrichResult(failed=2).broken and EnrichResult(raised=True).broken


def test_no_writer_means_no_write(home, upstream, clock) -> None:
    assert _run(home, upstream, clock, None).enrich is None


def test_enrichment_settings_defaults_and_validation() -> None:  # enrich-7
    grid = parse_settings({}).grid
    assert grid.enrich is True and grid.max_nodes_per_run == 2000
    for bad in ({"enrich": {"enabled": "yes"}}, {"enrich": {"max_nodes_per_run": 0}}, {"enrich": {"x": 1}}):
        with pytest.raises(SettingsError):
            parse_settings({"grid": bad})


def test_the_enrichment_core_stays_free_of_the_grid() -> None:  # enrich-7
    import inspect

    text = inspect.getsource(enrich_mod)
    assert "tap_grid" not in text and "django" not in text
    assert "from tap_grid" in inspect.getsource(gridwrite).split("def _write")[1]
