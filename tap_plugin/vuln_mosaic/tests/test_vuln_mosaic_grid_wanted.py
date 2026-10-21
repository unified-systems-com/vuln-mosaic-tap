"""The vulnerability ids the grid already holds become wanted ids (req-vuln-mosaic-wanted-7, -7)."""

from __future__ import annotations

import pytest

from tap_plugin.vuln_mosaic import refresh as refresh_mod
from tap_plugin.vuln_mosaic.collectors.refresh import gridread
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.outcome import GridRead
from tap_plugin.vuln_mosaic.settings import SettingsError, parse_settings
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import ingest_grid

from .conftest import PUBLISHED_SSVC, FakeOpener, fetcher_for
from .test_vuln_mosaic_cvelist import seed as seed_upstream

SLUG = "compliance_core__compliance_vulnerability"
TOCTOU = "GHSA-fmf4-pr35-46c2"
ONLY_CVELIST = {"sources": {"kev": {"enabled": False}, "epss": {"enabled": False}}}


def run(home, upstream, clock, reader, settings=None):
    return refresh_mod.run_refresh(
        home,
        settings=parse_settings({**ONLY_CVELIST, **(settings or {})}),
        now=clock,
        fetcher_factory=fetcher_for(FakeOpener({})),
        git_factory=lambda repo, h, remote=None: Git(repo, h, remote=upstream.url, allow_protocol="file"),
        grid_reader=reader,
    )


def test_a_grid_id_is_fetched_with_no_wanted_file(home, upstream, clock) -> None:  # wanted-7
    seed_upstream(upstream)
    report = run(home, upstream, clock, lambda s: GridRead(ids=[PUBLISHED_SSVC]))
    assert report.clean and report.grid_ids == 1 and not report.grid_problems
    store = RecordStore.open_reader(home, "cvelist")
    assert store is not None and store.get(PUBLISHED_SSVC) is not None
    with RecordStore.open_writer(home, "cvelist") as writer:
        assert PUBLISHED_SSVC in writer.wanted_ids()


def test_a_value_that_is_not_an_id_is_refused_and_reported(home, upstream, clock) -> None:  # wanted-8
    seed_upstream(upstream)
    bad = [PUBLISHED_SSVC + "\n", "../../etc/passwd", "CVE-2022-0001; rm -rf /", "", "cve-2022-0001"]
    report = run(home, upstream, clock, lambda s: GridRead(ids=[PUBLISHED_SSVC, *bad]))
    assert report.clean
    with RecordStore.open_writer(home, "cvelist") as writer:
        assert writer.wanted_ids() == {PUBLISHED_SSVC}
    assert len(report.grid_problems) == len(bad) - 0 and all("not a CVE or GHSA id" in p for p in report.grid_problems)


def test_an_unreadable_grid_never_stops_the_sources(home, upstream, clock) -> None:  # wanted-8
    seed_upstream(upstream)

    def broken(settings):
        raise RuntimeError("grid is down")

    report = run(home, upstream, clock, broken)
    assert report.clean and report.grid_ids == 0
    assert report.grid_problems == ["grid: RuntimeError: grid is down"]


def test_a_type_that_is_not_installed_is_reported_and_the_rest_is_read(home, upstream, clock) -> None:
    pages = {SLUG: ["CVE-2022-0001"]}

    def execute(query, inputs):
        slug = query.split("(v:")[1].split(")")[0]
        if slug not in pages:
            raise LookupError(f"unknown entity type {slug}")
        return {"rows": [{"id": i} for i in pages[slug] if i > inputs["after"]]}

    settings = parse_settings({"grid": {"vulnerability_types": ["not_installed__vulnerability", SLUG]}})
    read = gridread.read_grid_ids(settings, execute)
    assert read.ids == ["CVE-2022-0001"]
    assert len(read.problems) == 1 and "not_installed__vulnerability" in read.problems[0]


def test_the_grid_is_read_in_pages_by_id(home) -> None:
    every = [f"CVE-2026-{n:05d}" for n in range(1, gridread.PAGE * 2 + 501)]
    seen_after: list[str] = []

    def execute(query, inputs):
        seen_after.append(inputs["after"])
        window = [i for i in every if i > inputs["after"]][: gridread.PAGE]
        return {"rows": [{"id": i} for i in window]}

    read = gridread.read_grid_ids(parse_settings({}), execute)
    assert read.ids == every and not read.problems
    assert seen_after == ["", every[gridread.PAGE - 1], every[gridread.PAGE * 2 - 1]]


def test_malformed_values_never_count_toward_the_id_bound(monkeypatch) -> None:  # wanted-8
    monkeypatch.setattr(gridread, "MAX_IDS", 3)
    rows = ["!" * 5 + str(n) for n in range(10)] + ["CVE-2026-00001", "CVE-2026-00002"]

    def execute(query, inputs):
        return {"rows": [{"id": i} for i in sorted(rows) if i > inputs["after"]][: gridread.PAGE]}

    read = gridread.read_grid_ids(parse_settings({}), execute)
    assert read.ids == ["CVE-2026-00001", "CVE-2026-00002"]
    assert sum("not a CVE or GHSA id" in p for p in read.problems) == 10


def test_the_pager_stops_when_the_id_bound_is_reached(monkeypatch) -> None:  # wanted-8
    monkeypatch.setattr(gridread, "MAX_IDS", 3)
    monkeypatch.setattr(gridread, "PAGE", 2)
    calls: list[str] = []
    every = [f"CVE-2026-{n:05d}" for n in range(1, 50)]

    def execute(query, inputs):
        calls.append(inputs["after"])
        return {"rows": [{"id": i} for i in every if i > inputs["after"]][:2]}

    read = gridread.read_grid_ids(parse_settings({}), execute)
    assert read.ids == every[:3] and any("stopped at 3 ids" in p for p in read.problems)
    assert len(calls) <= 3, "it must not walk the rest of the type"


def test_the_pager_stops_after_the_row_bound(monkeypatch) -> None:  # wanted-8
    monkeypatch.setattr(gridread, "MAX_ROWS", 4)
    monkeypatch.setattr(gridread, "PAGE", 2)

    def execute(query, inputs):
        n = int(inputs["after"][1:] or 0)
        return {"rows": [{"id": f"x{n + 1}"}, {"id": f"x{n + 2}"}]}  # never a valid id, always advancing

    read = gridread.read_grid_ids(parse_settings({}), execute)
    assert any("scanning 4 rows" in p for p in read.problems) and read.ids == []


def test_a_repeated_or_non_string_row_is_ignored() -> None:
    def execute(query, inputs):
        return {"rows": [{"id": "CVE-2022-0001"}, {"id": "CVE-2022-0001"}, {"id": 7}, {"other": 1}, "x"]}

    read = gridread.read_grid_ids(parse_settings({}), execute)
    assert read.ids == ["CVE-2022-0001"]


def test_grid_reading_can_be_switched_off(home, upstream, clock) -> None:
    seed_upstream(upstream)
    calls: list[int] = []

    def reader(settings):
        calls.append(1)
        return GridRead(ids=[PUBLISHED_SSVC])

    report = run(home, upstream, clock, reader, {"grid": {"enabled": False}})
    assert calls == [] and report.grid_ids == 0


def test_a_run_with_no_reader_reads_no_grid(home, upstream, clock) -> None:
    seed_upstream(upstream)
    report = run(home, upstream, clock, None)
    assert report.grid_ids == 0 and not report.grid_problems


def test_each_store_takes_only_its_own_kind(home) -> None:  # wanted-7
    with RecordStore.open_writer(home, "cvelist") as cve, RecordStore.open_writer(home, "ghsa") as ghsa:
        assert ingest_grid(cve, ["CVE-2022-0001", TOCTOU]) == (1, [])
        assert ingest_grid(ghsa, ["CVE-2022-0001", TOCTOU], kind="ghsa") == (1, [])
        assert cve.wanted_ids() == {"CVE-2022-0001"} and ghsa.wanted_ids() == {TOCTOU}


def test_grid_settings_defaults_and_validation() -> None:  # wanted-7
    default = parse_settings({}).grid
    assert default.enabled is True and default.vulnerability_types == (SLUG,)
    for bad in ({"vulnerability_types": ["Bad Slug; x"]}, {"vulnerability_types": ["single"]}, {"extra": 1}, {"enabled": "yes"}):
        with pytest.raises(SettingsError):
            parse_settings({"grid": bad})


def test_the_refresh_core_stays_free_of_the_grid() -> None:  # wanted-8
    import inspect

    from tap_plugin.vuln_mosaic import refresh, settings, wanted

    for module in (refresh, settings, wanted):
        text = inspect.getsource(module)
        assert "tap_grid" not in text and "django" not in text, module.__name__
    assert "from tap_grid" in inspect.getsource(gridread).split("def read_grid_ids")[1]  # imported inside the function
