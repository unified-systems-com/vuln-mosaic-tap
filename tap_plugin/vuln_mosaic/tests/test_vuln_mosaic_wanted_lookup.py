"""Wanted files, the spool and the read function (req-vuln-mosaic-wanted, -lookup)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import lookup
from tap_plugin.vuln_mosaic.locking import writer_lock
from tap_plugin.vuln_mosaic.store import RecordStore
from tap_plugin.vuln_mosaic.wanted import ingest_spool, request_id, scan_wanted_files, wanted_set

from .conftest import PUBLISHED_SSVC, REJECTED, corpus


def write_wanted(home: Path, name: str, ids: list[str]) -> None:
    (home / "wanted").mkdir(parents=True, exist_ok=True)
    (home / "wanted" / name).write_text(json.dumps({"ids": ids}))


def test_bad_file_does_not_abort(home: Path) -> None:  # wanted-2
    write_wanted(home, "good.json", ["CVE-2022-0001"])
    (home / "wanted" / "broken.json").write_text("{")
    write_wanted(home, "badid.json", ["not-a-cve"])
    scan = scan_wanted_files(home)
    assert scan.ids == {"CVE-2022-0001"} and len(scan.problems) == 2


def test_consumer_name_and_symlink_refused(home: Path, tmp_path: Path) -> None:  # wanted-6
    write_wanted(home, "good.json", ["CVE-2022-0001"])
    write_wanted(home, "A B.json", ["CVE-2022-0002"])
    write_wanted(home, "..x.json", ["CVE-2022-0003"])
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"ids": ["CVE-2022-0004"]}))
    (home / "wanted" / "link.json").symlink_to(outside)
    scan = scan_wanted_files(home)
    assert scan.ids == {"CVE-2022-0001"}
    assert any("symlink" in p for p in scan.problems) and len(scan.problems) == 3


def test_spool_is_idempotent_and_ingested(home: Path) -> None:  # wanted-3
    assert request_id(home, "CVE-2022-0001") is True
    assert request_id(home, "CVE-2022-0001") is False
    assert [p.name for p in (home / "spool").iterdir()] == ["CVE-2022-0001"]
    with RecordStore.open_writer(home, "cvelist") as store:
        assert ingest_spool(home, store) == ["CVE-2022-0001"]
        assert store.wanted_ids() == {"CVE-2022-0001"}
    assert list((home / "spool").iterdir()) == []


def test_spool_ignores_foreign_names(home: Path) -> None:
    (home / "spool").mkdir(parents=True)
    (home / "spool" / "junk").write_text("x")
    with RecordStore.open_writer(home, "cvelist") as store:
        assert ingest_spool(home, store) == []
    assert (home / "spool" / "junk").exists()


def test_wanted_set_includes_held(home: Path) -> None:
    write_wanted(home, "a.json", ["CVE-2022-0001"])
    with RecordStore.open_writer(home, "cvelist") as store:
        store.put("CVE-2022-0002", "PUBLISHED", None, b"{}")
        store.add_wanted("CVE-2022-0003", "spool")
        assert wanted_set(scan_wanted_files(home), store) == {"CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003"}


def test_malformed_id_refused_before_any_io(home: Path) -> None:  # lookup-5
    for bad in ("../etc/passwd", "CVE-1-1", "cve-2022-0001", "CVE-2022-0001\n", "", 7):
        with pytest.raises(ValueError):
            lookup.get_cve(bad, home=home)  # type: ignore[arg-type]
    assert not home.exists()


def seed(home: Path, cve_id: str, state: str = "PUBLISHED", raw: bytes | None = None, checked: str = "2026-10-18T00:00:00Z") -> None:
    with RecordStore.open_writer(home, "cvelist") as store:
        store.put(cve_id, state, None, raw or corpus(cve_id))
        store.set_facts(as_of=checked, checked_at=checked, source_version="abc", fetched_at="x")


def test_three_outcomes(home: Path) -> None:  # lookup-1
    seed(home, PUBLISHED_SSVC)
    seed(home, REJECTED, "REJECTED")
    found = lookup.get_cve(PUBLISHED_SSVC, home=home)
    assert found.state == lookup.FOUND and found.record["cveMetadata"]["cveId"] == PUBLISHED_SSVC
    assert lookup.get_cve(REJECTED, home=home).record is None
    miss = lookup.get_cve("CVE-2022-0777", home=home)
    assert miss.state == lookup.NOT_FETCHED and miss.record is None


def test_miss_queues_and_makes_no_connection(home: Path) -> None:  # lookup-2 (conftest blocks sockets)
    result = lookup.get_cve("CVE-2022-0777", home=home)
    assert result.state == lookup.NOT_FETCHED and result.dataset.stale is None
    assert [p.name for p in (home / "spool").iterdir()] == ["CVE-2022-0777"]


def test_stale_dataset_still_returns_record_flagged(home: Path) -> None:
    seed(home, PUBLISHED_SSVC, checked="2026-01-01T00:00:00Z")
    result = lookup.get_cve(PUBLISHED_SSVC, home=home)
    assert result.state == lookup.FOUND and result.dataset.stale is True


def test_immediate_off_does_not_touch_git(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lookup, "_immediate", lambda *a, **k: pytest.fail("immediate path used"))
    lookup.get_cve("CVE-2022-0777", home=home)


def test_immediate_uses_shared_fetch_and_stores(home: Path, upstream, monkeypatch: pytest.MonkeyPatch) -> None:  # lookup-3
    from tap_plugin.vuln_mosaic import gitops
    from tap_plugin.vuln_mosaic.sources import cvelist

    from .test_vuln_mosaic_cvelist import seed as seed_upstream

    seed_upstream(upstream)
    home.mkdir(parents=True)
    (home / "settings.json").write_text(json.dumps({"immediate_fetch": True}))
    real = gitops.Git

    def local_git(repo, h, **kw):  # type: ignore[no-untyped-def]
        return real(repo, h, remote=upstream.url, allow_protocol="file", **kw)

    monkeypatch.setattr(gitops, "Git", local_git)
    calls = []
    original = cvelist.fetch_ids
    monkeypatch.setattr(cvelist, "fetch_ids", lambda *a: calls.append(1) or original(*a))
    result = lookup.get_cve(PUBLISHED_SSVC, home=home)
    assert result.state == lookup.FOUND and calls == [1]
    assert lookup.get_cve(PUBLISHED_SSVC, home=home).state == lookup.FOUND  # now held
    absent = lookup.get_cve("CVE-2022-9998", home=home)
    assert absent.state == lookup.NOT_FETCHED and "not present upstream" in absent.reason


def test_immediate_respects_writer_lock(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # lookup-6
    home.mkdir(parents=True)
    (home / "settings.json").write_text(json.dumps({"immediate_fetch": True}))
    with writer_lock(home):
        result = lookup.get_cve("CVE-2022-0777", home=home)
    assert result.state == lookup.NOT_FETCHED and "refresh is running" in result.reason
    assert (home / "spool" / "CVE-2022-0777").exists()
    assert not (home / "stores" / "cvelist.sqlite").exists()


def test_lookup_imports_no_django() -> None:  # lookup-4
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in ('django','tap_cares','tap_grid','tap_web','tap_plugins'):\n"
        "            raise ImportError(name)\n"
        "sys.meta_path.insert(0, Block())\n"
        "import tap_plugin.vuln_mosaic.lookup\n"
        "print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "ok", out.stderr


def test_package_imports_no_other_plugin() -> None:  # wanted-4
    root = Path(lookup.__file__).parent
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(("import tap_plugin.", "from tap_plugin.")):
                assert stripped.split()[1].startswith("tap_plugin.vuln_mosaic"), f"{path.name}: {stripped}"


def test_cross_process_reader_sees_consistent_data(home: Path) -> None:  # corpus-3 (WAL across processes)
    seed(home, PUBLISHED_SSVC)
    reader = (
        "import sys, json, time\n"
        "from pathlib import Path\n"
        "from tap_plugin.vuln_mosaic.store import fetch_record\n"
        "home = Path(sys.argv[1]); bad = 0; reads = 0\n"
        "end = time.monotonic() + 3\n"
        "while time.monotonic() < end:\n"
        "    rec, _ = fetch_record(home, 'cvelist', 'CVE-2022-0001')\n"
        "    reads += 1\n"
        "    if rec is None or json.loads(rec.raw)['cveMetadata']['cveId'] != 'CVE-2022-0001': bad += 1\n"
        "print(reads, bad)\n"
    )
    proc = subprocess.Popen([sys.executable, "-I", "-c", reader, str(home)], stdout=subprocess.PIPE, text=True)
    with RecordStore.open_writer(home, "cvelist") as store:  # the writer keeps writing meanwhile
        for n in range(300):
            with store.transaction():
                for k in range(20):
                    store.put(f"CVE-2023-{n * 20 + k + 1:04d}", "PUBLISHED", None, b'{"x": 1}')
                store.set_meta("checked_at", f"2026-10-19T00:00:{n % 60:02d}Z")
    reads, bad = map(int, proc.communicate()[0].split())
    assert reads > 10 and bad == 0
    assert os.path.exists(home / "stores" / "cvelist.sqlite")
