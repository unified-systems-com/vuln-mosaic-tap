"""Stores, staleness, settings, lock (req-vuln-mosaic-store, -staleness, -settings)."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.locking import LockBusy, writer_lock
from tap_plugin.vuln_mosaic.settings import SettingsError, load_settings, parse_settings
from tap_plugin.vuln_mosaic.staleness import DatasetFacts, is_stale
from tap_plugin.vuln_mosaic.store import RecordStore, fetch_record

from .conftest import PUBLISHED_SSVC, corpus


def test_record_round_trip_is_byte_identical(home: Path) -> None:  # store-1
    raw = corpus(PUBLISHED_SSVC)
    with RecordStore.open_writer(home, "cvelist") as store:
        store.put(PUBLISHED_SSVC, "PUBLISHED", "2022-01-01", raw)
    stored, _ = fetch_record(home, "cvelist", PUBLISHED_SSVC)
    assert stored is not None and stored.raw == raw
    with RecordStore.open_writer(home, "cvelist") as store:
        row = store._conn.execute("SELECT record_gz FROM records").fetchone()[0]
    assert gzip.decompress(row) == raw


def test_empty_home_reads_not_fetched(home: Path) -> None:  # store-4
    stored, facts = fetch_record(home, "cvelist", PUBLISHED_SSVC)
    assert stored is None and facts == DatasetFacts()


def test_second_writer_refuses(home: Path) -> None:  # store-3
    with writer_lock(home):
        with pytest.raises(LockBusy):
            with writer_lock(home):
                pass
    with writer_lock(home):  # released
        pass


def test_lock_refuses_symlink(home: Path, tmp_path: Path) -> None:
    home.mkdir()
    (home / ".lock").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        with writer_lock(home):
            pass


def test_transaction_rolls_back(home: Path) -> None:
    with RecordStore.open_writer(home, "cvelist") as store:
        with pytest.raises(RuntimeError):
            with store.transaction():
                store.put("CVE-2022-0001", "PUBLISHED", None, b"{}")
                raise RuntimeError
        assert store.count() == 0


def test_stale_is_computed_strictly_after_limit() -> None:  # staleness-1
    checked = "2026-10-16T12:00:00Z"
    at = datetime(2026, 10, 16, 12, tzinfo=UTC)
    assert is_stale(checked, 3, at + timedelta(days=3)) is False
    assert is_stale(checked, 3, at + timedelta(days=3, seconds=1)) is True


def test_unobserved_is_not_fresh() -> None:  # staleness-4
    assert is_stale(None, 3) is None


def test_no_change_fetch_advances_checked_at_only(home: Path) -> None:  # staleness-2
    staging = files.new_staging(home, "kev", "b1")
    (staging / "x").write_text("1")
    facts = DatasetFacts(as_of="2026-10-15T00:00:00Z", checked_at="2026-10-15T01:00:00Z", source_version="1", fetched_at="t")
    files.publish(home, "kev", "b1", staging, facts)
    files.touch_checked(home, "kev", "2026-10-18T00:00:00Z")
    read = files.read_facts(home, "kev")
    assert read.checked_at == "2026-10-18T00:00:00Z" and read.as_of == "2026-10-15T00:00:00Z"


def test_publish_is_atomic_and_keeps_two_builds(home: Path) -> None:  # store-2
    for n in range(4):
        staging = files.new_staging(home, "kev", f"b{n}")
        (staging / "f.txt").write_text(str(n))
        files.publish(home, "kev", f"b{n}", staging, DatasetFacts(checked_at=f"2026-10-1{n}T00:00:00Z"))
        if n == 0:
            held = files.open_current(home, "kev", "f.txt")  # a reader with an open descriptor
    assert files.current_build(home, "kev") == "b3"
    builds = sorted(p.name for p in files.source_dir(home, "kev").iterdir() if p.is_dir() and not p.is_symlink() and not p.name.startswith("."))
    assert len(builds) == 2
    assert held.read() == b"0"  # still readable after b0 was pruned and two further publications
    held.close()


def test_failed_stage_leaves_current(home: Path) -> None:
    staging = files.new_staging(home, "kev", "b1")
    (staging / "f").write_text("ok")
    files.publish(home, "kev", "b1", staging, DatasetFacts(checked_at="2026-10-15T00:00:00Z"))
    bad = files.new_staging(home, "kev", "b2")
    files.discard(bad)
    assert files.current_build(home, "kev") == "b1"


def test_source_dir_refuses_escape(home: Path) -> None:
    with pytest.raises(ValueError):
        files.source_dir(home, "osv/../../etc")


def test_settings_defaults_when_absent(home: Path) -> None:  # settings-2
    s = load_settings(home)
    assert s.sources["cvelist"].enabled and s.sources["kev"].enabled and s.sources["epss"].enabled
    assert not s.sources["nvd"].enabled and not s.sources["osv"].enabled
    assert s.sources["cvelist"].mode == "wanted" and s.sources["cvelist"].max_age_days == 3
    assert s.immediate_fetch is False


@pytest.mark.parametrize(
    "bad",
    [
        {"sources": {"nope": {}}},
        {"sources": {"kev": {"max_age_days": 0}}},
        {"sources": {"kev": {"enabled": "yes"}}},
        {"sources": {"osv": {"ecosystems": ["../x"]}}},
        {"sources": {"osv": {"ecosystems": ["a/b"]}}},
        {"immediate_fetch": 1},
    ],
)
def test_settings_schema_violations_name_the_key(bad: dict) -> None:  # settings-1
    with pytest.raises(SettingsError) as exc:
        parse_settings(bad)
    assert "settings invalid at" in str(exc.value)


def test_settings_file_invalid_json_fails_loud(home: Path) -> None:
    home.mkdir()
    (home / "settings.json").write_text("{not json")
    with pytest.raises(SettingsError):
        load_settings(home)


def test_settings_loader_reads_file(home: Path) -> None:
    home.mkdir()
    (home / "settings.json").write_text(json.dumps({"sources": {"cvelist": {"mode": "full"}, "osv": {"enabled": True, "ecosystems": ["PyPI"]}}}))
    s = load_settings(home)
    assert s.sources["cvelist"].mode == "full" and s.sources["osv"].ecosystems == ("PyPI",)


def test_settings_module_has_no_grid_import() -> None:  # settings-3
    import tap_plugin.vuln_mosaic.settings as mod

    src = Path(mod.__file__).read_text()
    assert "django" not in src and "tap_grid" not in src and "tap_cares" not in src


def test_lock_blocks_across_processes(home: Path) -> None:
    code = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from tap_plugin.vuln_mosaic.locking import writer_lock\n"
        "with writer_lock(Path(sys.argv[1])):\n"
        "    print('held', flush=True)\n"
        "    sys.stdin.readline()\n"
    )
    proc = subprocess.Popen([sys.executable, "-I", "-c", code, str(home)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "held"
        with pytest.raises(LockBusy):
            with writer_lock(home):
                pass
    finally:
        proc.communicate("\n", timeout=30)
    with writer_lock(home):  # released once the holder exits
        pass
    assert os.path.exists(home / ".lock")
