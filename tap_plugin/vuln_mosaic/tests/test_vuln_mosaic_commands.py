"""The two management commands (req-vuln-mosaic-commands)."""

from __future__ import annotations

import json

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from tap_plugin.vuln_mosaic import lookup
from tap_plugin.vuln_mosaic.wanted import scan_wanted_files


def test_want_writes_a_valid_consumer_file(home, monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("VULN_MOSAIC_HOME", str(home))
    listing = tmp_path / "ids.txt"
    listing.write_text("CVE-2021-44228\nCVE-2022-0001\n\nnot-an-id\nCVE-2021-44228\n")
    call_command("vuln_mosaic_want", "rampart_20x_playground", "CVE-2023-4863", "--from-file", str(listing))
    written = json.loads((home / "wanted" / "rampart_20x_playground.json").read_text())
    assert written["ids"] == ["CVE-2023-4863", "CVE-2021-44228", "CVE-2022-0001"]
    scan = scan_wanted_files(home)
    assert scan.ids == set(written["ids"]) and scan.problems == []
    assert "not-an-id" in capsys.readouterr().err
    call_command("vuln_mosaic_want", "rampart_20x_playground", "CVE-2020-1472")  # replaces that consumer's list
    assert json.loads((home / "wanted" / "rampart_20x_playground.json").read_text())["ids"] == ["CVE-2020-1472"]


@pytest.mark.parametrize("consumer", ["../x", "A B", "", "9lives"])
def test_want_refuses_bad_consumer_names(home, monkeypatch, consumer) -> None:
    monkeypatch.setenv("VULN_MOSAIC_HOME", str(home))
    with pytest.raises(CommandError):
        call_command("vuln_mosaic_want", consumer, "CVE-2021-44228")
    assert not (home / "wanted").exists()


def test_want_refuses_when_no_id_is_valid(home, monkeypatch) -> None:
    monkeypatch.setenv("VULN_MOSAIC_HOME", str(home))
    with pytest.raises(CommandError):
        call_command("vuln_mosaic_want", "demo", "nope")


def test_refresh_command_prints_outcomes_and_fails_when_not_clean(home, monkeypatch, capsys) -> None:
    from tap_plugin.vuln_mosaic.management.commands import vuln_mosaic_refresh as mod
    from tap_plugin.vuln_mosaic.outcome import RunReport, SourceOutcome

    clean = RunReport(outcomes=[SourceOutcome("kev", stale=False, source_version="1")])
    monkeypatch.setattr(mod, "run_refresh", lambda: clean)
    call_command("vuln_mosaic_refresh")
    assert "kev: ok" in capsys.readouterr().out
    bad = RunReport(outcomes=[SourceOutcome("kev", ok=False, error="boom")])
    monkeypatch.setattr(mod, "run_refresh", lambda: bad)
    with pytest.raises(CommandError, match="failed: kev"):
        call_command("vuln_mosaic_refresh")


def test_the_cli_path_feeds_the_read_function(home, monkeypatch) -> None:
    monkeypatch.setenv("VULN_MOSAIC_HOME", str(home))
    call_command("vuln_mosaic_want", "demo", "CVE-2022-0001")
    assert lookup.get_cve("CVE-2022-0777", home=home).state == lookup.NOT_FETCHED
