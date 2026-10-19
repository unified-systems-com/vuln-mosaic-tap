"""The refresh orchestration and the collector (req-vuln-mosaic-refresh, -nongoals, -fips, -corpus)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import refresh as refresh_mod
from tap_plugin.vuln_mosaic.locking import LockBusy, writer_lock
from tap_plugin.vuln_mosaic.settings import parse_settings

from .conftest import FakeOpener, PUBLISHED_SSVC, corpus, fetcher_for
from .test_vuln_mosaic_cvelist import seed as seed_upstream, want
from .test_vuln_mosaic_files_sources import EPSS_URL, KEV_URL, epss_body, kev_body

PACKAGE = Path(refresh_mod.__file__).parent


def run(home, upstream, clock, opener, settings=None):
    from tap_plugin.vuln_mosaic.gitops import Git

    return refresh_mod.run_refresh(
        home,
        settings=parse_settings(settings or {}),
        now=clock,
        fetcher_factory=fetcher_for(opener),
        git_factory=lambda repo, h: Git(repo, h, remote=upstream.url, allow_protocol="file"),
    )


def test_all_sources_refresh_clean(home, upstream, clock) -> None:
    seed_upstream(upstream)
    want(home, PUBLISHED_SSVC)
    report = run(home, upstream, clock, FakeOpener({KEV_URL: (kev_body(), {}), EPSS_URL: (epss_body(), {})}))
    assert [o.source for o in report.outcomes] == ["cvelist", "kev", "epss"]
    assert report.clean, report.summary()


def test_one_source_failing_never_skips_the_rest(home, upstream, clock) -> None:  # refresh-3
    seed_upstream(upstream)
    want(home, PUBLISHED_SSVC)
    report = run(home, upstream, clock, FakeOpener({KEV_URL: 503, EPSS_URL: (epss_body(), {})}))
    by = {o.source: o for o in report.outcomes}
    assert not by["kev"].ok and by["cvelist"].ok and by["epss"].ok
    assert report.failed_sources == ["kev"] and not report.clean
    assert "failed: kev" in report.summary()


def test_stale_source_makes_the_run_not_clean(home, upstream, clock) -> None:
    seed_upstream(upstream)
    want(home, PUBLISHED_SSVC)
    settings = {"sources": {"kev": {"max_age_days": 1}}}
    mirror = home.parent / "m"
    mirror.mkdir()
    body = kev_body()
    import hashlib

    (mirror / "k.json").write_bytes(body)
    (mirror / "manifest.json").write_text(json.dumps({"archive": "k.json", "sha256": hashlib.sha256(body).hexdigest(), "built": "2026-10-10T00:00:00Z", "source": "kev"}))
    settings["mirror"] = {"kev": str(mirror)}
    report = run(home, upstream, clock, FakeOpener({EPSS_URL: (epss_body(), {})}), settings)
    assert report.stale_sources == ["kev"] and not report.clean and "stale: kev" in report.summary()


def test_second_refresh_refuses_while_one_runs(home, upstream, clock) -> None:  # store-3 via the run
    with writer_lock(home):
        with pytest.raises(LockBusy):
            run(home, upstream, clock, FakeOpener({}))


def test_disabled_sources_are_not_touched(home, upstream, clock) -> None:
    settings = {"sources": {"cvelist": {"enabled": False}, "kev": {"enabled": False}, "epss": {"enabled": False}}}
    report = run(home, upstream, clock, FakeOpener({}), settings)
    assert report.outcomes == [] and report.clean


def test_collector_registered_with_literal_scope() -> None:  # refresh-4
    source = (PACKAGE / "apps.py").read_text()
    assert 'scope="vuln_mosaic"' in source and 'key="refresh"' in source


def test_collector_lands_no_batch_and_fails_when_a_source_does(home, upstream, clock, monkeypatch) -> None:  # refresh-2 (unit half)
    from tap_plugin.vuln_mosaic.collectors.refresh import collector as mod

    seed_upstream(upstream)
    want(home, PUBLISHED_SSVC)
    report = run(home, upstream, clock, FakeOpener({KEV_URL: 503, EPSS_URL: (epss_body(), {})}))
    monkeypatch.setattr(mod, "run_refresh", lambda: report)
    instance = mod.VulnMosaicRefreshCollector.__new__(mod.VulnMosaicRefreshCollector)
    instance.results = {"info": [], "warn": [], "error": []}
    instance._produced_batches, instance._surfaces, instance._surfaces_declared, instance.summary = [], [], False, ""
    with pytest.raises(mod.VulnMosaicRefreshError) as exc:
        instance.run()
    assert "kev" in str(exc.value) and instance.summary == report.summary()
    assert instance._produced_batches == [] and instance._surfaces_declared is True
    assert any(e["message_code"] == "SOURCE_FAILED" for e in instance.results["error"])
    assert any(e["message_code"] == "SOURCE_REFRESHED" for e in instance.results["info"])


def test_self_test_names_what_is_wrong(tmp_path, monkeypatch) -> None:  # refresh-5
    from tap_plugin.vuln_mosaic.collectors.refresh import collector as mod

    monkeypatch.setenv("VULN_MOSAIC_HOME", str(tmp_path / "h"))
    (tmp_path / "h").mkdir()
    (tmp_path / "h" / "settings.json").write_text('{"sources": {"nope": {}}}')
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    result = mod.VulnMosaicRefreshCollector.self_test()
    codes = {c.code for c in result.checks if c.is_failure}
    assert {"SETTINGS_INVALID", "GIT_MISSING"} <= codes
    (tmp_path / "h").chmod(0o500)
    try:
        locked = mod.VulnMosaicRefreshCollector.self_test()
    finally:
        (tmp_path / "h").chmod(0o700)
    assert "HOME_UNWRITABLE" in {c.code for c in locked.checks if c.is_failure} or tmp_path.owner() == "root"


def test_manifest_declares_no_pages_panels_models_or_edges() -> None:  # nongoals-2
    manifest = tomllib.loads((PACKAGE / "tap-plugin.toml").read_text())
    for table in ("models", "edges", "pages", "panels"):
        assert table not in manifest
    assert set(manifest["grift"]) == {"schedule"}


def test_fips_declaration_present() -> None:  # fips-1
    manifest = tomllib.loads((PACKAGE / "tap-plugin.toml").read_text())
    fips = manifest["fips"]
    assert fips["status"] in {"compatible", "uses-nonvalidated"}
    assert fips["status"] == "compatible" or fips.get("reason")


def test_schedule_targets_the_collector_id() -> None:  # refresh-1 (the guard re-checks it on the stack)
    import uuid

    doc = json.loads((PACKAGE / "grift" / "schedule.grift.json").read_text())
    edge = doc["batches"][0]["edges"][0]["edge"]
    namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "tap_cares.collector")
    assert edge["to_entity_id"] == str(uuid.uuid5(namespace, "vuln_mosaic:refresh"))
    assert doc["batches"][0]["nodes"][0]["node"]["cron_expression"] == "41 * * * *"


def test_corpus_covers_the_required_shapes() -> None:  # corpus-1
    from .conftest import CNA_ONLY, NO_ADP_NO_CPE, REJECTED

    states = {c: json.loads(corpus(c))["cveMetadata"]["state"] for c in (PUBLISHED_SSVC, CNA_ONLY, NO_ADP_NO_CPE, REJECTED)}
    assert states[REJECTED] == "REJECTED" and states[PUBLISHED_SSVC] == "PUBLISHED"
    adp = json.loads(corpus(NO_ADP_NO_CPE))["containers"].get("adp", [])
    assert not any(c.get("providerMetadata", {}).get("shortName") == "CISA-ADP" for c in adp)


def test_git_links_only_the_system_openssl() -> None:  # fips-2 (git half; the crypto-providers check runs in conformance)
    import re
    import shutil
    import subprocess

    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    exec_path = subprocess.run([git, "--exec-path"], capture_output=True, text=True, check=True).stdout.strip()
    helper = Path(exec_path) / "git-remote-https"
    if not helper.is_file():
        pytest.skip("git-remote-https is not installed")
    libs: set[bytes] = set()
    for binary in [helper]:
        libs |= set(re.findall(rb"lib[A-Za-z0-9_+-]+\.so[0-9.]*", binary.read_bytes()))
    curl = next((p for d in ("/usr/lib", "/usr/lib64", "/lib") for p in Path(d).glob("libcurl.so*") if p.is_file()), None)
    if curl is None:
        pytest.skip("libcurl not found; the TLS library cannot be inspected here")
    libs |= set(re.findall(rb"lib[A-Za-z0-9_+-]+\.so[0-9.]*", curl.read_bytes()))
    names = b" ".join(sorted(libs))
    assert b"libssl" in names or b"libcrypto" in names, names
    for foreign in (b"gnutls", b"mbedtls", b"libnss", b"wolfssl", b"boringssl"):
        assert foreign not in names, foreign
