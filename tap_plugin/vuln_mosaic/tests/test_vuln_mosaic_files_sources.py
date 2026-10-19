"""KEV, EPSS, OSV, NVD and the mirror, against canned HTTP and local files (no network)."""

from __future__ import annotations

import gzip
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.integrity import IntegrityError
from tap_plugin.vuln_mosaic.mirror import MirrorError, load_artifact
from tap_plugin.vuln_mosaic.settings import parse_settings
from tap_plugin.vuln_mosaic.sources import epss, kev, nvd, osv
from tap_plugin.vuln_mosaic.store import RecordStore

from .conftest import FakeOpener, fetcher_for, make_context

KEV_URL = kev.URL
EPSS_URL = epss.URL


def kev_body(version: str = "2026.10.15", released: str = "2026-10-15T00:00:00Z") -> bytes:
    return json.dumps({"catalogVersion": version, "dateReleased": released, "count": 1,
                       "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode()


def epss_body(score_date: str = "2026-10-16T12:02:51Z", rows=("CVE-2021-44228,0.97,0.99",)) -> bytes:
    text = f"#model_version:v2026.06.15,score_date:{score_date}\ncve,epss,percentile\n" + "\n".join(rows) + "\n"
    return gzip.compress(text.encode())


def test_kev_swap_then_unchanged_then_refused(home, clock) -> None:  # kev-1, kev-2
    opener = FakeOpener({KEV_URL: (kev_body(), {})})
    ctx = make_context(home, None, clock, fetcher=fetcher_for(opener))
    first = kev.refresh(ctx)
    assert first.source_version == "2026.10.15" and first.stale is False
    assert json.loads(kev.catalog_path(home).read_text())["catalogVersion"] == "2026.10.15"
    unchanged = kev.refresh(ctx)
    assert "unchanged" in unchanged.notes[0]
    opener.routes[KEV_URL] = (kev_body("2026.10.16"), {})
    kev.refresh(ctx)
    assert files.read_facts(home, "kev").source_version == "2026.10.16"
    opener.routes[KEV_URL] = (kev_body("2026.10.01"), {})  # rollback
    with pytest.raises(IntegrityError):
        kev.refresh(ctx)
    assert files.read_facts(home, "kev").source_version == "2026.10.16"  # current unchanged


def test_epss_header_kept_and_bad_file_refused(home, clock) -> None:  # epss-1, epss-2
    opener = FakeOpener({EPSS_URL: (epss_body(), {})})
    ctx = make_context(home, None, clock, fetcher=fetcher_for(opener))
    out = epss.refresh(ctx)
    facts = files.read_facts(home, "epss")
    assert facts.source_version == "v2026.06.15" and facts.as_of == "2026-10-16T12:02:51Z" and out.counts["rows"] == 1
    opener.routes[EPSS_URL] = (epss_body(rows=("CVE-2021-44228,1.5,0.1",)), {})
    with pytest.raises(IntegrityError):
        epss.refresh(ctx)
    assert files.read_facts(home, "epss") == facts
    assert not [p for p in files.source_dir(home, "epss").iterdir() if p.name.startswith(".staging")]


def osv_zip(n: int = 3) -> bytes:
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(n):
            z.writestr(f"PYSEC-{i}.json", json.dumps({"id": f"PYSEC-{i}"}))
    return buf.getvalue()


def osv_ctx(home, clock, opener, ecosystems=("PyPI",)):
    settings = parse_settings({"sources": {"osv": {"enabled": True, "ecosystems": list(ecosystems)}}})
    return make_context(home, None, clock, settings, fetcher_for(opener))


ECO_LIST = f"{osv.BASE}/ecosystems.txt"
PYPI = f"{osv.BASE}/PyPI/all.zip"


def test_osv_opt_in_only(home, clock) -> None:  # osv-1
    out = osv.refresh(make_context(home, None, clock, parse_settings({"sources": {"osv": {"enabled": True}}}), fetcher_for(FakeOpener({}))))
    assert out.skipped and not (home / "files").exists()


def test_osv_swap_conditional_and_name_refusal(home, clock) -> None:  # osv-2, osv-1
    opener = FakeOpener({ECO_LIST: (b"PyPI\nGo\n", {}), PYPI: (osv_zip(), {"ETag": '"abc"', "Last-Modified": "Sun, 18 Oct 2026 10:00:00 GMT"})})
    ctx = osv_ctx(home, clock, opener)
    out = osv.refresh(ctx)
    assert out.ok and out.counts["PyPI_members"] == 3
    facts = files.read_facts(home, "osv/PyPI")
    assert facts.source_version == '"abc"' and facts.as_of == "2026-10-18T10:00:00Z"
    opener.routes[PYPI] = 304
    again = osv.refresh(ctx)
    assert again.ok and again.counts["PyPI_unchanged"] == 1
    sent = [h for url, h in opener.requests if url == PYPI][-1]
    assert sent.get("If-none-match") == '"abc"'
    refused = osv.refresh(osv_ctx(home, clock, opener, ecosystems=("Nope",)))
    assert not refused.ok and "refused" in refused.notes[0]
    assert not (home / "files" / "osv" / "Nope").exists()


def test_osv_bad_zip_leaves_current(home, clock) -> None:
    opener = FakeOpener({ECO_LIST: (b"PyPI\n", {}), PYPI: (osv_zip(), {"ETag": '"v1"'})})
    ctx = osv_ctx(home, clock, opener)
    osv.refresh(ctx)
    build = files.current_build(home, "osv/PyPI")
    opener.routes[PYPI] = (b"PK-not-a-zip", {"ETag": '"v2"'})
    bad = osv.refresh(ctx)
    assert not bad.ok and files.current_build(home, "osv/PyPI") == build


def write_mirror(directory: Path, name: str, body: bytes, source: str, built: str = "2026-10-18T00:00:00Z", digest: str | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(body)
    (directory / "manifest.json").write_text(json.dumps({"archive": name, "sha256": digest or hashlib.sha256(body).hexdigest(), "built": built, "source": source}))


NOW = datetime(2026, 10, 19, 12, tzinfo=UTC)


def test_mirror_imports_without_network_and_ages_from_build(home, clock, tmp_path) -> None:  # mirror-1, staleness-3
    mirror = tmp_path / "mirror"
    write_mirror(mirror, "kev.json", kev_body(), "kev", built="2026-10-14T00:00:00Z")
    settings = parse_settings({"mirror": {"kev": str(mirror)}})
    ctx = make_context(home, None, clock, settings)  # no fetcher: any HTTP attempt would assert
    out = kev.refresh(ctx)
    assert out.facts.checked_at == "2026-10-14T00:00:00Z"
    assert out.stale is True  # built five days ago, three-day limit, however recent the import


@pytest.mark.parametrize("case", ["digest", "future", "malformed", "symlink", "wrong_source", "traversal"])
def test_mirror_refusals(tmp_path, case) -> None:  # mirror-2, mirror-3
    d = tmp_path / "m"
    body = b"hello"
    kwargs = {}
    if case == "digest":
        kwargs["digest"] = "0" * 64
    if case == "future":
        kwargs["built"] = "2027-01-01T00:00:00Z"
    write_mirror(d, "a.bin", body, "kev", **kwargs)
    if case == "malformed":
        (d / "manifest.json").write_text("{")
    if case == "symlink":
        (d / "real.bin").write_bytes(body)
        (d / "a.bin").unlink()
        (d / "a.bin").symlink_to(d / "real.bin")
    if case == "wrong_source":
        load_source = "epss"
    else:
        load_source = "kev"
    if case == "traversal":
        m = json.loads((d / "manifest.json").read_text())
        m["archive"] = "../a.bin"
        (d / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(MirrorError):
        load_artifact(d, load_source, None, NOW)


def test_mirror_refuses_rollback(tmp_path) -> None:  # mirror-2
    write_mirror(tmp_path / "m", "a.bin", b"x", "kev", built="2026-10-10T00:00:00Z")
    with pytest.raises(MirrorError):
        load_artifact(tmp_path / "m", "kev", "2026-10-15T00:00:00Z", NOW)
    assert load_artifact(tmp_path / "m", "kev", "2026-10-01T00:00:00Z", NOW).sha256


def test_cvelist_from_a_git_bundle_mirror(home, upstream, clock, tmp_path) -> None:  # mirror (bundle) - was NOT TRIED
    import subprocess

    from .conftest import PUBLISHED_SSVC
    from .test_vuln_mosaic_cvelist import held, seed, want
    from tap_plugin.vuln_mosaic.sources import cvelist

    seed(upstream)
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    subprocess.run(["git", "-C", str(upstream.path), "bundle", "create", str(bundle_dir / "cvelist.bundle"), "main"], check=True, capture_output=True)
    body = (bundle_dir / "cvelist.bundle").read_bytes()
    write_mirror(bundle_dir, "cvelist.bundle", body, "cvelist", built="2026-10-18T00:00:00Z")
    want(home, PUBLISHED_SSVC)
    settings = parse_settings({"mirror": {"cvelist": str(bundle_dir)}})
    ctx = make_context(home, None, clock, settings)
    with RecordStore.open_writer(home, "cvelist") as store:
        out = cvelist.refresh(ctx, store)
    assert out.ok and PUBLISHED_SSVC in held(home)
    assert out.facts.checked_at == "2026-10-18T00:00:00Z"


NVD_ITEM = {"cve": {"id": "CVE-2021-44228", "vulnStatus": "Analyzed", "lastModified": "2026-10-01T00:00:00.000"}}


def test_nvd_by_id_paginates_and_rate_limits(home, clock) -> None:  # nvd-2, nvd-3
    from urllib.parse import urlencode

    url_id = f"{nvd.BASE}?{urlencode({'cveId': 'CVE-2021-44228'})}"
    opener = FakeOpener({url_id: (json.dumps({"vulnerabilities": [NVD_ITEM], "totalResults": 1, "resultsPerPage": 1}).encode(), {})})
    (home / "wanted").mkdir(parents=True)
    (home / "wanted" / "t.json").write_text(json.dumps({"ids": ["CVE-2021-44228"]}))
    settings = parse_settings({"sources": {"nvd": {"enabled": True}}})
    ctx = make_context(home, None, clock, settings, fetcher_for(opener))
    sleeps: list[float] = []
    with RecordStore.open_writer(home, "nvd") as store:
        out = nvd.refresh(ctx, store, sleep=sleeps.append)
        assert out.ok and out.counts["stored"] == 1 and store.get("CVE-2021-44228").state == "Analyzed"
    assert out.facts.checked_at is not None


def test_nvd_backs_off_on_429(home, clock) -> None:  # nvd-3
    import urllib.error
    from urllib.parse import urlencode

    url_id = f"{nvd.BASE}?{urlencode({'cveId': 'CVE-2021-44228'})}"
    attempts = []

    class Flaky(FakeOpener):
        def open(self, request, timeout):  # type: ignore[no-untyped-def]
            attempts.append(1)
            if len(attempts) < 3:
                raise urllib.error.HTTPError(request.full_url, 429, "slow", {}, None)  # type: ignore[arg-type]
            return super().open(request, timeout)

    opener = Flaky({url_id: (json.dumps({"vulnerabilities": [NVD_ITEM]}).encode(), {})})
    (home / "wanted").mkdir(parents=True)
    (home / "wanted" / "t.json").write_text(json.dumps({"ids": ["CVE-2021-44228"]}))
    ctx = make_context(home, None, clock, parse_settings({"sources": {"nvd": {"enabled": True}}}), fetcher_for(opener))
    slept: list[float] = []
    with RecordStore.open_writer(home, "nvd") as store:
        out = nvd.refresh(ctx, store, sleep=slept.append)
    assert out.ok and len(attempts) == 3 and 30.0 in slept and 60.0 in slept


def test_nvd_quarantines_a_foreign_id(home, clock) -> None:
    from urllib.parse import urlencode

    wrong = {"cve": {"id": "CVE-2021-99999", "vulnStatus": "Analyzed"}}
    url_id = f"{nvd.BASE}?{urlencode({'cveId': 'CVE-2021-44228'})}"
    opener = FakeOpener({url_id: (json.dumps({"vulnerabilities": [wrong]}).encode(), {})})
    (home / "wanted").mkdir(parents=True)
    (home / "wanted" / "t.json").write_text(json.dumps({"ids": ["CVE-2021-44228"]}))
    ctx = make_context(home, None, clock, parse_settings({"sources": {"nvd": {"enabled": True}}}), fetcher_for(opener))
    with RecordStore.open_writer(home, "nvd") as store:
        out = nvd.refresh(ctx, store, sleep=lambda s: None)
        assert store.count() == 0
    assert out.counts["stored"] == 0 and out.counts["quarantined"] == 1 and not out.ok


def test_nvd_quarantine_does_not_advance_cursor_or_facts(home, clock) -> None:
    from urllib.parse import urlencode

    wrong = {"cve": {"id": "CVE-2021-99999", "vulnStatus": "Analyzed"}}
    url_id = f"{nvd.BASE}?{urlencode({'cveId': 'CVE-2021-44228'})}"
    opener = FakeOpener({url_id: (json.dumps({"vulnerabilities": [wrong]}).encode(), {})})
    (home / "wanted").mkdir(parents=True)
    (home / "wanted" / "t.json").write_text(json.dumps({"ids": ["CVE-2021-44228"]}))
    ctx = make_context(home, None, clock, parse_settings({"sources": {"nvd": {"enabled": True}}}), fetcher_for(opener))
    with RecordStore.open_writer(home, "nvd") as store:
        nvd.refresh(ctx, store, sleep=lambda s: None)
        assert store.get_meta("last_mod_end") is None and store.facts().checked_at is None


def test_get_kev_and_get_epss_read_the_held_files(home, clock) -> None:  # kev-3, epss-3
    from tap_plugin.vuln_mosaic import lookup

    for fn in (lookup.get_kev, lookup.get_epss):
        empty = fn("CVE-2021-44228", home=home)
        assert empty.state == "not-fetched" and empty.dataset.stale is None
    kev_doc = json.dumps({
        "catalogVersion": "2026.10.15", "dateReleased": "2026-10-15T00:00:00Z", "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                             "requiredAction": "Apply updates.", "knownRansomwareCampaignUse": "Known"}],
    }).encode()
    opener = FakeOpener({KEV_URL: (kev_doc, {}), EPSS_URL: (epss_body(rows=("CVE-2021-44228,0.97,0.99", "CVE-2022-0001,0.01,0.2")), {})})
    ctx = make_context(home, None, clock, fetcher=fetcher_for(opener))
    kev.refresh(ctx)
    epss.refresh(ctx)
    listed = lookup.get_kev("CVE-2021-44228", home=home)
    assert listed.state == "listed" and listed.entry["dueDate"] == "2021-12-24"
    assert listed.entry["knownRansomwareCampaignUse"] == "Known" and listed.dataset.source_version == "2026.10.15"
    assert lookup.get_kev("CVE-2022-0001", home=home).state == "not-listed"
    scored = lookup.get_epss("CVE-2021-44228", home=home)
    assert (scored.state, scored.epss, scored.percentile) == ("scored", 0.97, 0.99)
    assert scored.model_version == "v2026.06.15" and scored.score_date == "2026-10-16T12:02:51Z"
    assert lookup.get_epss("CVE-2022-0001", home=home).epss == 0.01
    assert lookup.get_epss("CVE-2023-1111", home=home).state == "not-scored"
    for fn in (lookup.get_kev, lookup.get_epss):
        with pytest.raises(ValueError):
            fn("../x", home=home)
