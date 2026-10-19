"""Every fail-closed path has a test that injects the fault (req-vuln-mosaic-integrity, corpus-4)."""

from __future__ import annotations

import gzip
import json
import urllib.error
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic import integrity
from tap_plugin.vuln_mosaic.fetch import FetchError, Fetcher, check_url

from .conftest import FakeOpener, FakeResponse, PUBLISHED_SSVC, REJECTED, corpus

NOW = datetime(2026, 10, 19, tzinfo=UTC)


def record(**meta: object) -> bytes:
    doc = json.loads(corpus(PUBLISHED_SSVC))
    for key, value in meta.items():
        target = doc if key in doc else doc["cveMetadata"]
        target[key] = value
    return json.dumps(doc).encode()


def test_real_records_pass() -> None:
    assert integrity.check_cve_record(corpus(PUBLISHED_SSVC), PUBLISHED_SSVC).state == "PUBLISHED"
    assert integrity.check_cve_record(corpus(REJECTED), REJECTED).state == "REJECTED"


@pytest.mark.parametrize(
    "raw",
    [
        record(dataType="CVE_RECORD_X"),
        record(dataVersion="4.0"),
        record(cveId="CVE-2022-9999"),
        record(state="RESERVED"),
        b"not json",
        b"[]",
        b"x" * (integrity.MAX_RECORD_BYTES + 1),
    ],
)
def test_malformed_cve_record_refused(raw: bytes) -> None:  # integrity-1
    with pytest.raises(integrity.IntegrityError):
        integrity.check_cve_record(raw, PUBLISHED_SSVC)


NVD = {"cve": {"id": "CVE-2021-44228", "vulnStatus": "Analyzed", "lastModified": "2026-01-01T00:00:00.000"}}


def test_nvd_object_uses_nvd_rules() -> None:  # integrity-5
    checked = integrity.check_nvd_object(json.dumps(NVD).encode(), "CVE-2021-44228")
    assert checked.state == "Analyzed"
    with pytest.raises(integrity.IntegrityError):
        integrity.check_nvd_object(json.dumps(NVD).encode(), "CVE-2021-44229")
    with pytest.raises(integrity.IntegrityError):
        integrity.check_nvd_object(json.dumps({"cve": {"vulnStatus": "x"}}).encode(), "CVE-2021-44228")
    with pytest.raises(integrity.IntegrityError):
        integrity.check_cve_record(json.dumps(NVD).encode(), "CVE-2021-44228")  # v5 rules reject it, as intended


def kev(version: str = "2026.10.15", released: str = "2026-10-15T00:00:00Z", count: int | None = None, ids=("CVE-2021-44228",)) -> bytes:
    vulns = [{"cveID": i} for i in ids]
    return json.dumps({"catalogVersion": version, "dateReleased": released, "count": len(vulns) if count is None else count, "vulnerabilities": vulns}).encode()


def test_kev_accepts_and_refuses() -> None:  # kev-2
    assert integrity.check_kev(kev(), "2026.10.14", NOW).count == 1
    for bad in (kev(version="2026.10.10"), kev(released="2027-01-01T00:00:00Z"), kev(count=5), kev(ids=("nope",)), b"[]"):
        with pytest.raises(integrity.IntegrityError):
            integrity.check_kev(bad, "2026.10.14", NOW)


def write_epss(tmp: Path, rows: list[str], header: str = "cve,epss,percentile", first: str = "#model_version:v2026.06.15,score_date:2026-10-16T12:02:51Z") -> Path:
    path = tmp / "e.csv.gz"
    path.write_bytes(gzip.compress("\n".join([first, header, *rows]).encode() + b"\n"))
    return path


def test_epss_valid(tmp_path: Path) -> None:  # epss-1
    result = integrity.check_epss(write_epss(tmp_path, ["CVE-2021-44228,0.97,0.99"]), None, NOW)
    assert result.model_version == "v2026.06.15" and result.score_date == "2026-10-16T12:02:51Z" and result.rows == 1


@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_epss_out_of_range_anywhere_refused(tmp_path: Path, position: str) -> None:  # epss-2
    good = [f"CVE-2021-{n:04d},0.5,0.5" for n in range(1000, 1010)]
    bad = "CVE-2021-9999,1.5,0.5"
    rows = {"first": [bad, *good], "middle": [*good[:5], bad, *good[5:]], "last": [*good, bad]}[position]
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(write_epss(tmp_path, rows), None, NOW)


def test_epss_other_refusals(tmp_path: Path) -> None:
    ok = ["CVE-2021-44228,0.5,0.5"]
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(write_epss(tmp_path, ok, header="cve,score"), None, NOW)
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(write_epss(tmp_path, ok), "2026-10-17T00:00:00Z", NOW)  # earlier than installed
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(write_epss(tmp_path, ok, first="#model_version:v1,score_date:2027-01-01T00:00:00Z"), None, NOW)
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(write_epss(tmp_path, ["notacve,0.5,0.5"]), None, NOW)
    broken = tmp_path / "b.gz"
    broken.write_bytes(b"not gzip")
    with pytest.raises(integrity.IntegrityError):
        integrity.check_epss(broken, None, NOW)


def make_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return path


def test_osv_zip_valid_and_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # integrity-3
    good = {f"GHSA-{n}.json": b'{"id": "x"}' for n in range(5)}
    assert integrity.check_osv_zip(make_zip(tmp_path / "ok.zip", good)) == 5
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "dots.zip", {"../evil.json": b"{}"}))
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "abs.zip", {"/etc/x.json": b"{}"}))
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "ext.zip", {"a.txt": b"{}"}))
    monkeypatch.setattr(integrity, "MAX_ZIP_MEMBERS", 3)
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "many.zip", good))
    monkeypatch.setattr(integrity, "MAX_ZIP_MEMBERS", 100)
    monkeypatch.setattr(integrity, "MAX_ZIP_MEMBER_BYTES", 10)
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "big.zip", {"a.json": b'{"k": "' + b"x" * 50 + b'"}'}))
    bad = tmp_path / "notzip.zip"
    bad.write_bytes(b"nope")
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(bad)


@pytest.mark.parametrize("position", [0, 2, 4])
def test_osv_malformed_member_anywhere_refused(tmp_path: Path, position: int) -> None:
    members = {f"a{n}.json": b"{}" for n in range(5)}
    members[f"a{position}.json"] = b"{broken"
    with pytest.raises(integrity.IntegrityError):
        integrity.check_osv_zip(make_zip(tmp_path / "m.zip", members))


HOSTS = frozenset({"good.example"})


def test_redirect_and_scheme_allow_list() -> None:  # integrity-4
    check_url("https://good.example/x", HOSTS)
    for url in ("http://good.example/x", "https://evil.example/x", "file:///etc/passwd"):
        with pytest.raises(FetchError):
            check_url(url, HOSTS)

    class Redirected(FakeOpener):
        def open(self, request, timeout):  # type: ignore[no-untyped-def]
            return FakeResponse(b"x", {}, "https://evil.example/landing")

    with pytest.raises(FetchError):
        Fetcher(HOSTS, Redirected({})).get_bytes("https://good.example/x", max_bytes=10)


def test_default_opener_rejects_redirect_off_list() -> None:
    from tap_plugin.vuln_mosaic.fetch import _AllowListRedirects

    handler = _AllowListRedirects(HOSTS)
    with pytest.raises(FetchError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/")  # type: ignore[arg-type]
    with pytest.raises(FetchError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://good.example/")  # type: ignore[arg-type]


def test_body_cap_and_truncation(tmp_path: Path) -> None:  # integrity-2
    url = "https://good.example/f"
    fetcher = Fetcher(HOSTS, FakeOpener({url: (b"x" * 100, {})}))
    with pytest.raises(FetchError):
        fetcher.get_bytes(url, max_bytes=10)
    with pytest.raises(FetchError):
        fetcher.download(url, tmp_path / "d", max_bytes=10)
    short = Fetcher(HOSTS, FakeOpener({url: (b"x" * 5, {"content-length": "50"})}))
    with pytest.raises(FetchError):
        short.download(url, tmp_path / "e", max_bytes=1000)
    http_error = Fetcher(HOSTS, FakeOpener({url: 503}))
    with pytest.raises(FetchError) as exc:
        http_error.get_bytes(url, max_bytes=10)
    assert exc.value.status == 503
    assert isinstance(urllib.error.HTTPError, type)
