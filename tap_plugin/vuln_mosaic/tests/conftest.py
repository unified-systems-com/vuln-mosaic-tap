"""Shared fixtures: real records, a local upstream git repository, and a network block.

Every test runs with outbound sockets blocked (req-vuln-mosaic-corpus-2). Git fixtures use a
``file://`` remote, which is a local transport and needs no network.
"""

from __future__ import annotations

import faulthandler
import io
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tap_plugin.vuln_mosaic.fetch import Fetcher
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.ids import record_path
from tap_plugin.vuln_mosaic.outcome import RunContext
from tap_plugin.vuln_mosaic.settings import Settings, parse_settings

CORPUS = Path(__file__).parent / "corpus"
PUBLISHED_SSVC = "CVE-2022-0001"  # CISA-ADP container with SSVC
CNA_ONLY = "CVE-2022-0179"  # CNA CVSS, no CISA-ADP
REJECTED = "CVE-2022-0303"
NO_ADP_NO_CPE = "CVE-2022-0382"
LOG4SHELL = "CVE-2021-44228"


def corpus(cve_id: str) -> bytes:
    return (CORPUS / f"{cve_id}.json").read_bytes()


_CURRENT: dict[str, str] = {"test": "(none started: collection or setup)"}
WATCHDOG_SECONDS = 420


def pytest_configure(config: pytest.Config) -> None:
    """A watchdog for the whole run. If it passes WATCHDOG_SECONDS, print which test was running
    and every thread's stack to the REAL stderr (capture suspended) and exit non-zero, so a stalled
    CI job leaves a readable log instead of sitting until the runner's time limit."""

    def watch() -> None:
        time.sleep(WATCHDOG_SECONDS)
        manager = config.pluginmanager.getplugin("capturemanager")
        if manager is not None:
            manager.suspend_global_capture(in_=False)
        sys.__stderr__.write(f"\nvuln_mosaic watchdog: run exceeded {WATCHDOG_SECONDS}s; current test: {_CURRENT['test']}\n")
        sys.__stderr__.flush()
        faulthandler.dump_traceback(file=sys.__stderr__, all_threads=True)
        os._exit(2)

    threading.Thread(target=watch, daemon=True, name="vuln-mosaic-watchdog").start()


def pytest_runtest_logstart(nodeid: str, location: object) -> None:
    _CURRENT["test"] = nodeid


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("network access attempted in a test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path / "home"


@pytest.fixture
def clock() -> Callable[[], datetime]:
    return lambda: datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


class Upstream:
    """A local stand-in for cvelistV5: a git repository whose records the test edits."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.url = f"file://{path}"
        path.mkdir(parents=True)
        self._git("init", "-q", "-b", "main")
        for key, value in (("uploadpack.allowFilter", "true"), ("uploadpack.allowAnySHA1InWant", "true"),
                           ("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
            self._git("config", key, value)

    def _git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.path), *args], check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, changes: Mapping[str, bytes | None], message: str = "c") -> str:
        for rel, data in changes.items():
            target = self.path / rel
            if data is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "-m", message)
        return self._git("rev-parse", "HEAD")

    def put_record(self, cve_id: str, data: bytes | None) -> dict[str, bytes | None]:
        return {record_path(cve_id): data}


@pytest.fixture
def upstream(tmp_path: Path) -> Upstream:
    return Upstream(tmp_path / "upstream")


def make_context(home: Path, upstream: Upstream | None, clock: Callable[[], datetime], settings: Settings | None = None,
                 fetcher: Callable[[frozenset[str]], Fetcher] | None = None) -> RunContext:
    def git_factory(repo: Path, h: Path) -> Git:
        assert upstream is not None
        return Git(repo, h, remote=upstream.url, allow_protocol="file")

    def no_fetcher(_hosts: frozenset[str]) -> Fetcher:
        raise AssertionError("unexpected HTTP fetch")

    return RunContext(home, settings or parse_settings({}), clock, fetcher or no_fetcher, git_factory)


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, headers: Mapping[str, str] | None = None, url: str = "https://x/") -> None:
        super().__init__(body)
        self.headers = dict(headers or {})
        self.url = url


class FakeOpener:
    """Serves canned bodies by URL; raises HTTPError for a status mapping."""

    def __init__(self, routes: Mapping[str, tuple[bytes, Mapping[str, str]] | int]) -> None:
        self.routes, self.requests = dict(routes), []

    def open(self, request, timeout):  # type: ignore[no-untyped-def]
        self.requests.append((request.full_url, dict(request.header_items())))
        route = self.routes[request.full_url]
        if isinstance(route, int):
            raise urllib.error.HTTPError(request.full_url, route, "status", {}, None)  # type: ignore[arg-type]
        body, headers = route
        return FakeResponse(body, headers, request.full_url)


def fetcher_for(opener: FakeOpener) -> Callable[[frozenset[str]], Fetcher]:
    return lambda hosts: Fetcher(hosts, opener)
