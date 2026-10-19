"""cvelistV5 fetch against a local git upstream (req-vuln-mosaic-cvelist). No network."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from tap_plugin.vuln_mosaic.gitops import Git, GitError
from tap_plugin.vuln_mosaic.ids import record_path
from tap_plugin.vuln_mosaic.settings import parse_settings
from tap_plugin.vuln_mosaic.sources import cvelist
from tap_plugin.vuln_mosaic.store import RecordStore, fetch_record
from tap_plugin.vuln_mosaic.wanted import request_id

from .conftest import CNA_ONLY, NO_ADP_NO_CPE, PUBLISHED_SSVC, REJECTED, Upstream, corpus, make_context


def seed(upstream: Upstream) -> str:
    changes: dict[str, bytes | None] = {}
    for cve_id in (PUBLISHED_SSVC, CNA_ONLY, NO_ADP_NO_CPE, REJECTED):
        changes.update(upstream.put_record(cve_id, corpus(cve_id)))
    changes["cves/delta.json"] = b"{}"
    changes["cves/deltaLog.json"] = b"[]"
    return upstream.commit(changes, "seed")


def want(home: Path, *ids: str) -> None:
    (home / "wanted").mkdir(parents=True, exist_ok=True)
    (home / "wanted" / "grype_tap.json").write_text(json.dumps({"ids": list(ids)}))


def run(home: Path, upstream: Upstream, clock, settings=None):
    ctx = make_context(home, upstream, clock, parse_settings(settings or {}))
    with RecordStore.open_writer(home, "cvelist") as store:
        return cvelist.refresh(ctx, store)


def held(home: Path) -> dict[str, bytes]:
    with RecordStore.open_writer(home, "cvelist") as store:
        return {i: store.get(i).raw for i in store.held_ids()}


def test_bootstrap_stores_only_wanted(home, upstream, clock) -> None:  # cvelist-1, wanted-1
    seed(upstream)
    want(home, PUBLISHED_SSVC, REJECTED)
    out = run(home, upstream, clock)
    assert out.ok and out.counts["stored"] == 2
    assert set(held(home)) == {PUBLISHED_SSVC, REJECTED}
    assert held(home)[PUBLISHED_SSVC] == corpus(PUBLISHED_SSVC)


def test_rejected_kept_as_state_never_live(home, upstream, clock) -> None:  # cvelist-3, lookup-1
    from tap_plugin.vuln_mosaic.lookup import REJECTED as R, get_cve

    seed(upstream)
    want(home, REJECTED)
    run(home, upstream, clock)
    stored, _ = fetch_record(home, "cvelist", REJECTED)
    assert stored.state == "REJECTED"
    result = get_cve(REJECTED, home=home)
    assert result.state == R and result.record is None


def test_increment_applies_exactly_the_diff(home, upstream, clock) -> None:  # cvelist-1, -4
    seed(upstream)
    want(home, PUBLISHED_SSVC, CNA_ONLY)
    run(home, upstream, clock)
    edited = json.loads(corpus(PUBLISHED_SSVC))
    edited["cveMetadata"]["dateUpdated"] = "2030-01-01T00:00:00.000Z"
    upstream.commit({**upstream.put_record(PUBLISHED_SSVC, json.dumps(edited).encode()),
                     **upstream.put_record(NO_ADP_NO_CPE, b"{}"), "cves/delta.json": b'{"x":1}'})
    out = run(home, upstream, clock)
    assert out.counts["stored"] == 1  # the changed wanted record only; the unwanted change and delta.json are ignored
    assert json.loads(held(home)[PUBLISHED_SSVC])["cveMetadata"]["dateUpdated"].startswith("2030")
    assert NO_ADP_NO_CPE not in held(home)
    assert out.counts["ignored_paths"] == 1


def test_catch_up_equals_stepwise(tmp_path, upstream, clock) -> None:  # cvelist-2
    seed(upstream)
    step_home, jump_home = tmp_path / "step", tmp_path / "jump"
    for h in (step_home, jump_home):
        want(h, PUBLISHED_SSVC, CNA_ONLY, NO_ADP_NO_CPE)
        run(h, upstream, clock)
    for n in range(4):
        rec = json.loads(corpus(PUBLISHED_SSVC))
        rec["cveMetadata"]["dateUpdated"] = f"2031-0{n + 1}-01T00:00:00.000Z"
        changes = upstream.put_record(PUBLISHED_SSVC, json.dumps(rec).encode())
        if n == 2:
            changes.update(upstream.put_record(CNA_ONLY, None))
        upstream.commit(changes)
        run(step_home, upstream, clock)
    run(jump_home, upstream, clock)
    assert held(step_home) == held(jump_home)
    assert CNA_ONLY not in held(jump_home)  # deleted upstream -> removed -> reads not fetched


def test_newly_wanted_id_is_fetched_without_upstream_change(home, upstream, clock) -> None:
    seed(upstream)
    want(home, PUBLISHED_SSVC)
    run(home, upstream, clock)
    want(home, PUBLISHED_SSVC, NO_ADP_NO_CPE)
    out = run(home, upstream, clock)  # same tip, a new wanted id
    assert out.counts["stored"] == 1 and NO_ADP_NO_CPE in held(home)


def test_held_records_stay_fresh_after_consumer_drops_id(home, upstream, clock) -> None:  # wanted-5
    seed(upstream)
    want(home, PUBLISHED_SSVC)
    run(home, upstream, clock)
    want(home)  # consumer drops the id
    rec = json.loads(corpus(PUBLISHED_SSVC))
    rec["cveMetadata"]["dateUpdated"] = "2032-01-01T00:00:00.000Z"
    upstream.commit(upstream.put_record(PUBLISHED_SSVC, json.dumps(rec).encode()))
    run(home, upstream, clock)
    assert json.loads(held(home)[PUBLISHED_SSVC])["cveMetadata"]["dateUpdated"].startswith("2032")


def test_malformed_record_quarantined_previous_kept(home, upstream, clock) -> None:  # integrity-1
    seed(upstream)
    want(home, PUBLISHED_SSVC)
    run(home, upstream, clock)
    broken = json.loads(corpus(PUBLISHED_SSVC))
    broken["dataType"] = "SOMETHING_ELSE"
    upstream.commit(upstream.put_record(PUBLISHED_SSVC, json.dumps(broken).encode()))
    out = run(home, upstream, clock)
    assert not out.ok and out.counts["quarantined"] == 1
    assert held(home)[PUBLISHED_SSVC] == corpus(PUBLISHED_SSVC)  # earlier copy keeps serving
    with RecordStore.open_writer(home, "cvelist") as store:
        assert store.quarantined()[0][0] == PUBLISHED_SSVC


def test_full_mode_takes_every_record(home, upstream, clock) -> None:
    seed(upstream)
    out = run(home, upstream, clock, {"sources": {"cvelist": {"mode": "full"}}})
    assert out.counts["stored"] == 4
    assert set(held(home)) == {PUBLISHED_SSVC, CNA_ONLY, NO_ADP_NO_CPE, REJECTED}


def test_unchanged_fetch_advances_checked_at_only(home, upstream, clock) -> None:  # staleness-2
    from datetime import UTC, datetime

    seed(upstream)
    want(home, PUBLISHED_SSVC)
    run(home, upstream, clock)
    first = fetch_record(home, "cvelist", PUBLISHED_SSVC)[1]
    later = lambda: datetime(2026, 10, 21, 12, 0, tzinfo=UTC)  # noqa: E731
    run(home, upstream, later)
    second = fetch_record(home, "cvelist", PUBLISHED_SSVC)[1]
    assert second.as_of == first.as_of and second.checked_at > first.checked_at


def test_git_subprocess_hygiene(home, upstream, clock) -> None:  # cvelist-5
    seen = []
    real = __import__("subprocess").Popen

    def spy(command, **kwargs):  # type: ignore[no-untyped-def]
        seen.append((command, kwargs))
        return real(command, **kwargs)

    seed(upstream)
    want(home, PUBLISHED_SSVC)
    with mock.patch("subprocess.Popen", spy):
        run(home, upstream, clock)
    assert seen
    for command, kwargs in seen:
        assert isinstance(command, list) and kwargs.get("shell") is not True
        env = kwargs["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_ALLOW_PROTOCOL"] == "file"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["HOME"].startswith(str(home))
        if command[0] == "git" and "-C" in command:
            assert "transfer.fsckObjects=true" in command and "core.hooksPath=/dev/null" in command


def test_git_timeout_is_set_and_stderr_is_capped(home) -> None:
    git = Git(home / "g.git", home)
    assert git._timeout > 0 and git._max_output > 0
    from tap_plugin.vuln_mosaic import gitops

    code = "import sys; sys.stderr.write('x' * (gitops_cap + 10)); sys.stderr.flush()"
    code = code.replace("gitops_cap", str(gitops.STDERR_CAP))
    _, _, err, outcome = gitops._run_bounded(["python3", "-c", code], None, {"PATH": "/usr/bin:/bin"}, 30, 10**9)
    assert outcome == "overflow" and len(err) < gitops.STDERR_CAP + 70000


def test_git_output_cap_and_timeout(home, upstream) -> None:
    seed(upstream)
    git = Git(home / "g.git", home, remote=upstream.url, allow_protocol="file", max_output=10)
    git.ensure_repo()
    with pytest.raises(GitError):
        git.run("ls-remote", upstream.url)
    slow = Git(home / "g.git", home, remote=upstream.url, allow_protocol="file", timeout=0.0001)
    with pytest.raises(GitError):
        slow.run("ls-remote", upstream.url)


def test_https_only_by_default() -> None:
    assert Git(Path("/x"), Path("/y"))._allow == "https"
    assert cvelist.HOSTS == {"github.com"}


def test_fetch_ids_is_the_shared_path(home, upstream, clock) -> None:  # lookup-3
    seed(upstream)
    git = Git(cvelist.repo_path(home), home, remote=upstream.url, allow_protocol="file")
    git.ensure_repo()
    with RecordStore.open_writer(home, "cvelist") as store:
        stored, bad, absent = cvelist.fetch_ids(git, store, [PUBLISHED_SSVC, "CVE-2022-9999"])
        assert (stored, bad, absent) == (1, 0, 1)


def test_record_path_shape() -> None:
    assert record_path("CVE-2021-44228") == "cves/2021/44xxx/CVE-2021-44228.json"
    assert record_path("CVE-2022-0001") == "cves/2022/0xxx/CVE-2022-0001.json"
    assert request_id  # imported for the lookup tests


def test_quarantined_record_is_retried_and_never_reads_fresh(home, upstream, clock) -> None:  # review: no silent acknowledge
    from datetime import UTC, datetime

    seed(upstream)
    want(home, PUBLISHED_SSVC)
    run(home, upstream, clock)
    before = fetch_record(home, "cvelist", PUBLISHED_SSVC)[1]
    broken = json.loads(corpus(PUBLISHED_SSVC))
    broken["dataType"] = "SOMETHING_ELSE"
    upstream.commit(upstream.put_record(PUBLISHED_SSVC, json.dumps(broken).encode()))
    later = lambda: datetime(2026, 10, 25, 12, 0, tzinfo=UTC)  # noqa: E731
    first = run(home, upstream, later)
    second = run(home, upstream, later)  # same tip again: the failure must repeat, not be acknowledged
    assert not first.ok and not second.ok
    after = fetch_record(home, "cvelist", PUBLISHED_SSVC)[1]
    assert after.checked_at == before.checked_at and second.stale is True
    with RecordStore.open_writer(home, "cvelist") as store:
        assert len(store.quarantined()) == 1  # one row per (id, reason)
    assert held(home)[PUBLISHED_SSVC] == corpus(PUBLISHED_SSVC)
