"""git as a hardened subprocess (req-vuln-mosaic-cvelist-5).

Every call is an argument list with no shell, a scrubbed environment, ``https`` only,
``transfer.fsckObjects``, a timeout and an output cap. No grid or record text reaches a command line:
the only variable arguments are object ids and paths this module derived from a validated CVE id.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

REMOTE = "https://github.com/CVEProject/cvelistV5.git"
BRANCH = "main"
APPLIED_REF = "refs/applied/last"
DEFAULT_TIMEOUT = 600.0
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BATCH = 200


class GitError(RuntimeError):
    """A git call failed, timed out or produced too much output."""


STDERR_CAP = 1024 * 1024


def _run_bounded(
    command: list[str], stdin: bytes | None, env: dict[str, str], timeout: float, max_output: int
) -> tuple[int, bytes, bytes, str]:
    """Run a command, reading both streams as they arrive and killing it past a cap or deadline.

    ``subprocess.run(capture_output=True)`` buffers without limit and checks afterwards; this stops
    the process the moment a stream passes its cap, so memory stays bounded by the cap.
    Returns (returncode, stdout, stderr, outcome) with outcome one of ok, timeout, overflow.
    """
    proc = subprocess.Popen(  # noqa: S603 - argument list, no shell
        command,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    buffers = {"out": bytearray(), "err": bytearray()}
    over = threading.Event()

    def pump(stream, key: str, cap: int) -> None:  # type: ignore[no-untyped-def]
        buf = buffers[key]
        while chunk := stream.read(65536):
            buf.extend(chunk)
            if len(buf) > cap:
                over.set()
                proc.kill()
                return

    def feed() -> None:
        try:
            assert proc.stdin is not None and stdin is not None
            proc.stdin.write(stdin)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, "out", max_output), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, "err", STDERR_CAP), daemon=True),
    ]
    if stdin is not None:
        threads.append(threading.Thread(target=feed, daemon=True))
    for t in threads:
        t.start()
    outcome = "ok"
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        outcome = "timeout"
    for t in threads:
        t.join(timeout=5)
    proc.wait()
    if over.is_set():
        outcome = "overflow"
    return proc.returncode, bytes(buffers["out"]), bytes(buffers["err"]), outcome


@dataclass(frozen=True)
class Change:
    status: str  # A, M, D, T
    path: str
    new_sha: str | None  # None for deletions


class Git:
    def __init__(
        self,
        repo: Path,
        home: Path,
        *,
        remote: str | None = None,
        allow_protocol: str = "https",
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = MAX_OUTPUT_BYTES,
    ) -> None:
        self.repo, self.remote = repo, remote or REMOTE
        self._home = home / "git-home"
        self._allow = allow_protocol
        self._timeout, self._max_output = timeout, max_output

    def _env(self) -> dict[str, str]:
        self._home.mkdir(parents=True, exist_ok=True)
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self._home),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": self._allow,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "LC_ALL": "C",
        }

    def run(self, *args: str, stdin: bytes | None = None, check: bool = True) -> bytes:
        command = [
            "git",
            "-c", "core.hooksPath=/dev/null",
            "-c", "transfer.fsckObjects=true",
            "-c", "protocol.allow=never",
            "-c", f"protocol.{self._allow}.allow=always",
            "-C", str(self.repo),
            *args,
        ]
        label = " ".join(args[:3])
        code, out, err, outcome = _run_bounded(command, stdin, self._env(), self._timeout, self._max_output)
        if outcome == "timeout":
            raise GitError(f"git {label} timed out after {self._timeout:.0f}s")
        if outcome == "overflow":
            raise GitError(f"git {label} output exceeded {self._max_output} bytes")
        if check and code != 0:
            raise GitError(f"git {label} failed ({code}): {err.decode(errors='replace')[-400:]}")
        return out

    # repository
    def ensure_repo(self, *, blobless: bool = True) -> None:
        if (self.repo / "HEAD").is_file():
            return
        self.repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603
            ["git", "init", "-q", "--bare", str(self.repo)],
            env=self._env(), check=True, capture_output=True, timeout=60,
        )
        self.run("remote", "add", "origin", self.remote)
        if blobless:
            self.run("config", "remote.origin.promisor", "true")
            self.run("config", "remote.origin.partialclonefilter", "blob:none")

    def fetch_tip(self, *, blobless: bool = True) -> str:
        """Fetch the branch tip at depth 1 and return its commit id."""
        args = ["fetch", "-q", "--depth", "1", "--no-tags"]
        args.append("--filter=blob:none" if blobless else "--no-filter")
        self.run(*args, "origin", BRANCH)
        return self.run("rev-parse", "FETCH_HEAD").decode().strip()

    def applied(self) -> str | None:
        out = self.run("rev-parse", "--verify", "-q", APPLIED_REF, check=False).decode().strip()
        return out if _SHA_RE.fullmatch(out) else None

    def mark_applied(self, commit: str) -> None:
        if not _SHA_RE.fullmatch(commit):
            raise GitError("not a commit id")
        self.run("update-ref", APPLIED_REF, commit)

    def commit_time(self, commit: str) -> str:
        return self.run("show", "-s", "--format=%cI", commit).decode().strip()

    # reading
    def blob_ids(self, commit: str, paths: list[str]) -> dict[str, str | None]:
        """Blob id per path at ``commit`` without fetching the blobs (``None`` when absent)."""
        found: dict[str, str | None] = {}
        for start in range(0, len(paths), 5000):
            chunk = paths[start : start + 5000]
            stdin = "".join(f"{commit}:{p}\n" for p in chunk).encode()
            out = self.run("cat-file", "--batch-check=%(objectname)", stdin=stdin).decode().splitlines()
            for path, line in zip(chunk, out, strict=True):
                found[path] = line if _SHA_RE.fullmatch(line) else None
        return found

    def prefetch_blobs(self, shas: list[str]) -> None:
        """Bring blobs local in batches by object id (observed to work against GitHub, 2026-10-19)."""
        for start in range(0, len(shas), _BATCH):
            chunk = [s for s in shas[start : start + _BATCH] if _SHA_RE.fullmatch(s)]
            if chunk:
                # noop negotiation: we want only these blobs and send no "have" lines; with haves present the
                # upstream's rev-list refuses a bare blob want ("bad revision").
                self.run("-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "--no-tags",
                         "--no-write-fetch-head", "origin", *chunk)

    def read_blobs(self, shas: list[str]) -> dict[str, bytes]:
        """Read blobs in bulk through ``cat-file --batch``, a bounded number per process."""
        out: dict[str, bytes] = {}
        unique = [s for s in dict.fromkeys(shas) if _SHA_RE.fullmatch(s)]
        for start in range(0, len(unique), 400):
            chunk = unique[start : start + 400]
            data = self.run("cat-file", "--batch", stdin=("\n".join(chunk) + "\n").encode())
            pos = 0
            for sha in chunk:
                eol = data.index(b"\n", pos)
                header = data[pos:eol].split(b" ")
                if len(header) != 3 or header[1] != b"blob":
                    raise GitError(f"object {sha} is not a readable blob")
                size = int(header[2])
                out[sha] = data[eol + 1 : eol + 1 + size]
                pos = eol + 1 + size + 1
        return out

    def diff(self, old: str, new: str) -> list[Change]:
        """Paths added, modified or deleted between two commits, whatever the gap."""
        raw = self.run("diff", "--raw", "--no-abbrev", "-z", "--no-renames", old, new)
        parts = raw.split(b"\0")
        changes: list[Change] = []
        i = 0
        while i + 1 < len(parts) and parts[i].startswith(b":"):
            meta = parts[i][1:].decode().split(" ")
            status, new_sha = meta[4][0], meta[3]
            path = parts[i + 1].decode("utf-8", "surrogateescape")
            changes.append(Change(status, path, None if status == "D" else new_sha))
            i += 2
        return changes

    def list_records(self, commit: str, prefix: str = "cves/") -> list[tuple[str, str]]:
        """Every blob path under ``prefix`` with its blob id at ``commit`` (full mode, and GHSA lookup)."""
        out = self.run("ls-tree", "-r", "-z", commit, prefix).decode("utf-8", "surrogateescape")
        entries = []
        for item in out.split("\0"):
            if not item:
                continue
            meta, _, path = item.partition("\t")
            parts = meta.split(" ")
            if len(parts) == 3 and parts[1] == "blob":
                entries.append((path, parts[2]))
        return entries

    def import_bundle(self, bundle: Path) -> str:
        """Fetch the branch from an operator-supplied git bundle (req-vuln-mosaic-mirror). Not network."""
        self.run("bundle", "verify", str(bundle))
        self.run("fetch", "-q", "--no-tags", str(bundle), f"+{BRANCH}:refs/mirror/{BRANCH}")
        return self.run("rev-parse", f"refs/mirror/{BRANCH}").decode().strip()
