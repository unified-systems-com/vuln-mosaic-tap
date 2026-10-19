"""The single-writer lock (req-vuln-mosaic-store-3, req-vuln-mosaic-lookup-6)."""

from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class LockBusy(RuntimeError):
    """Another writer holds ``<home>/.lock``."""


@contextmanager
def writer_lock(home: Path, wait_seconds: float = 0.0) -> Iterator[None]:
    """Hold an exclusive ``flock`` on ``<home>/.lock``; raise ``LockBusy`` past ``wait_seconds``."""
    home.mkdir(parents=True, exist_ok=True)
    fd = os.open(home / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusy("another vuln_mosaic writer holds the lock") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
