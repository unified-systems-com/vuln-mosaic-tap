"""Staleness is derived at read time, never stored (req-vuln-mosaic-staleness)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str | None) -> datetime | None:
    """Parse an ISO-8601 time to an aware UTC datetime; ``None`` stays ``None`` (unobserved)."""
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


@dataclass(frozen=True)
class DatasetFacts:
    """What is known about one dataset. ``None`` in any field is unobserved, not empty."""

    as_of: str | None = None
    checked_at: str | None = None
    source_version: str | None = None
    fetched_at: str | None = None


def is_stale(checked_at: str | None, max_age_days: int, now: datetime | None = None) -> bool | None:
    """``True`` once strictly more than ``max_age_days`` have passed since ``checked_at``.

    ``None`` when ``checked_at`` is absent: an unobserved dataset is never reported fresh.
    """
    checked = parse_time(checked_at)
    if checked is None:
        return None
    return ((now or utcnow()) - checked) > timedelta(days=max_age_days)
