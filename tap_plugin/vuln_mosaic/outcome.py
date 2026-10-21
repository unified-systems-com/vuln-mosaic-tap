"""What a source's refresh reports back, and the run's shape (req-vuln-mosaic-refresh)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from tap_plugin.vuln_mosaic.fetch import Fetcher
from tap_plugin.vuln_mosaic.gitops import Git
from tap_plugin.vuln_mosaic.settings import Settings
from tap_plugin.vuln_mosaic.staleness import DatasetFacts


@dataclass
class GridRead:
    """What reading the grid produced: the ids, and a plain sentence for each thing that went wrong."""

    ids: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class EnrichResult:
    """What writing the facts back to the grid did: nodes patched, left alone, and a sentence per problem."""

    patched: int = 0
    unchanged: int = 0
    skipped: int = 0  # nodes beyond max_nodes_per_run, left for the next run
    failed: int = 0
    lists_deferred: int = 0  # nodes whose list-valued facts (cwes) the grid's patch could not take
    fields: int = 0
    problems: list[str] = field(default_factory=list)


@dataclass
class SourceOutcome:
    source: str
    ok: bool = True
    skipped: bool = False
    stale: bool | None = None
    source_version: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    facts: DatasetFacts = field(default_factory=DatasetFacts)

    def line(self) -> str:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(self.counts.items()))
        state = "skipped" if self.skipped else ("ok" if self.ok else f"FAILED: {self.error}")
        stale = {None: "unobserved", True: "STALE", False: "fresh"}[self.stale]
        return f"{self.source}: {state}; {stale}; version={self.source_version}; {counts}".rstrip("; ")


@dataclass
class RunContext:
    home: Path
    settings: Settings
    now: Callable[[], datetime]
    fetcher_factory: Callable[[frozenset[str]], Fetcher]
    git_factory: Callable[..., Git]  # (repo, home, remote=None); remote None is cvelistV5
    grid_ids: tuple[str, ...] = ()  # vulnerability ids read from the grid for this run (req-vuln-mosaic-wanted-7)


@dataclass
class RunReport:
    outcomes: list[SourceOutcome] = field(default_factory=list)
    wanted_problems: list[str] = field(default_factory=list)
    spooled: list[str] = field(default_factory=list)
    grid_ids: int = 0  # ids the grid supplied this run
    enrich: EnrichResult | None = None
    grid_problems: list[str] = field(default_factory=list)

    @property
    def failed_sources(self) -> list[str]:
        return [o.source for o in self.outcomes if not o.ok]

    @property
    def stale_sources(self) -> list[str]:
        return [o.source for o in self.outcomes if o.ok and not o.skipped and o.stale]

    @property
    def clean(self) -> bool:
        return not self.failed_sources and not self.stale_sources

    def summary(self) -> str:
        if self.clean:
            return "all enabled sources refreshed and fresh"
        parts = []
        if self.failed_sources:
            parts.append("failed: " + ", ".join(self.failed_sources))
        if self.stale_sources:
            parts.append("stale: " + ", ".join(self.stale_sources))
        return "; ".join(parts)
