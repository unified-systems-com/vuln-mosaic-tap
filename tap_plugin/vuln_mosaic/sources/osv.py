"""OSV advisories, one whole zip per opted-in ecosystem (req-vuln-mosaic-osv)."""

from __future__ import annotations

import json
import re
import shutil
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote

from tap_plugin.vuln_mosaic import files
from tap_plugin.vuln_mosaic.fetch import FetchError
from tap_plugin.vuln_mosaic.integrity import check_osv_zip
from tap_plugin.vuln_mosaic.mirror import load_artifact
from tap_plugin.vuln_mosaic.outcome import RunContext, SourceOutcome
from tap_plugin.vuln_mosaic.staleness import DatasetFacts, is_stale, to_iso

SOURCE = "osv"
BASE = "https://osv-vulnerabilities.storage.googleapis.com"
HOSTS = frozenset({"osv-vulnerabilities.storage.googleapis.com"})
ARTIFACT = "all.zip"
MAX_BYTES = 4 * 1024 * 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$")


def _validators(home: Path, key: str) -> dict[str, str]:
    try:
        return json.loads((files.source_dir(home, key) / "current" / "validators.json").read_text())
    except (OSError, ValueError):
        return {}


def refresh(ctx: RunContext) -> SourceOutcome:
    cfg = ctx.settings.sources[SOURCE]
    outcome = SourceOutcome(SOURCE)
    if not cfg.ecosystems:
        outcome.skipped = True
        outcome.notes.append("no ecosystems opted in")
        return outcome
    mirror_dir = ctx.settings.mirror.get(SOURCE)
    known: set[str] | None = None
    if not mirror_dir:
        body, _ = ctx.fetcher_factory(HOSTS).get_bytes(f"{BASE}/ecosystems.txt", max_bytes=1 << 20)
        known = {line.strip() for line in body.decode().splitlines() if line.strip()}
    stale_any = False
    for eco in cfg.ecosystems:
        if not NAME_RE.fullmatch(eco) or (known is not None and eco not in known):
            outcome.ok = False
            outcome.notes.append(f"ecosystem {eco!r} refused: not a known ecosystem name")
            continue
        try:
            stale_any |= bool(_one(ctx, eco, outcome, mirror_dir))
        except Exception as exc:  # one ecosystem failing never skips the others
            outcome.ok = False
            outcome.notes.append(f"{eco}: {exc}")
    if not outcome.ok:
        outcome.error = "; ".join(n for n in outcome.notes if "refused" in n or ": " in n)[:400]
    outcome.stale = stale_any if outcome.ok else None
    return outcome


def _one(ctx: RunContext, eco: str, outcome: SourceOutcome, mirror_dir: Path | None) -> bool | None:
    key = f"{SOURCE}/{eco}"
    now = to_iso(ctx.now())
    installed = files.read_facts(ctx.home, key)
    staging = files.new_staging(ctx.home, key, "incoming")
    try:
        target = staging / ARTIFACT
        validators: dict[str, str] = {}
        if mirror_dir:
            artifact = load_artifact(mirror_dir / eco, SOURCE, installed.checked_at, ctx.now())
            shutil.copyfile(artifact.path, target)
            checked_at, as_of, version = artifact.built, artifact.built, artifact.sha256[:16]
        else:
            held = _validators(ctx.home, key)
            headers = {}
            if held.get("etag"):
                headers["If-None-Match"] = held["etag"]
            elif held.get("last_modified"):
                headers["If-Modified-Since"] = held["last_modified"]
            try:
                got = ctx.fetcher_factory(HOSTS).download(
                    f"{BASE}/{quote(eco)}/all.zip", target, max_bytes=MAX_BYTES, timeout=600, headers=headers
                )
            except FetchError as exc:
                if exc.status == 304:
                    files.discard(staging)
                    files.touch_checked(ctx.home, key, now)
                    outcome.counts[f"{eco}_unchanged"] = 1
                    return is_stale(now, ctx.settings.sources[SOURCE].max_age_days, ctx.now())
                raise
            validators = {k: v for k, v in (("etag", got.headers.get("etag")), ("last_modified", got.headers.get("last-modified"))) if v}
            checked_at = now
            lm = got.headers.get("last-modified")
            as_of = to_iso(parsedate_to_datetime(lm)) if lm else now
            version = got.headers.get("etag") or got.sha256[:16]
        members = check_osv_zip(target)
        (staging / "validators.json").write_text(json.dumps(validators))
        facts = DatasetFacts(as_of=as_of, checked_at=checked_at, source_version=version, fetched_at=now)
        files.publish(ctx.home, key, f"{ctx.now():%Y%m%dT%H%M%S}", staging, facts)
        outcome.counts[f"{eco}_members"] = members
    except BaseException:
        files.discard(staging)
        raise
    return is_stale(checked_at, ctx.settings.sources[SOURCE].max_age_days, ctx.now())
