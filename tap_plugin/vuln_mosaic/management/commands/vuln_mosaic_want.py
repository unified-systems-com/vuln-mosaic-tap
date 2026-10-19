"""Write a consumer's wanted-ids file (req-vuln-mosaic-wanted): manage.py vuln_mosaic_want <consumer> ids...

The consumer file is plain data in <home>/wanted/<consumer>.json. This command validates the consumer
name and every id, then writes the file atomically, replacing that consumer's earlier list. It touches
no other consumer's file and makes no network call.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from tap_plugin.vuln_mosaic.home import resolve_home
from tap_plugin.vuln_mosaic.ids import validate_vuln_id
from tap_plugin.vuln_mosaic.wanted import CONSUMER_FILE_RE


class Command(BaseCommand):
    help = "Write <home>/wanted/<consumer>.json from CVE or GHSA ids given as arguments or read from a file (one id per line)."

    def add_arguments(self, parser) -> None:  # type: ignore[no-untyped-def]
        parser.add_argument("consumer", help="Consumer name, a plugin slug: ^[a-z][a-z0-9_]{0,63}$")
        parser.add_argument("ids", nargs="*", help="CVE or GHSA ids")
        parser.add_argument("--from-file", dest="from_file", help="A file with one id per line")
        parser.add_argument("--description", default="", help="Who wrote the list and why")

    def handle(self, *args, **options) -> None:  # type: ignore[no-untyped-def]
        consumer = options["consumer"]
        if not CONSUMER_FILE_RE.fullmatch(f"{consumer}.json"):
            raise CommandError("consumer must match ^[a-z][a-z0-9_]{0,63}$")
        raw: list[str] = list(options["ids"])
        if options["from_file"]:
            raw += [line.strip() for line in Path(options["from_file"]).read_text().splitlines() if line.strip()]
        ids: list[str] = []
        for value in raw:
            try:
                vuln_id = validate_vuln_id(value)
            except ValueError:
                self.stderr.write(f"skipped (not a CVE or GHSA id): {value!r}")
                continue
            if vuln_id not in ids:
                ids.append(vuln_id)
        if not ids:
            raise CommandError("no valid CVE or GHSA ids given")
        wanted = resolve_home() / "wanted"
        wanted.mkdir(parents=True, exist_ok=True)
        target = wanted / f"{consumer}.json"
        tmp = wanted / f".{consumer}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps({"description": options["description"] or f"Written by manage.py vuln_mosaic_want for {consumer}", "ids": ids}))
        os.replace(tmp, target)
        self.stdout.write(f"wrote {target} with {len(ids)} id(s)")
