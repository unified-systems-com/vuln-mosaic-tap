"""CVE id validation: the one place untrusted text becomes a key (req-vuln-mosaic-lookup)."""

from __future__ import annotations

import re

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
CVE_ID_RE = re.compile(CVE_ID_PATTERN)


def validate_cve_id(value: object) -> str:
    """Return ``value`` if it is a well-formed CVE id, else raise ``ValueError``.

    ``fullmatch`` on a ``str`` only: a bytes value, a trailing newline or a lookalike
    never passes, and the result is safe to place in a path or a command argument.
    """
    if not isinstance(value, str) or not CVE_ID_RE.fullmatch(value):
        raise ValueError("not a CVE id")
    return value


def record_path(cve_id: str) -> str:
    """The repository path of an id's record in cvelistV5: ``cves/<year>/<n>xxx/<id>.json``."""
    validate_cve_id(cve_id)
    _, year, number = cve_id.split("-")
    return f"cves/{year}/{int(number) // 1000}xxx/{cve_id}.json"


_PATH_RE = re.compile(r"^cves/[0-9]{4}/[0-9]+xxx/(CVE-[0-9]{4}-[0-9]{4,})\.json$")


def id_from_record_path(path: str) -> str | None:
    """The CVE id a cvelistV5 path names, or ``None`` for anything not a record path."""
    match = _PATH_RE.fullmatch(path)
    return match.group(1) if match else None
