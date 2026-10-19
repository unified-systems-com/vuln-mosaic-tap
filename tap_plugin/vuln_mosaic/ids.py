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


GHSA_ID_PATTERN = r"^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$"
GHSA_ID_RE = re.compile(GHSA_ID_PATTERN)


def validate_ghsa_id(value: object) -> str:
    """Return ``value`` if it is a well-formed GitHub advisory id, else raise ``ValueError``."""
    if not isinstance(value, str) or not GHSA_ID_RE.fullmatch(value):
        raise ValueError("not a GHSA id")
    return value


def validate_vuln_id(value: object) -> str:
    """A CVE id or a GHSA id; anything else raises ``ValueError``."""
    if isinstance(value, str) and (CVE_ID_RE.fullmatch(value) or GHSA_ID_RE.fullmatch(value)):
        return value
    raise ValueError("not a CVE or GHSA id")


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


_ADVISORY_PATH_RE = re.compile(
    r"^advisories/(github-reviewed|unreviewed)/[0-9]{4}/[0-9]{2}/(GHSA(?:-[2-9cfghjmpqrvwx]{4}){3})/\2\.json$"
)


def id_from_advisory_path(path: str) -> str | None:
    """The GHSA id an advisory-database path names, or ``None`` for anything else.

    The year and month directories come from the advisory's publication date, which the id does not
    carry, so a path cannot be derived from an id: it is found by listing the tree (req-vuln-mosaic-ghsa-1).
    """
    match = _ADVISORY_PATH_RE.fullmatch(path)
    return match.group(2) if match else None


def is_reviewed_path(path: str) -> bool:
    return path.startswith("advisories/github-reviewed/")
