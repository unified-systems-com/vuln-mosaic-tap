"""CVSS v3.x base scores computed from a vector string (req-vuln-mosaic-ghsa-4).

GitHub's advisories carry a vector and no number, so a consumer that wants a score gets it here.
Standard library only. Only the base metrics are read; temporal and environmental metrics in a
vector are ignored, as the base score is defined without them. A vector that is not a complete
v3.0 or v3.1 base vector returns ``None``: this module never guesses a score, and it does not
compute v2 or v4 scores (those vectors are kept by the parser with ``base_score = None``).
"""

from __future__ import annotations

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# Temporal and environmental metric names defined by v3.x: accepted and ignored. Any other key refuses the vector.
_IGNORED = frozenset({"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"})


def _roundup_31(value: float) -> float:
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10 - 1e-9) / 10.0


def severity(score: float) -> str:
    """The qualitative rating of a v3 base score."""
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def parse_vector(vector: str) -> tuple[str, dict[str, str]] | None:
    """(version, metrics) of a v3.0 or v3.1 vector, or ``None`` when it is not a complete base vector."""
    if not isinstance(vector, str) or len(vector) > 512:
        return None
    parts = vector.split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            return None
        metrics[key] = value
    if any(key not in metrics for key in _BASE) or any(key not in _BASE and key not in _IGNORED for key in metrics):
        return None
    valid = {**_WEIGHTS, "PR": _PR["U"], "S": {"U": 0, "C": 0}}
    if any(metrics[key] not in valid[key] for key in _BASE):
        return None
    return parts[0][5:], metrics


def base_score(vector: str) -> float | None:
    """The v3.0/v3.1 base score of ``vector`` (0.0 to 10.0), or ``None`` when it cannot be computed."""
    parsed = parse_vector(vector)
    if parsed is None:
        return None
    version, m = parsed
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22 * _WEIGHTS["AV"][m["AV"]] * _WEIGHTS["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    roundup = _roundup_31 if version == "3.1" else _roundup_30
    total = (impact + exploitability) * (1.08 if changed else 1.0)
    return roundup(min(total, 10.0))
