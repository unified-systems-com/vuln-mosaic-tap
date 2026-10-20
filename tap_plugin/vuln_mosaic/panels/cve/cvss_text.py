"""Plain-English meanings of CVSS metrics, as constants (req-vuln-mosaic-panel-cve-8).

The text is static: it describes what each metric value means in the FIRST CVSS specifications (v2, v3.0 and
v3.1, v4.0), worded for a reader who is not a scorer. Nothing here is fetched or computed. Any metric or value
the tables do not know is returned as its raw code and never raises.
"""

from __future__ import annotations

from typing import Any

# metric key -> (name, {value code: (label, meaning)})
_V3_IMPACT = {
    "C": ("Confidentiality impact", {
        "N": ("None", "No information is exposed."),
        "L": ("Low", "Some restricted information is exposed, but the attacker cannot choose what."),
        "H": ("High", "All, or the most sensitive, information is exposed."),
    }),
    "I": ("Integrity impact", {
        "N": ("None", "Nothing can be modified."),
        "L": ("Low", "Some data can be modified, but the attacker has little control over what."),
        "H": ("High", "Data can be modified at will, which compromises the component."),
    }),
    "A": ("Availability impact", {
        "N": ("None", "No effect on availability."),
        "L": ("Low", "Performance is reduced or service is interrupted now and then."),
        "H": ("High", "The component can be shut down or made unusable."),
    }),
}

V3: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
    "AV": ("Attack vector", {
        "N": ("Network", "Can be exploited remotely over the network."),
        "A": ("Adjacent", "The attacker must be on the same local network segment, such as the same Wi-Fi or VLAN."),
        "L": ("Local", "The attacker needs access to the machine itself, or must get a local user to run something."),
        "P": ("Physical", "The attacker must physically touch the device."),
    }),
    "AC": ("Attack complexity", {
        "L": ("Low", "No special conditions are needed; the attack works whenever it is tried."),
        "H": ("High", "Depends on conditions outside the attacker's control, such as a race, a specific configuration or prior reconnaissance."),
    }),
    "PR": ("Privileges required", {
        "N": ("None", "No account is needed."),
        "L": ("Low", "A basic user account is enough."),
        "H": ("High", "An administrator-level account is needed."),
    }),
    "UI": ("User interaction", {
        "N": ("None", "No user has to do anything."),
        "R": ("Required", "A user has to take an action, such as opening a file or clicking a link."),
    }),
    "S": ("Scope", {
        "U": ("Unchanged", "The impact stays within the vulnerable component's own security boundary."),
        "C": ("Changed", "The attack can reach beyond the vulnerable component, for example out of a sandbox or to other systems."),
    }),
    **_V3_IMPACT,
}

V2: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
    "AV": ("Attack vector", {
        "L": ("Local", "The attacker needs local access to the machine."),
        "A": ("Adjacent network", "The attacker must be on the same local network segment."),
        "N": ("Network", "Can be exploited remotely over the network."),
    }),
    "AC": ("Attack complexity", {
        "H": ("High", "Specialised conditions must exist for the attack to work."),
        "M": ("Medium", "Some conditions must exist for the attack to work."),
        "L": ("Low", "No special conditions are needed."),
    }),
    "Au": ("Authentication", {
        "M": ("Multiple", "The attacker must authenticate two or more times."),
        "S": ("Single", "The attacker must authenticate once."),
        "N": ("None", "No authentication is needed."),
    }),
    "C": ("Confidentiality impact", {
        "N": ("None", "No information is exposed."),
        "P": ("Partial", "Some information is exposed."),
        "C": ("Complete", "All information in the system is exposed."),
    }),
    "I": ("Integrity impact", {
        "N": ("None", "Nothing can be modified."),
        "P": ("Partial", "Some data can be modified."),
        "C": ("Complete", "Any data in the system can be modified."),
    }),
    "A": ("Availability impact", {
        "N": ("None", "No effect on availability."),
        "P": ("Partial", "Performance is reduced or service is interrupted now and then."),
        "C": ("Complete", "The system can be shut down or made unusable."),
    }),
}

_V4_VULN = {
    "N": ("None", "No impact."),
    "L": ("Low", "Limited impact."),
    "H": ("High", "Total or serious impact."),
}
V4: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
    "AV": V3["AV"],
    "AC": ("Attack complexity", {
        "L": ("Low", "No special conditions are needed to defeat the built-in defences."),
        "H": ("High", "The attacker must defeat security measures that are built in to the system."),
    }),
    "AT": ("Attack requirements", {
        "N": ("None", "No particular deployment or execution conditions are needed."),
        "P": ("Present", "Depends on conditions of the target system, such as a race or a specific configuration."),
    }),
    "PR": V3["PR"],
    "UI": ("User interaction", {
        "N": ("None", "No user has to do anything."),
        "P": ("Passive", "A user takes a limited, involuntary action, such as viewing content."),
        "A": ("Active", "A user must deliberately perform specific actions."),
    }),
    "VC": ("Confidentiality impact (vulnerable system)", {
        "N": ("None", "No information is exposed."), "L": ("Low", "Some information is exposed."),
        "H": ("High", "All, or the most sensitive, information is exposed."),
    }),
    "VI": ("Integrity impact (vulnerable system)", {
        "N": ("None", "Nothing can be modified."), "L": ("Low", "Some data can be modified."),
        "H": ("High", "Data can be modified at will."),
    }),
    "VA": ("Availability impact (vulnerable system)", {
        "N": ("None", "No effect on availability."), "L": ("Low", "Reduced performance or occasional interruption."),
        "H": ("High", "The system can be shut down or made unusable."),
    }),
    "SC": ("Confidentiality impact (other systems)", {
        "N": ("None", "No information is exposed on other systems."),
        "L": ("Low", "Some information on other systems is exposed."),
        "H": ("High", "All, or the most sensitive, information on other systems is exposed."),
    }),
    "SI": ("Integrity impact (other systems)", {
        "N": ("None", "Nothing can be modified on other systems."),
        "L": ("Low", "Some data on other systems can be modified."),
        "H": ("High", "Data on other systems can be modified at will."),
    }),
    "SA": ("Availability impact (other systems)", {
        "N": ("None", "No effect on other systems' availability."),
        "L": ("Low", "Other systems see reduced performance or occasional interruption."),
        "H": ("High", "Other systems can be shut down or made unusable."),
    }),
}

# Optional metrics (v3 temporal and environmental, v4 threat, environmental and supplemental): published as ``X``
# they mean "not defined" and are skipped as noise; with a defined value they are shown as their raw code.
OPTIONAL_V3 = frozenset({"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"})
OPTIONAL_V4 = frozenset({
    "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
    "S", "AU", "R", "V", "RE", "U",
})
OPTIONAL = {"2.0": frozenset(), "3.0": OPTIONAL_V3, "3.1": OPTIONAL_V3, "4.0": OPTIONAL_V4}
TABLES = {"2.0": V2, "3.0": V3, "3.1": V3, "4.0": V4}
AFFECTED_NOTE = "Versions in these ranges are affected; upgrade to a fixed-in version."
UNRECOGNISED = "Not in this panel's glossary; shown as published."


def vector_version(vector: str, declared: str | None = None) -> str | None:
    """The CVSS version of a vector: its ``CVSS:x.y`` prefix, else a v2 vector (it has an ``Au`` metric), else ``declared``."""
    first = vector.split("/", 1)[0]
    if first.startswith("CVSS:"):
        return first[5:]
    if any(part.startswith("Au:") for part in vector.split("/")):
        return "2.0"
    return {"2": "2.0"}.get(declared or "", declared)


def explain_vector(vector: str | None, declared_version: str | None = None) -> list[dict[str, Any]]:
    """One row per metric: ``{key, name, code, label, meaning, known}``. Never raises, never blank.

    Metrics come out in the vector's own order. A key the version's table does not define is listed with its raw
    code, except an optional metric published as ``X`` (not defined), which is skipped as noise. A known key with
    an unknown value keeps the raw value as its label.
    """
    if not isinstance(vector, str) or not vector.strip():
        return []
    version = vector_version(vector, declared_version) or ""
    table, optional = TABLES.get(version, {}), OPTIONAL.get(version, frozenset())
    rows: list[dict[str, Any]] = []
    for part in vector.split("/"):
        key, sep, code = part.partition(":")
        if not sep or key == "CVSS" or not key or not code:
            continue
        if key in table:
            name, values = table[key]
            label, meaning = values.get(code, (code, UNRECOGNISED))
            rows.append({"key": key, "name": name, "code": code, "label": label, "meaning": meaning, "known": code in values})
        elif not (code == "X" and key in optional):
            rows.append({"key": key, "name": key, "code": code, "label": code, "meaning": UNRECOGNISED, "known": False})
    return rows
