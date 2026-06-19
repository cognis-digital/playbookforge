"""Built-in MITRE ATT&CK reference data for validation and labeling.

The 14 enterprise ATT&CK tactics are referenced here by their public
identifiers (TA0001-TA0043) and tactic names. Only generic identifiers and
short names are stored - no third-party prose is reproduced. This is used to
label technique references and validate tactic tags inside playbooks.
"""

import re

# Generic ATT&CK tactic identifiers and their canonical short names.
# (identifier, name, slug-style key) - authored from public tactic names.
ATTACK_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Technique IDs look like T1059 or, for a sub-technique, T1059.001.
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Tactic IDs look like TA0001.
TACTIC_RE = re.compile(r"^TA\d{4}$")


def is_valid_technique(value: str) -> bool:
    """Return True if value matches the ATT&CK technique-ID format."""
    return bool(TECHNIQUE_RE.match(value.strip())) if isinstance(value, str) else False


def is_valid_tactic(value: str) -> bool:
    """Return True if value matches the ATT&CK tactic-ID format."""
    return bool(TACTIC_RE.match(value.strip())) if isinstance(value, str) else False


def base_technique(value: str) -> str:
    """Return the parent technique ID for a sub-technique.

    base_technique("T1059.001") -> "T1059"
    base_technique("T1059")     -> "T1059"
    """
    value = value.strip()
    return value.split(".", 1)[0]


def tactic_name(tactic_id: str) -> str:
    """Return the friendly tactic name, or the id itself if unknown."""
    return ATTACK_TACTICS.get(tactic_id.strip(), tactic_id.strip())
