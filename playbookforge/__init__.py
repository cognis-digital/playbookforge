"""playbookforge - incident-response playbook generator and linter.

Maps incident-response playbooks to MITRE ATT&CK tactics and techniques,
renders them to Markdown/JSON, and lints them for CI gating.

Original Cognis Digital IP. Defensive/analytical scope only.
"""

__version__ = "0.1.0"

from .model import (
    Playbook,
    Phase,
    Step,
    IR_PHASES,
    parse_playbook,
)
from .attack import (
    ATTACK_TACTICS,
    TECHNIQUE_RE,
    is_valid_technique,
    base_technique,
)

__all__ = [
    "__version__",
    "Playbook",
    "Phase",
    "Step",
    "IR_PHASES",
    "parse_playbook",
    "ATTACK_TACTICS",
    "TECHNIQUE_RE",
    "is_valid_technique",
    "base_technique",
]
