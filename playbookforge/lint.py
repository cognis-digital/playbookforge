"""Playbook linter.

Validates technique-ID format, required fields, and phase coverage. Produces
a list of findings (errors + warnings). Errors should fail a CI gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attack import is_valid_technique, is_valid_tactic, ATTACK_TACTICS
from .model import Playbook, IR_PHASES

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    location: str = ""

    def __str__(self) -> str:
        loc = f" [{self.location}]" if self.location else ""
        return f"{self.severity.upper()}: {self.code}{loc} {self.message}"


def lint(playbook: Playbook) -> list[Finding]:
    """Return all lint findings for a playbook (errors first, then warnings)."""
    findings: list[Finding] = []

    # --- required top-level fields ---
    if not playbook.title.strip():
        findings.append(
            Finding(SEVERITY_ERROR, "PB001", "playbook is missing a 'title'")
        )

    if not playbook.phases:
        findings.append(
            Finding(SEVERITY_ERROR, "PB002", "playbook has no phases")
        )

    # --- tactic tags (top level) ---
    for tactic in playbook.tactics:
        if not is_valid_tactic(tactic):
            findings.append(
                Finding(
                    SEVERITY_ERROR,
                    "PB010",
                    f"tactic '{tactic}' is not a valid ATT&CK tactic ID (expected TAxxxx)",
                    location="tactics",
                )
            )
        elif tactic not in ATTACK_TACTICS:
            findings.append(
                Finding(
                    SEVERITY_WARNING,
                    "PB011",
                    f"tactic '{tactic}' is not a known enterprise tactic",
                    location="tactics",
                )
            )

    # --- phase-level checks ---
    seen_phase_names = set()
    for phase in playbook.phases:
        loc = f"phase:{phase.name}"

        if phase.name in seen_phase_names:
            findings.append(
                Finding(SEVERITY_WARNING, "PB020", "duplicate phase name", location=loc)
            )
        seen_phase_names.add(phase.name)

        if phase.name not in IR_PHASES:
            findings.append(
                Finding(
                    SEVERITY_WARNING,
                    "PB021",
                    f"phase name '{phase.name}' is not a standard IR phase "
                    f"({', '.join(IR_PHASES)})",
                    location=loc,
                )
            )

        if not phase.steps:
            findings.append(
                Finding(SEVERITY_WARNING, "PB022", "phase has no steps", location=loc)
            )

        # --- step-level checks ---
        for index, step in enumerate(phase.steps):
            sloc = f"{loc}/step#{index}"
            label = step.name or step.id or f"#{index}"

            if not step.name.strip():
                findings.append(
                    Finding(
                        SEVERITY_ERROR,
                        "PB030",
                        f"step {label} is missing a 'name'",
                        location=sloc,
                    )
                )

            for tech in step.techniques:
                if not is_valid_technique(tech):
                    findings.append(
                        Finding(
                            SEVERITY_ERROR,
                            "PB031",
                            f"technique '{tech}' is not a valid ATT&CK ID "
                            f"(expected Txxxx or Txxxx.xxx)",
                            location=sloc,
                        )
                    )

            # Detection/Containment/Eradication steps should say *how*.
            if phase.name == "Detection" and not step.detection.strip():
                findings.append(
                    Finding(
                        SEVERITY_WARNING,
                        "PB032",
                        f"detection step {label} has no 'detection' guidance",
                        location=sloc,
                    )
                )
            if (
                phase.name in ("Containment", "Eradication", "Recovery")
                and not step.response.strip()
                and not step.description.strip()
            ):
                findings.append(
                    Finding(
                        SEVERITY_WARNING,
                        "PB033",
                        f"response step {label} has no 'response' or 'description'",
                        location=sloc,
                    )
                )

    # --- missing standard phases (informational warning) ---
    present = {p.name for p in playbook.phases}
    for required in IR_PHASES:
        if required not in present:
            findings.append(
                Finding(
                    SEVERITY_WARNING,
                    "PB040",
                    f"standard IR phase '{required}' is not present",
                    location="playbook",
                )
            )

    # errors first, stable otherwise
    findings.sort(key=lambda f: 0 if f.severity == SEVERITY_ERROR else 1)
    return findings


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == SEVERITY_ERROR for f in findings)
