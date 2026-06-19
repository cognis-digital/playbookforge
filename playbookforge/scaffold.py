"""Scaffolding for new playbooks."""

from __future__ import annotations

from .model import IR_PHASES, Playbook, Phase, Step


def new_playbook(title: str) -> Playbook:
    """Build a starter playbook with all standard IR phases and one example
    step per phase, ready for an analyst to fill in."""
    hints = {
        "Preparation": "Confirm tooling, contacts, and access are ready.",
        "Detection": "Identify and triage the suspected incident.",
        "Containment": "Limit the blast radius without destroying evidence.",
        "Eradication": "Remove the root cause from affected systems.",
        "Recovery": "Restore systems to known-good operation and monitor.",
        "Lessons-Learned": "Capture findings and improve future response.",
    }
    phases = []
    for name in IR_PHASES:
        step = Step(
            name=f"{name} step",
            description=hints.get(name, ""),
            detection="Describe the signal or query here." if name == "Detection" else "",
            response="Describe the action to take here."
            if name in ("Containment", "Eradication", "Recovery")
            else "",
        )
        phases.append(Phase(name=name, steps=[step]))

    return Playbook(
        title=title,
        description="Describe the scope and trigger of this playbook.",
        author="Cognis Digital",
        version="0.1.0",
        tactics=[],
        phases=phases,
    )
