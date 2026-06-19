"""Renderers for playbooks: Markdown (headline) and JSON."""

from __future__ import annotations

import json

from .attack import base_technique, tactic_name, ATTACK_TACTICS
from .model import Playbook


def render_json(playbook: Playbook, *, indent: int = 2) -> str:
    """Render the playbook back to canonical JSON."""
    return json.dumps(playbook.to_dict(), indent=indent, ensure_ascii=False)


def _badge(technique: str) -> str:
    """Format a technique as an inline Markdown badge."""
    return f"`{technique}`"


def coverage_rows(playbook: Playbook) -> list[tuple[str, str, str]]:
    """Build coverage rows: (technique_id, parent_id, label-hint).

    Returns one row per unique technique referenced, in first-seen order.
    """
    rows: list[tuple[str, str, str]] = []
    for tech in playbook.all_techniques():
        parent = base_technique(tech)
        sub = " (sub-technique)" if "." in tech else ""
        rows.append((tech, parent, sub))
    return rows


def render_markdown(playbook: Playbook) -> str:
    """Render the playbook to clean Markdown.

    Layout: title, metadata, ATT&CK coverage summary table, then each phase as
    a section with its steps and technique badges.
    """
    lines: list[str] = []

    title = playbook.title or "Untitled Playbook"
    lines.append(f"# {title}")
    lines.append("")

    if playbook.description:
        lines.append(playbook.description)
        lines.append("")

    meta: list[str] = []
    if playbook.author:
        meta.append(f"**Author:** {playbook.author}")
    if playbook.version:
        meta.append(f"**Version:** {playbook.version}")
    if meta:
        lines.append("  ".join(meta))
        lines.append("")

    # --- ATT&CK coverage summary ---
    lines.append("## ATT&CK Coverage")
    lines.append("")

    techniques = playbook.all_techniques()
    if playbook.tactics:
        tactic_labels = [
            f"{t} ({tactic_name(t)})" if t in ATTACK_TACTICS else t
            for t in playbook.tactics
        ]
        lines.append("**Tactics:** " + ", ".join(tactic_labels))
        lines.append("")

    if techniques:
        lines.append("| Technique | Type |")
        lines.append("| --- | --- |")
        for tech in techniques:
            kind = "Sub-technique" if "." in tech else "Technique"
            lines.append(f"| {_badge(tech)} | {kind} |")
        lines.append("")
        lines.append(f"_Total techniques referenced: {len(techniques)}_")
    else:
        lines.append("_No ATT&CK techniques referenced._")
    lines.append("")

    # --- phases ---
    for phase in playbook.phases:
        lines.append(f"## {phase.name}")
        lines.append("")
        if not phase.steps:
            lines.append("_No steps defined for this phase._")
            lines.append("")
            continue

        for index, step in enumerate(phase.steps, start=1):
            heading = step.name or step.id or f"Step {index}"
            lines.append(f"### {index}. {heading}")
            badges = " ".join(_badge(t) for t in step.techniques)
            if badges:
                lines.append("")
                lines.append(f"ATT&CK: {badges}")
            lines.append("")
            if step.description:
                lines.append(step.description)
                lines.append("")
            if step.detection:
                lines.append(f"- **Detection:** {step.detection}")
            if step.response:
                lines.append(f"- **Response:** {step.response}")
            if step.detection or step.response:
                lines.append("")

    text = "\n".join(lines).rstrip() + "\n"
    return text
