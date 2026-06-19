"""Data model for incident-response playbooks.

A playbook is a titled document made of phases (the standard IR lifecycle),
each phase containing ordered steps. Steps may carry ATT&CK technique tags
plus detection / response guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Canonical incident-response lifecycle phases, in execution order.
IR_PHASES = [
    "Preparation",
    "Detection",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons-Learned",
]


class PlaybookFormatError(ValueError):
    """Raised when the input document cannot be parsed into a Playbook."""


@dataclass
class Step:
    """A single action within an IR phase."""

    id: str = ""
    name: str = ""
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: str = ""
    response: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], index: int) -> "Step":
        if not isinstance(data, dict):
            raise PlaybookFormatError(f"step #{index} must be an object")
        techniques = data.get("techniques", []) or []
        if isinstance(techniques, str):
            techniques = [techniques]
        if not isinstance(techniques, list):
            raise PlaybookFormatError(
                f"step '{data.get('name', index)}' techniques must be a list"
            )
        return cls(
            id=str(data.get("id", "") or ""),
            name=str(data.get("name", "") or ""),
            description=str(data.get("description", "") or ""),
            techniques=[str(t).strip() for t in techniques if str(t).strip()],
            detection=str(data.get("detection", "") or ""),
            response=str(data.get("response", "") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name}
        if self.id:
            out["id"] = self.id
        if self.description:
            out["description"] = self.description
        if self.techniques:
            out["techniques"] = list(self.techniques)
        if self.detection:
            out["detection"] = self.detection
        if self.response:
            out["response"] = self.response
        return out


@dataclass
class Phase:
    """A named IR lifecycle phase holding ordered steps."""

    name: str
    steps: list[Step] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Phase":
        if not isinstance(data, dict):
            raise PlaybookFormatError("phase must be an object")
        name = str(data.get("name", "") or "").strip()
        if not name:
            raise PlaybookFormatError("phase is missing a 'name'")
        raw_steps = data.get("steps", []) or []
        if not isinstance(raw_steps, list):
            raise PlaybookFormatError(f"phase '{name}' steps must be a list")
        steps = [Step.from_dict(s, i) for i, s in enumerate(raw_steps)]
        return cls(name=name, steps=steps)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "steps": [s.to_dict() for s in self.steps]}


@dataclass
class Playbook:
    """A complete incident-response playbook."""

    title: str
    description: str = ""
    author: str = ""
    version: str = ""
    tactics: list[str] = field(default_factory=list)
    phases: list[Phase] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Playbook":
        if not isinstance(data, dict):
            raise PlaybookFormatError("playbook must be a JSON/YAML object")
        title = str(data.get("title", "") or "").strip()
        raw_phases = data.get("phases", []) or []
        if not isinstance(raw_phases, list):
            raise PlaybookFormatError("'phases' must be a list")
        phases = [Phase.from_dict(p) for p in raw_phases]
        tactics = data.get("tactics", []) or []
        if isinstance(tactics, str):
            tactics = [tactics]
        return cls(
            title=title,
            description=str(data.get("description", "") or ""),
            author=str(data.get("author", "") or ""),
            version=str(data.get("version", "") or ""),
            tactics=[str(t).strip() for t in tactics if str(t).strip()],
            phases=phases,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"title": self.title}
        if self.description:
            out["description"] = self.description
        if self.author:
            out["author"] = self.author
        if self.version:
            out["version"] = self.version
        if self.tactics:
            out["tactics"] = list(self.tactics)
        out["phases"] = [p.to_dict() for p in self.phases]
        return out

    def all_techniques(self) -> list[str]:
        """Return every technique referenced across all steps, de-duplicated,
        in first-seen order."""
        seen: list[str] = []
        for phase in self.phases:
            for step in phase.steps:
                for tech in step.techniques:
                    if tech not in seen:
                        seen.append(tech)
        return seen


def parse_playbook(text: str, *, prefer_yaml: bool = False) -> Playbook:
    """Parse a playbook from JSON (always) or YAML (if available).

    JSON is attempted first unless prefer_yaml is set. YAML support is optional
    and only used when PyYAML is installed; otherwise a clear error is raised.
    """
    import json

    loaders = []
    if prefer_yaml:
        loaders = ["yaml", "json"]
    else:
        loaders = ["json", "yaml"]

    last_err: Exception | None = None
    for kind in loaders:
        try:
            if kind == "json":
                data = json.loads(text)
            else:
                try:
                    import yaml  # type: ignore
                except ImportError:
                    continue
                data = yaml.safe_load(text)
            return Playbook.from_dict(data)
        except PlaybookFormatError:
            raise
        except Exception as exc:  # parse error - try the next loader
            last_err = exc
            continue

    raise PlaybookFormatError(
        f"could not parse input as JSON or YAML: {last_err}"
    )
