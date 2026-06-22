"""SARIF 2.1.0 export for playbookforge lint findings.

SARIF (Static Analysis Results Interchange Format, OASIS standard, version
2.1.0) is the format GitHub code scanning and most security dashboards ingest.
Emitting lint findings as SARIF lets a playbook author wire `playbookforge lint`
into a CI gate whose results show up as annotations on a pull request.

Standard-library only; produces a SARIF log object that validates against the
2.1.0 schema's required fields.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .lint import Finding, SEVERITY_ERROR, SEVERITY_WARNING

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Map playbookforge severities to SARIF result levels.
_LEVEL = {
    SEVERITY_ERROR: "error",
    SEVERITY_WARNING: "warning",
}

# Short, stable descriptions for each rule the linter can emit. Keyed by code.
# Used to populate the SARIF run's rule metadata so dashboards can group and
# explain findings.
RULE_DESCRIPTIONS = {
    "PB001": "Playbook is missing a title.",
    "PB002": "Playbook has no phases.",
    "PB010": "Tactic tag is not a valid ATT&CK tactic ID.",
    "PB011": "Tactic is not a known enterprise ATT&CK tactic.",
    "PB020": "Duplicate phase name.",
    "PB021": "Phase name is not a standard IR phase.",
    "PB022": "Phase has no steps.",
    "PB030": "Step is missing a name.",
    "PB031": "Technique ID is not a valid ATT&CK technique ID.",
    "PB032": "Detection step has no detection guidance.",
    "PB033": "Response step has no response or description.",
    "PB040": "A standard IR phase is not present.",
}


def _rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build the unique, sorted SARIF rule descriptors referenced by findings."""
    codes = sorted({f.code for f in findings})
    rules = []
    for code in codes:
        text = RULE_DESCRIPTIONS.get(code, code)
        rules.append(
            {
                "id": code,
                "name": code,
                "shortDescription": {"text": text},
                "helpUri": "https://github.com/cognis-digital/playbookforge#lint-rules",
            }
        )
    return rules


def _result_for(finding: Finding, artifact_uri: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.code,
        "level": _LEVEL.get(finding.severity, "note"),
        "message": {"text": finding.message},
    }
    if finding.location:
        props = {"playbookLocation": finding.location}
        result["properties"] = props
    if artifact_uri:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                }
            }
        ]
    return result


def to_sarif(findings: list[Finding], *, artifact_uri: str | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object for a list of lint findings.

    artifact_uri, when given, attaches the playbook path to each result so a
    dashboard can link the finding back to the source file.
    """
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "playbookforge",
                        "informationUri": (
                            "https://github.com/cognis-digital/playbookforge"
                        ),
                        "version": __version__,
                        "rules": _rules_for(findings),
                    }
                },
                "results": [_result_for(f, artifact_uri) for f in findings],
            }
        ],
    }


def render_sarif(findings: list[Finding], *, artifact_uri: str | None = None) -> str:
    """Render lint findings as a pretty-printed SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(findings, artifact_uri=artifact_uri), indent=2)
