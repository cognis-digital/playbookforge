"""Test suite for playbookforge: render, lint (pass + fail), coverage."""

import json
import os
import pathlib

import pytest

from playbookforge.attack import (
    is_valid_technique,
    is_valid_tactic,
    base_technique,
    tactic_name,
    ATTACK_TACTICS,
)
from playbookforge.model import parse_playbook, Playbook, PlaybookFormatError, IR_PHASES
from playbookforge.lint import lint, has_errors
from playbookforge.render import render_markdown, render_json
from playbookforge.scaffold import new_playbook
from playbookforge.cli import main

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


# --------------------------------------------------------------------------- #
# ATT&CK reference data
# --------------------------------------------------------------------------- #

def test_attack_has_14_enterprise_tactics():
    assert len(ATTACK_TACTICS) == 14


@pytest.mark.parametrize("tid", ["T1059", "T1059.001", "T1566.002", "T1486"])
def test_valid_technique_ids(tid):
    assert is_valid_technique(tid)


@pytest.mark.parametrize("tid", ["T105", "1059", "T10599", "T1059.1", "TX1059", ""])
def test_invalid_technique_ids(tid):
    assert not is_valid_technique(tid)


def test_valid_and_invalid_tactic_ids():
    assert is_valid_tactic("TA0001")
    assert not is_valid_tactic("T0001")
    assert not is_valid_tactic("TA1")


def test_base_technique():
    assert base_technique("T1059.001") == "T1059"
    assert base_technique("T1059") == "T1059"


def test_tactic_name_lookup():
    assert tactic_name("TA0001") == "Initial Access"
    assert tactic_name("TA9999") == "TA9999"


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def test_parse_minimal_playbook():
    pb = parse_playbook('{"title": "X", "phases": []}')
    assert pb.title == "X"
    assert pb.phases == []


def test_parse_rejects_non_object():
    with pytest.raises(PlaybookFormatError):
        parse_playbook("[1, 2, 3]")


def test_parse_string_technique_coerced_to_list():
    pb = parse_playbook(
        '{"title": "X", "phases": [{"name": "Detection",'
        ' "steps": [{"name": "s", "techniques": "T1059"}]}]}'
    )
    assert pb.phases[0].steps[0].techniques == ["T1059"]


# --------------------------------------------------------------------------- #
# Examples load and lint clean
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "fname", ["phishing-response.json", "ransomware-response.json"]
)
def test_examples_parse_and_lint_clean(fname):
    text = (EXAMPLES / fname).read_text(encoding="utf-8")
    pb = parse_playbook(text)
    findings = lint(pb)
    assert not has_errors(findings), [str(f) for f in findings]


@pytest.mark.parametrize(
    "fname", ["phishing-response.json", "ransomware-response.json"]
)
def test_examples_have_all_standard_phases(fname):
    pb = parse_playbook((EXAMPLES / fname).read_text(encoding="utf-8"))
    names = [p.name for p in pb.phases]
    assert names == IR_PHASES


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _sample() -> Playbook:
    return parse_playbook(
        json.dumps(
            {
                "title": "Sample",
                "description": "desc",
                "author": "Cognis Digital",
                "version": "1.0.0",
                "tactics": ["TA0001"],
                "phases": [
                    {
                        "name": "Detection",
                        "steps": [
                            {
                                "name": "Find it",
                                "techniques": ["T1059", "T1566.002"],
                                "detection": "look here",
                            }
                        ],
                    }
                ],
            }
        )
    )


def test_render_markdown_contains_key_sections():
    md = render_markdown(_sample())
    assert "# Sample" in md
    assert "## ATT&CK Coverage" in md
    assert "## Detection" in md
    assert "`T1059`" in md
    assert "`T1566.002`" in md
    assert "Initial Access" in md  # tactic label expanded
    assert "Total techniques referenced: 2" in md


def test_render_markdown_empty_phase():
    pb = parse_playbook('{"title": "E", "phases": [{"name": "Recovery", "steps": []}]}')
    md = render_markdown(pb)
    assert "_No steps defined for this phase._" in md


def test_render_json_roundtrips():
    pb = _sample()
    out = render_json(pb)
    again = parse_playbook(out)
    assert again.title == pb.title
    assert again.all_techniques() == pb.all_techniques()


# --------------------------------------------------------------------------- #
# Coverage extraction
# --------------------------------------------------------------------------- #

def test_all_techniques_dedup_and_order():
    pb = parse_playbook(
        json.dumps(
            {
                "title": "C",
                "phases": [
                    {
                        "name": "Detection",
                        "steps": [
                            {"name": "a", "techniques": ["T1059", "T1078"]},
                            {"name": "b", "techniques": ["T1059", "T1486"]},
                        ],
                    }
                ],
            }
        )
    )
    assert pb.all_techniques() == ["T1059", "T1078", "T1486"]


# --------------------------------------------------------------------------- #
# Linting: pass + fail
# --------------------------------------------------------------------------- #

def test_lint_clean_playbook_has_no_errors():
    pb = new_playbook("Test")
    findings = lint(pb)
    assert not has_errors(findings)


def test_lint_flags_bad_technique_id():
    pb = parse_playbook(
        '{"title": "X", "phases": [{"name": "Detection",'
        ' "steps": [{"name": "s", "techniques": ["NOTANID"], "detection": "d"}]}]}'
    )
    findings = lint(pb)
    assert has_errors(findings)
    assert any(f.code == "PB031" for f in findings)


def test_lint_flags_missing_title():
    pb = parse_playbook('{"title": "", "phases": [{"name": "Detection", "steps": []}]}')
    findings = lint(pb)
    assert has_errors(findings)
    assert any(f.code == "PB001" for f in findings)


def test_lint_flags_missing_step_name():
    pb = parse_playbook(
        '{"title": "X", "phases": [{"name": "Detection",'
        ' "steps": [{"name": "", "detection": "d"}]}]}'
    )
    findings = lint(pb)
    assert any(f.code == "PB030" and f.severity == "error" for f in findings)


def test_lint_warns_on_empty_phase():
    pb = parse_playbook('{"title": "X", "phases": [{"name": "Detection", "steps": []}]}')
    findings = lint(pb)
    assert any(f.code == "PB022" for f in findings)


def test_lint_warns_on_bad_tactic():
    pb = parse_playbook(
        '{"title": "X", "tactics": ["TA0001", "BOGUS"],'
        ' "phases": [{"name": "Detection", "steps": [{"name": "s", "detection": "d"}]}]}'
    )
    findings = lint(pb)
    assert any(f.code == "PB010" for f in findings)


def test_lint_warns_on_detection_step_without_detection():
    pb = parse_playbook(
        '{"title": "X", "phases": [{"name": "Detection",'
        ' "steps": [{"name": "s"}]}]}'
    )
    findings = lint(pb)
    assert any(f.code == "PB032" for f in findings)


# --------------------------------------------------------------------------- #
# CLI end-to-end
# --------------------------------------------------------------------------- #

def test_cli_render_md(capsys):
    rc = main(["render", str(EXAMPLES / "phishing-response.json"), "--format", "md"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Credential Phishing Response" in out
    assert "## ATT&CK Coverage" in out


def test_cli_render_json(capsys):
    rc = main(["render", str(EXAMPLES / "ransomware-response.json"), "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["title"] == "Ransomware Incident Response"


def test_cli_lint_clean_returns_zero(capsys):
    rc = main(["lint", str(EXAMPLES / "phishing-response.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "0 error(s)" in out


def test_cli_lint_bad_file_returns_nonzero(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "title": "Bad",
                "phases": [
                    {
                        "name": "Detection",
                        "steps": [{"name": "s", "techniques": ["XXX"]}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rc = main(["lint", str(bad)])
    assert rc == 1


def test_cli_new_emits_valid_playbook(capsys):
    rc = main(["new", "--title", "My Playbook"])
    assert rc == 0
    out = capsys.readouterr().out
    pb = parse_playbook(out)
    assert pb.title == "My Playbook"
    assert not has_errors(lint(pb))


def test_cli_coverage(capsys):
    rc = main(["coverage", str(EXAMPLES / "phishing-response.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "T1566.002" in out
    assert "Initial Access" in out


def test_cli_coverage_json(capsys):
    rc = main(["coverage", str(EXAMPLES / "ransomware-response.json"), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    ids = [t["id"] for t in data["techniques"]]
    assert "T1486" in ids


def test_cli_missing_file_returns_two(capsys):
    rc = main(["lint", "does-not-exist.json"])
    assert rc == 2


# --------------------------------------------------------------------------- #
# Demos: every shipped demo playbook must behave as documented
# --------------------------------------------------------------------------- #

DEMOS = pathlib.Path(__file__).resolve().parent.parent / "demos"

CLEAN_DEMOS = [
    "01-bec-wire-fraud",
    "02-okta-mfa-fatigue",
    "03-aws-s3-exfil",
    "04-malicious-oauth-grant",
    "05-linux-cryptominer",
    "06-ci-supply-chain",
    "07-data-exfil-insider",
]


@pytest.mark.parametrize("demo", CLEAN_DEMOS)
def test_clean_demos_lint_strict_clean(demo):
    pb = parse_playbook((DEMOS / demo / "playbook.json").read_text(encoding="utf-8"))
    findings = lint(pb)
    # No errors AND no warnings -> survives `lint --strict`.
    assert not findings, [str(f) for f in findings]


@pytest.mark.parametrize("demo", CLEAN_DEMOS)
def test_clean_demos_render_and_have_techniques(demo):
    pb = parse_playbook((DEMOS / demo / "playbook.json").read_text(encoding="utf-8"))
    md = render_markdown(pb)
    assert md.startswith("# ")
    assert "## ATT&CK Coverage" in md
    assert pb.all_techniques(), "demo should reference at least one technique"
    # every technique ID in the demo is a well-formed ATT&CK ID
    for tech in pb.all_techniques():
        assert is_valid_technique(tech), tech


@pytest.mark.parametrize("demo", CLEAN_DEMOS)
def test_clean_demos_have_all_standard_phases(demo):
    pb = parse_playbook((DEMOS / demo / "playbook.json").read_text(encoding="utf-8"))
    assert [p.name for p in pb.phases] == IR_PHASES


def test_broken_demo_lints_with_errors():
    pb = parse_playbook(
        (DEMOS / "08-broken-playbook-cigate" / "playbook.json").read_text(
            encoding="utf-8"
        )
    )
    findings = lint(pb)
    assert has_errors(findings)
    codes = {f.code for f in findings}
    # the documented findings are all present
    assert {"PB001", "PB010", "PB031"} <= codes


def test_cli_lint_broken_demo_returns_nonzero():
    rc = main(["lint", str(DEMOS / "08-broken-playbook-cigate" / "playbook.json")])
    assert rc == 1


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 export
# --------------------------------------------------------------------------- #

from playbookforge.sarif import to_sarif, render_sarif, SARIF_VERSION  # noqa: E402
from playbookforge.lint import Finding, SEVERITY_ERROR, SEVERITY_WARNING  # noqa: E402


def _broken_pb():
    return parse_playbook(
        '{"title": "", "tactics": ["BOGUS"], "phases": [{"name": "Detection",'
        ' "steps": [{"name": "s", "techniques": ["XXX"]}]}]}'
    )


def test_sarif_top_level_shape():
    findings = lint(_broken_pb())
    doc = to_sarif(findings)
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "playbookforge"
    assert driver["version"]


def test_sarif_results_and_rules_match_findings():
    findings = lint(_broken_pb())
    doc = to_sarif(findings)
    run = doc["runs"][0]
    assert len(run["results"]) == len(findings)
    # every result's ruleId has a matching rule descriptor
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]


def test_sarif_severity_levels_mapped():
    findings = [
        Finding(SEVERITY_ERROR, "PB001", "missing title"),
        Finding(SEVERITY_WARNING, "PB022", "empty phase", location="phase:X"),
    ]
    doc = to_sarif(findings)
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "warning"]
    # warning carried its playbook location into properties
    warn = doc["runs"][0]["results"][1]
    assert warn["properties"]["playbookLocation"] == "phase:X"


def test_sarif_artifact_uri_attached():
    findings = lint(_broken_pb())
    doc = to_sarif(findings, artifact_uri="path/to/playbook.json")
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "path/to/playbook.json"


def test_render_sarif_is_valid_json():
    findings = lint(_broken_pb())
    text = render_sarif(findings)
    again = json.loads(text)
    assert again["version"] == "2.1.0"


def test_cli_lint_sarif_to_stdout(capsys):
    rc = main(["lint", str(DEMOS / "08-broken-playbook-cigate" / "playbook.json"),
               "--sarif"])
    assert rc == 1  # still fails the gate
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_cli_lint_sarif_clean_playbook_exits_zero(capsys):
    rc = main(["lint", str(EXAMPLES / "phishing-response.json"), "--sarif"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_cli_lint_sarif_to_file(tmp_path):
    out = tmp_path / "out.sarif"
    rc = main(["lint", str(DEMOS / "08-broken-playbook-cigate" / "playbook.json"),
               "--sarif", "-o", str(out)])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
