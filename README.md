# playbookforge

Incident-response playbook generator and linter, mapped to MITRE ATT&CK tactics and techniques.

Analysts author an IR playbook as structured data — steps grouped by the standard incident-response phases (Preparation, Detection, Containment, Eradication, Recovery, Lessons-Learned), each step optionally tagged with ATT&CK technique IDs. `playbookforge` renders the playbook to clean Markdown and JSON, and **lints** it so a malformed or incomplete playbook fails your CI gate.

## Install

```bash
pip install cognis-playbookforge
```

The core is **standard library only**. Optional YAML input support:

```bash
pip install "cognis-playbookforge[yaml]"
```

Python 3.10+.

## Usage

### Render a playbook to Markdown (the headline output)

```bash
playbookforge render examples/phishing-response.json --format md
```

```markdown
# Credential Phishing Response

Response playbook for a reported or detected credential-harvesting phishing campaign...

**Author:** Cognis Digital  **Version:** 1.0.0

## ATT&CK Coverage

**Tactics:** TA0001 (Initial Access), TA0006 (Credential Access), TA0009 (Collection)

| Technique | Type |
| --- | --- |
| `T1566.002` | Sub-technique |
| `T1056.003` | Sub-technique |
| `T1078` | Technique |

_Total techniques referenced: 3_

## Preparation

### 1. Confirm reporting channels are live
...
```

Or render canonical JSON with `--format json`. Use `-o FILE` to write to a file, or pass `-` as the playbook to read from stdin.

### Lint a playbook (CI gate)

```bash
playbookforge lint examples/phishing-response.json
```

```
0 error(s), 0 warning(s)
```

On a malformed playbook the tool prints findings and **exits non-zero**:

```bash
playbookforge lint broken.json
```

```
ERROR: PB031 [phase:Detection/step#0] technique 'XXX' is not a valid ATT&CK ID (expected Txxxx or Txxxx.xxx)
WARNING: PB022 [phase:Containment] phase has no steps

1 error(s), 1 warning(s)
```

Add `--strict` to also fail on warnings.

### Scaffold a new playbook

```bash
playbookforge new --title "Business Email Compromise" -o bec.json
```

Writes a starter playbook with all six standard IR phases and one placeholder step each.

### Show ATT&CK coverage

```bash
playbookforge coverage examples/phishing-response.json
```

```
Playbook: Credential Phishing Response

Tactics:
  TA0001  Initial Access
  TA0006  Credential Access
  TA0009  Collection

Techniques (3):
  T1566.002  (sub-technique, base T1566)
  T1056.003  (sub-technique, base T1056)
  T1078  (technique, base T1078)
```

Add `--json` for machine-readable output.

## Lint rules

| Code | Severity | Checks |
| --- | --- | --- |
| PB001 | error | Playbook has a title |
| PB002 | error | Playbook has at least one phase |
| PB010 | error | Tactic tags match the `TAxxxx` format |
| PB011 | warning | Tactic is a known enterprise tactic |
| PB020 | warning | No duplicate phase names |
| PB021 | warning | Phase name is a standard IR phase |
| PB022 | warning | Phase has at least one step |
| PB030 | error | Each step has a name |
| PB031 | error | Technique IDs match `Txxxx` / `Txxxx.xxx` |
| PB032 | warning | Detection steps carry detection guidance |
| PB033 | warning | Response phases carry response/description |
| PB040 | warning | All standard IR phases are present |

## Playbook format

A playbook is a JSON (or, with the `yaml` extra, YAML) object:

```json
{
  "title": "Credential Phishing Response",
  "description": "...",
  "author": "Cognis Digital",
  "version": "1.0.0",
  "tactics": ["TA0001", "TA0006"],
  "phases": [
    {
      "name": "Detection",
      "steps": [
        {
          "name": "Triage the reported message",
          "description": "...",
          "techniques": ["T1566.002"],
          "detection": "Mail-gateway logs for the sending domain..."
        }
      ]
    }
  ]
}
```

See `examples/` for full phishing-response and ransomware-response playbooks.

## Features

- Markdown renderer with an ATT&CK coverage summary table and technique badges
- Canonical JSON renderer (round-trips cleanly)
- Linter with technique-ID regex validation, required-field checks, and phase-coverage warnings; non-zero exit on errors for CI
- `new` scaffolder for starter playbooks
- `coverage` extractor for referenced tactics and techniques
- Built-in list of the 14 enterprise ATT&CK tactics for labeling and validation
- Standard library only for the core; optional YAML input via an extra

## Scope

Defensive and analytical use only.

## License

License: COCL 1.0
