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

#### SARIF 2.1.0 output (GitHub code scanning)

Emit lint findings as [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) so they
show up as annotations on a pull request:

```bash
playbookforge lint examples/phishing-response.json --sarif -o playbook-lint.sarif
```

The command still exits non-zero on errors, so it doubles as both a hard gate
and a results file. In a GitHub Actions workflow:

```yaml
- run: playbookforge lint playbooks/*.json --sarif -o playbook-lint.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: playbook-lint.sarif
```

Each lint rule (`PB001`-`PB040`) is emitted as a SARIF rule descriptor with a
short description, and each finding becomes a result with the matching severity
level and the playbook path attached.

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

## Demos

The `demos/` directory holds varied, real-use-case playbooks. Each demo is a
folder with a `playbook.json` in the real input format plus a `SCENARIO.md`
describing where the data came from, what to expect, the exact command to run,
and how to act. Demos 01-07 lint clean (including `--strict`); demo 08 is
deliberately broken to show the CI gate and SARIF output.

| Demo | Scenario | Notable ATT&CK |
| --- | --- | --- |
| `01-bec-wire-fraud` | Business email compromise / payment redirection | `T1566.002`, `T1657`, `T1114.002` |
| `02-okta-mfa-fatigue` | MFA fatigue / push-bombing account takeover | `T1621`, `T1078.004`, `T1556.006` |
| `03-aws-s3-exfil` | Leaked AWS key -> S3 data exfiltration | `T1552.001`, `T1530`, `T1537` |
| `04-malicious-oauth-grant` | Illicit consent grant (malicious OAuth app) | `T1528`, `T1098.003` |
| `05-linux-cryptominer` | Cryptojacking on an exposed Linux server | `T1496`, `T1190`, `T1053.003` |
| `06-ci-supply-chain` | Poisoned dependency in CI/CD | `T1195.002`, `T1552.001`, `T1567` |
| `07-data-exfil-insider` | Departing-insider data exfiltration (authorized) | `T1530`, `T1052.001`, `T1567.002` |
| `08-broken-playbook-cigate` | A flawed draft that fails the lint gate | (intentionally invalid) |

```bash
# Render any demo to a runbook
playbookforge render demos/02-okta-mfa-fatigue/playbook.json --format md

# The broken demo fails the gate (exit 1) and can emit SARIF
playbookforge lint demos/08-broken-playbook-cigate/playbook.json --sarif -o lint.sarif
```

## Features

- Markdown renderer with an ATT&CK coverage summary table and technique badges
- Canonical JSON renderer (round-trips cleanly)
- Linter with technique-ID regex validation, required-field checks, and phase-coverage warnings; non-zero exit on errors for CI
- SARIF 2.1.0 lint export for GitHub code scanning and security dashboards
- `new` scaffolder for starter playbooks
- `coverage` extractor for referenced tactics and techniques
- Built-in list of the 14 enterprise ATT&CK tactics for labeling and validation
- Standard library only for the core; optional YAML input via an extra

## Scope

Defensive and analytical use only.

## License

License: COCL 1.0
