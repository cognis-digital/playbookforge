# Demo 08 - Broken playbook (the CI gate in action)

## Where this comes from
An analyst opens a pull request adding a new playbook. It is a rough first draft
with the kinds of mistakes the linter exists to catch. This demo shows what a
failing CI gate looks like and how to feed the findings into GitHub code
scanning via SARIF.

## What to expect
This playbook is **intentionally invalid**. `playbookforge lint` will print
multiple findings and **exit non-zero** (1), failing the gate:

- `PB001` missing title (error)
- `PB010` invalid tactic `BOGUS` (error)
- `PB031` invalid technique `NOTATECHNIQUE` (error)
- `PB021` non-standard phase name `Triage` (warning)
- `PB022` empty phase (warning)
- `PB032` detection step with no detection guidance (warning)
- `PB040` several standard IR phases missing (warning)

## Run it
```bash
# Human-readable findings; exit code is 1
playbookforge lint demos/08-broken-playbook-cigate/playbook.json
echo "exit code: $?"

# SARIF 2.1.0 for GitHub code scanning (NEW): write a results file to upload
playbookforge lint demos/08-broken-playbook-cigate/playbook.json \
  --sarif -o playbook-lint.sarif
```

## How to act
Fix each finding before merging. In CI, run the SARIF variant and upload
`playbook-lint.sarif` with `github/codeql-action/upload-sarif` so the findings
appear as annotations on the pull request. The non-zero exit alone is enough to
block a merge if you prefer a simple gate.
