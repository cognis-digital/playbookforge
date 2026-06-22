# Demo 06 - CI/CD supply-chain compromise (poisoned dependency)

## Where this comes from
A nightly build starts making outbound connections to an unfamiliar host during
`npm install`. A lockfile diff shows a transitive dependency jumped to a brand
new version whose post-install script reads environment variables. The build
runner had production-adjacent secrets in scope. This is the dependency-
confusion / typosquat / poisoned-package pattern behind multiple real incidents.

## What to expect
A six-phase supply-chain IR playbook with real ATT&CK techniques: compromise
software supply chain (`T1195.002`), command/scripting interpreter (`T1059`),
unsecured credentials (`T1552.001`), and exfiltration over web service
(`T1567`). Lints clean.

## Run it
```bash
playbookforge render demos/06-ci-supply-chain/playbook.json --format md
playbookforge lint demos/06-ci-supply-chain/playbook.json --strict
playbookforge coverage demos/06-ci-supply-chain/playbook.json
```

## How to act
Treat **every** secret the build could read as compromised and rotate it
(`con-2`) - confirmation of theft is not worth waiting for. Quarantine artifacts
built from poisoned runs (`con-1`) so the compromise does not flow to your own
downstream consumers.
