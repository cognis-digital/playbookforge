# Demo 02 - MFA fatigue / push-bombing account takeover

## Where this comes from
An engineer messages the help desk: "My phone won't stop buzzing with login
approvals." The SOC sees ~40 denied MFA challenges to that account from an
unfamiliar ASN over ten minutes, then one approval and a successful sign-in.
This is the classic push-bombing pattern that has driven several real-world SaaS
intrusions.

## What to expect
A clean six-phase identity-incident playbook referencing real ATT&CK techniques
for MFA request generation (`T1621`), cloud-account abuse (`T1078.004`), MFA
modification (`T1556.006`), and additional cloud-credential persistence
(`T1098.005`). Renders to a runbook and lints clean.

## Run it
```bash
playbookforge render demos/02-okta-mfa-fatigue/playbook.json --format md
playbookforge lint demos/02-okta-mfa-fatigue/playbook.json
playbookforge coverage demos/02-okta-mfa-fatigue/playbook.json --json
```

## How to act
Session/token revocation (`con-1`) is the action that actually evicts the actor
- a password reset alone does not. Always check whether the actor enrolled a new
MFA factor or recovery contact (`det-2` / `con-2`); leaving one in place lets
them walk straight back in.
