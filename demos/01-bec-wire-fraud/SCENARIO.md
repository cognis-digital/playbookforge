# Demo 01 - Business Email Compromise (wire fraud)

## Where this comes from
An accounts-payable analyst forwards a "change our remittance bank details"
email that claims to be from a long-standing vendor. The message arrived from a
look-alike domain, and a $48,000 invoice was about to be paid to the new
account. This is the most common high-loss BEC pattern: payment redirection.

## What to expect
The playbook has all six standard IR phases and references real ATT&CK
techniques for phishing (`T1566.002`), valid-account abuse (`T1078`), email
collection (`T1114.002`), internal spearphishing (`T1534`), and financial
theft (`T1657`). It lints clean and renders a one-page Markdown runbook for the
finance and IR teams.

## Run it
```bash
# Render the analyst-facing runbook
playbookforge render demos/01-bec-wire-fraud/playbook.json --format md

# Confirm it passes the CI gate (exit 0, no errors)
playbookforge lint demos/01-bec-wire-fraud/playbook.json

# See the ATT&CK coverage at a glance
playbookforge coverage demos/01-bec-wire-fraud/playbook.json
```

## How to act
The first containment action is time-critical: a wire recall must start inside
the bank's recall window, so `con-1` is the step to execute before anything
else. Verify whether the real vendor/exec mailbox was taken over (`det-2`)
before assuming the request was merely spoofed.
