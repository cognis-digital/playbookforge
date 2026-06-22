# Demo 07 - Departing-insider data exfiltration

## Where this comes from
HR notifies security that a senior salesperson resigned to join a competitor.
Within the same week, DLP flags that the account downloaded the entire customer
pipeline and copied files to a personal cloud-sync folder and a USB drive. This
is the classic high-risk-departure exfil case.

## Authorized-use note
This is an HR/Legal-coordinated, authorized internal investigation. The playbook
is written to be proportionate and privacy-respecting - it is not surveillance
tooling and must only be run under documented authorization.

## What to expect
A six-phase insider-IR playbook with real ATT&CK techniques: data from cloud
storage (`T1530`), data from information repositories (`T1213`), exfiltration to
removable media (`T1052.001`), exfiltration to cloud storage (`T1567.002`), and
valid accounts (`T1078`). Lints clean.

## Run it
```bash
playbookforge render demos/07-data-exfil-insider/playbook.json --format md
playbookforge lint demos/07-data-exfil-insider/playbook.json
playbookforge coverage demos/07-data-exfil-insider/playbook.json
```

## How to act
Chain of custody (`con-2`) comes before eradication - capture the evidence
before the user is notified or access is cut, or the case becomes unprovable.
Coordinate every containment action with HR and Legal.
