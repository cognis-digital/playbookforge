# Demo 04 - Illicit consent grant (malicious OAuth app)

## Where this comes from
A user reports a slick "Sign in to view the shared document" page that asked
them to *Accept* permissions for an app called "Doc Reader Pro." The app
requested `Mail.Read`, `Files.Read.All`, and `offline_access`. After consent, the
app's service principal began pulling mail over the Graph API - no password,
no MFA prompt, because the user handed over a refresh token.

## What to expect
A six-phase consent-phishing playbook with real ATT&CK techniques: steal
application access token (`T1528`), consent-grant phishing (`T1566.002`),
additional cloud roles (`T1098.003`), email collection (`T1114.002`), and data
from cloud storage (`T1530`). Lints clean.

## Run it
```bash
playbookforge render demos/04-malicious-oauth-grant/playbook.json --format md
playbookforge lint demos/04-malicious-oauth-grant/playbook.json
playbookforge coverage demos/04-malicious-oauth-grant/playbook.json
```

## How to act
A password reset does nothing here - the app holds a refresh token. The eviction
action is revoking the grant and deleting the service principal (`con-1`).
Always check what the token already pulled (`det-2`) and whether the app planted
inbox rules before you close the case.
