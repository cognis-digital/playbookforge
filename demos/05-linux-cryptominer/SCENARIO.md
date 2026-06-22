# Demo 05 - Linux server cryptojacking via exposed service

## Where this comes from
A cloud cost alert flags one EC2 instance pinned at 100% CPU around the clock.
EDR labels a process as a known XMRig-family miner, and the host is beaconing to
a Monero pool. The entry point turns out to be an unpatched internet-facing
service that gave the actor remote code execution.

## What to expect
A six-phase host-IR playbook with real ATT&CK techniques: resource hijacking
(`T1496`), Unix shell execution (`T1059.004`), exploit public-facing application
(`T1190`), cron persistence (`T1053.003`), and valid accounts (`T1078`). Lints
clean.

## Run it
```bash
playbookforge render demos/05-linux-cryptominer/playbook.json --format md
playbookforge lint demos/05-linux-cryptominer/playbook.json
playbookforge coverage demos/05-linux-cryptominer/playbook.json --json
```

## How to act
Isolate but **keep the host powered on** (`con-1`) to preserve memory evidence.
Cryptojacking is rarely the actor's only goal - treat the entry vector (`det-2`)
as a foothold and assume credential theft until proven otherwise. Rebuild beats
in-place cleanup once root is suspected.
