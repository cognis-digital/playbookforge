# Demo 03 - AWS access-key compromise and S3 exfiltration

## Where this comes from
A secret-scanning alert fires: a long-lived AWS access key was pushed to a
public GitHub repo. Within minutes CloudTrail shows `ListBuckets` and a spike of
`GetObject` calls from an IP in a region the company never operates in. This is
the textbook leaked-key-to-S3-exfil chain.

## What to expect
A six-phase cloud-IR playbook with real ATT&CK techniques: cloud-account abuse
(`T1078.004`), unsecured credentials (`T1552.001`), cloud service discovery
(`T1580`), data from cloud storage (`T1530`), transfer to cloud account
(`T1537`), and IAM persistence (`T1098.001`). Lints clean.

## Run it
```bash
playbookforge render demos/03-aws-s3-exfil/playbook.json --format md -o /tmp/aws-runbook.md
playbookforge lint demos/03-aws-s3-exfil/playbook.json --strict
playbookforge coverage demos/03-aws-s3-exfil/playbook.json
```

## How to act
Set the key to **Inactive**, not deleted (`con-1`), so you keep attribution in
CloudTrail. The exfil-path containment (`con-2`) and the IAM-persistence sweep
(`era-1`) matter as much as killing the key - actors routinely mint a second
backdoor user before you notice the first.
