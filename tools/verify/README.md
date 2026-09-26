# verify — deployed lab checks

Runs the checks that were done by hand during the build against a deployed
lab and exits non-zero if any fails (`AC-03`, `NFR-03`, `ADR-036`).

```powershell
$env:AWS_PROFILE = "soc-lab"
..\probe\.venv\Scripts\python.exe verify.py            # about 100 seconds
..\probe\.venv\Scripts\python.exe verify.py --skip-detection
```

It reads `terraform output` from `envs/lab`, works out which approach is
deployed and whether traffic is routed through it, and adjusts: the IPS
checks are skipped for approach A without routing.

| Check | Requirement |
|---|---|
| No ingress rule opens 22; all-protocol rules stay inside the VPC | SR-01, AC-07 |
| IMDSv2 required, hop limit 1, no key pair, volumes encrypted | SR-02, SR-09 |
| Session Manager reaches every instance | SR-01 |
| WAF answers over HTTPS | FR-01 |
| No software version in responses, block pages included | SR-20 |
| Attack blocked over HTTPS (WAF) and over HTTP (IPS when routed) | AC-06 |
| A spoofed X-Forwarded-For does not replace the real client address | SR-18 |
| The app container cannot reach instance metadata; the host can | SR-02 |
| Every instance takes time from the link-local service only | SR-19 |
| Suricata holds the queue with every rule in the file loaded, and forwarding is on | SR-13 |
| WAF detection over HTTPS at least 40%; real traffic flagged by no layer | AC-05a, AC-05b |
| Recent events in every log group | FR-05, SR-14 |

Results are written to `results/` (git ignored).
