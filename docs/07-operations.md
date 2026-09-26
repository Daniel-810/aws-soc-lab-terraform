# Deployment and Operations

| Item | Details |
|---|---|
| Date | 2026-09-26 |
| Related | `ADR-007`, `ADR-014`, `ADR-024`, `ADR-032`, `ADR-035`, `ADR-036` |

A longer version of the README's quick start: first-time deployment order, switching the inspection approach, setting up the measurement and verification tools, and the places people usually get stuck.

## 1. Prerequisites

- Terraform 1.10 or later. State locking uses S3's native lock file (`use_lockfile`), so no DynamoDB table is needed.
- AWS CLI v2. The verification tool uses it for remote commands and log queries.
- Python 3. Used by the measurement and verification tools; developed and run on 3.12.
- Temporary credentials rather than long-lived access keys. This repository was built with a session from `aws login`, assuming a role that requires MFA (`ADR-014`).

## 2. One-time setup

```bash
# State bucket. Created with local state, which stays local
cd bootstrap
terraform init
terraform apply

# Audit environment. Created once and left running
cd ../envs/audit
cp backend.hcl.example backend.hcl              # set the real bucket name
cp terraform.tfvars.example terraform.tfvars    # budget alert recipients
terraform init -backend-config=backend.hcl
terraform apply
```

`backend.hcl` and `terraform.tfvars` are excluded from git. The bucket name contains the account ID and the alert addresses are personal data, so neither goes into a public repository.

The audit environment manages a monthly budget that was first created in the console. In a new account the code creates the budget. If the account already has one, import it before applying so the names do not collide (`ADR-035`).

```bash
terraform import aws_budgets_budget.monthly <account-id>:<budget-name>
```

The log bucket uses Object Lock in compliance mode for one day. While an object is locked, not even an administrator can delete it. To remove the audit environment, stop CloudTrail first, wait for the last log's lock to expire, then empty every version in the bucket (`ADR-032`).

## 3. Bringing the lab up and down

```bash
cd envs/lab
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl

terraform apply                                   # create the inspection layer, routes unchanged
terraform apply -var=route_through_firewall=true  # switch routes after confirming management access

terraform destroy -var=route_through_firewall=true
```

At apply time the lab looks up the deploying machine's public IP from `checkip.amazonaws.com` and allows it as a `/32` on the WAF's inbound rules, so only that machine can reach the WAF (`ADR-019`). If you move to another network, your address changes and you need to apply again.

On Windows PowerShell 5.1, arguments in the form `-name=value` must be quoted. Unquoted, they get split and Terraform fails with "Too many command line arguments".

```powershell
terraform init "-backend-config=backend.hcl"
terraform apply "-var=route_through_firewall=true"
```

## 4. Choosing the inspection approach

| Variable | Controls | Values | Default |
|---|---|---|---|
| `firewall_mode` | Which approach to build | `managed` (approach A) / `oss` (approach B) | `managed` |
| `route_through_firewall` | Whether traffic is routed through the inspection layer | `true` / `false` | `false` |

```bash
# Approach B
terraform apply -var=firewall_mode=oss
terraform apply -var=firewall_mode=oss -var=route_through_firewall=true
```

Build the inspection layer first, confirm management access, then switch routes. If you apply both at once and something breaks, you cannot tell whether the policy or the routing is at fault, and you may lose management access (`ADR-024`). The app's management traffic also goes through NAT and the inspection layer, so if the inspection layer blocks outbound 443, there is no way left into Session Manager (`ADR-015`).

Terraform does not remember variables passed on a previous run. If approach B is deployed and you leave out `-var=firewall_mode=oss`, Terraform reads the default, approach A, and plans to delete Suricata and create a managed firewall. An unexpected deletion in the plan means a missing variable. When switching approaches, turn routing off first. Variables are passed on the command line rather than in a file so that the command itself shows what is running.

For a few tens of seconds after routing is switched on, the internet gateway's edge route has not taken effect yet, and plaintext requests reach the WAF without passing the inspection layer. Measuring in that window shows zero network-layer detections. The verification tool retries this check for up to 90 seconds (`ADR-036`).

## 5. Measurement and verification tools

Both tools share one virtual environment. The only external package is PyYAML; HTTP requests use the standard library.

```bash
cd tools/probe
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt      # Windows: .venv\Scripts\python.exe
```

Run them with the lab up and AWS credentials configured. The verification tool reads instance IDs and addresses from the `envs/lab` outputs.

```bash
cd tools/verify
../probe/.venv/bin/python verify.py                    # 12 checks, about 100 seconds
../probe/.venv/bin/python verify.py --skip-detection   # faster, without the detection run
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`. The list of checks and pass criteria is in [`tools/verify/README.md`](../tools/verify/README.md); the measurement tool's options are in [`tools/probe/README.md`](../tools/probe/README.md).

Results are written as JSON to `tools/probe/results/` and `tools/verify/results/` and are excluded from git, because they contain the operator's public IP and full request contents.

## 6. Common problems

| Symptom | Cause | Fix |
|---|---|---|
| Error mentions `169.254.169.254` | No credentials found, so the SDK fell through to EC2 instance metadata | Set `AWS_PROFILE` again in the shell |
| Instance launch fails with `Invalid IAM Instance Profile name` | IAM propagation delay | Do not change the code; run `apply` again |
| Plan wants to delete the inspection layer | `firewall_mode` was left out | Pass the variable for the approach that is running |
| WAF times out | Your public IP changed | Run `apply` again to update the inbound rule |
| Plaintext attacks not caught at the network layer | Edge route not yet in effect after switching | Wait about a minute before measuring |
| Commands to the app stall after restarting Suricata (approach B) | Suricata drops connections established before the restart | Wait for the agent to reconnect (about 6 minutes) |

## 7. Cost

The lab is not left running; it is created for a test and destroyed afterwards. The monthly budget is ₩50,000, and the budget alarm was set up before any resources were created. This account pays with credits, so the alarm measures cost before credits are applied. Measured after credits, spending would show as zero even as usage grew, and the alarm would never fire (`ADR-035`).

The managed firewall endpoint is most of the cost: running everything with approach A costs about $0.50 an hour, and about $0.12 with approach B. The audit environment and the state bucket stay up but cost only cents a month. Figures use Seoul region on-demand prices.
