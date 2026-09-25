# probe — layer coverage measurement

Sends tagged requests through the lab and reports which layer saw each one.

Every request carries a unique id in the `X-Probe-Id` header and in the query
string. Afterwards the id is looked up in each layer's log, so a request can
be traced to the layer that detected it even when nothing is blocked. That is
what a status code alone cannot show: in detection-only mode (`ADR-018`
stage 2) the response looks identical whether or not a rule matched.

Two layers are read today: the WAF's ModSecurity audit log, and the managed
network firewall's alert log (Phase 8). Suricata on the self-managed path
follows in Phase 9, using the same ids.

Results are kept per scheme. The network firewall sits in front of TLS
termination, so it can only act on the plaintext leg; sending the same probe
over 80 and 443 is what shows each layer's reach (`T-11`).

## Running

```powershell
$env:AWS_PROFILE = "soc-lab"
.venv\Scripts\python.exe probe.py --host <waf public ip> --instance-id <waf instance id>

# with the managed firewall in the path
.venv\Scripts\python.exe probe.py --host <waf public ip> --instance-id <waf instance id> `
    --firewall-log-group /soc-lab/firewall/alert
```

Both values come from `terraform output` in `envs/lab`. The WAF only answers
the address that deployed it (`ADR-019`), so run this from that machine.

Results land in `results/` as one timestamped JSON per run. They are git
ignored: they carry the public address and full request payloads (`SR-10`).

## Payloads

`payloads/gotestwaf/` is copied unchanged from GoTestWAF v0.5.8 (MIT). Only
the payload lists are used; the tool itself is not. See `payloads/README.md`.

## Limitations

- Every payload is sent to one place, the `q` parameter of the search API.
  Several files expect the URL path or a request body instead, so detection
  is understated until placements are added.
- Run Command truncates long output, so the audit log is summarised on the
  instance and only one line per probe and scheme comes back.
- The firewall's alert log keeps no request headers, so its matches are found
  by the `probe=` id every placement also puts in the query string.
- Firewall alerts reach CloudWatch in batches. The log is read until the
  count stops growing, for at most five minutes.
- A firewall drop gives no answer, so dropped requests wait out `--timeout`.
  Requests are sent in parallel (`--workers`) to keep the run short.
