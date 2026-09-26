"""Check a deployed lab against its requirements in one command (AC-03).

Every check here was first done by hand while the lab was being built. Each
one reads the deployed state, prints PASS or FAIL with what it saw, and the
script exits non-zero if anything failed, so a rebuild can be judged without
anyone repeating the checks (NFR-03).

Run from tools/verify with the probe's environment, which this reuses:

    ..\\probe\\.venv\\Scripts\\python.exe verify.py
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import http.client
import json
import secrets
import ssl
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "probe"))
import probe  # noqa: E402  (shares the request and Run Command helpers)

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "envs" / "lab"
RESULT_DIR = Path(__file__).parent / "results"

# One marker the app's own traffic never contains, so the audit log lookup
# finds only the request this script sent.
SPOOFED_ADDRESS = "198.51.100.77"  # TEST-NET-2, never routable


# --- helpers ---------------------------------------------------------------

def aws(*args, region=None):
    """Run an aws CLI call and return its parsed JSON output."""
    cmd = ["aws", *args, "--output", "json"]
    if region:
        cmd += ["--region", region]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out or "null")


def terraform_outputs():
    out = subprocess.run(
        ["terraform", f"-chdir={LAB}", "output", "-json"],
        capture_output=True, text=True, check=True,
    ).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}


def request(host, path, scheme="https", headers=None, timeout=8):
    """Return (status, headers) or (None, reason) when nothing answered."""
    if scheme == "https":
        conn = http.client.HTTPSConnection(
            host, timeout=timeout, context=ssl._create_unverified_context()
        )
    else:
        conn = http.client.HTTPConnection(host, timeout=timeout)
    try:
        conn.request("GET", path, headers={**probe.CLIENT_HEADERS, **(headers or {})})
        resp = conn.getresponse()
        resp.read()
        return resp.status, dict(resp.getheaders())
    except OSError as e:
        return None, str(e)
    finally:
        conn.close()


def remote(instance_id, region, script):
    """Run a shell script on an instance; never raises on a non-zero grep."""
    return probe._ssm_run(instance_id, region, script + "\ntrue")


# --- checks ------------------------------------------------------------------
# Each returns (passed, detail). Requirement IDs are in the check names.

def check_no_ssh(ctx):
    groups = [g["GroupId"] for g in aws(
        "ec2", "describe-security-groups",
        "--filters", f"Name=vpc-id,Values={ctx['vpc_id']}", region=ctx["region"],
    )["SecurityGroups"]]
    rules = aws(
        "ec2", "describe-security-group-rules",
        "--filters", f"Name=group-id,Values={','.join(groups)}", region=ctx["region"],
    )["SecurityGroupRules"]
    ingress = [r for r in rules if not r["IsEgress"]]
    ssh = [r for r in ingress if r["IpProtocol"] != "-1" and r["FromPort"] <= 22 <= r["ToPort"]]
    # All-protocol rules also cover 22. They are internal by design (NAT
    # forwarding into Suricata, the unused default group); reported, not
    # failed, and failed if one ever reaches beyond the VPC.
    wide = [r for r in ingress if r["IpProtocol"] == "-1"]
    external = [r for r in wide if r.get("CidrIpv4") and not r["CidrIpv4"].startswith("10.")]
    return (not ssh and not external,
            f"rules naming 22: {len(ssh)}, all-protocol rules: {len(wide)} (outside the VPC: {len(external)})")


def check_instances(ctx):
    res = aws(
        "ec2", "describe-instances",
        "--instance-ids", *ctx["instances"].values(), region=ctx["region"],
    )["Reservations"]
    problems = []
    volumes = []
    for inst in (i for r in res for i in r["Instances"]):
        name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
        m = inst["MetadataOptions"]
        if m["HttpTokens"] != "required" or m["HttpPutResponseHopLimit"] != 1:
            problems.append(f"{name}: IMDS {m['HttpTokens']}/hop {m['HttpPutResponseHopLimit']}")
        if inst.get("KeyName"):
            problems.append(f"{name}: key pair {inst['KeyName']}")
        volumes += [b["Ebs"]["VolumeId"] for b in inst["BlockDeviceMappings"]]
    for v in aws("ec2", "describe-volumes", "--volume-ids", *volumes, region=ctx["region"])["Volumes"]:
        if not v["Encrypted"]:
            problems.append(f"{v['VolumeId']}: unencrypted")
    return (not problems, "; ".join(problems) or
            f"{len(ctx['instances'])} instances: IMDSv2 required, hop 1, no key pair, {len(volumes)} volumes encrypted")


def check_session_manager(ctx):
    info = aws("ssm", "describe-instance-information", region=ctx["region"])["InstanceInformationList"]
    online = {i["InstanceId"] for i in info if i["PingStatus"] == "Online"}
    missing = [n for n, i in ctx["instances"].items() if i not in online]
    return (not missing, "all Online" if not missing else f"not Online: {', '.join(missing)}")


def check_waf_answers(ctx):
    status, headers = request(ctx["waf_ip"], "/")
    server = headers.get("Server", "") if isinstance(headers, dict) else headers
    return (status == 200, f"HTTPS {status}, Server: {server!r}")


def check_no_version(ctx):
    status, headers = request(ctx["waf_ip"], "/rest/products/search?q=1%20union%20select%201")
    server = headers.get("Server", "") if isinstance(headers, dict) else ""
    leaks = [h for h in ("X-Powered-By", "X-AspNet-Version") if isinstance(headers, dict) and h in headers]
    has_version = any(c.isdigit() for c in server)
    return (status == 403 and not has_version and not leaks,
            f"block page {status}, Server: {server!r}, extra headers: {leaks or 'none'}")


def check_attack_blocked(ctx):
    path = "/rest/products/search?q=1%20union%20select%201"
    https_status, _ = request(ctx["waf_ip"], path, "https")
    # With traffic routed through the IPS the plaintext attack is dropped
    # before it reaches the WAF, so no answer is the expected outcome there.
    # Right after routes switch, the gateway edge route can take tens of
    # seconds to apply and the attack still reaches the WAF directly; the
    # check waits that out rather than reporting a routing fault.
    expect = "dropped by the IPS" if ctx["routed"] else "403 from the WAF"
    deadline = time.monotonic() + (90 if ctx["routed"] else 0)
    tries = 0
    while True:
        tries += 1
        http_status, _ = request(ctx["waf_ip"], path, "http", timeout=5)
        http_ok = http_status is None if ctx["routed"] else http_status == 403
        if http_ok or time.monotonic() >= deadline:
            break
        time.sleep(10)
    return (https_status == 403 and http_ok,
            f"HTTPS {https_status}; HTTP {http_status or 'no answer'} after {tries} tries (expected {expect})")


def check_spoofed_forwarded_for(ctx):
    marker = f"verify{secrets.token_hex(4)}"
    request(ctx["waf_ip"], f"/rest/products/search?q=1%20union%20select%201&probe={marker}",
            headers={"X-Forwarded-For": SPOOFED_ADDRESS, "X-Real-IP": SPOOFED_ADDRESS})
    query = f"filter @message like /{marker}/ | fields transaction.client_ip as ip"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(15)
        rows = logs_insights(ctx, [ctx["waf_log_group"]], query)
        if rows:
            ip = rows[0].get("ip")
            return (ip != SPOOFED_ADDRESS, f"audit log recorded {ip}, spoofed header said {SPOOFED_ADDRESS}")
    return (False, "request not found in the WAF log group within 120s")


def check_container_metadata(ctx):
    # Hop limit 1 is what keeps the app container from instance credentials
    # (SR-02, measured by hand in Phase 6). The app image is distroless:
    # no shell, and node only at its full path.
    js = ("fetch('http://169.254.169.254/latest/api/token',{method:'PUT',"
          "headers:{'X-aws-ec2-metadata-token-ttl-seconds':'60'},signal:AbortSignal.timeout(3000)})"
          ".then(r=>console.log('REACHED',r.status)).catch(()=>console.log('BLOCKED'))")
    # The host asking the same thing is the control: it must get an answer,
    # or a blocked container would say nothing about the hop limit.
    host = ("curl -s -o /dev/null -m 3 -w 'HOST %{http_code}' -X PUT "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token; echo")
    out = remote(ctx["instances"]["app"], ctx["region"],
                 host + "\n" + f"docker exec $(docker ps -q | head -n 1) /nodejs/bin/node -e \"{js}\"")
    return ("HOST 200" in out and "BLOCKED" in out, " ".join(out.split()) or "no output")


def check_time_sync(ctx):
    bad = []
    for name, iid in ctx["instances"].items():
        out = remote(iid, ctx["region"], "chronyc -n sources | grep '^\\^\\*' ; echo; chronyc -n sources | grep -c '^\\^'")
        lines = [l for l in out.splitlines() if l.strip()]
        selected = next((l for l in lines if l.startswith("^*")), "")
        count = lines[-1] if lines else "?"
        if "169.254.169.123" not in selected or count != "1":
            bad.append(f"{name}: selected {selected.split()[1] if selected else 'none'}, sources {count}")
    return (not bad, "; ".join(bad) or "every instance on 169.254.169.123 only")


def check_logs_arriving(ctx):
    since = int((time.time() - 900) * 1000)
    empty = []
    for group in [ctx["waf_log_group"], ctx["flow_log_group"]] + ctx["ips_log_groups"]:
        n = len(aws("logs", "filter-log-events", "--log-group-name", group,
                    "--start-time", str(since), "--max-items", "5",
                    region=ctx["region"]).get("events", []))
        if n == 0:
            empty.append(group)
    return (not empty, "events in the last 15 minutes in every group" if not empty
            else f"no recent events: {', '.join(empty)}")


def check_suricata(ctx):
    iid = ctx["instances"].get("suricata")
    if not iid:
        return (True, "approach A deployed; not applicable")
    out = remote(iid, ctx["region"],
                 "awk '$1 == 0 {print \"QUEUE_BOUND\"}' /proc/net/netfilter/nfnetlink_queue; "
                 "grep -o '[0-9]* rules successfully loaded, [0-9]* rules failed' /var/log/suricata/suricata.log | tail -n 1")
    ok = "QUEUE_BOUND" in out and "15 rules successfully loaded, 0 rules failed" in out
    return (ok, " ".join(out.split()))


def check_detection(ctx):
    """AC-05a and AC-05b from a full probe run."""
    kwargs = {}
    if ctx["instances"].get("suricata"):
        kwargs["suricata_instance_id"] = ctx["instances"]["suricata"]
    elif ctx["routed"]:
        kwargs["firewall_log_group"] = "/soc-lab/firewall/alert"
    results, detections, firewall, summary, layers, context = probe.run(
        ctx["waf_ip"], ctx["instances"]["waf"], ctx["region"], **kwargs)
    ctx["probe_run"] = context["run_id"]
    # AC-05b measures the WAF's ruleset. Over plaintext the IPS may drop an
    # attack before the WAF sees it, which would count against the WAF, so
    # the rate is taken on the HTTPS leg, where every request reaches it.
    https = layers.get("https", {})
    attacks = [r for n, r in https.items() if n not in (probe.BENIGN, probe.TRAFFIC)]
    sent = sum(r["sent"] for r in attacks)
    detected = sum(r["waf"] for r in attacks)
    rate = round(100 * detected / sent, 1) if sent else 0
    # Real traffic must pass every layer on both legs.
    fp = sum(layers.get(s, {}).get(probe.TRAFFIC, {}).get("either", 0) for s in ("https", "http"))
    return (rate >= 40 and fp == 0,
            f"WAF detection over HTTPS {rate}% (AC-05b needs 40%), real traffic flagged by any layer {fp} (AC-05a needs 0)")


def logs_insights(ctx, groups, query, minutes=15):
    now = int(time.time())
    qid = aws("logs", "start-query", "--start-time", str(now - minutes * 60),
              "--end-time", str(now + 60), "--query-string", query,
              "--log-group-names", *groups, region=ctx["region"])["queryId"]
    while True:
        r = aws("logs", "get-query-results", "--query-id", qid, region=ctx["region"])
        if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            return [{f["field"]: f["value"] for f in row} for row in r["results"]]
        time.sleep(2)


CHECKS = [
    ("SR-01 AC-07  no SSH ingress", check_no_ssh),
    ("SR-02 SR-09  instance hardening", check_instances),
    ("SR-01        Session Manager reaches every instance", check_session_manager),
    ("FR-01        WAF answers", check_waf_answers),
    ("SR-20        no version in responses", check_no_version),
    ("AC-06        attack blocked on both legs", check_attack_blocked),
    ("SR-18        spoofed forwarding header ignored", check_spoofed_forwarded_for),
    ("SR-02        container cannot reach metadata", check_container_metadata),
    ("SR-19        time from the link-local service only", check_time_sync),
    ("SR-13        Suricata inline with every rule", check_suricata),
    ("AC-05a AC-05b detection measured", check_detection),
    # Last: the checks above generate the alerts this one looks for.
    ("FR-05 SR-14  logs arriving in every group", check_logs_arriving),
]


def context_from_outputs(region):
    o = terraform_outputs()
    instances = {"app": o["instance_id"], "waf": o["waf_instance_id"]}
    if o.get("suricata_instance_id"):
        instances["suricata"] = o["suricata_instance_id"]
    tables = aws("ec2", "describe-route-tables", "--filters",
                 f"Name=vpc-id,Values={o['vpc_id']}", "Name=tag:Name,Values=soc-lab-igw-rt",
                 region=region)["RouteTables"]
    return {
        "region": region,
        "vpc_id": o["vpc_id"],
        "waf_ip": o["waf_public_ip"],
        "instances": instances,
        # The edge route table exists only while traffic is routed through
        # the inspection layer (ADR-024).
        "routed": bool(tables),
        "waf_log_group": "/soc-lab/waf",
        "flow_log_group": "/soc-lab/vpc/flow",
        # Alerts exist only once traffic passes the IPS.
        "ips_log_groups": [] if not tables else (
            ["/soc-lab/suricata"] if "suricata" in instances else ["/soc-lab/firewall/alert"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--skip-detection", action="store_true",
                        help="leave out the probe run (about two minutes)")
    args = parser.parse_args()

    ctx = context_from_outputs(args.region)
    mode = "B (Suricata)" if "suricata" in ctx["instances"] else "A (managed)"
    print(f"approach {mode}, traffic {'routed through' if ctx['routed'] else 'not routed through'} the IPS\n")

    report = []
    for name, check in CHECKS:
        if args.skip_detection and check is check_detection:
            continue
        try:
            passed, detail = check(ctx)
        except Exception as e:  # a check that cannot run is a failed check
            passed, detail = False, f"error: {e}"
        print(f"{'PASS' if passed else 'FAIL'}  {name}\n      {detail}")
        report.append({"check": name, "passed": passed, "detail": detail})

    failed = [r for r in report if not r["passed"]]
    print(f"\n{len(report) - len(failed)} of {len(report)} checks passed")

    RESULT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (RESULT_DIR / f"verify-{stamp}.json").write_text(
        json.dumps({"approach": mode, "routed": ctx["routed"], "checks": report}, indent=2),
        encoding="utf-8")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
