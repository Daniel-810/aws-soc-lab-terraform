"""Send tagged probes through the lab and check which layer saw them."""
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus
import argparse
import http.client
import json
import secrets
import ssl
import subprocess
import time

import yaml

PAYLOAD_DIR = Path(__file__).parent / "payloads" / "gotestwaf"
RESULT_DIR = Path(__file__).parent / "results"

# Payload files without a type hold ordinary text used to measure false
# positives. Kept as a constant so a typo fails loudly instead of quietly
# counting no benign requests.
BENIGN = "benign"

# Any name works: the WAF answers as the default server.
HOST_HEADER = "waf.soc-lab.internal"

# A browser sends these, and rules at higher paranoia levels flag requests
# that leave them out. Without them the measurement would report on the
# client rather than on the payload.
CLIENT_HEADERS = {
    "Host": HOST_HEADER,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) probe",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# CRS scores each match and acts only when the total crosses its threshold,
# which this rule records. A match on any other rule is a finding, not a
# verdict.
ANOMALY_RULE = "949110"


def load_payloads(path):
    """Read one GoTestWAF test case file and return its payloads.

    Each item is a dict: {"type": ..., "payload": ..., "source": ...}
    """
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # GoTestWAF's Go parser accepts \' inside double quotes; YAML does not.
    text = text.replace("\\'", "'")
    data = yaml.safe_load(text)

    payloads = []
    for payload in data["payload"]:
        payloads.append({"type": data.get("type", "benign"), "payload": payload, "source": path.name})
    return payloads

def load_all(directory=PAYLOAD_DIR):
    """Load every test case file under directory, skipping unreadable ones."""
    items = []
    for path in sorted(directory.glob("*/*.yml")):
        try:
            items.extend(load_payloads(path))
        except yaml.YAMLError as e:
            print(f"skipped {path.name}: {e}")

    return items

# Rules differ in which part of a request they inspect, and several payload
# files are written for the URL path rather than a parameter. Sending each
# payload to one place only would understate detection.
PLACEMENTS = ("urlparam", "urlpath", "header", "jsonbody")


def make_probe(item, index, placement="urlparam", run_id="0000"):
    """Turn one payload into a single tagged request.

    Returns None when the payload cannot be carried in that place.

    The id carries a per-run token because the audit log is never cleared:
    without it, a numbering that restarts at one would match entries left by
    an earlier run and mix two measurements together. It stays alphanumeric
    because a digit-hyphen-digit id reads as arithmetic to the SQL injection
    rules, which made the tool flag its own tracking parameter.
    """
    probe_id = f"probe{run_id}n{index:04d}"
    payload = item["payload"]
    method = "GET"
    body = None

    # The id goes in a header and in the query string: layers differ in how
    # much of a request they log, so it has to be findable in either.
    #
    # Host carries a name although the lab is reached by address: a numeric
    # Host is itself a CRS finding, and it would add to the anomaly score of
    # every request, measuring the client rather than the payload.
    headers = {"X-Probe-Id": probe_id, **CLIENT_HEADERS}

    if placement == "urlparam":
        path = f"/rest/products/search?q={quote_plus(payload)}&probe={probe_id}"
    elif placement == "urlpath":
        # Slashes stay as they are: encoding them would turn a traversal
        # attempt into one oddly named segment, which is a different request.
        path = f"/{quote(payload, safe='/')}?probe={probe_id}"
    elif placement == "jsonbody":
        # Request bodies are a main way attacks arrive, and the engine reads
        # them (SecRequestBodyAccess). Leaving them out measured only half
        # of what the ruleset inspects.
        method = "POST"
        headers["Content-Type"] = "application/json"
        body = json.dumps({"email": payload, "password": "probe"})
        path = f"/rest/user/login?probe={probe_id}"
    elif placement == "header":
        # Header values cannot hold line breaks, and the CRLF payloads are
        # built from them. Skipping is better than sending a mangled value.
        if "\n" in payload or "\r" in payload:
            return None
        headers["X-Probe-Payload"] = payload
        path = f"/rest/products/search?probe={probe_id}"
    else:
        raise ValueError(f"unknown placement: {placement}")

    return {
        "id": probe_id,
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "placement": placement,
        "type": item["type"],
        "payload": payload,
        "source": item["source"],
    }


# Requests a browser actually made while using the application, taken from
# its access log. The payload set for false positives is written to be
# confusing on purpose, so it measures how the ruleset handles hard text,
# not how it handles ordinary traffic. AC-05a is judged on this set.
REALISTIC_REQUESTS = [
    "/",
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    "/rest/languages",
    "/rest/products/search?q=",
    "/rest/products/search?q=apple+juice",
    "/rest/products/search?q=lemon",
    "/rest/products/1/reviews",
    "/rest/user/whoami",
    "/api/Challenges/?name=Score%20Board",
    "/api/Quantitys/",
    "/assets/i18n/en.json",
    "/assets/public/images/products/apple_juice.jpg",
    "/assets/public/favicon_js.ico",
    "/main.js",
    "/styles.css",
    "/vendor.js",
    "/socket.io/?EIO=4&transport=polling",
]

TRAFFIC = "traffic"


def build_traffic_probes(run_id="0000"):
    """Tag ordinary application requests so they can be scored alongside.

    Their ids carry their own letter: payload numbering counts placements it
    skips, so continuing from the number of probes built would reuse ids.
    """
    probes = []
    for index, path in enumerate(REALISTIC_REQUESTS, start=1):
        probe_id = f"probe{run_id}t{index:04d}"
        joiner = "&" if "?" in path else "?"
        probes.append({
            "id": probe_id,
            "method": "GET",
            "path": f"{path}{joiner}probe={probe_id}",
            "headers": {"X-Probe-Id": probe_id, **CLIENT_HEADERS},
            "placement": "realistic",
            "type": TRAFFIC,
            "payload": path,
            "source": "access log",
        })
    return probes


def build_probes(items, placements=PLACEMENTS, run_id="0000"):
    """Make one probe per payload and placement, numbering them in order."""
    probes = []
    index = 0
    for item in items:
        for placement in placements:
            index += 1
            probe = make_probe(item, index, placement, run_id)
            if probe is not None:
                probes.append(probe)
    return probes

def send(probe, host, scheme="https", timeout=10):
    """Send one probe and return the HTTP status code."""
    if scheme == "https":
        # The internet leg uses a self-signed certificate, so the client
        # cannot verify it. This says nothing about the WAF to app leg,
        # where verification stays on (SR-08).
        conn = http.client.HTTPSConnection(
            host, timeout=timeout, context=ssl._create_unverified_context()
        )
    else:
        conn = http.client.HTTPConnection(host, timeout=timeout)

    try:
        conn.request(
            probe["method"],
            probe["path"],
            body=probe.get("body"),
            headers=probe["headers"],
        )
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


# --- collecting what the layers saw ------------------------------------

# Run on the WAF instance, not here: the audit log holds full requests and
# Run Command truncates long output, so the summary is built where the log
# lives and only one line per probe comes back.
REMOTE_SUMMARY = r"""
import json, sys

prefix = sys.argv[1] if len(sys.argv) > 1 else ""
found = {}

for line in open("/var/log/nginx/modsec_audit.log", encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        tx = json.loads(line)["transaction"]
    except (ValueError, KeyError):
        continue

    headers = tx.get("request", {}).get("headers", {})
    probe_id = next(
        (v for k, v in headers.items() if k.lower() == "x-probe-id"), None
    )
    # The log keeps every run, and Run Command truncates long output, so
    # entries from other runs are dropped here rather than in the caller.
    if probe_id is None or not probe_id.startswith(prefix):
        continue

    rules = found.setdefault(probe_id, set())
    for m in tx.get("messages", []):
        rule = m.get("details", {}).get("ruleId")
        if rule:
            rules.add(str(rule))

# One line per probe, not per log entry: a probe is sent over both schemes.
for probe_id in sorted(found):
    print(probe_id, ",".join(sorted(found[probe_id])))
"""


def _ssm_run(instance_id, region, script, timeout=180):
    """Run a shell script on an instance through Run Command, return stdout."""
    command = subprocess.run(
        [
            "aws", "ssm", "send-command",
            "--region", region,
            "--instance-ids", instance_id,
            "--document-name", "AWS-RunShellScript",
            "--parameters", json.dumps({"commands": [script]}),
            "--query", "Command.CommandId",
            "--output", "text",
        ],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    deadline = time.monotonic() + timeout
    while True:
        result = subprocess.run(
            [
                "aws", "ssm", "get-command-invocation",
                "--region", region,
                "--command-id", command,
                "--instance-id", instance_id,
                "--query", "[Status,StandardOutputContent,StandardErrorContent]",
                "--output", "json",
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            status, stdout, stderr = json.loads(result.stdout)
            if status in ("Success", "Failed", "TimedOut", "Cancelled"):
                if status != "Success":
                    raise RuntimeError(f"Run Command {status}: {stderr or stdout}")
                return stdout
        if time.monotonic() > deadline:
            raise RuntimeError(f"Run Command did not finish within {timeout}s")
        time.sleep(3)


def collect_context(instance_id, region):
    """Return the package versions and engine mode a run was measured on.

    Versions are not pinned (ADR-021), so a result is only reproducible if
    it carries the versions it came from.
    """
    output = _ssm_run(
        instance_id,
        region,
        "cat /etc/nginx/modsec-versions.txt; "
        "grep -h '^SecRuleEngine' /etc/nginx/modsec/main.conf",
    )

    context = {"packages": {}, "engine": None}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "SecRuleEngine":
            context["engine"] = parts[1]
        elif len(parts) == 2:
            context["packages"][parts[0]] = parts[1]
    return context


def collect(instance_id, region, run_id=None):
    """Return {probe id: [rule ids]} for the probes the WAF logged.

    The log keeps earlier runs, so entries from other runs are dropped.
    """
    prefix = f"probe{run_id}" if run_id else "probe"
    output = _ssm_run(
        instance_id,
        region,
        f"sudo python3 - {prefix} <<'PROBE_EOF'\n{REMOTE_SUMMARY}\nPROBE_EOF",
    )

    detections = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        probe_id = parts[0]
        rules = parts[1].split(",") if len(parts) > 1 and parts[1] else []
        # One probe can appear twice: it is sent over both 80 and 443.
        detections.setdefault(probe_id, [])
        detections[probe_id] = sorted(set(detections[probe_id]) | set(rules))
    return detections


# --- scoring -------------------------------------------------------------

def score(results, detections, blocked_status=403, key="type"):
    """Summarise results grouped by key: payload type, or placement.

    results is a list of {"probe": ..., "scheme": ..., "status": ...}.

    Two counts, because they answer different questions:

    flagged  — any rule matched. Single rules carry a score rather than a
               verdict, so this includes requests the ruleset would let
               through.
    detected — the anomaly score crossed the threshold, which is what the
               ruleset acts on. This is the number that becomes a block
               once the engine is allowed to block.

    Merely appearing in the audit log is neither: the recommended
    configuration also logs transactions by response status, so an
    application error would otherwise count as a detection. With the engine
    running and no ruleset loaded both counts stay at zero, which is the
    point of the baseline.
    """
    summary = {}
    for entry in results:
        probe = entry["probe"]
        rules = detections.get(probe["id"], [])
        row = summary.setdefault(
            probe[key], {"sent": 0, "flagged": 0, "detected": 0, "blocked": 0}
        )
        row["sent"] += 1
        if rules:
            row["flagged"] += 1
        if ANOMALY_RULE in rules:
            row["detected"] += 1
        if entry["status"] == blocked_status:
            row["blocked"] += 1

    for row in summary.values():
        row["detection_rate"] = round(100 * row["detected"] / row["sent"], 1)
        row["block_rate"] = round(100 * row["blocked"] / row["sent"], 1)
    return summary


def print_summary(summary, title="type"):
    """Print one table, attacks first and benign text last."""
    print(f"{title:<18}{'sent':>6}{'flagged':>9}{'detected':>13}{'blocked':>13}")
    for name in sorted(summary, key=lambda n: (n in (BENIGN, TRAFFIC), n)):
        row = summary[name]
        detected = f"{row['detected']} ({row['detection_rate']}%)"
        blocked = f"{row['blocked']} ({row['block_rate']}%)"
        print(f"{name:<18}{row['sent']:>6}{row['flagged']:>9}{detected:>13}{blocked:>13}")


# --- run -----------------------------------------------------------------

def run(host, instance_id, region, schemes=("https", "http")):
    """Send every payload over each scheme, then score what the WAF logged."""
    context = collect_context(instance_id, region)
    context["run_id"] = f"{secrets.token_hex(3)}"
    versions = ", ".join(f"{k} {v}" for k, v in sorted(context["packages"].items()))
    print(f"run {context['run_id']} | engine {context['engine']} | {versions}")

    probes = build_probes(load_all(), run_id=context["run_id"])
    probes += build_traffic_probes(run_id=context["run_id"])
    print(f"sending {len(probes)} requests over {', '.join(schemes)}")

    results = []
    for scheme in schemes:
        for probe in probes:
            try:
                status = send(probe, host, scheme=scheme)
            except OSError as e:
                # A refused or timed out request is a result too: a layer
                # may drop the connection instead of answering.
                status = f"error: {e}"
            results.append({"probe": probe, "scheme": scheme, "status": status})

    # Give the audit log a moment to reach disk before reading it.
    time.sleep(5)
    detections = collect(instance_id, region, run_id=context["run_id"])
    print(f"{len(detections)} of {len(probes)} probes appear in the WAF log")

    summary = score(results, detections)
    print_summary(summary)
    print()
    print_summary(score(results, detections, key="placement"), title="placement")
    return results, detections, summary, context


def save(results, detections, summary, context, directory=RESULT_DIR):
    """Write one timestamped run to results/ (git ignored: SR-10)."""
    directory.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"run-{stamp}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "context": context,
                "summary": summary,
                "detections": detections,
                "results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"saved {path}")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="WAF public address")
    parser.add_argument("--instance-id", required=True, help="WAF instance id")
    parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()

    save(*run(args.host, args.instance_id, args.region))
