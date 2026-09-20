"""Send tagged probes through the lab and check which layer saw them."""
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus
import argparse
import http.client
import json
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
PLACEMENTS = ("urlparam", "urlpath", "header")


def make_probe(item, index, placement="urlparam"):
    """Turn one payload into a single tagged request.

    Returns None when the payload cannot be carried in that place.
    """
    probe_id = f"probe-{index:04d}"
    payload = item["payload"]

    # The id goes in a header and in the query string: layers differ in how
    # much of a request they log, so it has to be findable in either.
    headers = {"X-Probe-Id": probe_id}

    if placement == "urlparam":
        path = f"/rest/products/search?q={quote_plus(payload)}&probe={probe_id}"
    elif placement == "urlpath":
        # Slashes stay as they are: encoding them would turn a traversal
        # attempt into one oddly named segment, which is a different request.
        path = f"/{quote(payload, safe='/')}?probe={probe_id}"
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
        "method": "GET",
        "path": path,
        "headers": headers,
        "placement": placement,
        "type": item["type"],
        "payload": payload,
        "source": item["source"],
    }


def build_probes(items, placements=PLACEMENTS):
    """Make one probe per payload and placement, numbering them in order."""
    probes = []
    index = 0
    for item in items:
        for placement in placements:
            index += 1
            probe = make_probe(item, index, placement)
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
        conn.request(probe["method"], probe["path"], headers=probe["headers"])
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
    if probe_id is None:
        continue

    rules = sorted({
        str(m.get("details", {}).get("ruleId", ""))
        for m in tx.get("messages", [])
        if m.get("details", {}).get("ruleId")
    })
    print(probe_id, ",".join(rules))
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


def collect(instance_id, region):
    """Return {probe id: [rule ids]} for every probe the WAF logged."""
    output = _ssm_run(
        instance_id,
        region,
        "sudo python3 - <<'PROBE_EOF'\n" + REMOTE_SUMMARY + "\nPROBE_EOF",
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

    A probe counts as detected when a rule matched it, not merely when it
    appears in the audit log: the recommended configuration also logs
    transactions by response status, so an application error would otherwise
    be counted as a detection. Blocked means the response carried the
    blocking status. With the engine running but no ruleset loaded both stay
    at zero, which is the point of the baseline.
    """
    summary = {}
    for entry in results:
        probe = entry["probe"]
        row = summary.setdefault(
            probe[key], {"sent": 0, "detected": 0, "blocked": 0}
        )
        row["sent"] += 1
        if detections.get(probe["id"]):
            row["detected"] += 1
        if entry["status"] == blocked_status:
            row["blocked"] += 1

    for row in summary.values():
        row["detection_rate"] = round(100 * row["detected"] / row["sent"], 1)
        row["block_rate"] = round(100 * row["blocked"] / row["sent"], 1)
    return summary


def print_summary(summary, title="type"):
    """Print one table, attacks first and benign text last."""
    print(f"{title:<18}{'sent':>6}{'detected':>12}{'blocked':>12}")
    for name in sorted(summary, key=lambda n: (n == BENIGN, n)):
        row = summary[name]
        detected = f"{row['detected']} ({row['detection_rate']}%)"
        blocked = f"{row['blocked']} ({row['block_rate']}%)"
        print(f"{name:<18}{row['sent']:>6}{detected:>12}{blocked:>12}")


# --- run -----------------------------------------------------------------

def run(host, instance_id, region, schemes=("https", "http")):
    """Send every payload over each scheme, then score what the WAF logged."""
    probes = build_probes(load_all())
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
    detections = collect(instance_id, region)
    print(f"{len(detections)} of {len(probes)} probes appear in the WAF log")

    summary = score(results, detections)
    print_summary(summary)
    print()
    print_summary(score(results, detections, key="placement"), title="placement")
    return results, detections, summary


def save(results, detections, summary, directory=RESULT_DIR):
    """Write one timestamped run to results/ (git ignored: SR-10)."""
    directory.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"run-{stamp}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {"results": results, "detections": detections, "summary": summary},
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
