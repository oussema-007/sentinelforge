#!/usr/bin/env python3
"""Demo backup: replay a saved REAL Wazuh SQLi alert (rule 100210, src 10.10.10.100) into the agent.
Usage: ./replay_alert.py [alert.json] [--url http://10.10.50.100:8080/alert] [--wait]
A fresh alert id is set each run so the agent's duplicate filter does not swallow it."""
import argparse
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("alert", nargs="?", default=str(HERE / "agent/samples/sqli_alert_10.10.10.100.json"))
ap.add_argument("--url", default="http://10.10.50.100:8080/alert")
ap.add_argument("--wait", action="store_true", help="poll until the case is finished and print the verdict")
a = ap.parse_args()

alert = json.loads(Path(a.alert).read_text())
alert["id"] = f"replay-{int(time.time())}"
alert["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
req = urllib.request.Request(a.url, data=json.dumps(alert).encode(), headers={"Content-Type": "application/json"})
resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
print("POST /alert ->", resp)
if a.wait and resp.get("case_id"):
    base = a.url.rsplit("/alert", 1)[0]
    for _ in range(60):
        c = json.loads(urllib.request.urlopen(f"{base}/case/{resp['case_id']}", timeout=10).read())
        if c["status"] != "processing":
            print(f"case #{c['id']}: {c['verdict']} conf={c['confidence']} severity={c['severity']} actions={c['actions']}")
            break
        time.sleep(3)
