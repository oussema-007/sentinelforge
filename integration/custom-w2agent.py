#!/usr/bin/env python3
"""
SentinelForge: Wazuh -> AI SOC agent integration.
Called by wazuh-integratord: custom-w2agent.py <alert_file> <api_key> <hook_url>
Derived from AeroSec custom-w2thive.py, but with ONE destination only (the agent's /alert endpoint) and no
TheHive dependency. Stdlib only. Never exits non-zero on a POST failure (logs it instead).
"""
import json
import sys
import urllib.request

DEFAULT_URL = "http://10.10.50.100:8080/alert"
MIN_LEVEL = 10
LOG = "/var/ossec/logs/integrations.log"


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"custom-w2agent: {msg}\n")
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        log("ERROR: no alert file argument")
        return
    hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3].startswith("http") else DEFAULT_URL
    try:
        with open(sys.argv[1]) as f:
            alert = json.load(f)
    except Exception as e:
        log(f"ERROR: cannot read alert file: {e}")
        return
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0) or 0)
    if level < MIN_LEVEL:
        return
    body = json.dumps(alert).encode()
    req = urllib.request.Request(hook_url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "wazuh-w2agent/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            log(f"OK: rule={rule.get('id')} level={level} srcip={alert.get('data', {}).get('srcip')} "
                f"status={resp.status} resp={resp.read(200).decode(errors='replace')}")
    except Exception as e:
        log(f"FAIL: rule={rule.get('id')} url={hook_url} error={e}")


if __name__ == "__main__":
    main()
