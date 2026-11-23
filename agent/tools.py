"""The five agent tools + the Groq function-calling schema."""
import ipaddress
import json
import time

import requests
import urllib3

import config as C
from guardrails import check_block

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ASSETS = json.loads(C.ASSETS_PATH.read_text())


# ---------------------------------------------------------------- enrichment
def get_ip_reputation(ip: str, **_):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"invalid ip {ip!r}"}
    if not addr.is_global:
        return {"ip": ip, "internal": True,
                "note": "Private/internal (RFC1918) address - no public reputation exists, lookup skipped. "
                        "Judge it on behaviour and asset context instead."}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": C.ABUSEIPDB_KEY, "Accept": "application/json", "User-Agent": "curl/8.0"},
                         params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=10)
        d = r.json().get("data", {})
        return {"ip": ip, "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"), "country": d.get("countryCode"),
                "isp": d.get("isp"), "usage_type": d.get("usageType"), "is_tor": d.get("isTor"),
                "last_reported_at": d.get("lastReportedAt")}
    except Exception as e:
        return {"ip": ip, "error": f"AbuseIPDB lookup failed: {e}"}


def search_wazuh_alerts(srcip: str, minutes: int = 60, **_):
    minutes = max(1, min(int(minutes or 60), 7 * 24 * 60))
    q = {"size": 0,
         "query": {"bool": {"filter": [{"term": {"data.srcip": srcip}},
                                       {"range": {"timestamp": {"gte": f"now-{minutes}m"}}}]}},
         "aggs": {"by_rule": {"terms": {"field": "rule.id", "size": 20},
                              "aggs": {"level": {"max": {"field": "rule.level"}},
                                       "first": {"min": {"field": "timestamp"}},
                                       "last": {"max": {"field": "timestamp"}},
                                       "sample": {"top_hits": {"size": 1, "_source": ["rule.description", "rule.mitre.id"]}}}},
                  "agents": {"terms": {"field": "agent.name", "size": 10}}}}
    try:
        r = requests.post(f"{C.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search", json=q, verify=False, timeout=15,
                          auth=(C.WAZUH_INDEXER_USER, C.WAZUH_INDEXER_PASS))
        d = r.json()
        rules = []
        for b in d["aggregations"]["by_rule"]["buckets"]:
            src = b["sample"]["hits"]["hits"][0]["_source"]["rule"]
            rules.append({"rule_id": b["key"], "count": b["doc_count"], "max_level": int(b["level"]["value"] or 0),
                          "mitre": (src.get("mitre") or {}).get("id", []),
                          # description embeds the attacker-supplied URL -> truncated, still untrusted
                          "description_untrusted": src.get("description", "")[:160],
                          "first_seen": b["first"]["value_as_string"], "last_seen": b["last"]["value_as_string"]})
        return {"srcip": srcip, "window_minutes": minutes, "total_alerts": d["hits"]["total"]["value"],
                "agents": [a["key"] for a in d["aggregations"]["agents"]["buckets"]], "by_rule": rules}
    except Exception as e:
        return {"srcip": srcip, "error": f"Wazuh indexer query failed: {e}"}


def get_asset_context(ip: str, **_):
    if ip in ASSETS:
        return {"ip": ip, **ASSETS[ip]}
    try:
        a = ipaddress.ip_address(ip)
        return {"ip": ip, "known": False,
                "note": "Not in the asset inventory" + ("; public/external address" if a.is_global else "; internal address")}
    except ValueError:
        return {"error": f"invalid ip {ip!r}"}


# ---------------------------------------------------------------- enforcement
def _pf(method, path, **kw):
    return requests.request(method, f"{C.PFSENSE_URL}/api/v2/{path}", auth=(C.PFSENSE_USER, C.PFSENSE_PASS),
                            timeout=15, **kw)


def pfsense_alias_get():
    for a in _pf("GET", "firewall/aliases").json().get("data", []):
        if a.get("name") == C.PFSENSE_ALIAS:
            return a
    raise RuntimeError(f"alias {C.PFSENSE_ALIAS} not found")


def pfsense_alias_set(addresses, details):
    a = pfsense_alias_get()
    r = _pf("PATCH", "firewall/alias", json={"id": a["id"], "address": addresses, "detail": details})
    r.raise_for_status()
    ap = _pf("POST", "firewall/apply", json={"async": False})
    ap.raise_for_status()
    return ap.json().get("data", {})


def pfsense_block(ip, label):
    a = pfsense_alias_get()
    addrs, dets = list(a.get("address") or []), list(a.get("detail") or [])
    if ip in addrs:
        applied = pfsense_alias_set(addrs, dets)  # re-apply anyway, idempotent
        return {"ok": True, "already_present": True, "applied": applied}
    addrs.append(ip)
    dets.append(label[:200])
    applied = pfsense_alias_set(addrs, dets)
    ok = ip in (pfsense_alias_get().get("address") or [])
    return {"ok": ok, "alias": C.PFSENSE_ALIAS, "applied": applied}


def wazuh_token():
    r = requests.post(f"{C.WAZUH_API_URL}/security/user/authenticate?raw=true",
                      auth=(C.WAZUH_API_USER, C.WAZUH_API_PASS), verify=False, timeout=10)
    r.raise_for_status()
    return r.text.strip()


def wazuh_ar_drop(ip):
    tok = wazuh_token()
    r = requests.put(f"{C.WAZUH_API_URL}/active-response?agents_list={C.AR_AGENT_ID}",
                     headers={"Authorization": f"Bearer {tok}"},
                     json={"command": "!firewall-drop", "alert": {"data": {"srcip": ip}}}, verify=False, timeout=15)
    d = r.json()
    ok = r.status_code == 200 and d.get("data", {}).get("total_affected_items", 0) >= 1
    return {"ok": ok, "status": r.status_code, "agent": C.AR_AGENT_ID,
            "message": d.get("message"), "failed": d.get("data", {}).get("failed_items")}


def block_ip(ip: str, reason: str = "", confidence=None, *, ctx, **_):
    allowed, why = check_block(ip, confidence, ctx.get("srcip"))
    ctx.setdefault("guardrail_log", []).append({"ip": ip, "confidence": confidence, "allowed": allowed, "why": why})
    if not allowed:
        return {"blocked": False, "guardrail": "DENIED", "why": why}
    res = {"blocked": False, "guardrail": "ALLOWED", "why": why}
    label = f"SentinelForge {time.strftime('%Y-%m-%d %H:%M')} {reason}"[:200]
    try:
        res["pfsense"] = pfsense_block(ip, label)
    except Exception as e:
        res["pfsense"] = {"ok": False, "error": str(e)}
    try:
        res["wazuh_ar"] = wazuh_ar_drop(ip)
    except Exception as e:
        res["wazuh_ar"] = {"ok": False, "error": str(e)}
    res["blocked"] = bool(res["pfsense"].get("ok") or res["wazuh_ar"].get("ok"))
    actions = []
    if res["pfsense"].get("ok"):
        actions.append(f"pfSense alias {C.PFSENSE_ALIAS} += {ip} (applied)")
    if res["wazuh_ar"].get("ok"):
        actions.append(f"Wazuh AR !firewall-drop {ip} on agent {C.AR_AGENT_ID}")
    if not actions:
        actions.append(f"block of {ip} attempted but FAILED")
    ctx.setdefault("actions", []).extend(actions)
    ctx["blocked"] = res["blocked"]
    return res


def write_incident_report(*, ctx, **report):
    ctx["report"] = report
    return {"saved": True, "case_id": ctx.get("case_id")}


TOOL_FUNCS = {
    "get_ip_reputation": get_ip_reputation,
    "search_wazuh_alerts": search_wazuh_alerts,
    "get_asset_context": get_asset_context,
    "block_ip": block_ip,
    "write_incident_report": write_incident_report,
}
NEEDS_CTX = {"block_ip", "write_incident_report"}


def _fn(name, desc, props, required):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required}}}


TOOLS = [
    _fn("get_ip_reputation", "AbuseIPDB reputation for an IP. Internal/private IPs return a note instead of a lookup.",
        {"ip": {"type": "string"}}, ["ip"]),
    _fn("search_wazuh_alerts", "Recent Wazuh alerts from a source IP (grouped by rule) to tell a one-off from a campaign.",
        {"srcip": {"type": "string"}, "minutes": {"type": "integer", "description": "look-back window, default 60"}},
        ["srcip"]),
    _fn("get_asset_context", "Asset inventory entry for a lab IP: name, Purdue zone, criticality, exposure.",
        {"ip": {"type": "string"}}, ["ip"]),
    _fn("block_ip", "Contain an attacker: add the IP to the pfSense SOAR_blocked_ips alias (applied) and send Wazuh "
        "active-response !firewall-drop to the DMZ portal. Guardrails in code may deny the request.",
        {"ip": {"type": "string"}, "reason": {"type": "string", "description": "short justification"},
         "confidence": {"type": "number", "description": "your confidence 0.0-1.0 that this IP is malicious"}},
        ["ip", "reason", "confidence"]),
    _fn("write_incident_report", "Persist the final structured incident report for this case. Call exactly once, last.",
        {"verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "false_positive"]},
         "confidence": {"type": "number"},
         "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
         "summary": {"type": "string"},
         "mitre": {"type": "array", "items": {"type": "string"}, "description": "ATT&CK IDs with names, e.g. 'T1190 Exploit Public-Facing Application'"},
         "iocs": {"type": "array", "items": {"type": "string"}},
         "actions_taken": {"type": "array", "items": {"type": "string"}},
         "recommendation": {"type": "string"},
         "analysis_markdown": {"type": "string", "description": "investigation narrative in Markdown"}},
        ["verdict", "confidence", "severity", "summary", "mitre", "iocs", "actions_taken", "recommendation"]),
]
