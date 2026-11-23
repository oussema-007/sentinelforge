"""SentinelForge agent service: FastAPI on 0.0.0.0:8080."""
import json
import logging
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

import config as C
import db
from agent_core import SYSTEM_PROMPT, run_agent

log = logging.getLogger("sentinelforge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

CORRELATION_WINDOW_S = 120  # alert bursts from the same IP fold into the first case (saves LLM quota)

app = FastAPI(title="SentinelForge AI SOC Agent")
work_q: "queue.Queue[tuple[int, dict]]" = queue.Queue()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def render_report(case_id, alert, ctx):
    r = ctx.get("report") or {}
    rule = alert.get("rule", {})
    lines = [f"# Incident report - case #{case_id}", "",
             f"**Verdict:** {r.get('verdict', 'n/a')}  |  **Confidence:** {r.get('confidence', 'n/a')}  |  "
             f"**Severity:** {r.get('severity', 'n/a')}", "",
             f"**Source:** `{ctx.get('srcip')}`  ->  **Target:** {(alert.get('agent') or {}).get('name')} "
             f"`{(alert.get('agent') or {}).get('ip')}`  |  **Wazuh rule:** {rule.get('id')} (level {rule.get('level')})",
             "", "## Summary", r.get("summary", "_no summary_"), "",
             "## MITRE ATT&CK", *[f"- {m}" for m in r.get("mitre", [])], "",
             "## IOCs", *[f"- `{i}`" for i in r.get("iocs", [])], "",
             "## Actions taken (verified by code)", *([f"- {a}" for a in ctx.get("actions")] or ["- none (monitor only)"]), ""]
    if ctx.get("injection_indicators"):
        lines += ["## Prompt-injection indicators (code pre-filter)",
                  "Attacker-controlled alert fields contained instruction-like text; it was passed to the model as "
                  "delimited untrusted data and the guardrails stayed in force:",
                  *[f"- `{i}`" for i in ctx["injection_indicators"]], ""]
    if ctx.get("guardrail_log"):
        lines += ["## Guardrail decisions", *[f"- block {g['ip']} @ conf {g['confidence']}: **{'ALLOWED' if g['allowed'] else 'DENIED'}** - {g['why']}"
                                             for g in ctx["guardrail_log"]], ""]
    if r.get("actions_taken"):
        lines += ["## Actions as reported by the agent", *[f"- {a}" for a in r["actions_taken"]], ""]
    lines += ["## Recommendation", r.get("recommendation", "_n/a_"), ""]
    if r.get("analysis_markdown"):
        lines += ["## Analysis", r["analysis_markdown"], ""]
    if ctx.get("error"):
        lines += ["## Error", f"`{ctx['error']}`", ""]
    return "\n".join(lines)


def notify(case):
    if not C.NOTIFY_WEBHOOK:
        return
    try:
        blocked = bool(case.get("blocked"))
        icon = "\U0001F6A8" if blocked else "\U0001F50E"
        conf = f"{case['confidence']:.2f}" if isinstance(case.get("confidence"), float) else str(case.get("confidence"))
        embed = {
            "title": f"{icon} Case #{case['id']}: {case.get('verdict')} - {'BLOCKED' if blocked else 'monitor only'}",
            "url": f"http://10.10.50.100:8080/#case-{case['id']}",
            "color": 0xE53935 if blocked else (0xFFB300 if case.get("verdict") in ("malicious", "suspicious") else 0x43A047),
            "fields": [
                {"name": "Source IP", "value": f"`{case.get('srcip')}`", "inline": True},
                {"name": "Wazuh rule", "value": str(case.get("rule_id")), "inline": True},
                {"name": "Confidence / severity", "value": f"{conf} / {case.get('severity')}", "inline": True},
                {"name": "Actions (verified by code)", "value": ("\n".join(f"- {a}" for a in case["actions"]) or "none")[:1000]},
            ],
            "footer": {"text": "SentinelForge AI SOC agent - dashboard http://10.10.50.100:8080/"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r = requests.post(C.NOTIFY_WEBHOOK, json={"username": "SentinelForge", "embeds": [embed]},
                          headers={"User-Agent": "DiscordBot (sentinelforge-lab, 1.0)"}, timeout=10)
        log.info("notify case %s -> %s", case["id"], r.status_code)
    except Exception as e:
        log.warning("notify failed: %s", e)


def process(case_id, alert):
    log.info("case %s: agent start (src %s)", case_id, (alert.get("data") or {}).get("srcip"))
    ctx = run_agent(alert, case_id)
    r = ctx.get("report") or {}
    try:
        conf = float(r.get("confidence")) if r.get("confidence") is not None else None
    except (TypeError, ValueError):
        conf = None
    report_md = render_report(case_id, alert, ctx)
    trace = {"system_prompt": SYSTEM_PROMPT, "messages": ctx.get("messages"), "steps": ctx.get("trace"),
             "guardrail_log": ctx.get("guardrail_log", []),
             "injection_indicators": ctx.get("injection_indicators", []), "error": ctx.get("error")}
    status = "done" if ctx.get("report") else "error"
    db.update(case_id, verdict=r.get("verdict", "error" if status == "error" else "n/a"), confidence=conf,
              severity=r.get("severity"), mitre=json.dumps(r.get("mitre", [])), actions=json.dumps(ctx.get("actions", [])),
              report_md=report_md, trace_json=json.dumps(trace, default=str), status=status)
    log.info("case %s: %s verdict=%s conf=%s actions=%s", case_id, status, r.get("verdict"), conf, ctx.get("actions"))
    notify({"id": case_id, "verdict": r.get("verdict"), "confidence": conf, "severity": r.get("severity"),
            "srcip": ctx.get("srcip"), "rule_id": (alert.get("rule") or {}).get("id"),
            "actions": ctx.get("actions", []), "blocked": ctx.get("blocked")})


def worker():
    while True:
        case_id, alert = work_q.get()
        try:
            process(case_id, alert)
        except Exception as e:
            log.exception("case %s crashed", case_id)
            db.update(case_id, status="error", verdict="error", report_md=f"# Case {case_id}\n\nAgent crashed: `{e}`")
        finally:
            work_q.task_done()


@app.on_event("startup")
def startup():
    db.init()
    threading.Thread(target=worker, daemon=True).start()


@app.post("/alert")
async def post_alert(request: Request):
    try:
        alert = await request.json()
    except Exception:
        raise HTTPException(400, "body must be a Wazuh alert JSON object")
    if not isinstance(alert, dict) or "rule" not in alert:
        raise HTTPException(400, "not a Wazuh alert (missing 'rule')")
    alert_id = str(alert.get("id") or "")
    if alert_id and (dup := db.find_by_alert_id(alert_id)):
        return {"status": "duplicate", "case_id": dup}  # integratord fires twice per alert (AeroSec gotcha 39)
    data, rule, agent = alert.get("data") or {}, alert.get("rule") or {}, alert.get("agent") or {}
    srcip = data.get("srcip")
    base = dict(ts=now_iso(), srcip=srcip, dstip=data.get("dstip") or agent.get("ip"), rule_id=str(rule.get("id")),
                level=int(rule.get("level") or 0), raw_alert_json=json.dumps(alert), alert_id=alert_id)
    if srcip and (parent := db.recent_for_ip(srcip, CORRELATION_WINDOW_S)):
        cid = db.insert(**base, verdict="correlated", status="correlated", confidence=parent.get("confidence"),
                        severity=parent.get("severity"), mitre=parent.get("mitre"), actions=json.dumps([]),
                        report_md=f"# Correlated alert\n\nSame source `{srcip}` as case #{parent['id']} "
                                  f"(within {CORRELATION_WINDOW_S}s). Folded into that investigation; no new LLM run.",
                        trace_json=json.dumps({"correlated_to": parent["id"]}))
        return {"status": "correlated", "case_id": cid, "parent_case": parent["id"]}
    cid = db.insert(**base, verdict="processing", status="processing")
    work_q.put((cid, alert))
    return JSONResponse({"status": "queued", "case_id": cid}, status_code=202)


@app.get("/cases")
def cases(limit: int = 200):
    return db.list_cases(limit)


@app.get("/case/{case_id}")
def case(case_id: int):
    c = db.get(case_id)
    if not c:
        raise HTTPException(404, "no such case")
    for k in ("mitre", "actions", "trace_json", "raw_alert_json"):
        try:
            c[k] = json.loads(c[k]) if c[k] else None
        except (json.JSONDecodeError, TypeError):
            pass
    return c


@app.get("/health")
def health():
    return {"ok": True, "queue": work_q.qsize(), "model": C.GROQ_MODEL, "threshold": C.CONF_THRESHOLD}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text()
