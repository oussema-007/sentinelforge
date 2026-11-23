#!/usr/bin/env python3
"""Daily SOC shift digest (cron 18:00): today's cases from SQLite -> one Groq summary -> digests/YYYY-MM-DD.md
(+ NOTIFY_WEBHOOK if set). Usage: daily_digest.py [YYYY-MM-DD]"""
import json
import sqlite3
import sys
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "agent"))
import requests  # noqa: E402
import config as C  # noqa: E402
from agent_core import groq_chat  # noqa: E402

day = date.fromisoformat(sys.argv[1]) if len(sys.argv) > 1 else date.today()
# cases.ts is UTC; take the local calendar day
local_tz = datetime.now().astimezone().tzinfo
start = datetime.combine(day, datetime.min.time(), local_tz).astimezone(timezone.utc)
end = start + timedelta(days=1)
db = sqlite3.connect(C.DB_PATH)
db.row_factory = sqlite3.Row
rows = [dict(r) for r in db.execute(
    "SELECT id, ts, srcip, rule_id, level, verdict, confidence, severity, mitre, actions FROM cases "
    "WHERE ts >= ? AND ts < ? ORDER BY id", (start.strftime("%Y-%m-%dT%H:%M:%S"), end.strftime("%Y-%m-%dT%H:%M:%S")))]
for r in rows:
    r["actions"] = json.loads(r["actions"] or "[]")
    r["mitre"] = json.loads(r["mitre"] or "[]")

investigated = [r for r in rows if r["verdict"] not in ("correlated",)]
blocked = [r for r in rows if r["actions"]]
stats = {"date": str(day), "alerts_received": len(rows), "investigations": len(investigated),
         "correlated_alerts": len(rows) - len(investigated), "blocked": len(blocked),
         "verdicts": Counter(r["verdict"] for r in investigated), "top_sources": Counter(r["srcip"] for r in rows).most_common(5),
         "rules": Counter(r["rule_id"] for r in rows).most_common(5),
         "mitre": Counter(m for r in investigated for m in r["mitre"]).most_common(5)}

summary = "_LLM summary unavailable._"
if rows:
    try:
        prompt = ("Write a concise end-of-shift SOC digest (max 150 words, Markdown bullets) for a smart-factory network "
                  "from these statistics and case list. State numbers exactly; do not invent incidents.\n"
                  + json.dumps({"stats": stats, "cases": investigated[:40]}, default=str))
        resp = groq_chat([{"role": "user", "content": prompt}], tools=None)
        summary = resp["choices"][0]["message"]["content"].strip()
    except Exception as e:
        summary = f"_LLM summary failed: {e}_"
else:
    summary = "Quiet shift: no alerts reached the agent."

md = [f"# SentinelForge shift digest - {day}", "",
      f"**Alerts:** {stats['alerts_received']} | **Investigations:** {stats['investigations']} | "
      f"**Correlated:** {stats['correlated_alerts']} | **Blocked:** {stats['blocked']}", "",
      "## Summary", summary, "", "## Cases", "| # | time (UTC) | source | rule | verdict | conf | action |", "|---|---|---|---|---|---|---|"]
md += [f"| {r['id']} | {r['ts'][11:]} | {r['srcip']} | {r['rule_id']} | {r['verdict']} | {r['confidence'] or ''} | "
       f"{'BLOCKED' if r['actions'] else 'monitor'} |" for r in rows]
out = HERE / "digests" / f"{day}.md"
out.parent.mkdir(exist_ok=True)
out.write_text("\n".join(md) + "\n")
print(f"wrote {out} ({len(rows)} cases)")
if C.NOTIFY_WEBHOOK:
    txt = f"**SentinelForge digest {day}**: {stats['alerts_received']} alerts, {stats['blocked']} blocked\n{summary}"
    r = requests.post(C.NOTIFY_WEBHOOK, json={"username": "SentinelForge", "content": txt[:1900]},
                      headers={"User-Agent": "DiscordBot (sentinelforge-lab, 1.0)"}, timeout=10)
    print("webhook:", r.status_code)
