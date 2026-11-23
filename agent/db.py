import json
import sqlite3
import threading

from config import DB_PATH

_lock = threading.Lock()

SCHEMA = """CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, srcip TEXT, dstip TEXT, rule_id TEXT, level INTEGER,
  verdict TEXT, confidence REAL, severity TEXT, mitre TEXT, actions TEXT,
  report_md TEXT, trace_json TEXT, raw_alert_json TEXT,
  alert_id TEXT, status TEXT
)"""


def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, conn() as c:
        c.execute(SCHEMA)
        c.execute("CREATE INDEX IF NOT EXISTS ix_alert ON cases(alert_id)")


def insert(**kw):
    cols = ",".join(kw)
    with _lock, conn() as c:
        cur = c.execute(f"INSERT INTO cases ({cols}) VALUES ({','.join('?' * len(kw))})", list(kw.values()))
        return cur.lastrowid


def update(case_id, **kw):
    sets = ",".join(f"{k}=?" for k in kw)
    with _lock, conn() as c:
        c.execute(f"UPDATE cases SET {sets} WHERE id=?", [*kw.values(), case_id])


def get(case_id):
    with conn() as c:
        r = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return dict(r) if r else None


def find_by_alert_id(alert_id):
    with conn() as c:
        r = c.execute("SELECT id FROM cases WHERE alert_id=? ORDER BY id LIMIT 1", (alert_id,)).fetchone()
    return r["id"] if r else None


def recent_for_ip(srcip, seconds):
    with conn() as c:
        r = c.execute("SELECT * FROM cases WHERE srcip=? AND status IN ('processing','done') "
                      "AND ts >= strftime('%Y-%m-%dT%H:%M:%S', 'now', ?) AND verdict != 'correlated' "
                      "ORDER BY id DESC LIMIT 1", (srcip, f"-{int(seconds)} seconds")).fetchone()
    return dict(r) if r else None


def list_cases(limit=200):
    with conn() as c:
        rows = c.execute("SELECT id, ts, srcip, dstip, rule_id, level, verdict, confidence, severity, mitre, "
                         "actions, status FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("mitre", "actions"):
            try:
                d[k] = json.loads(d[k]) if d[k] else []
            except json.JSONDecodeError:
                pass
        out.append(d)
    return out
