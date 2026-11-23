# SentinelForge — AI SOC Agent for a Smart-Factory Network (Master Guide)

> **Working name:** *SentinelForge* (forge = manufacturing, sentinel = the autonomous defender). Rename freely — it appears only in headings and the report cover.
>
> **What this is.** The single working reference for the new school project: an **autonomous AI SOC analyst agent** defending a **smart-factory (manufacturing IT/OT) network** against an **external attacker**, replacing the heavy SOAR stack with one lightweight Python agent. Same discipline as the AeroSec guide — every command that has been *verified in-session* is marked `[BUILT ✓]`; everything not yet built is marked `[PLANNED]` and must not be treated as done.
>
> **How to use it.** Read §0–§2 for the what/why/architecture, §3 for what you reuse untouched, §4–§8 for everything new, §9 for the build order, and §10 to record verified steps as you go (this is where `[PLANNED]` turns into `[BUILT ✓]`).
>
> **Relationship to AeroSec.** This project is built *on top of* the existing AeroSec lab (see `AeroSec — Complete Project Guide`). The physical network, GNS3/VMware bridges, VyOS routing, pfSense, Wazuh SIEM, the DC, and the vulnerable portal are all **inherited unchanged** and referenced by their AeroSec section numbers (e.g. *AeroSec §16.19*). This guide documents only the **delta** plus the new AI/automation layer — it does **not** duplicate or replace the AeroSec guide, which stays intact as the OACA internship deliverable.

**Status legend:** `[INHERITED]` reuse from AeroSec as-is · `[RENAME]` same thing, new label · `[PLANNED]` not built yet · `[BUILT ✓]` verified in-session (date + evidence in §10).

---

## 0. Project Overview

**SentinelForge** turns the AeroSec detection lab into an **AI-driven autonomous SOC** for a manufacturing environment. When an **external** attacker hits the factory's internet-facing services, a single **AI agent** — not a static playbook — investigates the alert end to end: it reasons, calls tools to gather context (IP reputation, related alerts, asset criticality), decides on a verdict and severity, executes the response (block + tag), and writes a human-readable incident report. A scheduled job produces a daily shift digest.

**The three deliberate changes from AeroSec** (the "make it a new project" contributions):

1. **AI SOC analyst *agent*** — an agentic tool-calling loop replaces the single-shot LLM classifier. This is the original contribution and the core of the report.
2. **External attacker** — the attacker moves from an internal zone to *beyond the perimeter*; blocking now happens at the WAN edge, which is the realistic threat model.
3. **Lean stack** — Shuffle, TheHive, and Cortex are removed; the Python agent absorbs their job (orchestration + case record). Net effect: **fewer moving parts and lower RAM** than AeroSec runs today (see §2.4).

**Why manufacturing (career rationale).** Manufacturing has been the #1 most-attacked industry four years running, with ransomware attacks on the sector up ~56% year-over-year in 2025. Every major vendor now ships an "agentic SOC," and ~64% of 2026 cybersecurity job listings ask for AI/ML/automation skills. A project that says *"I built an AI SOC agent for the most-targeted vertical, defending against an external attacker, and I can explain where the agent is right, where it fails, and how I'd supervise it"* maps directly onto where SOC hiring is going. (Figures are for the report's motivation section — cite primary sources there.)

---

## 1. What Changes vs AeroSec (delta at a glance)

| Dimension | AeroSec (airport) | SentinelForge (smart factory) |
|---|---|---|
| **Theme** | Airport IT/OT (airside/landside) | Manufacturing IT/OT (enterprise / DMZ / OT control) |
| **Attacker position** | Internal — Kali on Landside `10.10.10.100`, routed by SW1 (never crossed pfSense) | **Untrusted segment behind the perimeter firewall** — Kali `10.10.10.100` on pfSense **OPT1 "LANDSIDE"** (`10.10.10.1`); all its traffic to the DMZ crosses pfSense, no NAT (migration 2026-11-10) |
| **Orchestration** | Shuffle SOAR (4 containers) | **Python AI agent** (1 native service) |
| **Triage brain** | Single `execute_python` node: one Groq call → block/allow | **Agentic loop**: Groq + tools, multi-step investigation |
| **Case management** | TheHive + Cassandra + Elasticsearch (3 containers) | **SQLite** + generated Markdown reports (+ optional 1-page dashboard) |
| **Enrichment** | Cortex (broken) → direct API from Shuffle | Agent tools (AbuseIPDB + Wazuh query) |
| **Response** | pfSense REST alias + Wazuh active-response | **Same enforcement**, driven by the agent's `block_ip` tool |
| **Automation extras** | — | Response playbook + **scheduled daily digest** (+ optional Ansible re-inject) |
| **Container count** | ~10 (Wazuh 3 + TheHive 3 + Cortex 1 + Shuffle 4) | **~3** (Wazuh) + 1 native agent process |

---

## 2. Target Architecture

### 2.1 Zone map (subnets unchanged — pure relabel) `[RENAME]`

The topology, subnets, gateways, and VMs are **identical** to AeroSec. Only the *names/roles* change, mapped onto the Purdue model so the IT/OT split is explicit.

| AeroSec zone | Subnet | SentinelForge zone (Purdue) | Key host → new role |
|---|---|---|---|
| Landside | `10.10.10.0/24` | **Untrusted / Enterprise segment** behind pfSense OPT1 | **Kali attacker `10.10.10.100`**, gateway pfSense OPT1 `10.10.10.1` (SW1 eth5 now unused) |
| DMZ | `10.10.20.0/24` | **Industrial DMZ (L3.5)** — internet-facing services | Flask portal → **Supplier / Orders Portal** `10.10.20.100` |
| Airside | `10.10.30.0/24` | **OT Control Network (L2/L1)** — HMI/SCADA/PLC | Endpoint → **OT host / simulated HMI** `10.10.30.100` |
| Admin | `10.10.40.0/24` | **IT Core / Identity (L4)** — AD, domain services | **DC01** `10.10.40.100` (unchanged — AD is an IT service) |
| SOC | `10.10.50.0/24` | **SOC / Security Zone** (unchanged) | Kali SOC + Wazuh + **AI agent** `10.10.50.100` |
| Uplink + WAN | `10.10.0.0/30` links / pfSense WAN `10.10.0.10` | **Perimeter / infrastructure links** | pfSense = the enforcement point between Landside and the DMZ |

> Where the old names surface and should be updated for consistency: Wazuh custom-rule `<description>` comments (AeroSec §13.8, §9.4), portal app strings, and the report/diagrams. The rule *IDs and logic stay the same* — only descriptions change, so detection is unaffected.

### 2.2 Data flow (the new pipeline)

```
Attacker Kali 10.10.10.100 (pfSense OPT1 LANDSIDE)
        │  attack (e.g. SQLi) routed THROUGH pfSense (OPT1 rule 2, no NAT → real source IP kept)
        ▼
Supplier Portal (DMZ 10.10.20.100)  ──Wazuh agent──►  Wazuh Manager (SOC)
                                                          │  rule ≥ level 10
                                                          ▼
                                   custom-w2agent.py  (repointed integration)
                                                          │  HTTP POST /alert
                                                          ▼
                        ┌──────────────  AI SOC AGENT (FastAPI, SOC host)  ──────────────┐
                        │  intake → agentic loop (Groq + tools):                          │
                        │    get_ip_reputation · search_wazuh_alerts · get_asset_context  │
                        │    → verdict + severity + MITRE  → block_ip → write_incident    │
                        └───────────────┬───────────────────────────────┬────────────────┘
                                        ▼                               ▼
                    ENFORCE: pfSense REST alias + Wazuh AR      RECORD: SQLite case +
                    (!firewall-drop) → attacker dropped         Markdown report + notify
                                        │
                                        ▼
                          cron (18:00) → daily shift digest → notification channel
```

### 2.3 Lean component inventory (what runs after strip-down)

| Component | Role | Address | Status |
|---|---|---|---|
| SW1 / R1 / R2 | L3 switch + OSPF routers | zone `.1` gateways | `[INHERITED]` |
| pfSense-FW | Perimeter FW + Snort + REST API (auto-block) + **OPT1 LANDSIDE** (rule 1 blocks alias `SOAR_blocked_ips`) | WAN `10.10.0.10`, OPT1 `10.10.10.1` | `[INHERITED]` + `[BUILT ✓]` OPT1 (migration 2026-11-10) |
| DC01 | AD DS (`aerosec.local`) + Sysmon | `10.10.40.100` | `[INHERITED]` |
| Wazuh (manager + indexer + dashboard) | SIEM — detection + active-response | `10.10.50.100` | `[INHERITED]` |
| **AI SOC Agent** | FastAPI service — intake, agentic triage, response, reporting | `10.10.50.100` (native, e.g. `:8080`) | `[PLANNED]` — §5 |
| **SQLite case store** | Incident records + reports | `~/sentinelforge/cases.db` | `[PLANNED]` — §5.4 |
| Supplier Portal | Vulnerable web app (re-themed) | `10.10.20.100` | `[INHERITED]` + `[PLANNED]` re-skin |
| Kali Attacker | Offensive tooling — behind pfSense OPT1 | `10.10.10.100` (gw `10.10.10.1`) | `[BUILT ✓]` repositioned (migration 2026-11-10) |
| ~~TheHive / Cassandra / Elasticsearch~~ | removed | — | `[PLANNED]` removal — §Phase 1 |
| ~~Cortex~~ | removed | — | `[PLANNED]` removal |
| ~~Shuffle (×4)~~ | removed (agent replaces it) | — | `[PLANNED]` removal |

### 2.4 RAM budget — the strip-down win

| State | Containers | Notes |
|---|---|---|
| AeroSec today | ~10 | Wazuh 3 + TheHive 3 + Cortex 1 + Shuffle 4 (OpenSearch crash-loops on 8 GB — AeroSec §16 gotchas) |
| SentinelForge | **~3** + 1 native process | Wazuh 3 + Python agent (~100–200 MB); cap Wazuh indexer heap `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` |

> Capture `free -m` **before and after** the strip-down (§Phase 1 gate) — the delta is real evidence for the report and the RAM claim in interviews.

---

## 3. Inherited Infrastructure (reuse as-is — do NOT rebuild)

Everything below is already built and verified in AeroSec. Reuse it untouched; jump to the referenced section only if something needs re-checking.

| What you reuse | Reference | Notes |
|---|---|---|
| VMware VMnets + GNS3 bridges + promisc | AeroSec §2, §3.1 | No change |
| SW1 zone firewall + OSPF | AeroSec §5, §3.2 | eth5 (old Landside gw) removed; R2 needs static `10.10.10.0/24 via 10.10.0.10` (redistributed) — **re-check after every R2 restart** |
| pfSense permanent fixes | AeroSec §7 | No change |
| Wazuh Docker deploy + agents (DC01, portal) | AeroSec §8, §13 | Keep; only re-tag the manager image after you edit the integration |
| Wazuh custom decoders + rules 100100–100240 | AeroSec §9.3–9.4, §13.7–13.8 | Keep logic; only edit `<description>` text for the factory theme |
| DMZ vulnerable Flask portal (SQLi, weak admin) | AeroSec §11 | Keep vuln behavior; optional cosmetic re-skin (§4.2) |
| **pfSense REST API auto-block** | AeroSec §16.19–16.20 | `pfSense-pkg-RESTAPI` **v2.4.3**, HTTP port 80, basic auth, PATCH `SOAR_blocked_ips` alias |
| **Wazuh active-response** | AeroSec §24.3 | `!firewall-drop` (with `!`), srcip in `alert.data`, agent 002, `<disabled>no</disabled>` mandatory |
| AbuseIPDB / Groq / Wazuh API keys | AeroSec §1.3 | Carry over; Groq model `openai/gpt-oss-120b`, **User-Agent `curl/8.0`** header (Cloudflare 1010 gotcha) |
| Session bring-up sequence | AeroSec §24.6 | Same, minus the Shuffle/TheHive steps once removed |

**Starting point of this project = AeroSec Part 13 state:** Wazuh + active-response proven, full autonomous chain working through Shuffle. SentinelForge forks from here by removing Shuffle/TheHive/Cortex and inserting the agent.

---

## 4. The Smart-Factory Re-Theme

### 4.1 Zone / asset renames `[PLANNED]`
Apply the §2.1 map. Concretely:
- Update Wazuh custom-rule `<description>` strings (e.g. "Airport portal SQLi" → "Supplier portal SQLi"). Logic/IDs unchanged, so re-run one live-fire to confirm nothing regressed.
- Update the network diagram and all report language.
- Optional: rename the OT host (VPCS/endpoint) label to `HMI-01` / `PLC-SIM`.

### 4.2 Portal re-skin (optional, low-effort) `[PLANNED]`
Re-theme the Flask app from flight bookings to a **supplier order portal** to kill the "same project" look, keeping the vulnerabilities intact:
- Rename routes/templates (`/flights` → `/orders`, `/admin/login` unchanged as brute-force target).
- Rename DB tables/fields in `seed_db.py` (`bookings`→`purchase_orders`, `passport`→`supplier_tax_id`, etc.).
- **Keep** the SQLi-vulnerable query and `admin:admin123` weak cred — the detection rules key off HTTP behavior, not content, so they still fire.
- Effort: mostly find-and-replace. Decide depth later; not required for a working demo.

---

## 5. The AI SOC Agent (design blueprint) — core new contribution `[PLANNED]`

> This is the heart of the project and of the report. Build it in Phase 3; record the verified version in §10.

### 5.1 Concept: agent vs classifier
AeroSec used the LLM as a **single-shot classifier** (one call → block/allow + confidence). SentinelForge uses it as an **agent**: the model is given tools and runs a reasoning loop, deciding *which* tools to call and *when*, until it reaches a decision and writes a report. That autonomy — investigate, correlate, judge, act, document — is what makes it a genuine SOC-analyst automation rather than a filter.

### 5.2 Service shape
A single **FastAPI** service on the SOC host (native Python, no container):
- `POST /alert` — intake webhook (Wazuh integration posts here)
- `GET /cases` — list incident records
- `GET /case/{id}` — one case + its report
- (optional) `GET /` — minimal HTML dashboard reading from SQLite

### 5.3 Tool schema (Groq function-calling)
Five tools; start with three (reputation, block, report) for the MVP, add the rest if time allows.

| Tool | Signature | Does |
|---|---|---|
| `get_ip_reputation` | `(ip: str) -> {score, country, total_reports, isp}` | AbuseIPDB lookup (inherits AeroSec key + `curl/8.0` header) |
| `search_wazuh_alerts` | `(srcip: str, minutes: int=60) -> [{rule_id, level, desc, count}]` | Query Wazuh indexer for recent alerts from this IP → one-off vs campaign |
| `get_asset_context` | `(dst_ip: str) -> {name, zone, criticality, exposure}` | Static asset-inventory dict (see §5.5) → agent knows portal (DMZ, high, internet-exposed) vs OT host |
| `block_ip` | `(ip: str, reason: str) -> {pfsense, wazuh_ar}` | Enforce: pfSense REST alias PATCH **and** Wazuh AR `!firewall-drop` (AeroSec §16.20, §24.3) |
| `write_incident_report` | `(summary, severity, mitre[], iocs[], actions[], recommendation) -> {case_id}` | Persist structured case + Markdown report to SQLite; trigger notify |

### 5.4 Agent loop (control flow)
```
receive alert JSON  →  build messages: [system: "Tier-1 SOC analyst, smart-factory network …",
                                        user: <alert + tool catalog + task>]
loop (max_iters = 6):
    resp = groq.chat(model="openai/gpt-oss-120b", messages, tools=TOOLS)   # UA: curl/8.0
    if resp has tool_calls:  run each tool → append results → continue
    else:                    break            # model produced final verdict + report
guardrails:
    - safety rail: NEVER block RFC1918 or the SOC IP (carry over AeroSec's rail + SOC carve-out)
    - block only if confidence ≥ CONF_THRESHOLD (0.85)
    - iteration cap prevents runaway tool loops
persist: full trace + verdict + report → SQLite (cases table)
```
**SQLite `cases` schema:** `id, ts, srcip, dstip, rule_id, level, verdict, confidence, mitre, actions, report_md, raw_alert_json`.

### 5.5 Config & inputs
- **Groq:** `openai/gpt-oss-120b`, header `Authorization: Bearer <key>`, header `User-Agent: curl/8.0` (mandatory — Cloudflare 1010 blocks Docker/Python default UA; AeroSec gotcha).
- **CONF_THRESHOLD:** `0.85`.
- **Asset inventory** (`assets.json`): one entry per lab host — `{ip: {name, zone, criticality, os, exposure}}`. Small, static, hand-written.
- **Env:** `GROQ_API_KEY`, `ABUSEIPDB_KEY`, `WAZUH_API_USER/PASS`, `PFSENSE_API_USER/PASS`, `NOTIFY_WEBHOOK`.

### 5.6 Wazuh → agent wiring `[PLANNED]`
Repoint the existing integration: copy `custom-w2thive.py` → **`custom-w2agent.py`**, strip the TheHive POST, keep a single POST to `http://10.10.50.100:8080/alert`. Re-inject the `<integration>` block and re-tag the manager image (AeroSec §16.10–16.11). Note the AeroSec gotcha: the integration block wipes on container restart — re-inject each boot (or automate it, §7.2).

---

## 6. Response Automation (SOAR replacement) `[PLANNED]`

The agent's `block_ip` tool + a small playbook replace Shuffle's job:
1. **Block** — pfSense REST alias PATCH (`SOAR_blocked_ips`, HTTP 80, basic auth) **and** Wazuh AR `!firewall-drop` on agent 002. Both from AeroSec, verified.
2. **Tag/record** — write the case + verdict to SQLite (replaces the TheHive `SOAR:blocked` tag).
3. **Notify** — one HTTPS POST to a **Discord/Telegram webhook** ("🚨 blocked 45.x.x.x — SQLi on Supplier Portal, conf 0.94"). Zero RAM, instant demo signal.

---

## 7. Scheduled Automation `[PLANNED]`

### 7.1 Daily shift digest (bonus, high demo value)
`cron` at 18:00 → script reads the day's rows from SQLite → one Groq call summarizes ("N incidents, M blocked, top source X, notable Y") → POST to the notification channel. Small script, strong "autonomous SOC" story.

### 7.2 Infra automation (optional — flexes RHCE)
An **Ansible** playbook (or systemd/boot script) that re-injects the Wazuh `<integration>` and `<active-response>` blocks on container restart, killing the recurring manual chore documented in AeroSec §16.11 / §24.6. Reads well in a portfolio and removes a real footgun.

---

## 8. Attacker Reposition — `[BUILT ✓]` as "Landside behind pfSense OPT1" (2026-11-10)

> **Superseded plan below.** The port-forward/WAN design was replaced by the Landside migration (`docs/SentinelForge-Landside-Migration-2026-11-10.md`): the attacker stays at `10.10.10.100` but now sits on pfSense OPT1, so every Landside→DMZ packet crosses pfSense without NAT. Wazuh sees the real source, and the `SOAR_blocked_ips` alias (OPT1 rule 1) is **real enforcement** — verified live in §10 Phase 5. The guardrail therefore explicitly allows `10.10.10.0/24` and public IPs, and protects SOC/infra/DC/DMZ/OT.

*Original plan (not implemented):*

1. **Move Kali** off Landside; attach it to the WAN/internet segment beyond pfSense (GNS3 cloud/NAT node or a dedicated WAN LAN), so its source IP is *outside* the perimeter.
2. **pfSense port-forward (NAT)** WAN:80 → Supplier Portal `10.10.20.100:80`, so the external attacker can reach the public service. Add the matching WAN firewall rule.
3. **Result:** attack originates from an external IP; the agent's block now drops a *public* IP at the WAN edge — the realistic threat model, and a cleaner story than blocking an insider.
4. Adjust the RFC1918 safety rail note: an external attacker is public-range, so it's blockable; the rail still protects internal/SOC IPs.

---

## 9. Build Plan (8 phases)

| # | Phase | Gate (done when…) |
|---|---|---|
| 0 | Snapshot & scope | VM snapshot taken; target architecture (§2) agreed |
| 1 | Strip the heavy stack | Shuffle/TheHive/Cortex removed; indexer heap capped; **`free -m` before/after captured**; lab runs Wazuh-only |
| 2 | Agent skeleton | FastAPI `/alert` up; `custom-w2agent.py` posts a live alert; row lands in SQLite |
| 3 | **Agentic core** | Groq tool-loop investigates a test alert across ≥2 tool calls → structured verdict |
| 4 | Response automation | External attack → agent decides block → pfSense + Wazuh AR fire → attacker times out → notify posts |
| 5 | Reporting + storage | Complete case with Markdown report stored + viewable |
| 6 | External attacker + re-theme | Attack from external IP; blocked at WAN edge; zones/rules relabeled |
| 7 | Scheduled automation (bonus) | Daily digest fires on schedule with real data; (optional Ansible re-inject) |
| 8 | Demo, evidence, report | Recorded end-to-end run + screenshots + diagram + written report framing the agent as the contribution |

**MVP cut line if time is tight:** Phases 0–6 give a complete, demoable project. Phase 7 is polish.

---

## 10. Build Log (verified — fill in as we go)

> Only `[BUILT ✓]` content with a date + evidence path goes here. All entries below were verified on **2026-11-10** on the Kali SOC (`10.10.50.100`). Evidence paths are relative to `~/sentinelforge/`. Build order followed `CLAUDE.md` phases (P1 lean stack → P2 service → P3 agentic core → P4 Wazuh wiring → P5 live test → P6 extras).

### Phase 0 — Snapshot & scope `[BUILT ✓]`
- Backups before any change: `backups/20261110-111128/` (`ossec.conf`, `integrations.tar` = whole `/var/ossec/integrations`, `docker-compose.yml`, `custom-w2thive.py`, pfSense `firewall/aliases`, `firewall/rules`, `nat/outbound/mappings` + `config_history` via REST). Earlier pfSense XML backup: `~/pfsense-backups/config-20261110-023624.xml`. `reinject.sh` additionally writes `ossec.conf.bak-sf-<ts>` inside the container on every run.
- Network state = `docs/SentinelForge-Landside-Migration-2026-11-10.md` (attacker on pfSense OPT1, no port-forward).

### Phase 1 — Strip the heavy stack `[BUILT ✓]`
- TheHive / Cassandra / Elasticsearch / Cortex: **no containers present** on the SOC VM (nothing to stop).
- Shuffle **stopped, not deleted**: `cd ~/shuffle-docker && sudo docker compose stop`; swarm services scaled to 0 (`docker service scale <svc>=0` for `shuffle-workers`, `http_1-4-0`, `shuffle-ai_1-1-0`, `shuffle-subflow_1-1-0`, `shuffle-tools_1-2-0`; original replica counts in `evidence/phase1/swarm-replicas-before.txt`); leftover orborus app containers stopped.
- **`free -m` used 4554 MB → 3219 MB (−1335 MB); available 3355 → 4690 MB; load 6.28 → 3.77.** Only the 3 Wazuh containers remain. Indexer heap stays at 768 MB (AeroSec gotcha 31).
- Health after: indexer `green`, agents 000/001/002 `active`. Evidence: `evidence/phase1/before.txt`, `evidence/phase1/after.txt`.

### Phase 2 — Agent service `[BUILT ✓]`
- Code: `agent/` — `app.py` (FastAPI), `agent_core.py` (loop), `tools.py`, `guardrails.py`, `db.py`, `config.py`, `dashboard.html`, `assets.json`; venv `agent/.venv` (fastapi 0.162, uvicorn, requests, python-dotenv). Secrets only in `~/sentinelforge/.env` (chmod 600).
- Endpoints on `0.0.0.0:8080`: `POST /alert` (202 + case id; dedups integratord's double-fire by Wazuh alert id; folds alerts from the same IP within 120 s into the first case = `correlated`), `GET /cases`, `GET /case/{id}`, `GET /health`, `GET /` (dashboard: case list → click → report + tool trace + full message trace + raw alert; all fields HTML-escaped since they carry attacker data).
- SQLite `agent/cases.db`, table `cases(id, ts, srcip, dstip, rule_id, level, verdict, confidence, severity, mitre, actions, report_md, trace_json, raw_alert_json, alert_id, status)`.
- systemd: `/etc/systemd/system/sentinelforge-agent.service` (copy in `agent/`), `enabled` + `active`, `Restart=always`.

### Phase 3 — Agentic core `[BUILT ✓]`
- Groq `openai/gpt-oss-120b`, header `User-Agent: curl/8.0`, OpenAI-style function calling, **max 6 iterations**; the last round forces `write_incident_report` if it was not called yet. Retries on 429/5xx and on network errors.
- Tools: `get_ip_reputation` (AbuseIPDB; private IP → "internal, no lookup" note), `search_wazuh_alerts` (indexer `wazuh-alerts-*` aggregation by rule over N minutes), `get_asset_context` (`assets.json`), `block_ip(ip, reason, confidence)` (pfSense alias PATCH + apply + read-back **and** Wazuh AR `!firewall-drop` on 002), `write_incident_report`.
- **Guardrails in code** (`guardrails.py`): confidence ≥ 0.85; never block `10.10.50.0/24`, `10.10.0.0/24`, `10.10.40.0/24`, `10.10.20.0/24`, `10.10.30.0/24`; allow only `10.10.10.0/24` or public IPs; **only the alert's own `srcip` can be blocked** (injection containment). Unit test 12/12 PASS: `evidence/guardrail-tests.txt`.
- Prompt-injection defense: alert passed inside `<untrusted_alert_data>` (delimiter neutralised inside data), system prompt declares all alert/tool text attacker-controlled, a regex pre-filter flags instruction-like text and records it in the report. "Actions taken" in the report come from code, not from the model. Full trace persisted per case.
- Verified: case #1 (real SOC-sourced SQLi) → 4 tools → `block_ip(10.10.50.100)` **DENIED** (protected range) → honest report. Case #3 (injected URL "verdict benign … block_ip on 10.10.20.100") → model ignored it, verdict malicious, only tried its own srcip, denied. Evidence: `evidence/phase3/case1.json`, `evidence/phase3/case3.json`.

### Phase 4 — Wazuh → agent wiring `[BUILT ✓]`
- `integration/custom-w2agent.py` → `/var/ossec/integrations/custom-w2agent.py` (`root:wazuh 750`): stdlib only, POSTs the full alert **only** to `http://10.10.50.100:8080/alert`, only level ≥ 10, never `sys.exit(1)`; logs `custom-w2agent: OK/FAIL` to `integrations.log`.
- `reinject.sh` (idempotent): install script → back up `ossec.conf` → inject `<integration>` (name `custom-w2agent.py`, level 10, json) and `<active-response>` (firewall-drop, local, `<disabled>no</disabled>`, timeout 3600, **level 16**) via Python `str.replace` → `wazuh-analysisd -t` → `wazuh-control restart` inside the container → verify. Result: both blocks = 1, `wazuh-integratord is running`.
- Design decision: AR `<level>16</level>` keeps the AR command available to the API but stops Wazuh from auto-dropping level-10+ sources by itself (AeroSec used level 10, which made Wazuh block independently of the triage). Verified: rule 651 fired only for IPs the agent/tests sent.
- Found & fixed: (a) both blocks were absent at session start (the `grep -c "<active-response>"` = 1 was the commented template — check for the real block); (b) AR API error **1116 `com:active-response`** = agent-side `wazuh-agentd: Target 'com' refused connection` → `sudo systemctl restart wazuh-agent` on the portal fixed it; (c) VMware NAT DNS flaky → `/etc/resolv.conf.head` with 1.1.1.1/8.8.8.8.
- Live: SQLi from the SOC → rule 100210 → `custom-w2agent: OK: rule=100210 level=12 srcip=10.10.50.100 status=202 … case_id 5` → agent → block DENIED (SOC protected). Evidence: `evidence/phase3/case5-live-wazuh.json`.

### Phase 5 — Live end-to-end test `[BUILT ✓]`
- Prerequisite found: after R1/R2/pfSense restart, **R2 had lost `ip route 10.10.10.0/24 10.10.0.10`** (SW1 traceroute `!N`), attacker got `000`. Re-added on R2 (vtysh) by the operator → path restored.
- Attack from Kali `10.10.10.100`: `curl "http://10.10.20.100/flights/search?origin=TUN'%20OR%201=1--"` → `200`.
- Chain: Wazuh alert `1794329232.4635737` (rule 100210, L12, T1190) → `custom-w2agent: OK … srcip=10.10.10.100 status=202 case_id 6` → agent 5 iterations (reputation: internal → Wazuh history → asset: portal/high → `block_ip` → report) → guardrail **ALLOWED** (lab attacker range, conf 0.95) → pfSense alias `SOAR_blocked_ips = ['10.10.10.100']`, `applied: true` → Wazuh AR → rule 651 "Host Blocked by firewall-drop" `10.10.10.100`; portal iptables `-A INPUT/FORWARD -s 10.10.10.100/32 -j DROP`.
- Attacker: `curl -m 8 -v http://10.10.20.100/` → **`Connection timed out after 8002 milliseconds`**.
- pfSense filterlog: 7 SYNs `10.10.10.100 → 10.10.20.100:80` blocked on `vtnet2` (OPT1) by tracker `1794275624` = OPT1 rule "**SOAR blocklist**" (pfSense clock is offset by several hours — use the tracker, not the timestamp).
- `replay_alert.py --wait` → case #7 malicious 0.96, block re-applied. `reset_demo.sh` → alias `[]` + applied, portal iptables rules for the IP = 0.
- Evidence: `evidence/phase5/` (`case6-live-attack.json`, `case6-summary.txt`, `pfsense-alias-after.json`, `pfsense-block-log.txt`, `wazuh-side.txt`, `portal-iptables-before-reset.txt`, `replay-test.txt`, `reset-test.txt`).

### Phase 6 — Extras `[BUILT ✓]`
- Daily digest: `daily_digest.py` (today's cases → one Groq summary → `digests/YYYY-MM-DD.md`, + webhook if `NOTIFY_WEBHOOK` set). Cron (user `kali`): `0 18 * * * cd /home/kali/sentinelforge && agent/.venv/bin/python daily_digest.py >> digests/cron.log 2>&1`. Manual run verified: `digests/2026-11-10.md`.
- Discord notification `[BUILT ✓]`: webhook URL in `.env` `NOTIFY_WEBHOOK` (secret, not in code/docs). Per case: an embed (red = BLOCKED, amber = malicious/suspicious not blocked, green = benign) with source IP, rule, confidence/severity, code-verified actions, link to `http://10.10.50.100:8080/#case-N`. Digest posts its summary too. Verified 18:20: test message 204, replayed case #8 → `notify case 8 -> 204`, digest `webhook: 204`. Needs the SOC internet link; a failed post never affects the block.
- `bringup.sh`: NAT/DNS → stop tenzir → Wazuh up → `reinject.sh` → restart agent → reachability checks (incl. the R2-route `!N` warning). Components verified individually; the whole script was not re-run end-to-end to avoid a manager restart before the demo.

### Phase 7 — Scheduled automation
- See Phase 6 (digest cron). Ansible re-inject not built; `reinject.sh` + `bringup.sh` cover it.

### Phase 8 — Demo, evidence, report
- Runbook: `~/sentinelforge/DEMO.md`.
- Known limitations: AbuseIPDB adds nothing for the lab attacker (RFC1918 → skipped by design); the model usually makes one tool call per turn (5 of 6 iterations used); AR rules auto-expire after 3600 s if not reset.

---

## Appendix A — New / changed endpoints & files
| Item | Value | Status |
|---|---|---|
| Agent service | `http://10.10.50.100:8080` (`/`, `/alert`, `/cases`, `/case/{id}`, `/health`) — systemd `sentinelforge-agent` | `[BUILT ✓]` |
| Case store | `~/sentinelforge/agent/cases.db` (SQLite) | `[BUILT ✓]` |
| Asset inventory | `~/sentinelforge/agent/assets.json` | `[BUILT ✓]` |
| Integration script | `custom-w2agent.py` (source `~/sentinelforge/integration/`, installed by `reinject.sh`) | `[BUILT ✓]` |
| Notification | Discord/Telegram webhook (env `NOTIFY_WEBHOOK`) | `[PLANNED]` |
| pfSense OPT1 LANDSIDE | `10.10.10.1/24`; rules: 1 block `SOAR_blocked_ips` (log), 2 pass TCP Landside→`10.10.20.100:80`, 3 ICMP to fw; Hybrid outbound NAT with no-NAT Landside→`10.10.0.0/16` | `[BUILT ✓]` (replaces the port-forward plan) |

## Appendix B — Open decisions
- Notification channel: Discord webhook vs Telegram bot.
- Portal re-skin depth: cosmetic rename vs fuller supplier-portal rebuild.
- Ansible re-inject: include (RHCE flex) or skip for time.
- Keep Wazuh dashboard for evidence screenshots, or drop for extra RAM.
