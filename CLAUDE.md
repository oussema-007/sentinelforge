# SentinelForge — project brief for Claude Code (Kali SOC VM)

You are building **SentinelForge**: an autonomous **AI SOC analyst agent** for a smart-factory (manufacturing IT/OT) lab network. It is a school project derived from the finished AeroSec lab. **The validation (demo) is today**, so working and demoable beats complete. Build the MVP first and add extras only after it is proven end to end.

## Documents in `~/sentinelforge/docs/`. Read them before starting.
| File | What it is | Authority |
|---|---|---|
| `SentinelForge-Landside-Migration-2026-11-10.md` | **Current network state**: what was changed tonight and verified | **Highest.** Overrides the others on anything about the network |
| `SentinelForge-Master-Guide.md` | Project spec: agent design (§5), response (§6), phases (§9), build log (§10) | Design target |
| `SentinelForge-Architecture.md` | Architecture views, guardrails, prompt-injection section | Design rationale |
| `AeroSec-Complete-Project-Guide.md` | **Verified-working** commands, credentials (§1.3), pfSense REST (§16.19–16.20), Wazuh integration re-inject (§16.10–16.11), active-response (§24.3), bring-up (§24.6) | Source of truth for *how* things work |

**Network notes (the master guide is outdated here):** there is **no port-forward**, and the attacker is not on the pfSense WAN. The attacker Kali is `10.10.10.100` on **pfSense OPT1 "LANDSIDE"** (`10.10.10.1`). Its traffic to the DMZ portal `10.10.20.100:80` goes **through pfSense** with no NAT, so Wazuh sees the real source `10.10.10.100`. OPT1 rule 1 already blocks source alias `SOAR_blocked_ips`, so **patching that alias and applying it really blocks the attacker at the firewall.**

## Lab facts
- This VM: Kali SOC `10.10.50.100` (eth0, VMnet7). Internet goes through `eth1` (VMware NAT, `192.168.13.0/24`, gw `.2`), which is normally DOWN. To get internet: bring eth1 up, delete the lab default route (`ip route del default via 10.10.50.1`), and keep `10.10.0.0/16 via 10.10.50.1` so the lab stays reachable (AeroSec gotcha).
- Wazuh 4.9.2 runs in Docker here (manager image `aerosec/wazuh-manager:4.9.2-part12`). The DMZ portal is Wazuh agent **002**.
- pfSense REST API: `http://10.10.0.10/api/v2/`, basic auth, **HTTP port 80 only** (package v2.4.3). Changing an alias **must be followed by an apply/filter reload** or it has no effect.
- LLM: Groq, model `openai/gpt-oss-120b`. **Every Groq request needs the header `User-Agent: curl/8.0`**, otherwise Cloudflare returns error 1010 (403).
- Enrichment: AbuseIPDB. Keys are in AeroSec §1.3. Put all secrets in `~/sentinelforge/.env` (chmod 600) and never hard-code them.

## Known gotchas (each one was hit before, do not rediscover them)
1. The `<integration>` **and** `<active-response>` blocks in `ossec.conf` are **wiped on every manager container restart**. Re-inject them after each restart (§16.11 method). Write a `reinject.sh` script for this.
2. The `tenzir-node` container takes port 1514. Run `docker stop tenzir-node` before Wazuh can start.
3. Cortex left running freezes the VM (load average ~28). Keep it stopped. On the TheHive stack, `docker compose up -d` restarts it.
4. `custom-w2thive.py` calls `sys.exit(1)` if the TheHive POST fails. That is why the new integration must not depend on TheHive.
5. The Wazuh AR API only accepts the command `!firewall-drop` (with the `!`), with `srcip` in `alert.data`, on agent 002. The variants `firewall-drop0` and bare `firewall-drop` are rejected.
6. Shuffle's OpenSearch crash-loops under RAM pressure. Shuffle is being retired anyway.

## What to build (in this order, with a verification gate after each)
**Phase 1: Lean stack.** Record `free -m` and `docker ps`. **Stop** (do not delete) Shuffle, TheHive, Cassandra, Elasticsearch and Cortex. Record `free -m` again; the before/after difference is evidence for the report. Wazuh must still be healthy afterwards.

**Phase 2: Agent service.** Project folder `~/sentinelforge/agent/`. Python venv, FastAPI, uvicorn, bound to `0.0.0.0:8080`. Endpoints: `POST /alert`, `GET /cases`, `GET /case/{id}`, and `GET /` (one HTML dashboard page listing cases: time, source IP, rule, verdict, confidence, action; click a case to see the full report and the agent's tool trace). SQLite `cases.db` with columns `id, ts, srcip, dstip, rule_id, level, verdict, confidence, severity, mitre, actions, report_md, trace_json, raw_alert_json`. Run it as a **systemd service** so it survives reboots.

**Phase 3: Agentic core.** Groq function-calling loop, **max 6 iterations**. Tools:
- `get_ip_reputation(ip)`: AbuseIPDB. For private IPs, return a note saying the IP is internal, with no lookup.
- `search_wazuh_alerts(srcip, minutes)`: query the Wazuh indexer for recent alerts from this IP, so the agent can tell a one-off from a campaign.
- `get_asset_context(ip)`: read from `assets.json` (one entry per lab host with name, Purdue zone, criticality, exposure).
- `block_ip(ip, reason)`: patch the pfSense `SOAR_blocked_ips` alias, apply it, **and** send Wazuh AR `!firewall-drop` to agent 002.
- `write_incident_report(...)`: severity, MITRE ATT&CK mapping, IOCs, actions taken, recommendation, written as Markdown into the case.

**Guardrails go in code, not in the prompt:**
- Only block when confidence ≥ **0.85**.
- **Never block** `10.10.50.0/24` (SOC), `10.10.0.0/24` (infrastructure links, including pfSense `10.10.0.10`), `10.10.40.0/24` (DC), `10.10.20.0/24` (the portal itself), `10.10.30.0/24` (OT).
- **Allow blocking** the lab attacker range `10.10.10.0/24` and any public IP.

**Prompt-injection defense:** alert fields (payload, URL, user-agent) are controlled by the attacker. Pass them to the model as clearly delimited, untrusted data, and say so in the system prompt. The model can never override the guardrails. Persist the full message trace for every case.

**Phase 4: Wazuh → agent wiring.** Create `custom-w2agent.py`: a copy of the integration that POSTs **only** to `http://10.10.50.100:8080/alert` (no TheHive), and only for rule level ≥ 10. Install it in the manager container, re-inject the `<integration>` block, and confirm `wazuh-integratord` is running.

**Phase 5: Test tooling.**
- `replay_alert.py`: posts a saved real Wazuh SQLi alert to `/alert`. This is the demo backup if the network fails.
- `reset_demo.sh`: removes `10.10.10.100` from the pfSense alias and applies the change, deletes the AR block on agent 002, and optionally clears the cases table, so the demo can be run again.
- When ready for a live test, **stop and ask me to fire the attack from Kali.** Example: `curl "http://10.10.20.100/search?q=' OR 1=1--"`. Check the real portal route in AeroSec §11 and give me the exact command. Then verify: a case is created, the alias contains `10.10.10.100`, and the attacker's curl times out.

**Phase 6 (extras, only after Phase 5 passes live):** a notification webhook (ask me for a Discord URL; skip it if I don't give one), a daily digest via cron at 18:00, and an optional `reinject.sh` hook.

**Phase 7: Docs.** Fill §10 "Build Log" of `SentinelForge-Master-Guide.md` with what was actually verified (date, commands, evidence paths). Also update the network sections to match the migration file. Write `DEMO.md`: an exact step-by-step runbook for the validation, covering bring-up order, the attack command, what to show on the dashboard and in the pfSense log, and how to reset.

## How to work
- I granted full permissions. Work autonomously, but **snapshot discipline first**: back up `ossec.conf`, the integration scripts, and the pfSense config (via API) before you modify them.
- **Never:** `docker system prune`, delete Docker volumes, `docker compose down -v`, remove the Wazuh indexer data, change the IDs or logic of Wazuh rules 100100–100240, or touch the GNS3 / VyOS config (the network part is finished).
- After each phase: run its verification, then give me a 3-line status (done / evidence / next). If something fails twice the same way, stop and tell me instead of looping.
- Don't redo fixes the AeroSec guide already documents. Read it first.
