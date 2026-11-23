# SentinelForge — Landside moved behind pfSense (2026-11-10)

## Goal
Move the Landside zone (10.10.10.0/24, attacker Kali) off SW1 eth5 and behind pfSense OPT1, so that
Landside → DMZ traffic goes through pfSense and the portal logs the real source address
(10.10.10.100) instead of the pfSense WAN address (10.10.0.10).

## 1. Audit (read-only)

### GNS3 wiring — `Sentinelforge.gns3` (clone of AeroSec), all matched the target
| Link | Status |
|---|---|
| SW1 e0 ↔ R1 e0 (uplink) | OK |
| R1 e1 ↔ R2 e0 | OK |
| R2 e1 ↔ pfSense e0 (WAN) | OK |
| pfSense e2 ↔ Cloud3-AttackerSide **eth4** | OK |
| SW1 e1 ↔ Cloud5-Mirror eth6 | OK |
| SW1 e2 ↔ Cloud2-ITCore eth3 | OK |
| SW1 e3 ↔ Cloud1-soc eth2 | OK |
| SW1 e4 ↔ Cloud4-DMZ eth5 | OK |
| SW1 e5 | empty (OK) |
| pfSense e1 ↔ OT-PLC-01 | extra link (Airside) |

GNS3 VM: 192.168.20.128. Consoles: SW1 = 5002, R1 = 5004, R2 = 5006 (telnet); pfSense = VNC 5900.

### VyOS interface names (GNS3 slot → VyOS name; the MAC's last octet = slot)
| Node | e0 | e1 | Notes |
|---|---|---|---|
| SW1 | eth4 10.10.0.1/30 | eth1 mirror | e2 = eth7 Admin, e3 = eth8 SOC, e4 = eth6 DMZ, e5 = eth5 |
| R1 | eth7 10.10.0.2/30 | eth8 10.10.0.5/30 | router-id 2.2.2.2 |
| R2 | eth4 10.10.0.6/30 | eth6 10.10.0.9/30 (to pfSense) | router-id 3.3.3.3 |
SW1 router-id 1.1.1.1. OSPF was Full on all adjacencies.

### Problems found
- R2 had no route to 10.10.10.0/24, so DMZ replies to Landside had no way back.
- SW1 eth5 still had the old Landside gateway 10.10.10.1/24 and its OSPF settings. The link was down, but the address would compete with pfSense if eth5 ever came up.
- pfSense: no OPT1 yet, and outbound NAT was **Automatic**, which would translate Landside traffic to 10.10.0.10.

## 2. Changes applied (each one approved separately)

### A. R2 — static route (vtysh, `write memory`)
```
ip route 10.10.10.0/24 10.10.0.10
```
Already redistributed into OSPF (`redistribute static`).
Verified: R1 learns it via 10.10.0.6 (eth8), SW1 via 10.10.0.2 (eth4).

### B. SW1 — removed the old Landside gateway (`commit` + `save`)
```
delete interfaces ethernet eth5 address 10.10.10.1/24
delete protocols ospf interface eth5
```
Verified: eth5 has no address, `/config/config.boot` has no 10.10.10.1, and the OSPF adjacency with R1 is still Full.

### C. pfSense — done through the REST API (v2.4.3)
- Config backed up first: `/home/kali/pfsense-backups/config-20261110-023624.xml`
- **OPT1 "LANDSIDE"** = vtnet2 (MAC 0c:db:88:88:00:02), 10.10.10.1/24, no gateway, block-private and block-bogon off.
- **OPT1 rules, in order:**
  1. Block source alias `SOAR_blocked_ips` (logged)
  2. Pass TCP 10.10.10.0/24 → 10.10.20.100:80
  3. Pass ICMP echo-request 10.10.10.0/24 → firewall itself
- **Outbound NAT:** Automatic → **Hybrid**, plus a manual rule at the top:
  *Do not NAT* on WAN, 10.10.10.0/24 → 10.10.0.0/16.
  Verified with `pfctl -s nat`: the `no nat` line comes before the automatic NAT rule.
  (Landside traffic to anywhere outside 10.10.0.0/16 is still translated to the WAN address.)

## 3. Verification
| Test | Result |
|---|---|
| Kali `ping 10.10.10.1` | done (pfSense OPT1) |
| Kali `curl -v http://10.10.20.100` | **HTTP 200**, connection made from 10.10.10.100:39570 |
| SW1 rule 300 (Landside → DMZ) | 0 → 7 packets, so the source arrived untranslated |
| SW1 default-drop | stayed at 0 |

## 4. Next plan
1. **Confirm the portal log**: the Werkzeug access line must start with `10.10.10.100`, not `10.10.0.10`.
2. **Security cleanup**: change the pfSense API/admin password (it was sent over plain HTTP), then get HTTPS (443) working again for the API.
3. **Optional**: recreate pfSense OPT1 rule 7 (ICMP) so it gets its own tracker ID (it shares one with rule 6).
4. **Test the SOAR block on OPT1**: add 10.10.10.100 to `SOAR_blocked_ips` (or let the Shuffle workflow do it), check that the curl fails and the block appears in the pfSense log, then remove it.
5. **Update the project guide** (AeroSec-Complete-Project-Guide):
   - §2.2: Cloud3 eth4 (VMnet4, Landside) now connects to **pfSense e2 / OPT1 (vtnet2)**, not SW1.
   - §2.3: SW1 Ethernet5 / eth5 is **unused** (no IP, no OSPF).
   - §3.2 / §5.5: add `ip route 10.10.10.0/24 10.10.0.10` to the R2 re-inject block.
   - New pfSense section: OPT1, the 3 rules, Hybrid NAT with the no-NAT mapping.
6. **Snort / Wazuh**: if Snort should watch Landside, enable it on OPT1 as well, and check the alerts reach Wazuh (SW1 rule 160 already allows syslog from 10.10.0.10).
7. **Each lab boot**: keep promiscuous mode on GNS3 VM eth4 (§3.1). Kali attacker = 10.10.10.100/24, gateway 10.10.10.1, NIC on VMnet4.
