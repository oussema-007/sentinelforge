#!/usr/bin/env bash
# SentinelForge demo reset. Usage: ./reset_demo.sh [--clear-cases] [IP]   (default IP 10.10.10.100)
#  1. remove IP from the pfSense SOAR_blocked_ips alias + apply
#  2. remove the Wazuh active-response iptables DROP for IP on the DMZ portal (agent 002) over SSH
#     (the Wazuh API "delete" does not revert firewall-drop on 4.9.2 - AeroSec §24.3.3)
#  3. optionally clear the cases table
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
CLEAR=0; IP=10.10.10.100
for a in "$@"; do case $a in --clear-cases) CLEAR=1;; *) IP=$a;; esac; done

echo "[1/3] pfSense: remove $IP from $PFSENSE_ALIAS"
agent/.venv/bin/python - "$IP" <<'EOF'
import sys
sys.path.insert(0, "agent")
import tools
ip = sys.argv[1]
try:
    a = tools.pfsense_alias_get()
    addrs, dets = list(a.get("address") or []), list(a.get("detail") or [])
    keep = [(x, d) for x, d in zip(addrs, dets + [""] * len(addrs)) if x != ip]
    print("  applied:", tools.pfsense_alias_set([x for x, _ in keep], [d for _, d in keep]))
    print("  alias now:", tools.pfsense_alias_get().get("address"))
except Exception as e:
    print("  pfSense FAILED:", e)
EOF

echo "[2/3] DMZ portal: remove AR iptables DROP for $IP"
sshpass -p "$PORTAL_SSH_PASS" ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "$PORTAL_SSH_USER@10.10.20.100" \
  "echo '$PORTAL_SSH_PASS' | sudo -S -p '' sh -c 'for ch in INPUT FORWARD; do while iptables -C \$ch -s $IP -j DROP >/dev/null 2>&1; do iptables -D \$ch -s $IP -j DROP; done; done; echo \"  remaining rules for $IP: \$(iptables -S | grep -c $IP)\"'" \
  || echo "  SSH FAILED - the AR rule expires by itself after 3600 s, or remove it on the portal console:
     sudo iptables -D INPUT -s $IP -j DROP; sudo iptables -D FORWARD -s $IP -j DROP"

echo "[3/3] cases table"
if [ $CLEAR = 1 ]; then
  agent/.venv/bin/python -c "import sqlite3;c=sqlite3.connect('agent/cases.db');c.execute('DELETE FROM cases');c.execute(\"DELETE FROM sqlite_sequence WHERE name='cases'\");c.commit();print('  cases cleared')"
else echo "  kept (use --clear-cases to wipe)"; fi
