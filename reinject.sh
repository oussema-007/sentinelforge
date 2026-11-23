#!/usr/bin/env bash
# SentinelForge: re-install custom-w2agent.py and re-inject the <integration> + <active-response> blocks into the
# Wazuh manager's ossec.conf (both are wiped on every manager container restart - AeroSec gotcha), then restart
# Wazuh *inside* the container (never `docker restart`) and verify integratord.
# Idempotent: safe to run any number of times. Usage: ./reinject.sh   (uses sudo)
set -euo pipefail
SUDO="sudo${SUDO_ASKPASS:+ -A}"
cd "$(dirname "$0")"
SF=$(pwd)
COMPOSE="$SUDO docker compose -f $HOME/wazuh-docker/single-node/docker-compose.yml"
EXEC="$COMPOSE exec -T wazuh.manager"

$SUDO docker stop tenzir-node >/dev/null 2>&1 || true   # squats on 1514 if running

echo "[1/5] install integration script"
$EXEC sh -c 'cat > /var/ossec/integrations/custom-w2agent.py' < "$SF/integration/custom-w2agent.py"
$EXEC sh -c 'chown root:wazuh /var/ossec/integrations/custom-w2agent.py && chmod 750 /var/ossec/integrations/custom-w2agent.py'

echo "[2/5] backup + inject blocks (python str.replace, never sed - AeroSec gotcha 35)"
$EXEC cp /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak-sf-$(date +%Y%m%d%H%M%S)"
$EXEC python3 - <<'PYEOF'
p = '/var/ossec/etc/ossec.conf'
c = open(p).read()
changed = []
if '<name>custom-w2agent.py</name>' not in c:
    c = c.replace('</ossec_config>', '''  <integration>
    <name>custom-w2agent.py</name>
    <hook_url>http://10.10.50.100:8080/alert</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>''', 1)
    changed.append('integration')
# Active-response: enabled so the API can run !firewall-drop on agent 002, but level 16 so Wazuh never
# auto-blocks by itself - the SentinelForge agent is the only component that decides to block.
if '<!-- sentinelforge-ar -->' not in c:
    c = c.replace('</ossec_config>', '''  <!-- sentinelforge-ar -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <level>16</level>
    <timeout>3600</timeout>
  </active-response>
</ossec_config>''', 1)
    changed.append('active-response')
open(p, 'w').write(c)
print('injected:', ', '.join(changed) if changed else 'nothing (already present)')
PYEOF

echo "[3/5] config test"
$EXEC /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1 && echo "analysisd -t OK" || { echo "CONFIG TEST FAILED - restore the .bak-sf file"; exit 1; }

echo "[4/5] restart wazuh inside the container"
$EXEC /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
sleep 12

echo "[5/5] verify"
$EXEC grep -c 'custom-w2agent' /var/ossec/etc/ossec.conf | sed 's/^/integration blocks: /'
$EXEC grep -c 'sentinelforge-ar' /var/ossec/etc/ossec.conf | sed 's/^/AR blocks: /'
$EXEC /var/ossec/bin/wazuh-control status | grep -E 'integratord|execd|analysisd|remoted'
