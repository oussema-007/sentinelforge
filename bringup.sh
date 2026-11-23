#!/usr/bin/env bash
# SentinelForge bring-up (SOC VM). Usage: ./bringup.sh
# Order: NAT+DNS -> tenzir stop -> Wazuh up -> reinject (integration + AR, wiped on every container restart) -> agent
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
SUDO="sudo${SUDO_ASKPASS:+ -A}"
echo "== NAT / routes / DNS"
ip -br a show eth1 | grep -q UP || $SUDO ip link set eth1 up
ip route | grep -q '^default via 192.168.13.2' || $SUDO dhcpcd eth1 >/dev/null 2>&1
$SUDO ip route del default via 10.10.50.1 dev eth0 2>/dev/null
$SUDO ip route replace 10.10.0.0/16 via 10.10.50.1 dev eth0
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | $SUDO tee /etc/resolv.conf.head >/dev/null
grep -q 1.1.1.1 /etc/resolv.conf || printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | $SUDO tee /etc/resolv.conf >/dev/null
echo "== Wazuh"
$SUDO docker stop tenzir-node >/dev/null 2>&1
(cd ~/wazuh-docker/single-node && $SUDO docker compose up -d 2>&1 | grep -v 'attribute `version`')
for i in $(seq 1 30); do $SUDO docker compose -f ~/wazuh-docker/single-node/docker-compose.yml exec -T wazuh.manager true 2>/dev/null && break; sleep 5; done
sleep 20
./reinject.sh 2>&1 | grep -v 'attribute `version`'
echo "== Agent"
$SUDO systemctl restart sentinelforge-agent; sleep 3
curl -s http://10.10.50.100:8080/health; echo
echo "== Reachability"
for h in 10.10.0.10 10.10.20.100; do printf "%s " $h; ping -c1 -W1 $h >/dev/null && echo up || echo DOWN; done
curl -s -o /dev/null -w "groq %{http_code}\n" -A curl/8.0 https://api.groq.com
curl -s -m8 -u "$PFSENSE_USER:$PFSENSE_PASS" "$PFSENSE_URL"/api/v2/firewall/aliases | python3 -c "import sys,json;[print('alias',a['name'],a['address']) for a in json.load(sys.stdin)['data']]" 2>/dev/null || echo "pfSense API unreachable"
traceroute -n -w1 -q1 -m3 10.10.10.100 2>/dev/null | grep -q '!N' && echo "WARNING: no route to 10.10.10.0/24 - re-add R2 static route (see DEMO.md)" || true
