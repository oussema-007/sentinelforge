"""Deterministic guardrails. The LLM decides *whether* to call block_ip; this code decides
whether the block is *allowed*. Nothing in the prompt or the model output can change these."""
import ipaddress

from config import CONF_THRESHOLD

# Never block these, whatever the model says.
PROTECTED_NETS = [ipaddress.ip_network(n) for n in (
    "10.10.50.0/24",  # SOC (this host, Wazuh, the agent)
    "10.10.0.0/24",   # infrastructure links incl. pfSense 10.10.0.10
    "10.10.40.0/24",  # DC / IT core
    "10.10.20.0/24",  # DMZ portal itself
    "10.10.30.0/24",  # OT control
)]
# Blocking allowed: the lab attacker range (Landside behind pfSense OPT1) and any public IP.
BLOCKABLE_LAB_NETS = [ipaddress.ip_network("10.10.10.0/24")]


def check_block(ip: str, confidence, alert_srcip: str | None):
    """Return (allowed: bool, reason: str)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False, f"'{ip}' is not a valid IP address"
    if alert_srcip and str(addr) != str(alert_srcip).strip():
        # Injection containment: the agent may only block the source IP of the alert it is
        # investigating, never an arbitrary IP named inside attacker-controlled data.
        return False, f"{addr} is not the source IP of this alert ({alert_srcip})"
    for net in PROTECTED_NETS:
        if addr in net:
            return False, f"{addr} is in protected range {net}"
    in_lab_attacker = any(addr in n for n in BLOCKABLE_LAB_NETS)
    if not in_lab_attacker and not addr.is_global:
        return False, f"{addr} is private/reserved and not in the lab attacker range"
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return False, f"confidence '{confidence}' is not a number"
    if conf < CONF_THRESHOLD:
        return False, f"confidence {conf:.2f} < threshold {CONF_THRESHOLD}"
    return True, f"allowed ({'lab attacker range' if in_lab_attacker else 'public IP'}, conf {conf:.2f})"
