"""SentinelForge config: everything secret comes from ~/sentinelforge/.env (chmod 600)."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE.parent / ".env")


def env(name, default=None):
    return os.environ.get(name, default)


GROQ_API_KEY = env("GROQ_API_KEY")
GROQ_MODEL = env("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Cloudflare in front of Groq returns 1010/403 for python-requests' default UA (AeroSec gotcha).
GROQ_UA = "curl/8.0"

ABUSEIPDB_KEY = env("ABUSEIPDB_KEY")

WAZUH_API_URL = env("WAZUH_API_URL", "https://10.10.50.100:55000")
WAZUH_API_USER = env("WAZUH_API_USER")
WAZUH_API_PASS = env("WAZUH_API_PASS")
WAZUH_INDEXER_URL = env("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
WAZUH_INDEXER_USER = env("WAZUH_INDEXER_USER")
WAZUH_INDEXER_PASS = env("WAZUH_INDEXER_PASS")
AR_AGENT_ID = env("AR_AGENT_ID", "002")

PFSENSE_URL = env("PFSENSE_URL", "http://10.10.0.10")
PFSENSE_USER = env("PFSENSE_USER")
PFSENSE_PASS = env("PFSENSE_PASS")
PFSENSE_ALIAS = env("PFSENSE_ALIAS", "SOAR_blocked_ips")

CONF_THRESHOLD = float(env("CONF_THRESHOLD", "0.85"))
MAX_ITERATIONS = 6
NOTIFY_WEBHOOK = env("NOTIFY_WEBHOOK", "")

DB_PATH = BASE / "cases.db"
ASSETS_PATH = BASE / "assets.json"
