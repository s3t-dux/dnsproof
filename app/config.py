

from pathlib import Path
import yaml

# Project base dir (1 level above /app)
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_YAML = BASE_DIR / "dns_config.yaml"

# DNS Config from YAML
DNS_CONFIG = {}
try:
    with open(CONFIG_YAML, "r") as f:
        DNS_CONFIG = yaml.safe_load(f)
except Exception as e:
    print(f"[WARN] Could not load dns_config.yaml: {e}")

# Dynamically loaded vars
AGENT_SECRET = str(DNS_CONFIG.get("agent_secret", "")).strip()
AGENT_IP = str(DNS_CONFIG.get("nameserver_ip", "127.0.0.1")).strip()
DOMAIN = DNS_CONFIG.get("domain", "example.com")
NS1 = DNS_CONFIG.get("ns_name", "ns1.example.com")
PASSWORD = DNS_CONFIG.get("password", "").strip()

# Other static paths
DB_PATH = BASE_DIR / "dnsproof.db"
JSON_DIR = Path(__file__).resolve().parent / "json"
