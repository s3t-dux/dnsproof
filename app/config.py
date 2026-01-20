

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
NAMESERVERS = DNS_CONFIG.get("nameservers", {})
AGENT_IPS = [v["ip"] for v in NAMESERVERS.values() if "ip" in v]
DOMAIN = DNS_CONFIG.get("domain", "example.com")
NS1 = DNS_CONFIG.get("ns_name", "ns1.example.com")
PASSWORD = DNS_CONFIG.get("password", "").strip()
USE_HTTPS = DNS_CONFIG.get("tls_enabled", False)
CERT_PATH = DNS_CONFIG.get("agent_cert_path_app", "./")
# Other static paths
DB_PATH = BASE_DIR / "dnsproof.db"
JSON_DIR = Path(__file__).resolve().parent / "json"

AGENT_IP = AGENT_IPS[0]