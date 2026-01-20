### config.py
from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv("/srv/dns/.env")

ZONE_DIR = Path("/etc/coredns/zone")
KEY_DIR = Path("/etc/coredns/keys")
JSON_DIR = Path("/srv/dns/json")
EXPIRY_THRESHOLD_DAYS = 14
AGENT_SECRET = os.getenv("AGENT_SECRET")
PRIMARY_NS = os.getenv("PRIMARY_NS")
