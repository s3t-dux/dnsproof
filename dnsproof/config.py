### config.py
from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv("/srv/dns/.env")

ZONE_DIR = Path("/etc/coredns/zone")
KEY_DIR = Path("/etc/coredns/keys")
JSON_DIR = Path("/srv/dns/json")

AGENT_SECRET = os.getenv("AGENT_SECRET")
#SERVER_NAME = os.getenv("SERVER_NAME")
SERVER_NAME = "ns1"