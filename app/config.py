from pathlib import Path

AGENT_SECRET = "dEcartes2026"
AGENT_IP = '35.193.201.64'
NS1 = "ns1.dnsproof.org"
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "dnsproof.db"
JSON_DIR = Path(__file__).resolve().parent / "json"