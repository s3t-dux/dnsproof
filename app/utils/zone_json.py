import hashlib
import json
from config import JSON_DIR

def generate_record_id(record: dict) -> str:
    """Generate a stable ID for a DNS record based on its type/name/value/priority/ttl."""
    content = json.dumps({
        "type": record["type"],
        "name": record["name"],
        "value": record["value"],
        "priority": record.get("priority"),
        "port": record.get("port"),
        "target": record.get("target"),
        "ttl": record.get("ttl", 3600),
    }, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()

def load_zone_json(domain: str) -> dict:
    path = JSON_DIR / f"{domain}.json"
    with open(path) as f:
        return json.load(f)
    
def clean_record(record: dict) -> dict:
    return {k: v for k, v in record.items() if v is not None}

def save_zone_json(domain: str, records: list[dict]) -> None:
    path = JSON_DIR / f"{domain}.json"
    with open(path, "w") as f:
        json.dump({"domain": domain, "records": records}, f, indent=2)

def add_record(domain: str, new_record: dict):
    zone = load_zone_json(domain)
    existing = zone.get("records", [])

    cleaned = clean_record(new_record)
    new_id = generate_record_id(cleaned)

    for record in existing:
        if generate_record_id(record) == new_id:
            raise ValueError("Record already exists")

    existing.append(cleaned)
    save_zone_json(domain, existing)

def edit_record(domain: str, record_id: str, updated_record: dict):
    zone = load_zone_json(domain)
    updated_records = []
    found = False

    for record in zone.get("records", []):
        if generate_record_id(record) == record_id:
            updated_records.append(clean_record(updated_record))  # 🧼 Clean before saving
            found = True
        else:
            updated_records.append(record)

    if not found:
        raise ValueError("Record to edit not found")

    save_zone_json(domain, updated_records)


def delete_record(domain: str, record_id: str):
    zone = load_zone_json(domain)
    new_records = [
        record for record in zone.get("records", [])
        if generate_record_id(record) != record_id
    ]

    if len(new_records) == len(zone.get("records", [])):
        raise ValueError("Record to delete not found")

    save_zone_json(domain, new_records)

def load_zone_json(domain: str) -> dict:
    path = JSON_DIR / f"{domain}.json"

    '''
    if not path.exists():
        raise FileNotFoundError(f"Zone file not found: {path}")
    '''
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"domain": domain, "records": []}))

    with open(path) as f:
        return json.load(f)
