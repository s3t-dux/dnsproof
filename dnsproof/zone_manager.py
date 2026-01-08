### zone_manager.py

from config import ZONE_DIR
from datetime import datetime
import os

def generate_zone_file(domain: str, records: list, ns_ip: str) -> str:
    serial = datetime.utcnow().strftime("%Y%m%d01")
    zone_lines = []

    zone_lines.append(f"$ORIGIN {domain}.")
    zone_lines.append("$TTL 3600")
    zone_lines.append(
        f"@ IN SOA ns1.{domain}. admin.{domain}. (\n"
        f"    {serial} ; serial\n"
        f"    7200       ; refresh\n"
        f"    1800       ; retry\n"
        f"    1209600    ; expire\n"
        f"    3600 )     ; minimum"
    )
    zone_lines.append(f"@ IN NS ns1.{domain}.")
    zone_lines.append(f"ns1 IN A {ns_ip}")

    for record in records:
        try:
            name = record.get("name", "@")
            rtype = record["type"].upper()
            value = record["value"]
            ttl = record.get("ttl", 3600)

            if rtype == "MX":
                priority = record.get("priority", 10)
                zone_lines.append(f"{name} {ttl} IN MX {priority} {value}")

            if rtype == "TXT":
                value = f"\"{value}\""
            zone_lines.append(f"{name} {ttl} IN {rtype} {value}")

        except KeyError:
            continue  # skip invalid records

    return "\n".join(zone_lines)

def write_zone_file_to_disk(domain: str, zone_text: str):
    ZONE_DIR.mkdir(parents=True, exist_ok=True)
    path = ZONE_DIR / f"{domain}.zone"
    with open(path, "w") as f:
        f.write(zone_text)

def sign_zone_with_dnssec(domain: str):
    # This is placeholder logic
    os.system(f"echo '[DNSSEC signing] {domain}'")

def reload_coredns():
    os.system("systemctl restart coredns")
