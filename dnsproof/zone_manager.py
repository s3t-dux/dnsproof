### zone_manager.py

from config import ZONE_DIR
from datetime import datetime
import os
from typing import List, Dict

def generate_zone_file(domain: str, records: List[Dict]) -> str:
    """
    Generates a BIND-style zone file string for a given domain and list of DNS records.

    Supports A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, SOA records.
    """
    zone_lines = [
        f"$ORIGIN {domain}.",
        "$TTL 3600",
    ]

    for record in records:
        record_type = record["type"].upper()
        record_name = record["name"] or "@"
        record_value = record["value"]
        ttl = record.get("ttl", 3600)

        # Normalize record name
        if record_name == "@":
            record_name = domain + "."
        elif not record_name.endswith("."):
            record_name = record_name + "."

        # Record-specific formatting
        if record_type == "TXT":
            line = f"{record_name} {ttl} IN TXT \"{record_value}\""

        elif record_type == "MX":
            priority = record.get("priority", 10)
            line = f"{record_name} {ttl} IN MX {priority} {record_value}"

        elif record_type == "NS":
            if not record_value.endswith("."):
                record_value += "."
            line = f"{record_name} {ttl} IN NS {record_value}"

        elif record_type == "CNAME":
            if not record_value.endswith("."):
                record_value += "."
            line = f"{record_name} {ttl} IN CNAME {record_value}"

        elif record_type == "SRV":
            # SRV requires: priority weight port target
            try:
                priority = record.get("priority", 0)
                weight = record.get("weight", 0)
                port = record.get("port")
                target = record.get("target")
                if not target.endswith("."):
                    target += "."
                line = f"{record_name} {ttl} IN SRV {priority} {weight} {port} {target}"
            except Exception:
                continue  # skip invalid SRV

        elif record_type == "CAA":
            # CAA requires: flag tag value
            try:
                flag = record.get("flag", 0)
                tag = record.get("tag", "issue")
                value = record_value
                line = f"{record_name} {ttl} IN CAA {flag} {tag} \"{value}\""
            except Exception:
                continue  # skip invalid CAA

        elif record_type == "SOA":
            # Typically fixed per domain
            # Example format: ns1.example.com. admin.example.com. 2026010100 3600 1800 604800 86400
            line = f"{record_name} {ttl} IN SOA {record_value}"

        else:
            # Generic fallback
            line = f"{record_name} {ttl} IN {record_type} {record_value}"

        zone_lines.append(line)

    return "\n".join(zone_lines) + "\n"

# legacy code
'''
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
'''
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
