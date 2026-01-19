### zone_manager.py

from config import ZONE_DIR, KEY_DIR
from datetime import datetime
import os
from typing import List, Dict
import subprocess
import glob

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
        #if record_name == "@":
        #    record_name = domain + "."
        #elif not record_name.endswith("."):
        #    record_name = record_name + "."

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

def write_zone_file_to_disk(domain: str, zone_text: str):
    ZONE_DIR.mkdir(parents=True, exist_ok=True)
    path = ZONE_DIR / f"{domain}.zone"
    with open(path, "w") as f:
        f.write(zone_text)

def sign_zone_with_dnssec(domain: str):
    if KEY_DIR.exists() and any(KEY_DIR.glob("K*.key")):
        print(f"[DEBUG] DNSSEC keys found, re-signing zone for {domain}")
        try:
            # Re-sign the zone after DNS update
            perform_zone_signing(domain)
            
        except Exception as e:
            print(f"[ERROR] DNSSEC re-signing failed for {domain}: {e}")
            # Don't fail the entire deployment, just log the error

def perform_zone_signing(domain: str):
    try:
        signed_zone, zone_file = sign_zone_with_keys(domain, KEY_DIR)

        if not os.path.exists(signed_zone):
            raise RuntimeError("Signed zone file was not created.")
        
        # ldns-signzone fully expands the zone file. SO this is not necessary
        '''
        # Patch signed file with $ORIGIN and $TTL
        with open(signed_zone, "r") as f:
            lines = f.readlines()

        with open(signed_zone, "w") as f:
            f.write(f"$ORIGIN {domain}.\n$TTL 3600\n")  # You can extract TTL from record if needed
            f.writelines(lines)
        '''
        # Overwrite the original zone with the signed one
        os.replace(signed_zone, zone_file)

        # Restart is done by the next function in the route.
        # Restart CoreDNS to load the new zone
        #subprocess.run(["systemctl", "restart", "coredns"], check=True)

        print(f"[DEBUG] DNSSEC re-signing completed for {domain}")
    except Exception as e:
        print(f"[ERROR] DNSSEC re-signing failed for {domain}: {e}")
        raise

def sign_zone_with_keys(domain, key_dir):
    """Sign the zone file using the DNSSEC keys"""
    zone_file = f"/etc/coredns/zone/{domain}.zone"
    if not os.path.exists(zone_file):
        raise Exception(f"Zone file {zone_file} not found")
    
    # Find ZSK and KSK key files (without .key/.private extension)
    key_files = glob.glob(os.path.join(key_dir, f"K{domain}.+008+*"))
    key_names = []
    
    for key_file in key_files:
        if key_file.endswith('.key'):
            key_name = key_file[:-4]  # Remove .key extension
            if key_name not in key_names:
                key_names.append(key_name)
    
    if len(key_names) < 2:
        raise Exception(f"Need both ZSK and KSK keys, found: {key_names}")
    
    # Sign the zone
    signed_zone = f"{zone_file}.signed"
    cmd = ["ldns-signzone", zone_file] + key_names
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=key_dir)
    if result.returncode != 0:
        raise Exception(f"Zone signing failed: {result.stderr}")
    
    return signed_zone, zone_file

def reload_coredns():
    os.system("systemctl restart coredns")

def delete_zone_completely(domain: str):
    zone_path = ZONE_DIR / f"{domain}.zone"
    if zone_path.exists():
        os.remove(zone_path)
        print(f"[INFO] Deleted zone file: {zone_path}")
    else:
        raise FileNotFoundError(f"Zone file not found: {zone_path}")

    # Reload CoreDNS to unload the deleted zone
    subprocess.run(["systemctl", "restart", "coredns"], check=True)
    print(f"[INFO] CoreDNS reloaded")