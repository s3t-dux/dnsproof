from fastapi import HTTPException
from config import ZONE_DIR, KEY_DIR, SERVER_NAME
from pathlib import Path
import subprocess
import dns.zone
import dns.dnssec
import dns.rdatatype
import dns.rrset
import dns.name
import glob
import os
import logging
from datetime import datetime
import time

# legacy codde - monolithic version
'''
def sign_dnssec(domain: str):
    zone_file = Path(ZONE_DIR) / f"{domain}.zone"
    if not zone_file.exists():
        raise HTTPException(status_code=400, detail="Zone file not found")

    # Detect DNSSEC keys (ZSK + KSK)
    key_files = glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*"))
    key_names = []

    for key_file in key_files:
        if key_file.endswith('.key'):
            key_name = key_file[:-4]  # strip .key
            if key_name not in key_names:
                key_names.append(key_name)

    # If insufficient keys, generate new ones (ns1 only)
    created_keys = False
    if len(key_names) < 2:
        if SERVER_NAME != "ns1":
            raise HTTPException(
                status_code=403,
                detail="DNSSEC keys missing and only ns1 can generate new keys"
            )

        os.makedirs(KEY_DIR, exist_ok=True)

        try:
            # ZSK
            result1 = subprocess.run(
                ["ldns-keygen", "-a", "RSASHA256", domain],
                check=True, cwd=KEY_DIR, capture_output=True, text=True
            )

            # KSK
            result2 = subprocess.run(
                ["ldns-keygen", "-a", "RSASHA256", "-k", domain],
                check=True, cwd=KEY_DIR, capture_output=True, text=True
            )

            created_keys = True

        except subprocess.CalledProcessError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Key generation failed: {e.stderr or e.stdout}"
            )

        # Re-scan keys after creation
        key_files = glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*"))
        key_names = [kf[:-4] for kf in key_files if kf.endswith(".key")]

    if len(key_names) < 2:
        raise HTTPException(
            status_code=500,
            detail=f"Key generation incomplete: keys={key_names}"
        )

    # Sign zone
    signed_zone = f"{zone_file}.signed"
    cmd = ["ldns-signzone", str(zone_file)] + key_names

    try:
        subprocess.run(cmd, capture_output=True, text=True, cwd=KEY_DIR, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"ldns-signzone failed: {e.stderr or e.stdout}"
        )

    # Parse signed zone BEFORE replacing
    try:
        z = dns.zone.from_file(signed_zone, origin=domain + ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse signed zone: {e}")

    # Then replace and reload CoreDNS
    try:
        os.replace(signed_zone, zone_file)
        subprocess.run(["systemctl", "restart", "coredns"], check=True)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"coredns restart failed: {e}"
        )

    rrsig_records = []
    ds_records = []
    zsk_digest = None
    zsk_key_tag = None
    zsk_algorithm = None

    for (name, node) in z.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                for rdata in rdataset:
                    rrsig_records.append(rdata.to_text())

            elif rdataset.rdtype == dns.rdatatype.DNSKEY:
                for rdata in rdataset:
                    if rdata.flags == 256:  # ZSK
                        dnskey_rrset = dns.rrset.from_rdata_list(name, 3600, [rdata])
                        ds = dns.dnssec.make_ds(name.concatenate(z.origin), rdata, 'SHA256')
                        zsk_digest = ds.digest.hex().upper()
                        zsk_key_tag = dns.dnssec.key_id(rdata)
                        zsk_algorithm = rdata.algorithm
                        ds_records.append(ds.to_text())

    if not rrsig_records:
        raise HTTPException(status_code=500, detail="No RRSIG records after signing")

    return {
        "status": "signed_unpublished" if created_keys else "signed",
        "created_keys": created_keys,
        "rrsig_records": rrsig_records,
        "ds_records": ds_records,
        "ds_digest": zsk_digest,
        "zsk_key_tag": zsk_key_tag,
        "zsk_algorithm": zsk_algorithm
    }
'''
def disable_dnssec(domain: str):
    try:
        logging.info(f"[disable DNSSEC] key_dir = {KEY_DIR}")
        # Remove local keys
        if os.path.exists(KEY_DIR):
            import shutil
            shutil.rmtree(KEY_DIR)
            logging.info("[disable DNSSEC] DNSSEC keys removed from VM")

        # remove the singed zone file
        signed_zone = f"/etc/coredns/zone/{domain}.zone.signed"
        if os.path.exists(signed_zone):
            os.remove(signed_zone)
        
        return {"status": "disabled", "message": "DNSSEC disabled successfully"}
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to disable DNSSEC: {e}"}
    
def get_dnssec_status(domain: str):
    zone_file = ZONE_DIR / f"{domain}.zone"
    if not zone_file.exists():
        raise HTTPException(status_code=404, detail="Zone file not found")

    # Collect file creation timestamps
    ksk_created_at = None
    zsk_created_at = None

    key_files = glob.glob(str(KEY_DIR / f"K{domain}.+008+*.key"))
    print(f"[DEBUG] key_files: {key_files}")
    for key_path in key_files:
        created_at = datetime.fromtimestamp(os.path.getctime(key_path))
        with open(key_path) as f:
            full_line = f.readline().strip()
            # Remove name and class prefix
            if full_line.startswith(domain):
                rdata_line = full_line.split("DNSKEY", 1)[1].strip()
            else:
                rdata_line = full_line  # fallback

            # Remove comments
            if ";" in rdata_line:
                rdata_line = rdata_line.split(";")[0].strip()

            try:
                rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.DNSKEY,
                    rdata_line
                )
            except Exception as e:
                print(f"Parse failed for {key_path}: {e}")
                continue

            if rdata.flags == 257:
                ksk_created_at = created_at
            elif rdata.flags == 256:
                zsk_created_at = created_at
                

    # Read zone file for DS info
    try:
        z = dns.zone.from_file(str(zone_file), origin=domain + ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zone parse failed: {e}")

    ds_digest = None
    key_tag = None
    algorithm = None

    for (name, node) in z.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.DNSKEY:
                for rdata in rdataset:
                    if rdata.flags == 256:  # ZSK
                        ds = dns.dnssec.make_ds(name.concatenate(z.origin), rdata, 'SHA256')
                        ds_digest = ds.digest.hex().upper()
                        key_tag = dns.dnssec.key_id(rdata)
                        algorithm = rdata.algorithm

    return {
        #"signed_at": datetime.fromtimestamp(os.path.getctime(zone_file)),
        "ksk_created_at": ksk_created_at,
        "zsk_created_at": zsk_created_at,
        "ds_digest": ds_digest,
        "key_tag": key_tag,
        "algorithm": algorithm,
        "days_since_last_key_creation": (
            (datetime.now() - max(filter(None, [ksk_created_at, zsk_created_at]))).days
            if ksk_created_at or zsk_created_at else None
        )
    }

# legacy code - monolithic version
'''
def rotate_dnssec_key_pair(domain: str):
    zone_file = Path(ZONE_DIR) / f"{domain}.zone"
    if not zone_file.exists():
        raise HTTPException(status_code=400, detail="Zone file not found")
    
    if SERVER_NAME != "ns1":
        raise HTTPException(
            status_code=403,
            detail="DNSSEC keys missing and only ns1 can generate new keys"
        )

    # Delete old DNSSEC keys and {doamin}.signed file
    try:
        for f in glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*")):
            os.remove(f)

        signed_zone = f"{zone_file}.signed"
        if os.path.exists(signed_zone):
            os.remove(signed_zone)
    except Exception as e:
        logging.info(f"Error in deleting existing DNSSEC keys: {e}")

    os.makedirs(KEY_DIR, exist_ok=True)

    try:
        # ZSK
        result1 = subprocess.run(
            ["ldns-keygen", "-a", "RSASHA256", domain],
            check=True, cwd=KEY_DIR, capture_output=True, text=True
        )

        # KSK
        result2 = subprocess.run(
            ["ldns-keygen", "-a", "RSASHA256", "-k", domain],
            check=True, cwd=KEY_DIR, capture_output=True, text=True
        )

        created_keys = True

    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Key generation failed: {e.stderr or e.stdout}"
        )

    # Re-scan keys after creation
    key_files = glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*"))
    key_names = [kf[:-4] for kf in key_files if kf.endswith(".key")]

    if len(key_names) < 2:
        raise HTTPException(
            status_code=500,
            detail=f"Key generation incomplete: keys={key_names}"
        )

    # Sign zone
    signed_zone = f"{zone_file}.signed"
    cmd = ["ldns-signzone", str(zone_file)] + key_names

    try:
        subprocess.run(cmd, capture_output=True, text=True, cwd=KEY_DIR, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"ldns-signzone failed: {e.stderr or e.stdout}"
        )

    # Parse signed zone BEFORE replacing
    try:
        z = dns.zone.from_file(signed_zone, origin=domain + ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse signed zone: {e}")

    # Then replace and reload CoreDNS
    try:
        os.replace(signed_zone, zone_file)
        subprocess.run(["systemctl", "restart", "coredns"], check=True)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"coredns restart failed: {e}"
        )

    rrsig_records = []
    ds_records = []
    zsk_digest = None
    zsk_key_tag = None
    zsk_algorithm = None

    for (name, node) in z.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                for rdata in rdataset:
                    rrsig_records.append(rdata.to_text())

            elif rdataset.rdtype == dns.rdatatype.DNSKEY:
                for rdata in rdataset:
                    if rdata.flags == 256:  # ZSK
                        dnskey_rrset = dns.rrset.from_rdata_list(name, 3600, [rdata])
                        ds = dns.dnssec.make_ds(name.concatenate(z.origin), rdata, 'SHA256')
                        zsk_digest = ds.digest.hex().upper()
                        zsk_key_tag = dns.dnssec.key_id(rdata)
                        zsk_algorithm = rdata.algorithm
                        ds_records.append(ds.to_text())

    if not rrsig_records:
        raise HTTPException(status_code=500, detail="No RRSIG records after signing")

    return {
        "status": "rotated_signed_unpublished" if created_keys else "signed",
        "created_keys": created_keys,
        "rrsig_records": rrsig_records,
        "ds_records": ds_records,
        "ds_digest": zsk_digest,
        "zsk_key_tag": zsk_key_tag,
        "zsk_algorithm": zsk_algorithm
    }
'''

def delete_old_keys(domain: str):
    prefix = f"K{domain}.+008+"
    for filename in os.listdir(KEY_DIR):
        if filename.startswith(prefix):
            full_path = os.path.join(KEY_DIR, filename)
            print(f"[DEBUG] Deleting old key file: {filename}")
            os.remove(full_path)

def generate_dnssec_keys(domain: str, force: bool = False) -> bool:
    if force:
        delete_old_keys(domain)
        time.sleep(1)  # allow FS to update
        signed_zone_file = ZONE_DIR / f"{domain}.zone.signed"
        if signed_zone_file.exists():
            print(f"[DEBUG] Deleting stale signed zone file: {signed_zone_file}")
            signed_zone_file.unlink()

    key_files = glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*.key"))
    if len(key_files) >= 2:
        return False  # keys already exist

    if SERVER_NAME != "ns1":
        raise HTTPException(status_code=403, detail="Only ns1 can generate keys")

    os.makedirs(KEY_DIR, exist_ok=True)
    try:
        subprocess.run(["ldns-keygen", "-a", "RSASHA256", domain], check=True, cwd=KEY_DIR)
        subprocess.run(["ldns-keygen", "-a", "RSASHA256", "-k", domain], check=True, cwd=KEY_DIR)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Keygen failed: {e}")

    return True

def sign_zone_with_keys(domain: str) -> dns.zone.Zone:
    zone_file = Path(ZONE_DIR) / f"{domain}.zone"
    signed_zone = f"{zone_file}.signed"

    key_files = glob.glob(os.path.join(KEY_DIR, f"K{domain}.+008+*.key"))
    key_names = [kf[:-4] for kf in key_files]

    if len(key_names) < 2:
        raise HTTPException(status_code=500, detail="Insufficient DNSSEC keys")

    if os.path.exists(signed_zone):
        os.remove(signed_zone)

    try:
        subprocess.run(["ldns-signzone", str(zone_file)] + key_names, cwd=KEY_DIR, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Sign failed: {e}")

    try:
        z = dns.zone.from_file(signed_zone, origin=domain + ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zone parse failed: {e}")

    os.replace(signed_zone, zone_file)
    subprocess.run(["systemctl", "restart", "coredns"], check=True)

    return z

def parse_zone_for_signatures(z: dns.zone.Zone, domain: str) -> dict:
    rrsig_records = []
    newest_ksk = None
    newest_ctime = None

    for (name, node) in z.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                rrsig_records.extend([r.to_text() for r in rdataset])
            elif rdataset.rdtype == dns.rdatatype.DNSKEY:
                for rdata in rdataset:
                    if rdata.flags == 257:  # KSK
                        key_tag = dns.dnssec.key_id(rdata)
                        key_file = KEY_DIR / f"K{domain}.+008+{key_tag:05}.key"
                        if key_file.exists():
                            ctime = os.path.getctime(key_file)
                            if not newest_ctime or ctime > newest_ctime:
                                newest_ctime = ctime
                                newest_ksk = (key_tag, rdata, name)

    ds_records = []
    ds_digest = None
    zsk_key_tag = None
    zsk_algorithm = None

    if newest_ksk:
        tag, rdata, name = newest_ksk
        ds = dns.dnssec.make_ds(name.concatenate(z.origin), rdata, 'SHA256')
        ds_records.append(ds.to_text())
        ds_digest = ds.digest.hex().upper()
        zsk_key_tag = tag
        zsk_algorithm = rdata.algorithm
        print(f"[DEBUG] Selected newest KSK key_tag={tag}, DS={ds.to_text()}")

    return {
        "rrsig_records": rrsig_records,
        "ds_records": ds_records,
        "ds_digest": ds_digest,
        "zsk_key_tag": zsk_key_tag,
        "zsk_algorithm": zsk_algorithm,
    }

def sign_dnssec(domain: str):
    created_keys = generate_dnssec_keys(domain, force=False)
    z = sign_zone_with_keys(domain)
    result = parse_zone_for_signatures(z, domain)
    result["status"] = "signed_unpublished" if created_keys else "signed"
    result["created_keys"] = created_keys
    return result

def rotate_dnssec_key_pair(domain: str):
    created_keys = generate_dnssec_keys(domain, force=True)
    z = sign_zone_with_keys(domain)
    result = parse_zone_for_signatures(z, domain)
    result["status"] = "rotated_signed_unpublished"
    result["created_keys"] = created_keys
    return result
