import os
import glob
import dns.zone
from dns.rdtypes.ANY.RRSIG import RRSIG
from datetime import datetime, timedelta, timezone
from dnssec import sign_zone_with_keys
from config import KEY_DIR, ZONE_DIR, EXPIRY_THRESHOLD_DAYS

def get_domains_from_keys():
    """Infer active domains from existing DNSSEC key files."""
    domains = set()
    for path in glob.glob(str(KEY_DIR / "K*.key")):
        filename = os.path.basename(path)
        if filename.startswith("K") and "+008+" in filename:
            domain = filename.split("+")[0][1:]  # Strip leading 'K'
            domains.add(domain)
    return domains

def earliest_rrsig_expiry(zone_file, domain):
    z = dns.zone.from_file(str(zone_file), origin=domain + ".", relativize=False)
    expiries = []
    for name, node in z.nodes.items():
        for rdataset in node.rdatasets:
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                for rdata in rdataset:
                    val = rdata.expiration
                    if isinstance(val, int):  # UNIX timestamp
                        dt = datetime.fromtimestamp(val, timezone.utc)
                    elif isinstance(val, str):
                        dt = datetime.strptime(val, "%Y%m%d%H%M%S")
                    elif isinstance(val, datetime):
                        dt = val
                    else:
                        print(f"[WARN] Unknown timestamp type: {type(val)}: {val}")
                        continue
                    expiries.append(dt)
    return min(expiries) if expiries else None

def main():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold = now + timedelta(days=EXPIRY_THRESHOLD_DAYS)
    
    for domain in get_domains_from_keys():
        domain = domain.rstrip('.')
        signed_path = ZONE_DIR / f"{domain}.zone"
        try:
            min_expiry = earliest_rrsig_expiry(signed_path, domain)
            if min_expiry is None:
                print(f"[ERROR] No RRSIG in {domain}")
                continue

            if min_expiry:
                sign_zone_with_keys(domain)
                print(f"[DONE] Re-signed zone for {domain}")
            else:
                print(f"[SKIP] {domain} RRSIG valid until {min_expiry}")
        except Exception as e:
            print(f"[FAIL] Could not process {domain}: {e}")

if __name__ == "__main__":
    main()
