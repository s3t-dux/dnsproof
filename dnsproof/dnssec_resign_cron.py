import os
import glob
import dns.zone
from dns.rdtypes.ANY.RRSIG import RRSIG
from datetime import datetime, timedelta, timezone
from dnssec import sign_zone_with_keys, earliest_rrsig_expiry, is_auto_resign_enabled
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

def main():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold = now + timedelta(days=EXPIRY_THRESHOLD_DAYS)

    if not is_auto_resign_enabled():
        print(f"[SKIP] Auto re-signing disabled by config at {now}")
        exit(0)

    domains = get_domains_from_keys()
    if domains:
        for domain in get_domains_from_keys():
            domain = domain.rstrip('.')
            signed_path = ZONE_DIR / f"{domain}.zone"
            try:
                min_expiry = earliest_rrsig_expiry(signed_path, domain)
                if min_expiry is None:
                    print(f"[ERROR] No RRSIG in {domain} at {now}")
                    continue

                if (min_expiry - datetime.now(tz=timezone.utc)).days < EXPIRY_THRESHOLD_DAYS:
                    sign_zone_with_keys(domain)
                    print(f"[DONE] Re-signed zone for {domain} at {now}")
                else:
                    print(f"[SKIP] {domain} RRSIG valid until {min_expiry} as of {now}")
            except Exception as e:
                print(f"[FAIL] Could not process {domain}: {e} at {now}")
    else:
        print(f"DNSSEC is disabled - at {now}")

if __name__ == "__main__":
    main()
