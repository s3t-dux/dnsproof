from models.models import DNSSECLog
from utils.db import engine
from sqlmodel import Session

def log_dnssec(domain: str, action: str, dnssec_meta: dict = {}, user_id="system", ip_address="127.0.0.1"):
    log_entry = DNSSECLog(
        domain=domain,
        action=action,
        key_tag=dnssec_meta.get("key_tag"),
        algorithm=dnssec_meta.get("algorithm"),
        ds_digest=dnssec_meta.get("ds_digest"),
        ds_digest_type=dnssec_meta.get("digest_type"),
        ip_address=ip_address,
        user_id=user_id
    )

    try:
        with Session(engine) as session:
            session.add(log_entry)
            session.commit()
            print(f"[LOG] DNSSEC {action} logged for {domain}")
    except Exception as e:
        print(f"[ERROR] Failed to log DNSSEC event: {e}")
