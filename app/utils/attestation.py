
from datetime import datetime, timezone
import hashlib, json
from pydantic import BaseModel
from utils.cryptographic_signing import get_local_signature
from models.models import DNSChangeLog
from fastapi import Request
from sqlmodel.ext.asyncio.session import AsyncSession
import json
from typing import Optional
import uuid

class DNSChangeAttestation(BaseModel):
    domain: str
    action: str  # 'ADD', 'UPDATE', 'DELETE'
    record: dict
    snapshot_hash: str
    signature: str
    public_key: str
    ip_address: str
    user_id: str

def create_dns_attestation(domain: str, action: str, record: dict, user_id: str, request_or_ip) -> DNSChangeAttestation:
    timestamp = datetime.now(timezone.utc).isoformat()

    # Check if this is a FastAPI Request object or just an IP string
    if hasattr(request_or_ip, "client"):
        ip_address = request_or_ip.client.host
    else:
        ip_address = str(request_or_ip)

    snapshot = {
        "timestamp": timestamp,
        "domain": domain,
        "action": action,
        "record": record,
        "user_id": str(user_id),
        "ip_address": ip_address,
    }

    json_str = json.dumps(snapshot, sort_keys=True, default=str)
    hash_digest = hashlib.sha256(json_str.encode()).hexdigest()

    signed = get_local_signature(hash_digest)

    return DNSChangeAttestation(
        domain=domain,
        action=action,
        record=record,
        snapshot_hash=hash_digest,
        signature=signed["signature"],
        public_key=signed["public_key"],
        ip_address=ip_address,
        user_id=str(user_id)
    )
