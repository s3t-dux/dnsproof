# dns_routes.py (updated with ns_ip)
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
from zone_manager import generate_zone_file, write_zone_file_to_disk, reload_coredns, sign_zone_with_dnssec
from dnssec import sign_dnssec
from auth import hmac_protected

router = APIRouter(prefix="/internal/dns")

class ZonePushRequest(BaseModel):
    domain: str
    records: list  # List of dicts: [{type, name, value, ttl, ...}]

@router.post("/push")
@hmac_protected()
async def push_zone(req: ZonePushRequest, request: Request):

    try:
        zone_text = generate_zone_file(req.domain, req.records)
        write_zone_file_to_disk(req.domain, zone_text)
        sign_zone_with_dnssec(req.domain)
        reload_coredns()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dnssec/sign/{domain}")
@hmac_protected()
async def sign_zone_internal(domain: str, request: Request):
    return sign_dnssec(domain)