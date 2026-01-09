# dns_routes.py (updated with ns_ip)
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
from zone_manager import generate_zone_file, write_zone_file_to_disk, reload_coredns, sign_zone_with_dnssec
from auth import verify_hmac, hmac_protected

router = APIRouter(prefix="/internal/dns")

class ZonePushRequest(BaseModel):
    domain: str
    records: list  # List of dicts: [{type, name, value, ttl, ...}]

@router.post("/push")
@hmac_protected()
async def push_zone(req: ZonePushRequest, request: Request):

    #await verify_hmac(request, x_signature)

    try:
        zone_text = generate_zone_file(req.domain, req.records)
        write_zone_file_to_disk(req.domain, zone_text)
        sign_zone_with_dnssec(req.domain)
        reload_coredns()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
