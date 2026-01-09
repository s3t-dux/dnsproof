# dns_routes.py (updated with ns_ip)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from zone_manager import generate_zone_file, write_zone_file_to_disk, reload_coredns, sign_zone_with_dnssec

router = APIRouter(prefix="/internal/dns")

class ZonePushRequest(BaseModel):
    domain: str
    records: list  # List of dicts: [{type, name, value, ttl, ...}]

@router.post("/push")
def push_zone(req: ZonePushRequest):
    try:
        zone_text = generate_zone_file(req.domain, req.records)
        write_zone_file_to_disk(req.domain, zone_text)
        sign_zone_with_dnssec(req.domain)
        reload_coredns()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
