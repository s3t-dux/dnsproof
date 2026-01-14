# dns_routes.py (updated with ns_ip)
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
from zone_manager import generate_zone_file, write_zone_file_to_disk, reload_coredns, sign_zone_with_dnssec, delete_zone_completely
from dnssec import enable_dnssec, disable_dnssec, get_dnssec_status, rotate_dnssec_key_pair, rotate_zsk_only, resign_zone_file
from auth import hmac_protected
from config import JSON_DIR
import json
import os

router = APIRouter(prefix="/internal/dns")

class ZonePushRequest(BaseModel):
    domain: str
    records: list  # List of dicts: [{type, name, value, ttl, ...}]

@router.post("/push")
@hmac_protected()
async def push_zone(req: ZonePushRequest, request: Request):

    data = await request.json()
    # 1. Save JSON
    JSON_DIR.mkdir(parents=True, exist_ok=True)
    json_path = JSON_DIR / f"{req.domain}.json"
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    try:
        zone_text = generate_zone_file(req.domain, req.records)
        write_zone_file_to_disk(req.domain, zone_text)
        sign_zone_with_dnssec(req.domain)
        reload_coredns()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dnssec/enable/{domain}")
@hmac_protected()
async def enable_zone_internal(domain: str, request: Request):
    return enable_dnssec(domain)

@router.post("/dnssec/disable/{domain}")
@hmac_protected()
async def disable_dnssec_route(domain: str, request: Request):
    try:
        disable_dnssec(domain)

        JSON_DIR.mkdir(parents=True, exist_ok=True)
        json_path = JSON_DIR / f"{domain}.json"

        with open(json_path, 'r') as f:
            json_file = json.load(f)
            records = json_file['records']

        zone_text = generate_zone_file(domain, records)
        write_zone_file_to_disk(domain, zone_text)
        reload_coredns()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/dnssec/status/{domain}")
@hmac_protected()
async def get_dnssec_status_route(domain: str, request: Request):
    return get_dnssec_status(domain)

@router.post("/dnssec/rotate/{domain}")
@hmac_protected()
async def rotate_dnssec_key_pair_route(domain: str, request: Request):
    return rotate_dnssec_key_pair(domain)

@router.post("/dnssec/rotate/zsk/{domain}")
@hmac_protected()
async def rotate_zsk_only_route(domain: str, request: Request):
    return rotate_zsk_only(domain)

@router.post("/dnssec/resign/{domain}")
@hmac_protected()
async def resign_zone_file_route(domain: str, request: Request):
    return resign_zone_file(domain)

@router.post("/dnssec/auto_resign/{state}")
@hmac_protected()
async def toggle_auto_resign(state: str, request: Request):
    state = state.lower()
    if state not in ["on", "off"]:
        raise HTTPException(status_code=400, detail="State must be 'on' or 'off'")
    
    os.makedirs("/etc/dnsproof", exist_ok=True)
    with open("/etc/dnsproof/auto_resign_enabled", "w") as f:
        f.write("true" if state == "on" else "false")
    
    return {"auto_resign": state}

@router.delete("/delete/{domain}")
@hmac_protected()
async def delete_zone_completely_route(domain: str, request: Request):
    try:
        delete_zone_completely(domain)
        return {"status": "zone deleted", "domain": domain}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete zone: {str(e)}")
