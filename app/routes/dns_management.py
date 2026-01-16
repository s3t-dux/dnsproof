from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from utils.agents import call_agent_hmac_async
from fastapi import APIRouter, HTTPException, Request
from utils.zone_json import add_record, edit_record, delete_record, load_zone_json
from config import AGENT_IP

from config import AGENT_IP

router = APIRouter()

class DNSRecord(BaseModel):
    type: str
    name: str
    value: str
    ttl: Optional[int] = 3600
    priority: Optional[int] = None
    port: Optional[int] = None
    target: Optional[str] = None

class AddRecordRequest(BaseModel):
    domain: str
    record: DNSRecord

@router.post("/push")
async def push_zone(request: Request):
    body = await request.json()

    if not AGENT_IP or not body:
        raise HTTPException(status_code=400, detail="Missing agent_ip or zone file")

    if not body:
        raise HTTPException(status_code=400, detail="Missing zone payload")

    # Forward directly as-is to agent
    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path="/internal/dns/push",
        json=body,
    )
    return response.json()

# Not exposing the delete endpoint to the app
'''
# Example: Delete zone from agent
@router.delete("/delete-zone")
async def delete_zone(domain: str, request: Request):
    body = await request.json()
    agent_ip = body.get("agent_ip")

    if not agent_ip:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=agent_ip,
        path=f"/internal/delete_zone",
        method="DELETE",
    )
    return {"status": "deleted"}
'''

@router.post("/records")
async def add_dns_record(req: AddRecordRequest):
    domain = req.domain
    record = req.record.dict()

    try:
        add_record(domain, record)

        zone_json = load_zone_json(domain)
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )

        return {"status": "success", "message": "Record added and zone deployed."}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add DNS record: {e}")

@router.put("/records/{record_id}")
async def edit_dns_record(req: AddRecordRequest, record_id: str):
    domain = req.domain
    record = req.record.dict()

    try:
        edit_record(domain, record_id, record)

        zone_json = load_zone_json(domain)
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )

        return {"status": "success", "message": "Record updated and zone deployed."}

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update DNS record: {e}")

@router.delete("/records/{record_id}")
async def delete_dns_record(domain: str, record_id: str):
    try:
        delete_record(domain, record_id)

        zone_json = load_zone_json(domain)
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )

        return {"status": "success", "message": "Record deleted and zone deployed."}

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete DNS record: {e}")
