from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from utils.agents import call_agent_hmac_async
from fastapi import APIRouter, HTTPException, Request
from utils.zone_json import add_record, edit_record, delete_record, load_zone_json
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
    records: list[DNSRecord]

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
    new_records = req.records

    added = []
    errors = []

    for rec in new_records:
        try:
            add_record(domain, rec.dict())
            added.append(rec)
        except ValueError as ve:
            errors.append({"record": rec, "error": str(ve)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    # After all adds, push to agent
    zone_json = load_zone_json(domain)
    try:
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zone updated locally but failed to push to agent: {e}")

    return {
        "status": "success",
        "added_count": len(added),
        "skipped": errors
    }

class EditRecordItem(BaseModel):
    record_id: str
    record: DNSRecord

class EditRecordsRequest(BaseModel):
    domain: str
    edits: list[EditRecordItem]

@router.put("/records")
async def edit_dns_records(req: EditRecordsRequest):
    domain = req.domain
    edits = req.edits

    updated = []
    errors = []

    for item in edits:
        try:
            edit_record(domain, item.record_id, item.record.dict())
            updated.append(item.record_id)
        except ValueError as ve:
            errors.append({"record_id": item.record_id, "error": str(ve)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    # Push final updated zone
    zone_json = load_zone_json(domain)
    try:
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zone updated locally but failed to push to agent: {e}")

    return {
        "status": "success",
        "updated_count": len(updated),
        "updated_ids": updated,
        "skipped": errors
    }

class DeleteRecordsRequest(BaseModel):
    domain: str
    record_ids: list[str]

@router.delete("/records")
async def delete_dns_records(req: DeleteRecordsRequest):
    domain = req.domain
    ids = req.record_ids

    deleted = []
    errors = []

    for record_id in ids:
        try:
            delete_record(domain, record_id)
            deleted.append(record_id)
        except ValueError as ve:
            errors.append({"record_id": record_id, "error": str(ve)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    # Push zone only once
    zone_json = load_zone_json(domain)
    try:
        await call_agent_hmac_async(
            ip=AGENT_IP,
            path="/internal/dns/push",
            json=zone_json
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zone updated locally but failed to push to agent: {e}")

    return {
        "status": "success",
        "deleted_count": len(deleted),
        "deleted_ids": deleted,
        "skipped": errors
    }
