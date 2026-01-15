from fastapi import APIRouter, Request, HTTPException
from utils.agents import call_agent_hmac_async
from utils.dns import query_ns_direct, check_ns_propagation_status
from config import AGENT_IP, NS1

router = APIRouter()

@router.get("/verify-ns/{domain}")
async def verify_ns_route(domain: str, request: Request):
    
    if not domain:
        raise HTTPException(status_code=400, detail="Missing domain")
    
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    return query_ns_direct(AGENT_IP, domain)

@router.get("/ns_propagation_status/{domain}")
async def ns_propagation_status_route(domain: str):
    return check_ns_propagation_status(domain, {NS1})

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