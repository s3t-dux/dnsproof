from fastapi import APIRouter, Request, HTTPException
from utils.dns import query_ns_direct, check_ns_propagation_status
from config import AGENT_IPS, NS_NAMES

router = APIRouter()

@router.get("/verify-ns/{domain}")
async def verify_ns_route(domain: str, request: Request):
    
    if not domain:
        raise HTTPException(status_code=400, detail="Missing domain")
    
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")
    
    results = []

    for agent_ip in AGENT_IPS:
        results.append({"ip": agent_ip, "details": query_ns_direct(agent_ip, domain)})

    return results

@router.get("/ns_propagation_status/{domain}")
async def ns_propagation_status_route(domain: str):
    return check_ns_propagation_status(domain, {s for s in NS_NAMES})