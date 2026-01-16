from fastapi import APIRouter, Request, HTTPException
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