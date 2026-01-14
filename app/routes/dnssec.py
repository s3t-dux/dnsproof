from fastapi import APIRouter, Request, HTTPException
from utils.agents import call_agent_hmac_async
from config import AGENT_IP
router = APIRouter()

# Enable DNSSEC (generate keys and return DS record)
@router.post("/enable/{domain}")
async def enable_dnssec(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/enable/{domain}"
    )
    return response.json()

# Disable DNSSEC
@router.post("/disable/{domain}")
async def disable_dnssec(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/disable/{domain}"
    )
    return response.json()

# Trigger re-signing (e.g. via cron or manual)
@router.post("/resign/{domain}")
async def resign_zone(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/resign/{domain}"
    )
    return response.json()

@router.get("/status/{domain}")
async def resign_zone(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/status/{domain}",
        method="GET"
    )
    return response.json()