from fastapi import APIRouter, Request, HTTPException
from utils.agents import call_agent_hmac_async
from config import AGENT_IP, NS1

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
from utils.dns import trace_ns, query_ns_direct
from utils.dnssec_logging import log_dnssec

router = APIRouter()

SUCCESS_STATES = {
    "signed_unpublished",
    "signed",
    "rotated_signed_unpublished",
    "zsk_rotated_signed",
    "disabled"
}

# Enable DNSSEC (generate keys and return DS record)
@router.post("/enable/{domain}")
async def enable_dnssec(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/enable/{domain}"
    )
    data = response.json()
    if data.get("status") in SUCCESS_STATES:
        log_dnssec(domain, action="enable", dnssec_meta=data)

    return data

# Disable DNSSEC
@router.post("/disable/{domain}")
async def disable_dnssec(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/disable/{domain}"
    )
    data = response.json()
    if data.get("status") in SUCCESS_STATES:
        log_dnssec(domain, action="disable", dnssec_meta=data)

    return data

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

@router.get("/status-nameserver/{domain}")
async def status_from_ns(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/status/{domain}",
        method="GET"
    )
    return response.json()

@router.post("/rotate/{domain}")
async def rotate_dnssec_keys(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/rotate/{domain}"
    )
    data = response.json()
    if data.get("status") in SUCCESS_STATES:
        log_dnssec(domain, action="rotate", dnssec_meta=data)

    return data

@router.post("/rotate/zsk/{domain}")
async def rotate_dnssec_zsk(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/rotate/zsk/{domain}"
    )
    data = response.json()
    if data.get("status") in SUCCESS_STATES:
        log_dnssec(domain, action="rotate_zsk", dnssec_meta=data)

    return data

@router.post("/resign/{domain}")
async def resign_zone_dnssec(domain: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/resign/{domain}"
    )
    return response.json()

@router.post("/auto_resign/{state}")
async def auto_resign_zone_dnssec(state: str):
    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")
    
    if not state.lower() in ['on','off']:
        raise HTTPException(status_code=400, detail="state must be on or off")

    response = await call_agent_hmac_async(
        ip=AGENT_IP,
        path=f"/internal/dns/dnssec/auto_resign/{state}"
    )
    return response.json()

def has_rrsig(domain: str, nameserver: str) -> bool:
    """Check if domain has RRSIG records (DNSSEC signatures)"""
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, nameserver, timeout=2)
        return any(ans.rdtype == dns.rdatatype.RRSIG for ans in response.answer + response.authority)
    except Exception:
        return False
    
def has_ds(domain: str) -> bool:
    """Check if domain has DS records published in parent zone"""
    '''
    try:
        answers = dns.resolver.resolve(domain, "DS", raise_on_no_answer=False)
        return bool(answers.rrset)
    except Exception:
        return False
    '''
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]  # Cloudflare DNS
        answers = resolver.resolve(domain, "DS", raise_on_no_answer=False)
        print(f"DS answer from resolver: {answers.rrset}")
        return bool(answers.rrset)
    except Exception as e:
        print(f"DS check error: {e}")
        return False

def check_nameserver(NS, NS_candidates):
    if NS in [ns.rstrip('.') for ns in NS_candidates]:
        return True
    else:
        return False
    
# Update the dnssec_status route to include GCS check and DS records
@router.get("/status/{domain}")
async def dnssec_status(
    domain: str,
):
    """Get DNSSEC status for a domain"""
    
    print(f"[DEBUG] here")
    # Get authentication context (existing code)
    #auth_obj = await api_key_or_jwt_auth(request, session)
    
    #trace_result = trace_ns(domain)
    #ns_ok = trace_result.get("status", False)
    ns_queried = query_ns_direct(AGENT_IP, domain)
    ns_ok = check_nameserver(NS1,ns_queried)

    # Check DNSSEC status (existing code)
    ds = has_ds(domain)
    rrsig = any(has_rrsig(domain, ip) for ip in [AGENT_IP])
    
    # NEW: Check GCS for keys and get DS records
    #keys_in_gcs = keys_exist_in_gcs(domain)
    #ds_records = get_ds_records_from_gcs(domain) if keys_in_gcs else []

    dnssec_vm = await call_agent_hmac_async(
        AGENT_IP,
        path=f"/internal/dns/dnssec/status/{domain}",
        method="GET"
        )
    ds_records = []
    ksk_created_at = None
    zsk_created_at = None
    days_since_last_key_creation = None
    days_before_rrsig_expiration = None
    auto_resign_enabled = None
    note = None
    if dnssec_vm:
        dnssec_result = dnssec_vm.json()
        print(f"[DEBUG] dnssec_result: {dnssec_result}")
        ds_records = [dnssec_result["key_tag"], dnssec_result["algorithm"], dnssec_result["digest_type"], dnssec_result["ds_digest"]]
        ksk_created_at = dnssec_result["ksk_created_at"]
        zsk_created_at = dnssec_result["zsk_created_at"]
        days_since_last_key_creation = dnssec_result["days_since_last_key_creation"]
        days_before_rrsig_expiration = dnssec_result["days_before_rrsig_expiration"]
        auto_resign_enabled = dnssec_result["auto_resign_enabled"]
        if "note" in dnssec_result:
            note = dnssec_result["note"]

    # Determine status (updated logic)
    if rrsig and ds:
        status = "published"
        message = "DNSSEC is fully enabled and published"
    #elif rrsig or keys_in_gcs:  # Include GCS check for signed status
    elif rrsig:
        status = "signed_unpublished"
        message = "Domain is signed but DS record not published in parent zone"
    elif ds:
        status = "not_singed_but_published"
        message = "DS record exists but domain is not signed (likely disabling)"
    else:
        status = "disabled"
        message = "DNSSEC is not enabled"

    '''
    # save the DNSSEC status to UserDomain
    domain_result = await session.exec(
            select(UserDomain).where(
                UserDomain.organization_id == UUID(organization_id),
                UserDomain.domain == domain
        )
    )
    domain_result = domain_result.first()
    domain_result.verified_dnssec = (rrsig and ds)
    session.add(domain_result)
    await session.commit()
    '''
    return {
        "domain": domain,
        #"organization_id": org_id,
        "status": status,
        "message": message,
        "ds_records": ds_records,  # NEW: Include DS records
        "ksk_created_at": ksk_created_at,
        "zsk_created_at": zsk_created_at,
        "days_since_last_key_creation": days_since_last_key_creation,
        "days_before_rrsig_expiration": days_before_rrsig_expiration,
        "auto_resign_enabled": auto_resign_enabled,
        "note": note,
        "details": {
            "has_rrsig": rrsig,
            "has_ds": ds,
            #"has_keys_in_gcs": keys_in_gcs,  # NEW: GCS key status
            "nameservers_checked": [AGENT_IP],
            "nameservers_verified": ns_ok,              
            #"nameservers_trace": trace_result 
        }
    }
