from fastapi import APIRouter, Request, HTTPException
from utils.agents import call_agent_hmac_async
from config import AGENT_IPS, NS1, AGENT_IP

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
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/enable/{domain}"
            )
            data = response.json()
            status = data.get("status")

            if status in SUCCESS_STATES:
                log_dnssec(domain, action="enable", dnssec_meta=data)

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

# Disable DNSSEC
@router.post("/disable/{domain}")
async def disable_dnssec(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/disable/{domain}"
            )
            data = response.json()
            status = data.get("status")

            if status in SUCCESS_STATES:
                log_dnssec(domain, action="disable", dnssec_meta=data)

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

# Trigger re-signing (e.g. via cron or manual)
@router.post("/resign/{domain}")
async def resign_zone(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/resign/{domain}"
            )
            data = response.json()
            status = data.get("status")

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

@router.get("/status-nameserver/{domain}")
async def status_from_ns(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/status/{domain}",
                method="GET"
            )
            data = response.json()
            status = data.get("status")

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}


@router.post("/rotate/{domain}")
async def rotate_dnssec_keys(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/rotate/{domain}"
            )
            data = response.json()
            status = data.get("status")

            if status in SUCCESS_STATES:
                log_dnssec(domain, action="rotate", dnssec_meta=data)

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

@router.post("/rotate/zsk/{domain}")
async def rotate_dnssec_zsk(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/rotate/zsk/{domain}"
            )
            data = response.json()
            status = data.get("status")

            if status in SUCCESS_STATES:
                log_dnssec(domain, action="rotate_zsk", dnssec_meta=data)

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

@router.post("/resign/{domain}")
async def resign_zone_dnssec(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/resign/{domain}"
            )
            data = response.json()
            status = data.get("status")

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

@router.post("/auto_resign/{state}")
async def auto_resign_zone_dnssec(state: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    if not state.lower() in ['on','off']:
        raise HTTPException(status_code=400, detail="state must be on or off")
    
    results = []

    for agent_ip in AGENT_IPS:
        try:
            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/auto_resign/{state}"
            )
            data = response.json()
            status = data.get("status")

            results.append({"ip": agent_ip, "status": status, "detail": data})
        except Exception as e:
            results.append({"ip": agent_ip, "status": "error", "error": str(e)})

    return {"results": results}

    if not AGENT_IP:
        raise HTTPException(status_code=400, detail="Missing agent_ip")

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
    
@router.get("/status/{domain}")
async def dnssec_status(domain: str):
    if not AGENT_IPS:
        raise HTTPException(status_code=400, detail="Missing agent IPs")

    # Step 1: DNS-level checks
    ns_queried = query_ns_direct(AGENT_IPS[0], domain)  # You can use any IP here
    ns_ok = check_nameserver(NS1, ns_queried)
    ds = has_ds(domain)

    # Step 2: Per-agent RRSIG and DNSSEC API checks
    rrsig_flags = []
    agent_results = []

    for agent_ip in AGENT_IPS:
        try:
            has_rrsig_flag = has_rrsig(domain, agent_ip)
            rrsig_flags.append(has_rrsig_flag)

            response = await call_agent_hmac_async(
                ip=agent_ip,
                path=f"/internal/dns/dnssec/status/{domain}",
                method="GET"
            )
            data = response.json()

            agent_results.append({
                "ip": agent_ip,
                "status": "ok",
                "rrsig": has_rrsig_flag,
                "dnssec": data
            })
        except Exception as e:
            agent_results.append({
                "ip": agent_ip,
                "status": "error",
                "error": str(e),
                "rrsig": False,
                "dnssec": None
            })
            rrsig_flags.append(False)

    # Step 3: Aggregate best-known values
    any_rrsig = any(rrsig_flags)

    # Pick first valid result for metadata (could be improved with consensus or primary-first)
    first_valid = next((r for r in agent_results if r["status"] == "ok" and r["dnssec"]), None)
    dnssec_data = first_valid["dnssec"] if first_valid else {}

    ds_records = []
    ksk_created_at = None
    zsk_created_at = None
    days_since_last_key_creation = None
    days_before_rrsig_expiration = None
    auto_resign_enabled = None
    note = None

    if dnssec_data:
        ds_records = [
            dnssec_data.get("key_tag"),
            dnssec_data.get("algorithm"),
            dnssec_data.get("digest_type"),
            dnssec_data.get("ds_digest"),
        ]
        ksk_created_at = dnssec_data.get("ksk_created_at")
        zsk_created_at = dnssec_data.get("zsk_created_at")
        days_since_last_key_creation = dnssec_data.get("days_since_last_key_creation")
        days_before_rrsig_expiration = dnssec_data.get("days_before_rrsig_expiration")
        auto_resign_enabled = dnssec_data.get("auto_resign_enabled")
        note = dnssec_data.get("note")

    # Step 4: Final status logic
    if any_rrsig and ds:
        status = "published"
        message = "DNSSEC is fully enabled and published"
    elif any_rrsig:
        status = "signed_unpublished"
        message = "Domain is signed but DS record not published in parent zone"
    elif ds:
        status = "not_signed_but_published"
        message = "DS record exists but domain is not signed (likely disabling)"
    else:
        status = "disabled"
        message = "DNSSEC is not enabled"

    return {
        "domain": domain,
        "status": status,
        "message": message,
        "ds_records": ds_records,
        "ksk_created_at": ksk_created_at,
        "zsk_created_at": zsk_created_at,
        "days_since_last_key_creation": days_since_last_key_creation,
        "days_before_rrsig_expiration": days_before_rrsig_expiration,
        "auto_resign_enabled": auto_resign_enabled,
        "note": note,
        "details": {
            "has_rrsig": any_rrsig,
            "has_ds": ds,
            "nameservers_checked": AGENT_IPS,
            "nameservers_verified": ns_ok,
            "agents": agent_results,
        }
    }

# legacy code 
'''
# Update the dnssec_status route to include GCS check and DS records
@router.get("/legacy/status/{domain}")
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
    print(f"[DEBUG] AGENT_IP: {AGENT_IP}")
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
'''