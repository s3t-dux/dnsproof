from fastapi import APIRouter, HTTPException, Depends, Request
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
from uuid import UUID
#from pydantic import BaseModel
#from sqlmodel.ext.asyncio.session import AsyncSession
#from sqlmodel import select

from config import AGENT_IP
from utils.agents import call_agent_hmac_async
#from utils.auth import api_key_or_jwt_auth
#from utils.access_management import verify_user_org_access
#from utils.db import get_session
#from utils.access_management import verify_domain_access
#from models.models import APIKey, UserDomain
from utils.dns import trace_ns, query_ns_direct

router = APIRouter()

AGENT_IPS = [AGENT_IP]
'''
# Request models for organization context
class DNSSECRequest(BaseModel):
    organization_id: str
'''
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
'''    
def get_ds_records_from_gcs(domain: str) -> list:
    """Retrieve DS records from GCS bucket for a domain"""
    try:
        client = storage.Client()
        bucket = client.bucket(DNSSEC_BUCKET)
        
        # List all blobs with the domain prefix
        blobs = list(bucket.list_blobs(prefix=f"keys/{domain}/"))
        
        ds_records = []
        for blob in blobs:
            # Check if this is a DS record file
            if blob.name.endswith('.ds'):
                try:
                    ds_content = blob.download_as_text().strip()
                    if ds_content:
                        ds_records.append(ds_content)
                except Exception as e:
                    print(f"Error reading DS file {blob.name}: {e}")
                    continue
        
        return ds_records
        
    except Exception as e:
        print(f"Error accessing GCS bucket for domain {domain}: {e}")
        return []
    
def keys_exist_in_gcs(domain: str) -> bool:
    """Check if DNSSEC keys exist in GCS for a domain"""
    try:
        client = storage.Client()
        bucket = client.bucket(DNSSEC_BUCKET)
        
        # Check if any key files exist
        blobs = list(bucket.list_blobs(prefix=f"keys/{domain}/", max_results=1))
        return len(blobs) > 0
        
    except Exception as e:
        print(f"Error checking GCS bucket for domain {domain}: {e}")
        return False
'''
# Update the dnssec_status route to include GCS check and DS records
@router.get("/status/{domain}")
async def dnssec_status_app(
    domain: str,
    #organization_id: str = None,
    #request: Request = None,
    #session: AsyncSession = Depends(get_session)
):
    """Get DNSSEC status for a domain"""
    
    print(f"[DEBUG] here")
    # Get authentication context (existing code)
    #auth_obj = await api_key_or_jwt_auth(request, session)
    '''
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        
        if not organization_id:
            raise HTTPException(status_code=400, detail="organization_id required for JWT auth")
        
        if not await verify_user_org_access(user_id, UUID(organization_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")
        
        org_id = organization_id

    # Verify domain access (existing code)
    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")
    '''
    #trace_result = trace_ns(domain)
    #ns_ok = trace_result.get("status", False)
    ns_ok = True

    # Check DNSSEC status (existing code)
    ds = has_ds(domain)
    rrsig = any(has_rrsig(domain, ip) for ip in AGENT_IPS)
    
    # NEW: Check GCS for keys and get DS records
    #keys_in_gcs = keys_exist_in_gcs(domain)
    #ds_records = get_ds_records_from_gcs(domain) if keys_in_gcs else []

    dnssec_vm = await call_agent_hmac_async(
        AGENT_IP,
        path=f"/internal/dns/dnssec/status/{domain}",
        method="GET"
        )
    ds_records = []
    if dnssec_vm:
        dnssec_result = dnssec_vm.json()
        print(f"[DEBUG] dnssec_result: {dnssec_result}")
        ds_records = [dnssec_result["key_tag"], dnssec_result["algorithm"], dnssec_result["digest_type"], dnssec_result["ds_digest"]]

    # Determine status (updated logic)
    if rrsig and ds:
        status = "published"
        message = "DNSSEC is fully enabled and published"
    #elif rrsig or keys_in_gcs:  # Include GCS check for signed status
    elif rrsig:
        status = "signed_unpublished"
        message = "Domain is signed but DS record not published in parent zone"
    elif ds:
        status = "error"
        message = "DS record exists but domain is not signed (configuration error)"
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
        "details": {
            "has_rrsig": rrsig,
            "has_ds": ds,
            #"has_keys_in_gcs": keys_in_gcs,  # NEW: GCS key status
            "nameservers_checked": AGENT_IPS,
            "nameservers_verified": ns_ok,              
            #"nameservers_trace": trace_result 
        }
    }

@router.get("/test/{domain}")
async def test(domain: str):
    return f"Hello {domain}"