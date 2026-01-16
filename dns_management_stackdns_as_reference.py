# routes/dns_management.py

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from sqlalchemy import select, func, delete
from uuid import UUID
from typing import List, Optional, Dict, Any, Tuple
from starlette.datastructures import Headers
from uuid import uuid4
import json
import os
from pathlib import Path
import shutil
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from urllib.parse import urlparse
import logging
from utils.db import get_session, async_session
from utils.auth import api_key_or_jwt_auth
from utils.access_management import verify_user_org_access, verify_domain_access
from utils.dns import (
    verify_nameservers, 
    is_valid_public_ip, 
    fetch_and_save_existing_records,
    trace_ns,
    split_fqdn,
    load_zone_from_gcs, 
    save_zone_to_gcs, 
    copy_zone_in_gcs,
    delete_zone_from_gcs,
    draft_file_exists,
    check_ip_blacklist
)
from utils.agents import call_agent, call_agent_hmac
from utils.proxy_routes import normalize_upstream_url
from utils.acme import request_cert_challenge, dig_txt_challenge, finalize_cert
from utils.datetime_utils import get_current_datetime_without_timezone
from utils.dns_logging import save_dns_change_log, create_dns_attestation, safe_json_dumps
from utils.send_nameserver_completion_email import send_nameserver_migration_completed_email
from routes.stripe_checkout import get_admin_email_for_org
from models.models import APIKey, UserDomain, ProxyRoute, ZoneOnboarding, Organization, DNSChangeLog
#from config import JSON_DIR,JSON_DRAFT_DIR, NS1_IP, NS2_IP, PROXY_AGENT_IP, PROXY_LIMIT_FREE, PROXY_LIMIT_PLUS, PROXY_LIMIT_PRO
from config import NS1_IP, NS2_IP, PROXY_AGENT_IP, PROXY_LIMIT_FREE, PROXY_LIMIT_PLUS, PROXY_LIMIT_PRO, DEFAULT_TTL
import logging

router = APIRouter(prefix="/api/dns")

AGENT_IPS = [NS1_IP, NS2_IP]

# ----------------------
# Helper Functions for Stable Record IDs
# ----------------------
def generate_record_id(domain: str, record_type: str, name: str, value: str, priority: Optional[int] = None) -> str:
    """Generate a stable, deterministic ID for a DNS record"""
    priority_str = str(priority) if priority is not None else ""
    composite = f"{domain}:{record_type}:{name}:{value}:{priority_str}"
    return hashlib.sha256(composite.encode()).hexdigest()[:12]

def extract_record_value(record_entry: Any, record_type: str) -> str:
    if isinstance(record_entry, dict):
        if record_type == "SRV":
            return f"{record_entry.get('weight', 0)} {record_entry.get('port', 80)} {record_entry.get('target', '')}"
        elif record_type == "CAA":
            return f"{record_entry.get('flags', 0)} {record_entry.get('tag', '')} {record_entry.get('value', '')}"
        elif "value" in record_entry:
            return record_entry["value"]
        elif "target" in record_entry:
            return record_entry["target"]
        else:
            return str(record_entry)
    return str(record_entry)

# legacy code with bugs
'''
def extract_record_value(record_entry: Any) -> str:
    """Extract the main value from a record entry (handles objects and strings)"""
    if isinstance(record_entry, dict):
        if "value" in record_entry:
            return record_entry["value"]
        elif "target" in record_entry:
            return record_entry["target"]
        else:
            # For complex records like CAA, create a composite value
            return str(record_entry)
    return str(record_entry)
'''

def find_record_by_id(zone_data: Dict[str, Any], record_id: str, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Find record location in zone_data by hash ID.
    Returns: (record_type, record_name, index_or_none)
    """
    for record_type, entries in zone_data.items():
        for name, values in entries.items():
            print(f"[DEBUG in find_record_by_id] - name: {name}, values: {values}")
            if isinstance(values, list):
                # Handle array records (MX, TXT, CAA, etc.)
                for idx, entry in enumerate(values):
                    if isinstance(entry, dict):
                        # Complex record with priority/flags
                        value = extract_record_value(entry, record_type)
                        priority = entry.get("priority") or entry.get("flags")
                        composite_id = generate_record_id(domain, record_type, name, value, priority)
                    else:
                        # Simple string record
                        composite_id = generate_record_id(domain, record_type, name, str(entry))
                    
                    if composite_id == record_id:
                        return record_type, name, idx
            else:
                # Handle single value records (A, AAAA, CNAME - old format)
                composite_id = generate_record_id(domain, record_type, name, str(values))
                if composite_id == record_id:
                    return record_type, name, None
    
    return None, None, None

def load_draft_file(domain: str) -> list[dict]:
    """
    Load the saved draft zone JSON and flatten it into a list of dicts,
    suitable for the frontend (same as the return of fetch_existing_records_for_migration()).
    """
    try:
        zone_data = load_zone_from_gcs(domain, prefix="json-draft/")
    except Exception as e:
        raise HTTPException(status_code=400, details="zone data does not exist")
    
    flat_records = []
    record_count = 0

    for rtype, entries in zone_data.get(domain, {}).items():
        for name, val in entries.items():
            values = val if isinstance(val, list) else [val]

            for entry in values:
                if record_count >= 30:
                    flat_records.append({
                        "type": "INFO",
                        "name": "Limit Reached",
                        "value": f"Showing first 30 records. Additional records will be migrated."
                    })
                    return flat_records

                record = {
                    "type": rtype,
                    "name": name,
                    "ttl": entry.get("ttl", DEFAULT_TTL)  # Default fallback, can be changed later
                }

                if rtype == "MX" and isinstance(entry, dict):
                    record["priority"] = entry["priority"]
                    record["value"] = entry["value"]
                elif rtype == "CAA" and isinstance(entry, dict):
                    record["value"] = f'{entry["flags"]} {entry["tag"]} "{entry["value"]}"'
                elif rtype == "SRV" and isinstance(entry, dict):
                    record["priority"] = entry["priority"]
                    record["value"] = f'{entry["weight"]} {entry["port"]} {entry["target"]}'
                else:
                    record["value"] = entry["value"]

                flat_records.append(record)
                record_count += 1

    return flat_records
    
def make_simple_record(value: str, ttl: Optional[int] = None) -> dict:
    entry = {"value": value}
    if ttl is not None:
        entry["ttl"] = ttl
    return entry

def make_priority_record(value: str, priority: int, ttl: Optional[int] = None):
    entry = {"value": value, "priority": priority}
    if ttl is not None:
        entry["ttl"] = ttl
    return entry

async def load_dns_records(
    domain: str,
    organization_id: str,
    user_id: Optional[str],
    session: AsyncSession
) -> list[dict]:
    # Check if domain NS is verified (UNCHANGED)
    result = await session.exec(
        select(UserDomain).where(
            UserDomain.domain == domain,
            UserDomain.organization_id == UUID(organization_id)
        )
    )
    domain_obj = result.scalars().first()
    
    if not domain_obj or not domain_obj.verified_ns:
        raise HTTPException(status_code=400, detail="Domain nameservers not verified")

    try:

        zone_data = load_zone_from_gcs(domain, prefix="json/")
        if not zone_data:
            return []

        # 🔥 NEW: Fetch all proxy routes for this domain
        proxy_stmt = select(ProxyRoute).where(
            ProxyRoute.domain == domain,
            ProxyRoute.organization_id == UUID(organization_id)
        )
        proxy_routes_result = await session.exec(proxy_stmt)
        # Group upstreams by (subdomain → list of upstream IPs)
        proxy_groups = defaultdict(list)
        for route in proxy_routes_result.scalars().all():
            if route.proxy_enabled:
                proxy_groups[route.subdomain].append(route.upstream_url)
        
        # Transform zone data to flat records list using stable IDs (UNCHANGED LOGIC)
        records = []
        if domain in zone_data:
            domain_data = zone_data[domain]
            
            # Process A records
            if "A" in domain_data:
                for name, a_values in domain_data["A"].items():
                    upstreams = proxy_groups.get(name, [])
                    
                    if isinstance(a_values, list):
                        for a_value in a_values:
                            normalized_url = normalize_upstream_url(a_value["value"], f"{name}.{domain}" if name != "@" else domain, "A")
                            proxy_enabled = normalized_url in upstreams
                            record_id = generate_record_id(domain, "A", name, str(a_value["value"]))
                            records.append({
                                "id": record_id,
                                "type": "A",
                                "name": name,
                                "value": str(a_value["value"]),
                                "ttl": a_value.get("ttl", DEFAULT_TTL),
                                "proxy_enabled": proxy_enabled  # 🔥 NEW
                            })
                    else:
                        a_value = a_values
                        normalized_url = normalize_upstream_url(a_value["value"], f"{name}.{domain}" if name != "@" else domain, "A")
                        proxy_enabled = normalized_url in upstreams
                        record_id = generate_record_id(domain, "A", name, a_value["value"])
                        records.append({
                            "id": record_id,
                            "type": "A",
                            "name": name,
                            "value": str(a_value["value"]),
                            "ttl": a_value.get("ttl", DEFAULT_TTL),
                            "proxy_enabled": proxy_enabled
                        })
            
            # Process AAAA records
            if "AAAA" in domain_data:
                for name, aaaa_values in domain_data["AAAA"].items():
                    upstreams = proxy_groups.get(name, [])
                    
                    if isinstance(aaaa_values, list):
                        for aaaa_value in aaaa_values:
                            normalized_url = normalize_upstream_url(aaaa_value["value"], f"{name}.{domain}" if name != "@" else domain, "AAAA")
                            proxy_enabled = normalized_url in upstreams
                            record_id = generate_record_id(domain, "AAAA", name, str(aaaa_value["value"]))
                            records.append({
                                "id": record_id,
                                "type": "AAAA",
                                "name": name,
                                "value": str(aaaa_value["value"]),
                                "ttl": aaaa_value.get("ttl", DEFAULT_TTL),
                                "proxy_enabled": proxy_enabled  # 🔥 NEW
                            })
                    else:
                        aaaa_value = aaaa_values
                        normalized_url = normalize_upstream_url(aaaa_value["value"], f"{name}.{domain}" if name != "@" else domain, "AAAA")
                        proxy_enabled = normalized_url in upstreams
                        record_id = generate_record_id(domain, "AAAA", name, aaaa_value["value"])
                        records.append({
                            "id": record_id,
                            "type": "AAAA", 
                            "name": name,
                            "value": str(aaaa_value["value"]),
                            "ttl": aaaa_value.get("ttl", DEFAULT_TTL),
                            "proxy_enabled": proxy_enabled
                        })
            
            # Process CNAME records
            if "CNAME" in domain_data:
                for name, cname_values in domain_data["CNAME"].items():
                    if isinstance(cname_values, list):
                        for cname_value in cname_values:
                            record_id = generate_record_id(domain, "CNAME", name, str(cname_value["value"]))
                            records.append({
                                "id": record_id,
                                "type": "CNAME",
                                "name": name, 
                                "value": str(cname_value["value"]),
                                "ttl": cname_value.get("ttl", DEFAULT_TTL)
                            })
                    else:
                        record_id = generate_record_id(domain, "CNAME", name, str(cname_values["value"]))
                        records.append({
                            "id": record_id,
                            "type": "CNAME",
                            "name": name, 
                            "value": str(cname_values["value"]),
                            "ttl": cname_values.get("ttl", DEFAULT_TTL)
                        })
            
            # Process MX records (UNCHANGED - no proxy status needed)
            if "MX" in domain_data:
                for name, mx_records in domain_data["MX"].items():
                    if isinstance(mx_records, list):
                        for mx_record in mx_records:
                            record_id = generate_record_id(domain, "MX", name, mx_record["value"], mx_record["priority"])
                            records.append({
                                "id": record_id,
                                "type": "MX",
                                "name": name,
                                "value": mx_record["value"],
                                "priority": mx_record["priority"],
                                "ttl": mx_record.get("ttl", DEFAULT_TTL)
                            })
            
            # Process TXT records (UNCHANGED - no proxy status needed)
            if "TXT" in domain_data:
                for name, txt_records in domain_data["TXT"].items():
                    if isinstance(txt_records, list):
                        for txt_value in txt_records:
                            record_id = generate_record_id(domain, "TXT", name, txt_value["value"])
                            records.append({
                                "id": record_id,
                                "type": "TXT",
                                "name": name,
                                "value": txt_value["value"],
                                "ttl": txt_value.get("ttl", DEFAULT_TTL)
                            })
                    else:
                        # Handle string value (e.g. "_dmarc": "v=DMARC1; p=none")
                        txt_record = txt_records  # just rename for clarity
                        record_id = generate_record_id(domain, "TXT", name, txt_record["value"])
                        records.append({
                            "id": record_id,
                            "type": "TXT",
                            "name": name,
                            "value": txt_record["value"],
                            "ttl": txt_record.get("ttl", DEFAULT_TTL)
                        })
            
            # Process SRV records (UNCHANGED - no proxy status needed)
            if "SRV" in domain_data:
                for name, srv_records in domain_data["SRV"].items():
                    if isinstance(srv_records, list):
                        for srv_record in srv_records:
                            srv_value = f"{srv_record.get('weight', 0)} {srv_record.get('port', 80)} {srv_record.get('target', '')}"
                            record_id = generate_record_id(domain, "SRV", name, srv_value, srv_record.get("priority", 10))
                            records.append({
                                "id": record_id,
                                "type": "SRV", 
                                "name": name,
                                "value": srv_value,
                                "priority": srv_record.get("priority", 10),
                                "ttl": srv_record.get("ttl", DEFAULT_TTL)
                            })
                    else:
                        srv_record = srv_records
                        srv_value = f"{srv_record.get('weight', 0)} {srv_record.get('port', 80)} {srv_record.get('target', '')}"
                        record_id = generate_record_id(domain, "SRV", name, srv_value, srv_record.get("priority", 10))
                        records.append({
                            "id": record_id,
                            "type": "SRV", 
                            "name": name,
                            "value": srv_value,
                            "priority": srv_record.get("priority", 10),
                            "ttl": srv_record.get("ttl", DEFAULT_TTL)
                        })
            
            # Process CAA records (UNCHANGED - no proxy status needed)
            if "CAA" in domain_data:
                for name, caa_records in domain_data["CAA"].items():
                    if isinstance(caa_records, list):
                        for caa_record in caa_records:
                            if isinstance(caa_record, dict):
                                caa_value = f"{caa_record.get('flags', 0)} {caa_record.get('tag', '')} {caa_record.get('value', '')}"
                                record_id = generate_record_id(domain, "CAA", name, caa_value, caa_record.get('flags', 0))
                                ttl = caa_record.get("ttl", DEFAULT_TTL)
                            else:
                                caa_value = str(caa_record)
                                record_id = generate_record_id(domain, "CAA", name, caa_value)
                                ttl = DEFAULT_TTL
                            
                            records.append({
                                "id": record_id,
                                "type": "CAA",
                                "name": name,
                                "value": caa_value,
                                "ttl": ttl
                            })
                    else:
                        caa_record = caa_records
                        if isinstance(caa_record, dict):
                            caa_value = f"{caa_record.get('flags', 0)} {caa_record.get('tag', '')} {caa_record.get('value', '')}"
                            record_id = generate_record_id(domain, "CAA", name, caa_value, caa_record.get('flags', 0))
                            ttl = caa_record.get("ttl", DEFAULT_TTL)
                        else:
                            caa_value = str(caa_record)
                            record_id = generate_record_id(domain, "CAA", name, caa_value)
                            ttl = DEFAULT_TTL
                        
                        records.append({
                            "id": record_id,
                            "type": "CAA",
                            "name": name,
                            "value": caa_value,
                            "ttl": ttl
                        })
        
        return records
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load DNS records: {str(e)}")
    
async def enforce_ip_reputation_policy(ip: str, org_id: str, domain: str, session: AsyncSession):
    if not is_valid_public_ip(ip):
        raise HTTPException(status_code=400, detail="A/AAAA value must be a public IP")
    
    try:
        ip_blocklisted = check_ip_blacklist(ip)
    except Exception as e:
        logging.error(f"DNSBL check failed for IP {ip} (domain: {domain}, org: {org_id}): {e}")
        raise HTTPException(status_code=500, detail="Domain reputation check failed. Please try again later.")

    if ip_blocklisted:
        org_result = await session.exec(select(Organization).where(Organization.id == UUID(org_id)))
        org_obj = org_result.scalars().first()
        if not org_obj:
            raise HTTPException(status_code=400, detail="Organization not found")
        if org_obj.tier.lower() == "free":
            raise HTTPException(status_code=400, detail="IP is listed on a known blocklist. Contact support for review.")
        logging.warning(f"IP {ip} is blocklisted but allowed for org {org_id}, domain {domain}")

# ----------------------
# Request Models
# ----------------------
class DNSRecordRequest(BaseModel):
    domain: str
    organization_id: str
    type: str  # A, AAAA, CNAME, MX, TXT, SRV, CAA
    name: str  # @ or subdomain
    value: str
    ttl: Optional[int] = Field(default=300)
    priority: Optional[int] = None  # For MX and SRV records
    proxy_enabled: Optional[bool] = None 

class OnboardDNSRequest(BaseModel):
    organization_id: str

class DeleteRecordRequest(BaseModel):
    domain: str
    organization_id: str
    value: Optional[str] = None

# ----------------------
# Get existing DNS records from current nameservers
# ----------------------
@router.get("/existing-records")
async def get_existing_records(
    domain: str,
    organization_id: str,
    request: Request,
    use_draft: bool = True,
    session: AsyncSession = Depends(get_session)
):
    """Get existing DNS records and save them for migration"""
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")
    
    if use_draft and draft_file_exists(domain):
        try:
            records = load_draft_file(domain)
            return records
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load draft zone: {str(e)}")
    else:
        # Fetch and save records
        result = await fetch_and_save_existing_records(domain, organization_id)
        
        # Check if it's an error response
        if "error" in result:
            # Still return 200 but with error info
            return {
                "records": [],
                "error": result["error"],
                "metadata": result.get("_metadata", {})
            }
        return result

# ----------------------
# Get DNS records from zone JSON files (ENHANCED to include proxy status)
# ----------------------
@router.get("/records")
async def get_dns_records(
    domain: str,
    organization_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Get DNS records for a verified domain from zone JSON files with proxy status"""
    
    # Auth (UNCHANGED)
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")
    
    return await load_dns_records(domain, org_id, user_id, session)

async def rebuild_proxy_route(fqdn: str, domain: str, subdomain: str, record_type: str, session: AsyncSession) -> None:
    # Fetch all enabled upstreams for this FQDN
    result = await session.exec(
        select(ProxyRoute.upstream_url).where(
            ProxyRoute.domain == domain,
            ProxyRoute.subdomain == subdomain,
            ProxyRoute.proxy_enabled == True
        )
    )
    upstream_urls = list(set(result.scalars().all()))  # deduplicate just in case

    if not upstream_urls:
        raise ValueError(f"No proxy routes found for {fqdn}")

    print('='*32)
    print(f"[DEBUG] upstream_urls: {upstream_urls}")
    print('='*32)

    # Send to proxy agent
    proxy_result = call_agent_hmac(PROXY_AGENT_IP, "/internal/proxy/add_route", json={
        "fqdn": fqdn,
        "upstream_urls": upstream_urls,
        "enable_tls": True,
        "host_override": fqdn
    }, timeout=10)

    return proxy_result

# ----------------------
# Helper function to prevent duplicate records
# ----------------------
def is_duplicate_record(existing_records, new_value, record_type, new_priority=None):
    """Check if a record with the same value (and priority if needed) already exists, ignoring TTL."""
    for rec in existing_records:
        if not isinstance(rec, dict):
            continue

        if record_type in ["A", "AAAA", "CNAME", "TXT"]:
            if rec.get("value") == new_value:
                return True

        elif record_type == "MX":
            if rec.get("value") == new_value and rec.get("priority") == new_priority:
                return True

        elif record_type == "SRV":
            parts = new_value.strip().split()
            if len(parts) >= 3:
                try:
                    weight = int(parts[0])
                    port = int(parts[1])
                    target = " ".join(parts[2:])
                    if (
                        rec.get("weight") == weight
                        and rec.get("port") == port
                        and rec.get("target") == target
                        and rec.get("priority") == new_priority
                    ):
                        return True
                except ValueError:
                    continue  # invalid integers in input

        elif record_type == "CAA":
            parts = new_value.strip().split(None, 2)
            if len(parts) >= 3:
                try:
                    flags = int(parts[0])
                    tag = parts[1]
                    value = parts[2]
                    if (
                        rec.get("flags") == flags
                        and rec.get("tag") == tag
                        and rec.get("value") == value
                    ):
                        return True
                except ValueError:
                    continue  # invalid integer in flags

    return False

# ----------------------
# Add DNS record to JSON file (MODIFIED for proxy support)
# ----------------------

@router.post("/records")
async def add_dns_record(
    record_data: DNSRecordRequest,
    request: Request,
    refresh: bool = False,
    session: AsyncSession = Depends(get_session)
):
    """Add a new DNS record to the zone JSON file with proxy support"""
    
    print("🔍 Incoming payload:", await request.json())  # add this line
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = record_data.organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    domain = record_data.domain
    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    # Validate record data
    if record_data.type in ['MX', 'SRV'] and record_data.priority is None:
        raise HTTPException(status_code=400, detail="Priority is required for MX and SRV records")
    
    # Validate IP for A and AAAA
    if record_data.type in ["A", "AAAA"] and not is_valid_public_ip(record_data.value):
        raise HTTPException(status_code=400, detail="A/AAAA value must be a public IP")
    
    # IP block list check
    if record_data.type in ["A", "AAAA"]:
        await enforce_ip_reputation_policy(record_data.value, org_id, domain, session)
        
    try:
        # Load existing zone data
        zone_data = load_zone_from_gcs(domain, prefix="json/")

        # Initialize domain structure if not exists
        if domain not in zone_data:
            zone_data[domain] = {}

        record_type = record_data.type
        record_name = record_data.name if record_data.name != "@" else "@"
        
        # Initialize record type if not exists
        if record_type not in zone_data[domain]:
            zone_data[domain][record_type] = {}

        # 🔥 NEW: Handle proxy logic for A/AAAA/CNAME records
        is_proxiable = record_type in ["A", "AAAA"]
        proxy_enabled = getattr(record_data, 'proxy_enabled', is_proxiable)  # Default ON for proxiable

        print('='*32)
        print(f"[DEBUG] proxy_enabled - {proxy_enabled}")
        print('='*32)
        #upstream_url = record_data.value  # Store original user value

        # before update the JSON zone file, check the proxy limit
        if is_proxiable and proxy_enabled:
            await check_proxy_limit(UUID(org_id), session)
        
        # Prevent duplicate records (ignoring TTL)
        existing_records = zone_data[domain][record_type].get(record_name, [])
        if is_duplicate_record(existing_records, record_data.value, record_type, record_data.priority):
            raise HTTPException(status_code=409, detail="Duplicate record already exists (ignoring TTL)")

        # Add record based on type (ALWAYS store user's original value in JSON)
        if record_type in ["A", "AAAA", "CNAME"]:
            # These can be either single values or arrays
            if record_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][record_name] = []
            
            # Always store as array for consistency - store USER'S original value
            if isinstance(zone_data[domain][record_type][record_name], list):
                zone_data[domain][record_type][record_name].append(make_simple_record(record_data.value, record_data.ttl))
            else:
                # Convert existing single value to array
                existing_value = zone_data[domain][record_type][record_name]
                zone_data[domain][record_type][record_name] = [existing_value, make_simple_record(record_data.value, record_data.ttl)]
            
        elif record_type == "MX":
            # MX records are arrays of {priority, value}
            if record_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][record_name] = []
                zone_data[domain][record_type][record_name].append(make_priority_record(record_data.value, record_data.priority, record_data.ttl))
            
        elif record_type == "TXT":
            # TXT records are arrays of strings
            if record_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][record_name] = []
            zone_data[domain][record_type][record_name].append(make_simple_record(record_data.value, record_data.ttl))
            
        elif record_type == "SRV":
            # SRV records need special parsing of value
            if record_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][record_name] = []
            
            # Parse SRV value format: "weight port target"
            parts = record_data.value.split()
            if len(parts) >= 3:
                weight, port, target = parts[0], parts[1], " ".join(parts[2:])
                if record_data.ttl is None:
                    zone_data[domain][record_type][record_name].append({
                        "priority": record_data.priority,
                        "weight": int(weight),
                        "port": int(port),
                        "target": target
                    })
                else:
                    zone_data[domain][record_type][record_name].append({
                        "priority": record_data.priority,
                        "weight": int(weight),
                        "port": int(port),
                        "target": target,
                        "ttl": record_data.ttl
                    })
            else:
                raise HTTPException(status_code=400, detail="SRV record value must be 'weight port target'")
                
        elif record_type == "CAA":
            # CAA records can be either simple strings or complex objects
            if record_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][record_name] = []
            
            # Parse CAA value format: "flags tag value" (e.g., "0 issue letsencrypt.org")
            parts = record_data.value.split(None, 2)  # Split into max 3 parts
            if len(parts) >= 3:
                flags, tag, value = parts[0], parts[1], parts[2]
                if record_data.ttl is None:
                    zone_data[domain][record_type][record_name].append({
                        "flags": int(flags),
                        "tag": tag,
                        "value": value
                    })
                else:
                    zone_data[domain][record_type][record_name].append({
                        "flags": int(flags),
                        "tag": tag,
                        "value": value,
                        "ttl": record_data.ttl
                    })
            else:
                # Fallback to simple string format
                zone_data[domain][record_type][record_name].append(make_simple_record(record_data.value, record_data.ttl))

        save_zone_to_gcs(domain, zone_data, prefix="json/")

        # 🔥 NEW: Handle ProxyRoute creation for proxiable records
        proxy_result = None
        if is_proxiable:
            fqdn = f"{record_name}.{domain}" if record_name != "@" else domain
            normalized_url = normalize_upstream_url(record_data.value, fqdn, record_type)
            subdomain, root_domain = split_fqdn(f"{record_name}.{domain}" if record_name != "@" else domain)
            # Create or update ProxyRoute record
            stmt = select(ProxyRoute).where(
                ProxyRoute.subdomain == subdomain,
                ProxyRoute.domain == root_domain,
                ProxyRoute.organization_id == UUID(org_id),
                ProxyRoute.upstream_url == normalized_url
            )
            existing_route = (await session.exec(stmt)).scalars().first()
            
            if not existing_route:
                # Add a new ProxyRoute record for this specific IP
                proxy_route = ProxyRoute(
                    domain=root_domain,
                    subdomain=subdomain,
                    organization_id=UUID(org_id),
                    upstream_url=normalized_url,
                    enable_tls=True,
                    proxy_enabled=proxy_enabled,
                    updated_at=get_current_datetime_without_timezone()
                )
                session.add(proxy_route)
                await session.commit()
            else:
                # If the existing route is currently disabled, re-enable it
                if proxy_enabled:
                    existing_route.proxy_enabled = True
                    existing_route.updated_at = get_current_datetime_without_timezone()
                    session.add(existing_route)
                    await session.commit()
                    
            # Rebuild the entire proxy config for this FQDN
            if proxy_enabled:
                try:
                    #fqdn = f"{record_name}.{domain}" if record_name != "@" else domain    # already declared above.
                    proxy_result = await rebuild_proxy_route(fqdn, domain, subdomain, record_type, session)
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Something went wrong in setting a proxy: {e}")

        # 🔥 NEW: Deploy with proxy substitution
        deployment_results = await deploy_zone_to_agents_with_proxy(domain, zone_data[domain], org_id, session)

        # Prepare response
        response_data = {
            "status": "success", 
            "message": "DNS record added successfully",
            "deployment": deployment_results
        }
        
        # Add proxy info to response
        if is_proxiable:
            response_data["proxy"] = {
                "enabled": proxy_enabled,
                "upstream_url": normalized_url,
                "proxy_configured": proxy_result.status_code == 200 if proxy_result else False
            }

        print(f"response_data: {response_data}") # debug

        record_ttl = record_data.ttl if record_data.ttl else DEFAULT_TTL

        # write to DNSChangeLog
        try:
            await save_dns_change_log(
                domain=domain,
                action="ADD",
                record={
                    "type": record_type,
                    "name": record_name,
                    "value": record_data.value,
                    "ttl": int(record_ttl),
                    "priority": record_data.priority if record_type in ["MX","SRV"] else None,
                    "proxied": record_data.proxy_enabled if is_proxiable else None
                },
                user_id=user_id,
                organization_id=UUID(org_id),
                request=request,
                session=session
            )
        except Exception as e:
            print(f"Failed to save DNSChangeLog: {e}")

        new_records = []
        if refresh:
            new_records = await load_dns_records(domain, org_id, user_id, session)

        response_data['new_records'] = new_records

        return response_data
    
    except HTTPException:
        raise

    except Exception as e:
        #raise HTTPException(status_code=500, detail=f"Failed to add DNS record: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to add DNS record: {str(e)}")

def extract_ip_from_url(url: str) -> str:
    """
    Extracts the IP address from a URL that starts with http:// or https://
    and has the IP as the network location.
    
    Args:
        url: The URL string (e.g., 'https://123.456.789' or 'http://123.456.789').
        
    Returns:
        The extracted IP address as a string.
    """
    # 1. Parse the URL string
    parsed_url = urlparse(url)
    
    # 2. The 'netloc' attribute contains the network location (the IP address in this case)
    ip_address = parsed_url.netloc
    
    return ip_address

def normalize_ip(ip: str) -> str:
    return ip.strip("[]")

def replace_with_proxy_ip(value_list, upstream_urls, type='A'):
    """
    Replace individual IPs in the list with proxy IP if matching any upstream.
    Also De-dupe redundant proxy IPs for multiple proxied IPs
    """
    from config import PROXY_AGENT_IP, PROXY_AGENT_IPV6
    proxy_ip = PROXY_AGENT_IP if type == 'A' else PROXY_AGENT_IPV6

    print(f"[DEBUG] IP is replaced for proxy: {proxy_ip}")

    # Extract origin IPs from upstream_urls
    upstream_ips = set(normalize_ip(extract_ip_from_url(url)) for url in upstream_urls)
    print(f"[DEBUG] upstream_ips: {upstream_ips}")
    result = []
    added_proxy = False

    for val in value_list:
        if not isinstance(val, dict) or "value" not in val:
            continue
        
        print(f"[DEBUG] value: {val['value']}")

        if val["value"] in upstream_ips:
            if not added_proxy:
                proxy_entry = {"value": proxy_ip}
                if "ttl" in val:
                    proxy_entry["ttl"] = val["ttl"]
                result.append(proxy_entry)
                added_proxy = True
        else:
            result.append(val)

    return result


async def deploy_zone_to_agents_with_proxy(domain: str, zone_data: Dict[str, Any], org_id: str, session: AsyncSession) -> Dict[str, Any]:
    """
    Deploy zone data to DNS agents with proxy IP substitution
    """
    from config import PROXY_AGENT_IP, PROXY_AGENT_IPV6

    try:

        # Fetch all enabled proxy routes for this domain
        proxy_stmt = select(ProxyRoute).where(
            ProxyRoute.domain == domain,
            ProxyRoute.organization_id == UUID(org_id),
            ProxyRoute.proxy_enabled == True
        )
        proxy_routes = await session.exec(proxy_stmt)
        #proxy_map = {route.subdomain: route for route in proxy_routes.scalars().all()}

        proxy_groups = defaultdict(list)
        for route in proxy_routes.scalars().all():
            if route.proxy_enabled:
                proxy_groups[route.subdomain].append(route.upstream_url)
    
    except Exception as e:
        print(f"error in fetch ProxyRoute - Error: {e}")
        raise
    
    # Create a copy of zone_data for modification
    deploy_zone_data = json.loads(json.dumps(zone_data))  # Deep copy
    
    # Apply proxy substitutions
    for subdomain, upstream_urls in proxy_groups.items():

        print(f"[DEBUG] subdomain: {subdomain}, upstream_urls: {upstream_urls}")

        if "A" in deploy_zone_data and subdomain in deploy_zone_data["A"]:
            if isinstance(deploy_zone_data["A"][subdomain], list):
                deploy_zone_data["A"][subdomain] = replace_with_proxy_ip(
                    deploy_zone_data["A"][subdomain], upstream_urls, type='A'
                )
            else:
                deploy_zone_data["A"][subdomain] = [{"value": PROXY_AGENT_IP}]

        if "AAAA" in deploy_zone_data and subdomain in deploy_zone_data["AAAA"]:
            if isinstance(deploy_zone_data["AAAA"][subdomain], list):
                deploy_zone_data["AAAA"][subdomain] = replace_with_proxy_ip(
                    deploy_zone_data["AAAA"][subdomain], upstream_urls, type='AAAA'
                )
                print(f"[DEBUG] AAAA IP replacement for list: {deploy_zone_data["AAAA"]}")
            else:
                deploy_zone_data["AAAA"][subdomain] = [{"value": PROXY_AGENT_IPV6}]
                print(f"[DEBUG] AAAA IP replacement for others: {deploy_zone_data["AAAA"]}")

    print(f"[DEBUG] - zone file to be deployed: {deploy_zone_data}")
    
    # Deploy the modified zone data
    return await deploy_zone_to_agents(domain, deploy_zone_data)

async def create_initial_proxy_routes(domain: str, zone_data: Dict[str, Any], org_id: str, session: AsyncSession):
    from datetime import datetime
    from models.models import ProxyRoute, Organization
    from sqlmodel import select
    from utils.proxy_routes import normalize_upstream_url
    from config import PROXY_LIMIT_FREE, PROXY_LIMIT_PLUS, PROXY_LIMIT_PRO

    # Get org tier
    tier_result = await session.exec(
        select(Organization.tier).where(Organization.id == UUID(org_id))
    )
    tier = tier_result.first()
    if tier is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    proxy_limit = {
        "free": PROXY_LIMIT_FREE,
        "plus": PROXY_LIMIT_PLUS,
        "pro": PROXY_LIMIT_PRO,
    }.get(tier, 0)

    # Get current active proxy count
    count_result = await session.exec(
        select(func.count()).select_from(ProxyRoute).where(
            ProxyRoute.organization_id == UUID(org_id),
            ProxyRoute.proxy_enabled == True
        )
    )
    current_count = count_result.first() or 0

    print('='*32)
    print(f"proxy_limit: {proxy_limit} - {type(proxy_limit)}")
    print(f"current_count: {current_count} - {type(current_count)}")
    print('='*32)

    available_slots = max(0, proxy_limit - current_count)

    used_slots = 0
    fqdns_to_build = set()

    for record_type in ["A", "AAAA"]:
        if record_type not in zone_data:
            continue

        for name, values in zone_data[record_type].items():
            if used_slots >= available_slots:
                break

            if not values:
                continue

            subdomain = name or "@"

            # ✅ Loop over all IPs under this subdomain
            for val in values:
                if used_slots >= available_slots:
                    break

                upstream_ip = val["value"]
                normalized_url = normalize_upstream_url(
                    upstream_ip,
                    f"{name}.{domain}" if name != "@" else domain,
                    record_type
                )

                fqdn = f"{name}.{domain}" if name != "@" else domain
                fqdns_to_build.add(fqdn)

                # Check for *any* existing route first
                stmt = select(ProxyRoute).where(
                    ProxyRoute.subdomain == subdomain,
                    ProxyRoute.domain == domain,
                    ProxyRoute.organization_id == UUID(org_id),
                    ProxyRoute.upstream_url == normalized_url
                )
                existing = (await session.exec(stmt)).first()

                if existing:
                    if not existing.proxy_enabled:
                        existing.proxy_enabled = True
                        existing.updated_at = datetime.utcnow()
                        session.add(existing)
                        used_slots += 1
                    # else: already active, skip
                else:
                    route = ProxyRoute(
                        domain=domain,
                        subdomain=subdomain,
                        organization_id=UUID(org_id),
                        upstream_url=normalized_url,
                        enable_tls=True,
                        proxy_enabled=True,
                        updated_at=datetime.utcnow()
                    )
                    session.add(route)
                    used_slots += 1

    await session.commit()

    if used_slots > 0:
        batch_payload = []

        for fqdn in fqdns_to_build:
            subdomain = fqdn.replace(f".{domain}", "") if fqdn != domain else "@"
            
            normalized_upstreams = (await session.exec(
                select(ProxyRoute.upstream_url)
                .where(
                    ProxyRoute.domain == domain,
                    ProxyRoute.organization_id == UUID(org_id),
                    ProxyRoute.subdomain == subdomain,
                    ProxyRoute.proxy_enabled == True
                )
            )).all()

            if normalized_upstreams and isinstance(normalized_upstreams[0], tuple):
                normalized_upstreams = [row[0] for row in normalized_upstreams]
                logging.info("Converting normalized_upstreams to list of strings")

            print('='*32)
            print(f"[DEBUG] normalized_upstreams: {normalized_upstreams}")
            print('='*32)

            if normalized_upstreams:
                batch_payload.append({
                    "fqdn": fqdn,
                    "upstream_urls": normalized_upstreams,
                    "enable_tls": True,
                    "host_override": fqdn
                })

        if batch_payload:
            try:
                call_agent_hmac(
                    PROXY_AGENT_IP,
                    "/internal/proxy/add_routes",
                    method="POST",
                    json=batch_payload,
                    timeout=15
                )
                print(f"🔁 Rebuilt {len(batch_payload)} proxy routes")
            except Exception as e:
                print(f"⚠️ Batch proxy rebuild failed: {e}")


# Not used any more
'''
async def deploy_ns_only_to_agents(domain: str):
    zone_data = {
        "NS": {
            "@": ["ns1.stackdns.io.", "ns2.stackdns.io."]
        }
    }
    return await deploy_zone_to_agents(domain, zone_data)
'''

async def deploy_minimal_apex_record(domain: str):
    from config import PROXY_AGENT_IP
    zone_data = {
        
        "A": {
            "@": [{"value": PROXY_AGENT_IP}]
        }
    }

    return await deploy_zone_to_agents(domain, zone_data)

async def deploy_zone_to_agents(domain: str, zone_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deploy zone data to both DNS agent VMs
    Returns deployment results from both agents
    """
    payload = {"zone_data": zone_data}
    results = []
    
    for ip in AGENT_IPS:
        try:
            res = call_agent(ip, f"/internal/deploy/{domain}", json=payload)
            results.append({
                "agent": ip, 
                "status": res.status_code,
                "success": res.status_code == 200
            })
        except HTTPException as e:
            results.append({
                "agent": ip,
                "status": "error", 
                "error": str(e.detail),
                "success": False
            })
        except Exception as e:
            results.append({
                "agent": ip,
                "status": "error",
                "error": str(e),
                "success": False
            })
    
    success_count = sum(1 for r in results if r.get("success", False))
    
    return {
        "results": results,
        "success_count": success_count,
        "total_agents": len(AGENT_IPS),
        "deployed": success_count > 0,
        "fully_deployed": success_count == len(AGENT_IPS)
    }

async def deploy_txt_to_zone(domain: str, txt_values: list[str]) -> dict:
    """
    Deploy ACME TXT records (_acme-challenge) to all DNS agents for given domain.
    Supports multiple TXT values (e.g. for apex and wildcard).
    """
    if not txt_values or not isinstance(txt_values, list):
        raise ValueError("txt_values must be a non-empty list")

    zone_data = {
        "TXT": {
            "_acme-challenge": [{"value": txt_value} for txt_value in txt_values]
        }
    }

    return await deploy_zone_to_agents(domain, zone_data)

async def log_all_dns_records_from_zone(
    zone_data: Dict[str, Any],
    domain: str,
    org_id: str,
    user_id: Optional[UUID],
    request: Request,
    session: AsyncSession
) -> None:
    """Efficiently log all DNS records in zone file as 'ADD' actions (batch insert)"""

    if not zone_data:
        zone_data = load_zone_from_gcs(domain, prefix="json/")
        if not zone_data or domain not in zone_data:
            return

    domain_data = zone_data[domain]
    org_uuid = UUID(org_id)

    # Fetch upstream proxy routes
    proxy_stmt = select(ProxyRoute).where(
        ProxyRoute.domain == domain,
        ProxyRoute.organization_id == org_uuid
    )
    proxy_result = await session.exec(proxy_stmt)
    proxy_groups = defaultdict(list)
    for route in proxy_result.scalars().all():
        if route.proxy_enabled:
            proxy_groups[route.subdomain].append(route.upstream_url)

    log_entries = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for record_type, record_entries in domain_data.items():
        for name, entry in record_entries.items():
            name = name or "@"
            records = entry if isinstance(entry, list) else [entry]

            for rec in records:
                value, priority, proxied = None, None, None
                ttl = int(rec.get("ttl", DEFAULT_TTL))

                if record_type in ["A", "AAAA"]:
                    value = rec.get("value")
                    fqdn = f"{name}.{domain}" if name != "@" else domain
                    normalized = normalize_upstream_url(value, fqdn, record_type)
                    proxied = normalized in proxy_groups.get(name, [])

                elif record_type == "CNAME":
                    value = rec.get("value")

                elif record_type == "MX":
                    value = rec.get("value")
                    priority = rec.get("priority")

                elif record_type == "TXT":
                    value = rec.get("value")

                elif record_type == "SRV":
                    weight = rec.get("weight", 0)
                    port = rec.get("port", 80)
                    target = rec.get("target", "")
                    value = f"{weight} {port} {target}"
                    priority = rec.get("priority")

                elif record_type == "CAA":
                    flags = rec.get("flags", 0)
                    tag = rec.get("tag", "")
                    val = rec.get("value", "")
                    value = f"{flags} {tag} {val}"

                if not value:
                    continue

                # ✅ Build the same record object
                record_dict = {
                    "type": record_type,
                    "name": name,
                    "value": value,
                    "ttl": ttl,
                    "priority": priority,
                    "proxied": proxied
                }

                # ✅ Generate attestation
                attestation = create_dns_attestation(
                    domain=domain,
                    action="ADD",
                    record=record_dict,
                    user_id=user_id,
                    request=request
                )

                log_entry = DNSChangeLog(
                    id=str(uuid4()),
                    domain=domain,
                    action="ADD",
                    record_type=record_type,
                    record_name=name,
                    record_value=value,
                    ttl=ttl,
                    priority=priority,
                    proxied=proxied,
                    full_snapshot=safe_json_dumps(record_dict),
                    snapshot_hash=attestation.snapshot_hash,
                    signature=attestation.signature,
                    public_key=attestation.public_key,
                    user_id=user_id,
                    organization_id=org_uuid,
                    created_at=now,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent") if request.headers else None
                )

                log_entries.append(log_entry)

    session.add_all(log_entries)
    await session.commit()

class DummyRequest(Request):
    def __init__(self):
        scope = {
            "type": "http",
            "method": "POST",
            "headers": Headers().raw,
            "client": ("127.0.0.1", 0),
            "path": "/internal/deploy",
            "query_string": b"",
            "server": ("localhost", 80),
        }
        super().__init__(scope)

async def deploy_final_zone(domain, organization_id, session):
    try:
        copy_zone_in_gcs(domain, src_prefix="json-draft/", dest_prefix="json/")
    except FileNotFoundError:
        logging.warning(f"⚠️ Draft zone file not found for {domain}")
        return

    zone_json = load_zone_from_gcs(domain, prefix="json/")

    # ✅ Step 3: Generate proxy routes if needed
    await create_initial_proxy_routes(domain, zone_json[domain], organization_id, session)

    # Now deploy with proxy substitution
    deploy_results = await deploy_zone_to_agents_with_proxy(domain, zone_json[domain], organization_id, session)

    logging.info(f"✅ zone file deployment status for {domain}: {deploy_results}")

    dummy_request = DummyRequest()
    await log_all_dns_records_from_zone(zone_json, domain, organization_id, user_id=None, request=dummy_request, session=session)
# ----------------------
# Update DNS record in JSON file (DEBUG VERSION with better error handling)
# ----------------------

async def check_proxy_limit(org_id: UUID, session: AsyncSession):
    # Get organization tier
    result = await session.exec(
        select(Organization.tier).where(Organization.id == org_id)
    )
    tier = result.scalars().first()
    if tier is None:
        raise HTTPException(status_code=404, detail="Organization not found")


    # Count current active proxies
    proxy_count_result = await session.exec(
        select(func.count()).select_from(ProxyRoute).where(
            ProxyRoute.organization_id == org_id,
            ProxyRoute.proxy_enabled == True
        )
    )
    active_proxy_count = int(proxy_count_result.scalars().first())

    # Determine limit
    if tier == "free":
        limit = PROXY_LIMIT_FREE
    elif tier == "plus":
        limit = PROXY_LIMIT_PLUS
    elif tier == "pro":
        limit = PROXY_LIMIT_PRO
    else:
        raise HTTPException(status_code=400, detail="Invalid organization tier")

    # difference is the equal sign in adding and editing.
    
    if active_proxy_count >= int(limit):
        raise HTTPException(
            status_code=403,
            detail=f"Proxy limit reached for your plan ({tier} tier allows {limit} proxies)"
        )

@router.post("/records/{record_id}")
async def update_dns_record(
    record_id: str,
    record_data: DNSRecordRequest,
    request: Request,
    refresh: bool = False,
    session: AsyncSession = Depends(get_session)
):
    """Update an existing DNS record in the zone JSON file with proxy support"""
    
    print(f"🔍 DEBUG: Starting update_dns_record for record_id: {record_id}")
    print(f"🔍 DEBUG: record_data: {record_data}")
    
    # Auth (UNCHANGED)
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = record_data.organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    domain = record_data.domain
    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")
    
    print(f"[DEBUG] record type: {record_data.type}")
    # Validate A/AAAA for public IP
    if record_data.type in ["A", "AAAA"] and not is_valid_public_ip(record_data.value):
        print(f"[DEBUG] HIT BY THIS ERROR")
        raise HTTPException(status_code=400, detail="A/AAAA value must be a public IP")
    
    # IP block list check
    if record_data.type in ["A", "AAAA"]:
        await enforce_ip_reputation_policy(record_data.value, org_id, domain, session)

    try:
        print(f"🔍 DEBUG: Loading zone data for domain: {domain}")
        # Load existing zone data
        zone_data = load_zone_from_gcs(domain, prefix="json/")

        if not zone_data:
            raise HTTPException(status_code=404, detail="Domain not found in zone file")

        print(f"🔍 DEBUG: Finding record by ID: {record_id}")
        # Find the record by stable ID
        record_type, record_name, record_index = find_record_by_id(zone_data[domain], record_id, domain)
        
        if not record_type:
            raise HTTPException(status_code=404, detail="DNS record not found")

        print(f"🔍 DEBUG: Found record - type: {record_type}, name: {record_name}, index: {record_index}")

        # Detect if name was changed
        new_name = record_data.name
        name_changed = new_name != record_name

        # 🔥 NEW: Get current proxy state before updating
        is_proxiable = record_type in ["A", "AAAA"]
        current_proxy_enabled = False
        
        print(f"🔍 DEBUG: Record is_proxiable: {is_proxiable}")
        
        if is_proxiable:
            try:
                print(f"🔍 DEBUG: Checking existing proxy state for {record_name}.{domain}")
                fqdn = f"{record_name}.{domain}" if record_name != "@" else domain
                normalized_url = normalize_upstream_url(record_data.value, fqdn, record_type)

                # Check existing proxy state
                stmt = select(ProxyRoute).where(
                    ProxyRoute.subdomain == record_name,
                    ProxyRoute.domain == domain,
                    ProxyRoute.organization_id == UUID(org_id),
                    ProxyRoute.upstream_url == normalized_url
                )
                existing_route = (await session.exec(stmt)).scalars().first()
                if existing_route:
                    current_proxy_enabled = existing_route.proxy_enabled
                    print(f"🔍 DEBUG: Found existing proxy route, enabled: {current_proxy_enabled}")
                else:
                    print(f"🔍 DEBUG: No existing proxy route found")
            except Exception as e:
                print(f"❌ DEBUG: Error checking proxy state: {e}")
                raise

        # 🔥 NEW: Determine new proxy state
        new_proxy_enabled = getattr(record_data, 'proxy_enabled', current_proxy_enabled)
        proxy_state_changed = is_proxiable and (current_proxy_enabled != new_proxy_enabled)
        
        print(f"🔍 DEBUG: current_proxy_enabled: {current_proxy_enabled}, new_proxy_enabled: {new_proxy_enabled}, state_changed: {proxy_state_changed}")

        #When proxy is turned on, check the limit
        if is_proxiable and current_proxy_enabled == False and new_proxy_enabled == True:
            await check_proxy_limit(UUID(org_id), session)

        # Update the record based on its type and location (UNCHANGED)
        print(f"🔍 DEBUG: Updating DNS record in zone data...")

        # ✅ If name changed, remove old record and insert into new name slot
        if name_changed:
            # Remove old record
            if record_index is not None:
                zone_data[domain][record_type][record_name].pop(record_index)
                if not zone_data[domain][record_type][record_name]: # Delete list if it's empty
                    del zone_data[domain][record_type][record_name]
            else:
                del zone_data[domain][record_type][record_name]

            # Prepare new record value
            if record_type == "MX":
                new_value = { "priority": record_data.priority, "value": record_data.value }
                if record_data.ttl is not None:
                    new_value["ttl"] = record_data.ttl
            elif record_type == "TXT":
                new_value = { "value": record_data.value }
                if record_data.ttl is not None:
                    new_value["ttl"] = record_data.ttl
            elif record_type == "CAA":
                parts = record_data.value.split(None, 2)
                if len(parts) >= 3:
                    flags, tag, value = parts[0], parts[1], parts[2]
                    new_value = { "flags": int(flags), "tag": tag, "value": value }
                    if record_data.ttl is not None:
                        new_value["ttl"] = record_data.ttl
                else:
                    new_value = { "value": record_data.value }
                    if record_data.ttl is not None:
                        new_value["ttl"] = record_data.ttl
            elif record_type == "SRV":
                parts = record_data.value.split()
                if len(parts) >= 3:
                    weight, port, target = parts[0], parts[1], " ".join(parts[2:])
                    new_value = {
                        "priority": record_data.priority,
                        "weight": int(weight),
                        "port": int(port),
                        "target": target,
                    }
                    if record_data.ttl is not None:
                        new_value["ttl"] = record_data.ttl
                else:
                    raise HTTPException(status_code=400, detail="SRV record value must be 'weight port target'")
            else:
                new_value = { "value": record_data.value }
                if record_data.ttl is not None:
                    new_value["ttl"] = record_data.ttl

            # Insert into new name
            if record_type not in zone_data[domain]:
                zone_data[domain][record_type] = {}

            if new_name not in zone_data[domain][record_type]:
                zone_data[domain][record_type][new_name] = []

            if isinstance(zone_data[domain][record_type][new_name], list):
                zone_data[domain][record_type][new_name].append(new_value)
            else:
                zone_data[domain][record_type][new_name] = new_value

        else:
            # 🔄 Name didn't change → update in place
            if record_index is not None:
                if record_type == "MX":
                    zone_data[domain][record_type][record_name][record_index] = {
                        "priority": record_data.priority,
                        "value": record_data.value
                    }
                    if record_data.ttl is not None:
                        zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
                elif record_type == "TXT":
                    zone_data[domain][record_type][record_name][record_index] = { "value": record_data.value }
                    if record_data.ttl is not None:
                        zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
                elif record_type == "CAA":
                    parts = record_data.value.split(None, 2)
                    if len(parts) >= 3:
                        flags, tag, value = parts[0], parts[1], parts[2]
                        zone_data[domain][record_type][record_name][record_index] = {
                            "flags": int(flags),
                            "tag": tag,
                            "value": value,
                        }
                        if record_data.ttl is not None:
                            zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
                    else:
                        zone_data[domain][record_type][record_name][record_index] = { "value": record_data.value }
                        if record_data.ttl is not None:
                            zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
                elif record_type == "SRV":
                    parts = record_data.value.split()
                    if len(parts) >= 3:
                        weight, port, target = parts[0], parts[1], " ".join(parts[2:])
                        zone_data[domain][record_type][record_name][record_index] = {
                            "priority": record_data.priority,
                            "weight": int(weight),
                            "port": int(port),
                            "target": target,
                        }
                        if record_data.ttl is not None:
                            zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
                    else:
                        raise HTTPException(status_code=400, detail="SRV record value must be 'weight port target'")
                else:
                    zone_data[domain][record_type][record_name][record_index] = { "value": record_data.value }
                    if record_data.ttl is not None:
                        zone_data[domain][record_type][record_name][record_index]["ttl"] = record_data.ttl
            else:
                # Single value record (non-list)
                zone_data[domain][record_type][record_name] = { "value": record_data.value }
                if record_data.ttl is not None:
                    zone_data[domain][record_type][record_name]["ttl"] = record_data.ttl

        # Save zone file with updated values (UNCHANGED)
        print(f"🔍 DEBUG: Saving zone file...")
        save_zone_to_gcs(domain, zone_data, prefix="json/")

        # 🔥 NEW: Handle proxy state changes for all proxiable records
        proxy_result = None
        if is_proxiable:  # Handle A, AAAA, CNAME records
            print(f"🔍 DEBUG: Handling proxy logic for {record_type} record...")
            fqdn = f"{record_name}.{domain}" if record_name != "@" else domain
            normalized_url = normalize_upstream_url(record_data.value, fqdn, record_type)

            try:
                # Update or create ProxyRoute record
                print(f"🔍 DEBUG: Updating ProxyRoute for {fqdn}")
                stmt = select(ProxyRoute).where(
                    ProxyRoute.subdomain == record_name,
                    ProxyRoute.domain == domain,
                    ProxyRoute.organization_id == UUID(org_id),
                    ProxyRoute.upstream_url == normalized_url
                )
                existing_route = (await session.exec(stmt)).scalars().first()
                
                if existing_route:
                    print(f"🔍 DEBUG: Updating existing ProxyRoute")
                    # Update existing route
                    #existing_route.upstream_url = normalized_url
                    existing_route.proxy_enabled = new_proxy_enabled
                    existing_route.updated_at = get_current_datetime_without_timezone()
                    session.add(existing_route)
                else:
                    # Create new route if proxy is being enabled
                    if new_proxy_enabled:
                        print(f"🔍 DEBUG: Creating new ProxyRoute")
                        proxy_route = ProxyRoute(
                            domain=domain,
                            subdomain=record_name,
                            organization_id=UUID(org_id),
                            upstream_url=normalized_url,
                            enable_tls=True,
                            proxy_enabled=True,
                            updated_at=get_current_datetime_without_timezone()
                        )
                        session.add(proxy_route)
                
                await session.commit()
                print(f"🔍 DEBUG: ProxyRoute updated successfully")
                
                # Handle proxy configuration changes
                if proxy_state_changed or (new_proxy_enabled and not existing_route): # the last condition is obsolete and unnecessary?
                    print(f"🔍 DEBUG: Proxy state changed, calling proxy agent...")
                    try:
                        from utils.agents import call_agent_hmac
                        from config import PROXY_AGENT_IP
                        
                        if new_proxy_enabled:
                            # Enable proxy
                            print(f"🔍 DEBUG: Enabling proxy for {fqdn}")

                            # legacy code for single IP proxy
                            '''
                            upstream_url = normalize_upstream_url(record_data.value, fqdn, record_type)
                            proxy_result = call_agent_hmac(PROXY_AGENT_IP, "/internal/proxy/add_route", json={
                                "fqdn": fqdn,
                                "upstream_url": upstream_url,
                                "enable_tls": True,
                                "host_override": fqdn
                            }, timeout=10)
                            '''
                            proxy_result = await rebuild_proxy_route(fqdn, domain, record_name, record_type, session)
                            print(f"✅ Enabled proxy for {fqdn} -> {normalized_url}, status: {proxy_result.status_code}")
                        else:
                            # Disable proxy
                            print(f"🔍 DEBUG: Disabling proxy for {fqdn}")

                            # legacy code for single proxy route logic
                            #proxy_result = call_agent_hmac(PROXY_AGENT_IP, f"/internal/proxy/delete_route/{fqdn}", method="DELETE", timeout=10)
                            
                            # new code for multiple IP proxy logic
                            result = await session.exec(
                                select(ProxyRoute).where(
                                    ProxyRoute.domain == domain,
                                    ProxyRoute.subdomain == record_name,
                                    ProxyRoute.proxy_enabled == True
                                )
                            )
                            remaining_routes = result.all()

                            if remaining_routes:
                                # Regenerate config with remaining upstreams
                                proxy_result = await rebuild_proxy_route(fqdn, domain, record_name, record_type, session)
                            else:
                                # Nothing left → delete proxy config
                                proxy_result = call_agent_hmac(PROXY_AGENT_IP, f"/internal/proxy/delete_route/{fqdn}", method="DELETE", timeout=10)
                            print(f"🔴 Disabled proxy for {fqdn}, status: {proxy_result.status_code}")
                            
                    except Exception as e:
                        print(f"❌ Failed to configure proxy for {fqdn}: {e}")
                        # Don't raise here, continue with deployment
                else:
                    print(f"🔍 DEBUG: No proxy state change needed")
                    
            except Exception as e:
                print(f"❌ DEBUG: Error in proxy handling: {e}")
                raise

        # Deploy with proxy substitution (use the new function)
        print(f"🔍 DEBUG: Starting deployment...")
        try:
            deployment_results = await deploy_zone_to_agents_with_proxy(domain, zone_data[domain], org_id, session)
            print(f"🔍 DEBUG: Deployment results: {deployment_results}")
        except Exception as e:
            print(f"❌ DEBUG: Deployment error: {e}")
            # Continue anyway, don't fail the whole operation

        if not deployment_results.get("deployed", True):
            print(f"⚠️ Deployment failed for {domain}: {deployment_results}")

        # Prepare response
        response_data = {
            "status": "success", 
            "message": "DNS record updated successfully",
            "deployment": deployment_results
        }
        
        # Add proxy info to response for proxiable records
        if is_proxiable:
            response_data["proxy"] = {
                "enabled": new_proxy_enabled,
                "state_changed": proxy_state_changed,
                "upstream_url": normalized_url,
                "proxy_configured": proxy_result.status_code == 200 if proxy_result else False
            }

        print(f"🔍 DEBUG: Sending response: {response_data}")

        record_ttl = record_data.ttl if record_data.ttl is not None else DEFAULT_TTL
        # write to DNSChangeLog
        try:
            await save_dns_change_log(
                domain=domain,
                action="EDIT",
                record={
                    "type": record_type,
                    "name": record_name,
                    "value": record_data.value,
                    "ttl": int(record_ttl),
                    "priority": record_data.priority if record_type in ["MX","SRV"] else None,
                    "proxied": record_data.proxy_enabled if is_proxiable else None
                },
                user_id=user_id,
                organization_id=UUID(org_id),
                request=request,
                session=session
            )
        except Exception as e:
            print(f"Failed to save DNSChangeLog: {e}")

        # return new record to avoid another round trip to the backend
        new_records = []
        if refresh:
            new_records = await load_dns_records(domain, org_id, user_id, session)

        response_data['new_records'] = new_records

        return response_data

    except HTTPException as e:
        print(f"❌ DEBUG: HTTPException: {e.detail}")
        raise
    except Exception as e:
        print(f"❌ DEBUG: Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update DNS record: {str(e)}")
    
# ----------------------
# Delete DNS record from JSON file (UPDATED with proxy soft delete)
# ----------------------
@router.post("/records/{record_id}/delete")
async def delete_dns_record(
    record_id: str,
    delete_data: DeleteRecordRequest,
    request: Request,
    refresh: bool = False,
    session: AsyncSession = Depends(get_session)
):
    """Delete a DNS record from the zone JSON file with proxy soft delete"""
    
    # Auth (UNCHANGED)
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = delete_data.organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    domain = delete_data.domain
    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")
    
    # debug 
    print(f"DELETE DNS RECORD reached this point: {record_id}")

    try:
        found_record_type = None
        found_record_name = None
        found_record_index = None
        
        zone_data = load_zone_from_gcs(domain, prefix="json/")
        record_type, record_name, record_index = find_record_by_id(zone_data[domain], record_id, domain)
        print(f"[DEBUG] record_type: {record_type}, record_name: {record_name}, record_index: {record_index}")
        if record_type:
            found_record_type = record_type
            found_record_name = record_name
            found_record_index = record_index

        # extract other values from zone_data
        record_value = None
        record_priority = None
        record_ttl = None
        record_obj = (
            zone_data[domain][record_type][record_name][record_index]
            if record_index is not None else
            zone_data[domain][record_type][record_name]
        )

        # Handle value flattening based on record type
        if record_type == "CAA":
            record_value = f"{record_obj.get('flags', 0)} {record_obj.get('tag', '')} {record_obj.get('value', '')}"
        elif record_type == "SRV":
            record_value = f"{record_obj.get('weight', 0)} {record_obj.get('port', 0)} {record_obj.get('target', '')}"
        else:
            record_value = record_obj.get("value")

        record_priority = record_obj.get("priority") if record_type in ["MX", "SRV"] else None
        record_ttl = record_obj.get("ttl", DEFAULT_TTL)

        # 🔥 NEW: Handle proxy soft delete BEFORE removing DNS record
        is_proxiable = found_record_type in ["A", "AAAA"]
        proxy_was_enabled = False
        proxy_result = None
        
        if is_proxiable:  # Handle A, AAAA, CNAME records
            fqdn = f"{record_name}.{domain}" if record_name != "@" else domain
            normalized_url = normalize_upstream_url(delete_data.value, fqdn, record_type)

            print("="*32)
            print(f'normalized_url: {normalized_url}')
            print("="*32)

            # Check if proxy was enabled for this record
            stmt = select(ProxyRoute).where(
                ProxyRoute.subdomain == found_record_name,
                ProxyRoute.domain == domain,
                ProxyRoute.organization_id == UUID(org_id),
                ProxyRoute.upstream_url == normalized_url
            )
            existing_route = (await session.exec(stmt)).scalars().first()

            print("="*32)
            print(f'existing_route: {existing_route}')
            print("="*32)
            
            if existing_route and existing_route.proxy_enabled:
                proxy_was_enabled = True
                #fqdn = f"{found_record_name}.{domain}" if found_record_name != "@" else domain  # already declared above
                
                # Soft delete: disable proxy but keep the record
                existing_route.proxy_enabled = False
                existing_route.updated_at = datetime.utcnow()
                session.add(existing_route)
                
                # Disable proxy route on proxy server
                try:
                    from utils.agents import call_agent_hmac
                    from config import PROXY_AGENT_IP
                    
                    # new code for multiple IP proxy logic
                    result = await session.exec(
                        select(ProxyRoute).where(
                            ProxyRoute.domain == domain,
                            ProxyRoute.subdomain == record_name,
                            ProxyRoute.proxy_enabled == True
                        )
                    )
                    remaining_routes = result.all()

                    if remaining_routes:
                        # Regenerate config with remaining upstreams
                        proxy_result= await rebuild_proxy_route(fqdn, domain, record_name, record_type, session)
                    else:
                        # Nothing left → delete proxy config
                        proxy_result = call_agent_hmac(
                            PROXY_AGENT_IP, 
                            f"/internal/proxy/delete_route/{fqdn}", 
                            method="DELETE", 
                            timeout=10
                        )

                    print(f"🔴 Disabled proxy for {fqdn} (DNS record deleted)")
                    
                except Exception as e:
                    print(f"⚠️ Failed to disable proxy for {fqdn}: {e}")
                
                await session.commit()

        # Delete the DNS record
        if found_record_index is not None:
            # Array-based record - remove from list
            zone_data[domain][found_record_type][found_record_name].pop(found_record_index)
            
            # Clean up empty arrays/objects
            if not zone_data[domain][found_record_type][found_record_name]:
                del zone_data[domain][found_record_type][found_record_name]
            if not zone_data[domain][found_record_type]:
                del zone_data[domain][found_record_type]
        else:
            # Single value record - delete the key
            del zone_data[domain][found_record_type][found_record_name]
            if not zone_data[domain][found_record_type]:
                del zone_data[domain][found_record_type]

        # Save zone file
        save_zone_to_gcs(domain, zone_data)
        # Deploy with proxy substitution (use the new function)
        deployment_results = await deploy_zone_to_agents_with_proxy(domain, zone_data[domain], org_id, session)

        if not deployment_results.get("deployed", True):
            print(f"⚠️ Deployment failed for {domain}: {deployment_results}")

        # Prepare response
        response_data = {
            "status": "success", 
            "message": "DNS record deleted successfully",
            "deployment": deployment_results
        }
        
        # Add proxy info to response if proxy was involved
        if is_proxiable:
            response_data["proxy"] = {
                "was_enabled": proxy_was_enabled,
                "disabled": proxy_was_enabled,
                "soft_deleted": proxy_was_enabled,  # ProxyRoute kept but disabled
                "proxy_unconfigured": proxy_result.status_code == 200 if proxy_result else False
            }


        # write to DNSChangeLog
        try:
            rttl = record_ttl if record_ttl else DEFAULT_TTL
            await save_dns_change_log(
                domain=domain,
                action="DELETE",
                record={
                    "type": record_type,
                    "name": record_name,
                    "value": record_value,
                    "ttl": int(rttl),
                    "priority": record_priority if record_type in ["MX","SRV"] else None,
                    "proxied": proxy_was_enabled if is_proxiable else None
                },
                user_id=user_id,
                organization_id=UUID(org_id),
                request=request,
                session=session
            )
        except Exception as e:
            print(f"Failed to save DNSChangeLog: {e}")

        # return new record to avoid another round trip to the backend
        new_records = []
        if refresh:
            new_records = await load_dns_records(domain, org_id, user_id, session)

        response_data['new_records'] = new_records

        return response_data
    
    except Exception as e:
        print(f"[ERROR] DNS record deletion failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="DNS record deletion failed")

    '''
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete DNS record: {str(e)}")   
    '''
# ----------------------
# DNS Onboarding - Capture existing records and start NS verification
# ----------------------
@router.post("/onboard/{domain}")
async def onboard_dns_domain(
    domain: str,
    payload: OnboardDNSRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Start DNS onboarding process - capture existing records and begin NS verification"""
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        organization_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        organization_id = payload.organization_id
        if not await verify_user_org_access(user_id, UUID(organization_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, organization_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    try:

        zone_result = await session.exec(select(ZoneOnboarding).where(
            ZoneOnboarding.domain == domain,
            ZoneOnboarding.organization_id == organization_id
        ))
        zone_obj = zone_result.scalars().first()
        if zone_obj:
            if zone_obj.status == "running":
                return {
                    "status": "running",
                    "message": "DNS onboarding has been running already",
                }
            elif zone_obj.status == "complete":
                return {
                    "status": "complete",
                    "message": "DNS onboarding has been completed",
                }
            elif zone_obj.status in ["rate_limited", "cert_request_rate_limited"]:
                now = get_current_datetime_without_timezone()
                if zone_obj.updated_at and (now - zone_obj.updated_at) < timedelta(hours=24*5):
                    return {
                        "status": "rate_limited",
                        "message": "Onboarding this domain has hit rate limit",
                    }
        
        user_email = await get_admin_email_for_org(UUID(organization_id), session)
        
        asyncio.create_task(run_onboarding_flow(domain, organization_id, user_email))

        return {
            "status": "initiated", 
            "message": "DNS onboarding started. Nameserver verification polling initiated.",
            #"records_captured": len(zone_data.get(domain, []))
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start DNS onboarding: {str(e)}")

# ----------------------
# Background task for NS verification polling
# ----------------------
async def run_onboarding_flow(domain: str, organization_id: str, user_email: str):

    print(f"[ONBOARDING] Started flow for {domain=} {organization_id=}")
    try:    
        async with async_session() as session:
            # legacy code - domain and organization_id are tied at the creation and never update
            '''
            result = await session.exec(select(ZoneOnboarding).where(
                ZoneOnboarding.domain == domain,
                ZoneOnboarding.organization_id == organization_id
            ))
            zone = result.scalars().first()

            if not zone:
                print("[ONBOARDING] Zone not found, creating new")
                zone = ZoneOnboarding(domain=domain, organization_id=organization_id, status="running")
                session.add(zone)
                await session.commit()
                await session.refresh(zone)

            zone.status = "running"
            session.add(zone)
            await session.commit()
            '''
            result = await session.exec(select(ZoneOnboarding).where(ZoneOnboarding.domain == domain))
            existing = result.scalars().first()

            cert_fields_to_preserve = {}

            if existing:
                if str(existing.organization_id) != organization_id:
                    print(f"[ONBOARDING] Domain owned by different org: {existing.organization_id}, reassigning")
                    
                    # Check if cert can be reused
                    if (
                        existing.cert_issued and 
                        existing.last_cert_request_at and 
                        (datetime.utcnow() - existing.last_cert_request_at) < timedelta(days=80)
                    ):
                        print("[ONBOARDING] Preserving cert info to avoid reissuance")
                        cert_fields_to_preserve = {
                            "cert_challenge_requested": existing.cert_challenge_requested,
                            "txt_record_deployed": existing.txt_record_deployed,
                            "cert_issued": existing.cert_issued,
                            "last_cert_request_at": existing.last_cert_request_at,
                            "txt_challenge_value": existing.txt_challenge_value,
                        }

                    # Delete old record
                    await session.delete(existing)
                    await session.commit()

                    # Create new onboarding record
                    zone = ZoneOnboarding(
                        domain=domain,
                        organization_id=organization_id,
                        status="running",
                        **cert_fields_to_preserve
                    )
                    session.add(zone)
                    await session.commit()
                    await session.refresh(zone)
                    print(f"[ONBOARDING] Zone onboarding record created for {domain} → {organization_id}")
                else:
                    print(f"[ONBOARDING] Domain already owned by this org.")
                    #return  # no need to create a new record
                    zone = existing
            else:
                print(f"[ONBOARDING] New domain {domain}, creating onboarding record")
                zone = ZoneOnboarding(
                    domain=domain,
                    organization_id=organization_id,
                    status="running"
                )
                session.add(zone)
                await session.commit()
                await session.refresh(zone)

            # Fetch corresponding UserDomain record
            user_domain_result = await session.exec(
                select(UserDomain).where(
                    UserDomain.domain == domain,
                    UserDomain.organization_id == organization_id
                )
            )
            user_domain = user_domain_result.scalars().first()
            if not user_domain:
                logging.error("[Error]: domain does not exist in UserDomain table")
                raise ValueError("UserDomain entry missing")

        # Step 1: Deploy Proxy A record
        if not zone.a_record_deployed:
            await deploy_minimal_apex_record(domain)
            zone.a_record_deployed = True
            session.add(zone)
            await session.commit()

        # Step 2: Poll until NS verified
        if not zone.ns_verified:
            intervals = [30]*10 + [60]*10 + [120]*10 + [600]*7  # ≈ 120 minutes
            for interval in intervals:
                trace_result = trace_ns(domain)
                if trace_result and trace_result.get("status"):
                    zone.ns_verified = True
                    zone.ns_verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    user_domain.verified_ns = True
                    session.add(zone)
                    session.add(user_domain)
                    await session.commit()
                    break
                    
                await asyncio.sleep(interval)

        # only for testing purposes
        await asyncio.sleep(40)
        
        # If cert was issued previously, skip the acme process
        now_naive = get_current_datetime_without_timezone()
        ssl_valid_period = timedelta(days=80)

        if not zone.cert_issued and (not zone.last_cert_request_at 
                                     or 
                                    (zone.last_cert_request_at and (now_naive - zone.last_cert_request_at) > ssl_valid_period)
                                    ):

            # Step 3: Get ACME challenge TXT (retry on 409, abort on 429)
            if not zone.cert_challenge_requested:
                cooldown = timedelta(minutes=3)
                now = get_current_datetime_without_timezone()

                if zone.last_cert_request_at and (now - zone.last_cert_request_at) < cooldown:
                    print(f"⏳ Cert request rate-limited for {domain}. Last issued at {zone.last_cert_request_at}")
                    zone.status = "cert_request_rate_limited"
                    session.add(zone)
                    await session.commit()
                    return
            
                max_retries = 5
                delay_seconds = 60

                for attempt in range(max_retries):
                    try:
                        txt_values = request_cert_challenge(domain)
                        zone.txt_challenge_value = ",".join(txt_values)
                        zone.cert_challenge_requested = True

                        zone.last_cert_request_at = get_current_datetime_without_timezone()

                        session.add(zone)
                        await session.commit()
                        break  # ✅ done
                    except RuntimeError as e:
                        message = str(e)
                        if "propagation incomplete" in message.lower():
                            print(f"⚠️ ACME TXT not ready yet (attempt {attempt+1}/{max_retries})")
                            await asyncio.sleep(delay_seconds)
                            continue
                        elif "rate limit" in message.lower():
                            print(f"❌ ACME rate limit hit: {e}")
                            zone.status = "rate_limited"
                            session.add(zone)
                            await session.commit()
                            return  # Exit onboarding cleanly
                        else:
                            print(f"❌ Unknown error requesting ACME challenge: {e}")
                            raise

            # Step 4: Deploy TXT
            if not zone.txt_record_deployed:
                await deploy_txt_to_zone(domain, txt_values)  
                zone.txt_record_deployed = True
                session.add(zone)
                await session.commit()

            # Step 5: Poll until TXT resolvable
            txt_value_str = zone.txt_challenge_value
            if not txt_value_str:
                raise HTTPException(status_code=400, detail="No TXT challenge stored for this domain")

            txt_values = txt_value_str.split(",")
            
            for _ in range(20):
                if await dig_txt_challenge(domain, txt_values, max_retries=6, delay_seconds=120):
                    await asyncio.sleep(120)  # 2-minute wait for global propagation
                    finalize_cert(domain)
                    zone.cert_issued = True
                    session.add(zone)
                    await session.commit()
                    break
                await asyncio.sleep(30)

        # Finalize onboarding
        if zone.cert_issued:
            await deploy_final_zone(domain, organization_id, session)
            zone.finalized = True
            zone.status = "complete"
            session.add(zone)
            await session.commit()

            try:
                if user_email:
                    await send_nameserver_migration_completed_email(user_email, domain)
                    print(f"Nameserver migration complete. Email was sent to {user_email}")
            except Exception as e:
                print(f"❌ Error in sending email on nameserver migration: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    
    except Exception as e:
        print(f"❌ Unhandled error during onboarding: {e}")
        async with async_session() as session:
            result = await session.exec(select(ZoneOnboarding).where(
                ZoneOnboarding.domain == domain,
                ZoneOnboarding.organization_id == organization_id
            ))
            zone = result.scalars().first()
            if zone:
                zone.status = "error"
                # Optionally: zone.error_message = str(e)[:500]
                session.add(zone)
                await session.commit()

# ----------------------
# Manual NS check endpoint
# ----------------------
@router.post("/check-nameservers/{domain}")
async def check_nameservers_manual(
    domain: str,
    payload: OnboardDNSRequest,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Manually check nameserver verification status"""
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        organization_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        organization_id = payload.organization_id
        if not await verify_user_org_access(user_id, UUID(organization_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, organization_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    try:
        # Check current NS status
        ns_verified = await verify_nameservers(domain)
        
        if ns_verified:
            # Update database
            result = await session.exec(
                select(UserDomain).where(
                    UserDomain.domain == domain,
                    UserDomain.organization_id == UUID(organization_id)
                )
            )
            record = result.scalars().first()
            
            if record and not record.verified_ns:
                record.verified_ns = True
                session.add(record)
                await session.commit()

        return {
            "domain": domain,
            "verified_ns": ns_verified,
            "status": "verified" if ns_verified else "not_verified",
            "message": "Nameservers verified successfully" if ns_verified else "Nameservers not yet pointing to our servers"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check nameservers: {str(e)}")

# ----------------------
# Manual deployment endpoint (for the "Deploy Changes" button)
# ----------------------
@router.post("/deploy/{domain}")
async def deploy_dns_changes(
    domain: str,
    payload: OnboardDNSRequest,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Manually deploy DNS changes to agents (for the Deploy Changes button)"""
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        organization_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        organization_id = payload.organization_id
        if not await verify_user_org_access(user_id, UUID(organization_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, organization_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    try:
        # Load current zone data
        zone_data = load_zone_from_gcs(domain)

        if not zone_data:
            raise HTTPException(status_code=404, detail="Domain data not found in zone file")

        # Deploy to agents
        deployment_results = await deploy_zone_to_agents(domain, zone_data[domain])

        return {
            "status": "deployed" if deployment_results["deployed"] else "failed",
            "message": f"Deployment completed on {deployment_results['success_count']}/{deployment_results['total_agents']} agents",
            "domain": domain,
            "deployment": deployment_results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to deploy DNS changes: {str(e)}")
    
# used by header domain management modal.
@router.post("/delete-domain")
async def delete_domain(
    request: Request,
    data: dict,  # expects { "domain": "accorda.shop", "organization_id": "..." }
    session: AsyncSession = Depends(get_session)
):
    domain = data.get("domain")
    org_id = data.get("organization_id")
    
    # Auth
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, UUID):  # JWT flow
        user_id = auth_obj
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")
    else:
        if str(auth_obj.organization_id) != org_id:
            raise HTTPException(status_code=403, detail="API key not valid for this org")

    if not await verify_domain_access(domain, org_id, None, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    # Step 1: Delete zone file + keys from NS1 and NS2
    for ip in [NS1_IP, NS2_IP]:
        try:
            res = call_agent(ip, f"/internal/delete/{domain}")
        except Exception as e:
            print(f"⚠️ Failed to delete from agent {ip}: {e}")

    # Step 2: Delete proxy routes (batch)
    result = await session.exec(
        select(ProxyRoute.subdomain)
        .where(
            ProxyRoute.domain == domain,
            ProxyRoute.organization_id == UUID(org_id),
            ProxyRoute.proxy_enabled == True
        )
        .distinct()
    )
    subdomains = result.scalars().all()

    fqdns_to_delete = [
        f"{sub}.{domain}" if sub != "@" else domain
        for sub in subdomains
    ]

    if fqdns_to_delete:
        try:
            from utils.agents import call_agent_hmac
            from config import PROXY_AGENT_IP

            delete_result = call_agent_hmac(
                PROXY_AGENT_IP,
                "/internal/proxy/delete_routes",
                method="POST",
                json=fqdns_to_delete,
                timeout=15
            )
            print(f"🧹 Batch proxy deletion result: {delete_result.status_code}")
        except Exception as e:
            print(f"⚠️ Batch proxy deletion failed: {e}")


    # Optional: Delete ProxyRoute records from DB
    await session.exec(
        delete(ProxyRoute).where(
            ProxyRoute.domain == domain,
            ProxyRoute.organization_id == UUID(org_id)
        )
    )
    
    # Optional: Delete UserDomain
    await session.exec(
        delete(UserDomain).where(
            UserDomain.domain == domain,
            UserDomain.organization_id == UUID(org_id)
        )
    )

    await session.commit()

    '''
    # Optional: Delete ZoneOnboarding
    await session.exec(
        delete(ZoneOnboarding).where(
            ZoneOnboarding.domain == domain,
            ZoneOnboarding.organization_id == UUID(org_id)
        )
    )
    '''
    onboarding_result = await session.exec(
        select(ZoneOnboarding).where(
            ZoneOnboarding.domain == domain,
            ZoneOnboarding.organization_id == UUID(org_id)
        )
    )
    onboarding = onboarding_result.scalars().first()

    if onboarding:
        onboarding.ns_verified = False
        onboarding.a_record_deployed = False
        #onboarding.txt_record_deployed = False
        #onboarding.cert_challenge_requested = False
        #onboarding.cert_issued = False
        onboarding.finalized = False
        onboarding.status = "reset"
        #onboarding.updated_at = get_current_datetime_without_timezone() # automatic update in SQLModel

        await session.commit()

    # Step 3: Delete local zone JSON if present
    delete_zone_from_gcs(domain, prefix="json/")

    return {
        "status": "deleted",
        "domain": domain,
        "message": "Domain successfully removed from platform"
    }

@router.delete("/existing-records/{record_id}")
async def delete_existing_preview_record(domain: str, record_id: str, organization_id: str):
    """
    Delete a specific record from the draft zone file (json-draft/).
    Now supports structured types like CAA and SRV by flattening their composite values.
    """
    try:
        zone_data = load_zone_from_gcs(domain, prefix="json-draft/")
    except Exception:
        raise HTTPException(status_code=400, detail="Zone data does not exist")
    
    # Decompose record_id
    try:
        rtype, name, value = record_id.split("|", 2)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid record ID format")

    # Helper: flatten record dicts to comparable strings
    def flatten_record_value(rtype: str, v: dict | str) -> str:
        if not isinstance(v, dict):
            return str(v)
        if rtype == "CAA":
            return f"{v.get('flags', 0)} {v.get('tag', '')} {v.get('value', '')}"
        elif rtype == "SRV":
            #return f"{v.get('priority', 0)} {v.get('weight', 0)} {v.get('port', 0)} {v.get('target', '')}"
            return f"{v.get('weight', 0)} {v.get('port', 0)} {v.get('target', '')}"
        else:
            return str(v.get("value") or v.get("exchange") or v.get("target") or "")

    modified = False

    # --- Perform deletion ---
    if domain in zone_data and rtype in zone_data[domain] and name in zone_data[domain][rtype]:
        existing = zone_data[domain][rtype][name]
        if isinstance(existing, list):
            new_vals = [v for v in existing if flatten_record_value(rtype, v) != value]
            if len(new_vals) != len(existing):
                modified = True
                if new_vals:
                    zone_data[domain][rtype][name] = new_vals
                else:
                    del zone_data[domain][rtype][name]
        else:
            if flatten_record_value(rtype, existing) == value:
                modified = True
                del zone_data[domain][rtype][name]

        # Clean up if type or domain becomes empty
        if rtype in zone_data[domain] and not zone_data[domain][rtype]:
            del zone_data[domain][rtype]

    if modified:
        save_zone_to_gcs(domain, zone_data, prefix="json-draft/")

    # --- Prepare response ---
    remaining_records = []
    if domain in zone_data:
        for typ, names in zone_data[domain].items():
            for n, val in names.items():
                values = val if isinstance(val, list) else [val]
                for v in values:
                    val_str = flatten_record_value(typ, v)
                    remaining_records.append({
                        "type": typ,
                        "name": n,
                        "value": val_str,
                        "priority": v.get("priority") if isinstance(v, dict) else None,
                        "id": f"{typ}|{n}|{val_str}"
                    })

    return {"remaining": remaining_records}

# legacy code - does not take care of CAA and SRV
'''
@router.delete("/existing-records/{record_id}")
async def delete_existing_preview_record(domain: str, record_id: str, organization_id: str):
    try:
        zone_data = load_zone_from_gcs(domain, prefix="json-draft/")
    except Exception as e:
        raise HTTPException(status_code=400, details="zone data does not exist")
    
    # Decompose record_id
    try:
        rtype, name, value = record_id.split("|", 2)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid record ID format")

    # Delete the matching record
    modified = False
    if domain in zone_data and rtype in zone_data[domain] and name in zone_data[domain][rtype]:
        existing = zone_data[domain][rtype][name]
        if isinstance(existing, list):
            new_vals = [v for v in existing if (v.get("value") if isinstance(v, dict) else v) != value]
            if len(new_vals) != len(existing):
                modified = True
                if new_vals:
                    zone_data[domain][rtype][name] = new_vals
                else:
                    del zone_data[domain][rtype][name]
        else:
            if (existing.get("value") if isinstance(existing, dict) else existing) == value:
                modified = True
                del zone_data[domain][rtype][name]

        # Clean up if type or domain becomes empty
        if not zone_data[domain][rtype]:
            del zone_data[domain][rtype]

        # DO NOT DELETE the domain in the file

    if modified:
        save_zone_to_gcs(domain, zone_data, prefix="json-draft/")

    # Return remaining records in frontend format
    remaining_records = []
    if domain in zone_data:
        for typ, names in zone_data[domain].items():
            for n, val in names.items():
                values = val if isinstance(val, list) else [val]
                for v in values:
                    val_str = str(v.get("value") or v.get("exchange") or v.get("target")) if isinstance(v, dict) else str(v)
                    remaining_records.append({
                        "type": typ,
                        "name": n,
                        "value": val_str,
                        "priority": v.get("priority") if isinstance(v, dict) else None,
                        "id": f"{typ}|{n}|{val_str}"
                    })

    return {"remaining": remaining_records}
'''

# legacy code
'''
@router.delete("/existing-records/{record_id}")
async def delete_existing_preview_record(domain: str, record_id: str, organization_id: str):
    zone_path = os.path.join(JSON_DRAFT_DIR, f"{domain}.json")

    try:
        with open(zone_path, "r") as f:
            zone = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Zone file not found")

    if domain not in zone:
        raise HTTPException(status_code=404, detail="Domain not in zone file")

    zone_data = zone[domain]
    updated_zone = {}

    def make_record_id(rtype, name, value):
        return f"{rtype}|{name}|{value}"

    for rtype, names in zone_data.items():
        updated_zone[rtype] = {}
        for name, value in names.items():
            values = value if isinstance(value, list) else [value]
            new_values = []

            for v in values:
                if isinstance(v, dict):
                    # e.g. MX, CAA, SRV etc.
                    if "value" in v:
                        val_str = v["value"]
                    elif "exchange" in v:
                        val_str = v["exchange"]
                    elif "target" in v:
                        val_str = v["target"]
                    else:
                        val_str = json.dumps(v, sort_keys=True)
                else:
                    val_str = v

                rid = make_record_id(rtype, name, val_str)

                if rid != record_id:
                    new_values.append(v)

            if new_values:
                # Collapse single-value lists into plain value
                updated_zone[rtype][name] = new_values if len(new_values) > 1 else new_values[0]

    with open(zone_path, "w") as f:
        json.dump({domain: updated_zone}, f, indent=2)

    return {"success": True}
'''

class DraftRecordRequest(BaseModel):
    domain: str
    organization_id: str
    type: str
    name: str
    value: str
    priority: int | None = None


@router.post("/draft-records")
async def add_dns_record_to_draft(data: DraftRecordRequest):
    """
    Add a DNS record to the draft zone file (in JSON_DRAFT_DIR).
    Returns updated flat record list (like in DELETE version).
    """
    zone = load_zone_from_gcs(data.domain, prefix="json-draft/")

    zone_records = zone.setdefault(data.domain, {})
    record_set = zone_records.setdefault(data.type, {})
    existing = record_set.setdefault(data.name, [])

    # Normalize into list form
    if not isinstance(existing, list):
        existing = [existing]

    new_record = (
        {
            "priority": data.priority,
            "value": data.value
        }
        if data.priority is not None else
        {"value": data.value}
    )

    # Prevent duplicate
    def _record_equals(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            #return a.get("value") == b.get("value") and a.get("priority") == b.get("priority")
            return a.get("value") == b.get("value")
        return a == b

    if any(_record_equals(existing_val, new_record) for existing_val in existing):
        pass  # Already exists, skip
    else:
        existing.append(new_record)

    # Assign back
    zone_records[data.type][data.name] = existing

    # Save draft
    save_zone_to_gcs(data.domain, zone, prefix="json-draft/")
    # Flatten and return
    try:
        remaining_records = load_draft_file(data.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to flatten updated zone: {str(e)}")

    return {"remaining": remaining_records}


@router.get("/initialize-dns-management")
async def initialize_dns_management(
    domain: str,
    organization_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Get DNS records for a verified domain from zone JSON files with proxy status"""
    
    # Auth (UNCHANGED)
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    # Get basic DNS status
    dns_status = {}
    dns_records = []
    if domain:
        result = await session.exec(
            select(UserDomain).where(
                UserDomain.organization_id == organization_id, 
                UserDomain.domain == domain
            )
        )
        domain_obj = result.scalars().first()
        if domain_obj:
            dns_status = {
                "verified_ns": domain_obj.verified_ns,
                "verified_mx_10": domain_obj.verified_mx_10,
                "verified_mx_20": domain_obj.verified_mx_20,
                "verified_spf": domain_obj.verified_spf,
                # Add SMTP DNS status fields
                "verified_smtp_spf": domain_obj.verified_smtp_spf,
                "verified_dkim": getattr(domain_obj, 'verified_dkim', False),
                #"verified_arc": getattr(domain_obj, 'verified_arc', False),
                "verified_dmarc": getattr(domain_obj, 'verified_dmarc', False),
                "verified_dnssec": getattr(domain_obj, 'verified_dnssec', False),
            }

            verified_ns = domain_obj.verified_ns
            if verified_ns:
                dns_records = await load_dns_records(domain, org_id, user_id, session)
    
    return {
        "domain": domain,
        "dns_status": dns_status,
        "dns_records": dns_records
    }

class BulkDeleteRequest(BaseModel):
    record_ids: List[str]  # 12-char hash-based IDs
    domain: str
    organization_id: str

@router.post("/delete-multiple")
async def delete_multiple_dns_records(
    request: Request,
    payload: BulkDeleteRequest,
    refresh: bool = False,
    session: AsyncSession = Depends(get_session)
):
    """
    Bulk delete DNS records with multi‑IP proxy support:
      ✅ Deletes DNS record values
      ✅ Soft‑disables only the matching upstream_url
      ✅ Rebuilds proxy config if any upstreams remain
      ✅ Removes proxy config if none remain
      ✅ Single batch call to proxy VM
    """

    # 1️⃣ Auth & org validation
    auth_obj = await api_key_or_jwt_auth(request, session)
    if isinstance(auth_obj, APIKey):
        org_id = str(auth_obj.organization_id)
        user_id = None
    else:
        user_id = auth_obj
        org_id = payload.organization_id
        if not await verify_user_org_access(user_id, UUID(org_id), session):
            raise HTTPException(status_code=403, detail="Access denied to organization")

    domain = payload.domain
    if not await verify_domain_access(domain, org_id, user_id, session):
        raise HTTPException(status_code=403, detail="Access denied to domain")

    # 2️⃣ Load zone file
    zone_data = load_zone_from_gcs(domain, prefix="json/")
    deleted_ids = []

    # Prepare record metadata: include actual value!
    record_metadata = {}  # record_id → (type, name, index, value)
    proxiable_fqdns = set()

    for record_id in payload.record_ids:
        rtype, rname, rindex = find_record_by_id(zone_data[domain], record_id, domain)
        if not rtype or not rname:
            continue
        
        # Extract record value and ttl from Zone JSON
        robj = zone_data[domain][rtype][rname] if rindex is None else zone_data[domain][rtype][rname][rindex]
        if rtype == "CAA":
            rvalue = f"{robj.get('flags', 0)} {robj.get('tag', '')} {robj.get('value', '')}"
        elif rtype == "SRV":
            rvalue = f"{robj.get('weight', 0)} {robj.get('port', 0)} {robj.get('target', '')}"
        else:
            rvalue = robj.get("value")

        rpriority = robj.get("priority") if rtype in ["MX", "SRV"] else None
        rttl = robj.get("ttl", DEFAULT_TTL)


        record_metadata[record_id] = (rtype, rname, rindex, rvalue, rpriority, rttl)

        if rtype in ["A", "AAAA"]:
            fqdn = domain if rname == "@" else f"{rname}.{domain}"
            proxiable_fqdns.add(fqdn)

    # 3️⃣ Fetch all ProxyRoute rows for affected subdomains
    if proxiable_fqdns:
        subdomains = [fqdn.replace(f".{domain}", "") if fqdn != domain else "@"
                      for fqdn in proxiable_fqdns]

        rows = (await session.exec(
            select(ProxyRoute).where(
                ProxyRoute.domain == domain,
                ProxyRoute.organization_id == UUID(org_id),
                ProxyRoute.subdomain.in_(subdomains)
            )
        )).scalars().all()

        # subdomain → [ProxyRoute,...]
        proxy_map = {}
        for r in rows:
            proxy_map.setdefault(r.subdomain, []).append(r)
    else:
        proxy_map = {}

    # Track soft‑disabled proxies
    disabled_proxy_entries = []  # list of (fqdn, upstream_url)

    # 4️⃣ Delete DNS values and disable matching proxy entries
    log_batch = []
    # Sort record IDs by reverse index to safely delete from end of list
    for record_id, (rtype, rname, rindex, rvalue,  rpriority, rttl) in sorted(
        record_metadata.items(),
        key=lambda x: (x[1][0], x[1][1], -1 if x[1][2] is None else -x[1][2])
    ):
        fqdn = domain if rname == "@" else f"{rname}.{domain}"

        # Proxy soft delete
        if rtype in ["A", "AAAA"]:
            normalized = normalize_upstream_url(rvalue, fqdn, rtype)
            for route in proxy_map.get(rname, []):
                if route.upstream_url == normalized and route.proxy_enabled:
                    route.proxy_enabled = False
                    route.updated_at = datetime.utcnow()
                    session.add(route)
                    disabled_proxy_entries.append((fqdn, normalized))

        try:
            # Prepare values for DNSChangeLog
            is_proxiable = rtype in ["A", "AAAA"]
            #fqdn = domain if rname == "@" else f"{rname}.{domain}" # already declared above
            proxy_was_enabled = False

            if is_proxiable and rvalue:
                normalized_url = normalize_upstream_url(rvalue, fqdn, rtype)
                for route in proxy_map.get(rname, []):
                    if route.upstream_url == normalized_url and route.proxy_enabled:
                        proxy_was_enabled = True
                        break

            # Delete from zone_data
            if rindex is None:
                del zone_data[domain][rtype][rname]
            else:
                zone_data[domain][rtype][rname].pop(rindex)
                if not zone_data[domain][rtype][rname]:
                    del zone_data[domain][rtype][rname]

            if not zone_data[domain][rtype]:
                del zone_data[domain][rtype]

            deleted_ids.append(record_id)

            # 🔐 Write to DNSChangeLog
            try:
                log_entry = await save_dns_change_log(
                    domain=domain,
                    action="DELETE",
                    record={
                        "type": rtype,
                        "name": rname,
                        "value": rvalue,
                        "ttl": int(rttl),
                        "priority": rpriority,
                        "proxied": proxy_was_enabled if is_proxiable else None
                    },
                    user_id=user_id if user_id else None,
                    organization_id=UUID(org_id),
                    request=request,
                    session=session,
                    commit=False
                )

                if log_entry:
                    log_batch.append(log_entry)
            except Exception as e:
                print(f"🧾 Failed to log DNS deletion {record_id}: {e}")

        except Exception as e:
            print(f"⚠️ Failed to delete record {record_id}: {e}")
            continue

    # 🧾 Batch commit: both DNSChangeLog and ProxyRoute soft disables
    if log_batch or disabled_proxy_entries:
        try:
            await session.commit()
        except Exception as e:
            print(f"⚠️ DNSChangeLog batch commit failed: {e}")

    # 5️⃣ Determine which FQDNs to fully delete vs rebuild
    active_subdomains = set((await session.exec(
        select(ProxyRoute.subdomain)
        .where(
            ProxyRoute.domain == domain,
            ProxyRoute.organization_id == UUID(org_id),
            ProxyRoute.proxy_enabled == True
        )
        .distinct()
    )).scalars().all())

    fqdns_to_delete = set()
    fqdns_to_rebuild = set()

    for fqdn, _ in disabled_proxy_entries:
        subd = fqdn.replace(f".{domain}", "") if fqdn != domain else "@"
        if subd in active_subdomains:
            fqdns_to_rebuild.add(fqdn)
        else:
            fqdns_to_delete.add(fqdn)

    # 6️⃣ Batch‑delete proxy configs
    proxy_result = None
    if fqdns_to_delete:
        try:
            proxy_result = call_agent_hmac(
                PROXY_AGENT_IP,
                "/internal/proxy/delete_routes",
                method="POST",
                json=list(fqdns_to_delete),
                timeout=15
            )
            print(f"🧹 Deleted {len(fqdns_to_delete)} proxy routes")
        except Exception as e:
            print(f"⚠️ Batch proxy delete failed: {e}")

    # 7️⃣ Batch‑rebuild proxy configs
    if fqdns_to_rebuild:
        batch_payload = []

        for fqdn in fqdns_to_rebuild:
            subdomain = fqdn.replace(f".{domain}", "") if fqdn != domain else "@"

            normalized_upstreams = (await session.exec(
                select(ProxyRoute.upstream_url)
                .where(
                    ProxyRoute.domain == domain,
                    ProxyRoute.organization_id == UUID(org_id),
                    ProxyRoute.subdomain == subdomain,
                    ProxyRoute.proxy_enabled == True
                )
            )).scalars().all()

            print('='*32)
            print(f"[DEBUG] - normalized_upstreams: {normalized_upstreams}")
            print('='*32)
            
            if normalized_upstreams:
                batch_payload.append({
                    "fqdn": fqdn,
                    "upstream_urls": normalized_upstreams,
                    "enable_tls": True,
                    "host_override": fqdn
                })

        if batch_payload:
            try:
                call_agent_hmac(
                    PROXY_AGENT_IP,
                    "/internal/proxy/add_routes",
                    method="POST",
                    json=batch_payload,
                    timeout=15
                )
                print(f"🔁 Rebuilt {len(batch_payload)} proxy routes")
            except Exception as e:
                print(f"⚠️ Batch proxy rebuild failed: {e}")

    # 8️⃣ Save updated zone & deploy
    save_zone_to_gcs(domain, zone_data)
    deployment_results = await deploy_zone_to_agents_with_proxy(domain, zone_data[domain], org_id, session)

    new_records = []
    if refresh:
        new_records = await load_dns_records(domain, org_id, user_id, session)

    return {
        "status": "success",
        "message": f"Deleted {len(deleted_ids)} DNS record(s)",
        "deleted": deleted_ids,
        "proxy_deleted": list(fqdns_to_delete),
        "proxy_rebuilt": list(fqdns_to_rebuild),
        "deployment": deployment_results,
        "new_records": new_records
    }
