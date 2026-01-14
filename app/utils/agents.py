from fastapi import HTTPException
from typing import Any, Dict, Optional
import json
import hmac
import hashlib
import httpx
from config import AGENT_SECRET

def json_dumps(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

async def call_agent_hmac_async(ip, path, secret=AGENT_SECRET, json=None, method="POST", timeout=5):
    url = f"http://{ip}:8000{path}"

    headers = {}
    body_bytes = b""

    # Set body content and Content-Type
    if method == "POST":
        if json:
            body_bytes = json_dumps(json)
            headers["Content-Type"] = "application/json"
    elif method == "DELETE":
        # Extract domain from path
        domain = path.split("/")[-1]
        body_bytes = domain.encode()
        headers["Content-Type"] = "text/plain"
    elif method == "GET":
        body_bytes = b""

    # Sign the body
    signature = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
    headers["X-Signature"] = signature

    async with httpx.AsyncClient(timeout=timeout) as client:
        res = await client.request(method, url, content=body_bytes, headers=headers)

    try:
        res.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Agent error: {e.response.text}"
        )

    return res

# legacy code - jumbled
'''
async def call_agent_hmac_async(ip, path, secret=AGENT_SECRET, json=None, method="POST", timeout=5):
    url = f"http://{ip}:8000{path}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        if method == "DELETE":
            fqdn = path.split("/")[-1]
            body_bytes = fqdn.encode()
            signature = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
            headers = {
                "Content-Type": "text/plain",
                "X-Signature": signature,
            }
            res = await client.request("DELETE", url, content=body_bytes, headers=headers)
        elif method == "POST":
            headers = {"Content-Type": "application/json"}
            if json:
                body_bytes = json_dumps(json)
                signature = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
                headers["X-Signature"] = signature
            else:
                body_bytes = None
            res = await client.post(url, content=body_bytes, headers=headers)
        elif method == "GET":
            body_bytes = b""
            signature = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
            headers = {"X-Signature": signature}
            res = await client.get(url, headers=headers)

    try:
        res.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Agent error: {e.response.text}"
        )
    return res
'''