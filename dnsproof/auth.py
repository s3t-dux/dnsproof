from fastapi import Request, Header, HTTPException
import hashlib
import hmac
from functools import wraps
from config import AGENT_SECRET

# simple function version - not in use
async def verify_hmac(request: Request, signature: str = Header(None)):
    if not signature:
        raise HTTPException(status_code=403, detail="Missing signature")

    if not AGENT_SECRET:
        raise HTTPException(status_code=500, detail="Server misconfigured: missing AGENT_SECRET")

    raw_body = await request.body()
    expected_sig = hmac.new(
        AGENT_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(status_code=403, detail="Invalid signature")

def hmac_protected():
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, request: Request, **kwargs):
            signature = request.headers.get("X-Signature")
            if not signature:
                raise HTTPException(status_code=403, detail="Missing signature")

            if not AGENT_SECRET:
                raise HTTPException(status_code=500, detail="Server misconfigured: missing AGENT_SECRET")

            raw_body = await request.body()
            expected_sig = hmac.new(
                AGENT_SECRET.encode(), raw_body, hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                raise HTTPException(status_code=403, detail="Invalid signature")

            return await func(*args, request=request, **kwargs)

        return wrapper
    return decorator