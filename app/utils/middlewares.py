from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from config import PASSWORD

class PasswordAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for root or healthcheck if needed
        if request.url.path in ["/", "/healthz"]:
            return await call_next(request)

        # Password from env var or config file
        expected_password = PASSWORD
        if not expected_password:
            return await call_next(request)  # no password set

        # Extract from header (e.g., `Authorization: Bearer mypass`)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized")

        password = auth.removeprefix("Bearer ").strip()
        if password != expected_password:
            raise HTTPException(status_code=403, detail="Forbidden")

        return await call_next(request)
