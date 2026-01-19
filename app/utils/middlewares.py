'''from fastapi import Request, HTTPException
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
'''
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request
from config import PASSWORD

class PasswordAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):  # skip docs, static, etc.
            auth = request.headers.get("Authorization")
            if not auth or not auth.startswith("Bearer "):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

            password = auth.split("Bearer ")[-1].strip()
            if password != PASSWORD:
                return JSONResponse({"detail": "Forbidden"}, status_code=403)

        return await call_next(request)
