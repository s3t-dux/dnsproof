from fastapi import FastAPI
from routes import ns_management, dns_management, dnssec_management, logs, signing_management
from utils.db import init_db
from utils.cryptographic_signing import ensure_signing_key_exists

app = FastAPI(title="DNSProof App Backend")

init_db() # Automatically create sqlite db if missing
ensure_signing_key_exists()  # Automatically creates and logs key if missing

app.include_router(ns_management.router, prefix="/api/ns", tags=["NS"])
app.include_router(dns_management.router, prefix="/api/dns", tags=["DNS"])
app.include_router(dnssec_management.router, prefix="/api/dnssec", tags=["DNSSEC"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(signing_management.router, prefix="/api/signing", tags=["Signing"])

@app.get("/")
async def root():
    return {"message": "Welcome to DNSProof App Backend"}
