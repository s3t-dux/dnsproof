from fastapi import FastAPI
from routes import ns_management, dns_management, dnssec_management, logs
from utils.db import init_db

app = FastAPI(title="DNSProof App Backend")

init_db()

app.include_router(ns_management.router, prefix="/api/ns", tags=["NS"])
app.include_router(dns_management.router, prefix="/api/dns", tags=["DNS"])
app.include_router(dnssec_management.router, prefix="/api/dnssec", tags=["DNSSEC"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])

@app.get("/")
async def root():
    return {"message": "Welcome to DNSProof App Backend"}
