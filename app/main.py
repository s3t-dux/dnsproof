from fastapi import FastAPI
from routes import ns_management, dns_management, dnssec_management

app = FastAPI(title="DNSProof App Backend")

app.include_router(ns_management.router, prefix="/api/ns", tags=["NS"])
app.include_router(dns_management.router, prefix="/api/dns", tags=["DNS"])
app.include_router(dnssec_management.router, prefix="/api/dnssec", tags=["DNSSEC"])

@app.get("/")
async def root():
    return {"message": "Welcome to DNSProof App Backend"}
