from fastapi import FastAPI
from routes import dns, dnssec, dnssec_app

app = FastAPI(title="DNSProof App Backend")

# Include DNS routes
app.include_router(dns.router, prefix="/api/dns", tags=["DNS"])

# Include DNSSEC routes
app.include_router(dnssec.router, prefix="/api/dnssec", tags=["DNSSEC"])

app.include_router(dnssec_app.router, prefix="/api/app/dnssec", tags=["DNSSEC_app"])

@app.get("/")
async def root():
    return {"message": "Welcome to DNSProof App Backend"}
