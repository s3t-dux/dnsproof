### agent.py
from fastapi import FastAPI
from dns_routes import router as dns_zone_router


app = FastAPI()
app.include_router(dns_zone_router)