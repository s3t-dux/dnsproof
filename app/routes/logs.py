from fastapi import APIRouter, HTTPException
from sqlmodel import select, Session
from models.models import DNSChangeLog
from utils.db import engine

router = APIRouter()

@router.get("/logs", tags=["Logs"])
def get_dns_logs(limit: int = 50):
    """
    Returns the last `limit` DNS change logs, most recent first.
    """
    try:
        with Session(engine) as session:
            statement = select(DNSChangeLog).order_by(DNSChangeLog.created_at.desc()).limit(limit)
            results = session.exec(statement).all()
            return [entry.dict() for entry in results]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")
