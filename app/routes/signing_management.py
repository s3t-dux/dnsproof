# signing_management.py

from fastapi import APIRouter, HTTPException, Request
from utils.cryptographic_signing import log_key_generation
from pathlib import Path
import time
import os
from models.models import KeyGenerationLog
from utils.db import engine
from sqlmodel import Session, select

router = APIRouter()

@router.post("/rotate")
async def rotate_signing_key(request: Request):
    try:
        from utils.cryptographic_signing import SIGNING_KEY_PATH

        # Backup old key
        old_path = SIGNING_KEY_PATH
        if not old_path.exists():
            raise HTTPException(status_code=404, detail="Signing key not found")

        timestamp = int(time.time())
        backup_path = old_path.with_name(f"signing_key.backup.{timestamp}")
        os.rename(old_path, backup_path)

        # Generate and log new key
        log_key_generation()

        return {
            "status": "success",
            "message": "Key rotated successfully",
            "backup_path": str(backup_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {e}")

# placeholder route to list previous keys
@router.get("/keys")
async def list_keys():
    try:
        with Session(engine) as session:
            results = session.exec(select(KeyGenerationLog).order_by(KeyGenerationLog.created_at.desc())).all()
            return [r.dict() for r in results]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not fetch keys: {e}")