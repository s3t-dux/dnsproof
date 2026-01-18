import os
from pathlib import Path
from nacl.signing import SigningKey
import base64

from models.models import KeyGenerationLog
from sqlmodel import Session
from utils.db import engine
from datetime import datetime
import time

DEFAULT_KEY_PATH = Path.home() / ".dnsproof" / "signing_key"
SIGNING_KEY_PATH = Path(os.getenv("SIGNING_KEY_PATH", DEFAULT_KEY_PATH))

def get_local_signature(message: str) -> dict:
    with open(SIGNING_KEY_PATH, "rb") as f:
        sk = SigningKey(f.read())
    signed = sk.sign(message.encode("utf-8"))
    return {
        "signature": base64.b64encode(signed.signature).decode(),
        "public_key": base64.b64encode(sk.verify_key.encode()).decode()
    }

def log_key_generation():
    path = SIGNING_KEY_PATH
    sk = SigningKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(sk.encode())

    pk = sk.verify_key.encode()
    log = KeyGenerationLog(
        key_type="dns_record",
        public_key=base64.b64encode(pk).decode(),
        key_path=str(path),
    )

    with Session(engine) as session:
        session.add(log)
        session.commit()

def ensure_signing_key_exists():
    if not SIGNING_KEY_PATH.exists():
        print("[INFO] No signing key found. Generating new key...")
        log_key_generation()
    else:
        try:
            with open(SIGNING_KEY_PATH, "rb") as f:
                SigningKey(f.read())  # Attempt to parse
            print("[INFO] Signing key already exists and is valid.")
        except Exception as e:
            print(f"[WARN] Signing key invalid or corrupted: {e}")
            backup_path = SIGNING_KEY_PATH.with_name(f"corrupted_signing_key.{int(time.time())}")
            os.rename(SIGNING_KEY_PATH, backup_path)
            print(f"[INFO] Backed up corrupted key to: {backup_path}")
            log_key_generation()
