import os
from pathlib import Path
from nacl.signing import SigningKey
import base64

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

def generate_local_key():
    path = os.path.expanduser("~/.dnsproof/signing_key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(SigningKey.generate().encode())
