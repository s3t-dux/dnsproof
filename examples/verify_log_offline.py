import json
import sys
import hashlib
import base64
from nacl.signing import VerifyKey


def canonical_snapshot(log_entry: dict) -> dict:
    """
    Reconstruct the canonical snapshot exactly as it was serialized for signing.
    """

    return {
        "timestamp": log_entry["snapshot_timestamp"],
        "domain": log_entry["domain"],
        "action": log_entry["action"],
        "record": json.loads(log_entry["full_snapshot"]),
        "user_id": log_entry["user_id"],
        "ip_address": log_entry["ip_address"],
    }


def compute_hash(snapshot: dict) -> str:
    """
    Deterministic JSON → SHA256 hex digest.
    """
    json_str = json.dumps(snapshot, sort_keys=True, default=str)
    return hashlib.sha256(json_str.encode()).hexdigest()


def verify_signature(snapshot_hash: str, signature_b64: str, public_key_b64: str) -> bool:
    """
    Verify Ed25519 signature over snapshot_hash.
    """
    verify_key = VerifyKey(base64.b64decode(public_key_b64))
    verify_key.verify(
        snapshot_hash.encode(),
        base64.b64decode(signature_b64)
    )
    return True

def main(path):
    with open(path) as f:
        logs = json.load(f)

    all_valid = True

    for entry in logs:
        print(f"\nLog ID: {entry['id']}")

        required_fields = [
            "snapshot_timestamp",
            "domain",
            "action",
            "full_snapshot",
            "user_id",
            "ip_address",
            "snapshot_hash",
            "signature",
            "public_key",
        ]

        for field in required_fields:
            if field not in entry:
                print(f"[FAIL] Missing required field: {field}")
                all_valid = False
                continue

        snapshot = canonical_snapshot(entry)
        recomputed_hash = compute_hash(snapshot)

        stored_hash = entry["snapshot_hash"]

        if recomputed_hash != stored_hash:
            print("[FAIL] Snapshot hash mismatch")
            print(f"  Stored:     {stored_hash}")
            print(f"  Recomputed: {recomputed_hash}")
            all_valid = False
            continue
        else:
            print("[OK] Snapshot integrity verified")

        try:
            verify_signature(
                stored_hash,
                entry["signature"],
                entry["public_key"]
            )
            print("[OK] Signature authenticity verified")
        except Exception as e:
            print(f"[FAIL] Signature verification failed: {e}")
            all_valid = False

    if not all_valid:
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_log_offline.py demo_logs.json")
        sys.exit(1)

    main(sys.argv[1])
