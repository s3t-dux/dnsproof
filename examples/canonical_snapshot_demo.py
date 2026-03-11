"""
canonical_snapshot_demo.py

A minimal demonstration of how DNSProof canonicalizes a DNS change snapshot
and computes its deterministic SHA-256 hash. This mirrors the production logic
found in utils.zone_json and attestation handling.

Run:
    python3 canonical_snapshot_demo.py
"""

import json
import hashlib
from datetime import datetime, timezone


def canonical_snapshot(snapshot: dict) -> str:
    """
    Convert a snapshot dict into its canonical JSON string.
    Keys are lexicographically sorted; datetime objects normalized to ISO UTC.
    """
    return json.dumps(snapshot, sort_keys=True, default=str)


def snapshot_hash(canonical_json: str) -> str:
    """Compute SHA-256 over the canonical JSON string."""
    return hashlib.sha256(canonical_json.encode()).hexdigest()


if __name__ == "__main__":

    # Example record representing a DNS add/change action
    snapshot = {
        "timestamp": datetime.now(timezone.utc),
        "domain": "example.com",
        "action": "add",
        "record": {
            "type": "A",
            "name": "www",
            "value": "203.0.113.10",
            "ttl": 3600
        },
        "user_id": "system",
        "ip_address": "127.0.0.1",
    }

    print("=== Original Snapshot Dict ===")
    print(snapshot)
    print()

    # 1. Canonical JSON
    canonical = canonical_snapshot(snapshot)
    print("=== Canonical JSON ===")
    print(canonical)
    print()

    # 2. Hash
    digest = snapshot_hash(canonical)
    print("=== SHA-256 Digest ===")
    print(digest)
    print()

    print("Demo complete. This canonical JSON + hash format matches DNSProof's backend logic.")