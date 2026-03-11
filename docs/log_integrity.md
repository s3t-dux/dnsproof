# DNSProof Log Integrity Specification (v1.1)

DNSProof maintains an append-only, cryptographically verifiable log of all DNS changes. Each log entry captures the complete semantic state of the change at the moment it occurred and produces a deterministic snapshot hash suitable for offline verification, auditing, and Merkle-based anchoring.

## 1. Canonical Snapshot

A snapshot captures the full state of a DNS change as a normalized JSON object. The current implementation produces a dictionary containing:

{
  "timestamp": "<UTC timestamp>",
  "domain": "<string>",
  "action": "<add|edit|delete|push-add|push-delete>",
  "record": { ... },
  "user_id": "<string>",
  "ip_address": "<string>"
}

### Canonicalization Rules

1. All keys are serialized using lexicographic key order.
2. Values are rendered in plain JSON, without whitespace deviations.
3. Null fields are preserved when historically present.
4. Datetime values are ISO-8601 / UTC.
5. Record objects follow fixed field ordering, enforced by JSON sorting.

Hashing:

```python
json_str = json.dumps(snapshot, sort_keys=True, default=str)
snapshot_hash = sha256(json_str.encode()).hexdigest()
```

## 2. Snapshot Hash & Ed25519 Signature

Each entry stores:

- snapshot_hash
- signature
- public_key

Signatures are Ed25519 over the snapshot hash.

## 3. Merkle Anchoring (Spec v1.1)

Given hashes h1...hN in chronological order, a Merkle tree is constructed using SHA-256(left||right). RFC6962 odd-leaf promotion applies.

This root can be published externally to guarantee immutability of the full sequence.

## 4. Offline Verification

The script `examples/verify_log_offline.py` performs:

1. Reconstruct canonical snapshots
2. Recompute hashes
3. Verify Ed25519 signatures
4. Recompute Merkle root (optional)

### Example: Canonical Snapshot Reconstruction  

A minimal demonstration of DNSProof’s canonical snapshot rules is provided in:  
`examples/canonical_snapshot_demo.py`  

This script shows:
- how a snapshot dictionary is serialized into canonical JSON
- how the SHA-256 digest is computed
- how deterministic hashing ensures independent verifiers produce identical results
Run it with:
```bash
python examples/canonical_snapshot_demo.py
```

## 5. Security Guarantees

- Integrity
- Non-repudiation
- Key-linked lineage
- Replay resistance
- Independent verification

## 6. Future Extensions

- DNSSEC-rooted Merkle commitments
- WASM/Rust verifiers
- Federated multi-party verification
