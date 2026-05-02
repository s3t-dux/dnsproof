# Examples

This directory contains minimal, self-contained examples for verifying DNSProof data structures without a running backend.

## Offline Log Verification

DNSProof logs can be verified independently of the backend.

Each DNS change is stored as a log entry containing:

- metadata (domain, action, user, IP)
- a serialized record snapshot (`full_snapshot`)
- a `snapshot_hash`
- a `signature`
- a `public_key`

The canonical snapshot used for verification is **reconstructed deterministically** from the log entry:

```json
{
  "timestamp": <snapshot_timestamp>,
  "domain": ...,
  "action": ...,
  "record": <parsed full_snapshot>,
  "user_id": ...,
  "ip_address": ...
}
```

This snapshot is:

- serialized using `json.dumps(..., sort_keys=True)`
- hashed using SHA-256
- verified against an Ed25519 signature


### Verify exported logs

```bash
python examples/verify_log_offline.py examples/demo_logs.json
```

Example output:

```
Log ID: 511fbed5-...
[OK] Snapshot integrity verified
[OK] Signature authenticity verified
```

This verifies:

- the reconstructed snapshot matches the stored hash  
- the signature is valid for the given public key  


## Canonical Snapshot Demo

To inspect the hashing rule in isolation:

```bash
python examples/canonical_snapshot_demo.py
```

This demonstrates:

- deterministic JSON serialization  
- stable SHA-256 hashing  
- canonical snapshot construction  

It mirrors the snapshot hashing logic used in DNSProof.


## Requirements

```bash
pip install -r requirements.txt
```

Requires:

- `pynacl` (Ed25519 verification)


## Properties

This verification process:

- does not require a running DNSProof backend  
- does not require a database  
- depends only on:
  - deterministic serialization
  - SHA-256 hashing
  - Ed25519 signature verification  


## Log Integrity & Cryptographic Guarantees

DNSProof maintains a verifiable, append-only change log for DNS modifications.

Each log entry includes:

- canonical snapshot (reconstructible)
- SHA-256 snapshot hash  
- Ed25519 signature  
- strict key lifecycle tracking  
- optional Merkle anchoring (Spec v1.1)  

This enables:

- offline verification  
- tamper detection  
- trust-minimized auditing  


## Further Reading

See:

- [`docs/log_integrity.md`](docs/log_integrity.md)
