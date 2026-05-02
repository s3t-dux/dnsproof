# Experiments

This directory contains experimental integrity-layer modules for DNSProof.

These are **not part of the core trust model** and may change without compatibility guarantees.


## Merkle Log (Experimental)

This experiment builds a deterministic Merkle tree over DNS change history using:

- ordered `DNSChangeLog.snapshot_hash` values  
- SHA-256 hashing  
- append-only construction  

Goal:

- evaluate whether DNS mutation history can be:
  - structurally verifiable  
  - compactly represented by a single root  
  - compared across independent instances  
  - optionally published via DNS (`_merkle.<domain>`)  


## How it works

- Leaves: `sha256("leaf:" + snapshot_hash)`   
- Parent: `sha256("node:" + left + right)`  
- Ordering: `(created_at ASC, id ASC)`  
- Odd nodes: last leaf is duplicated  

This ensures deterministic tree construction across environments.


## Included scripts

### `merkle_log.py`

- builds Merkle tree from local logs  
- computes root  
- generates inclusion proofs  
- verifies proofs locally  

Runs against the local database.


### `verify_merkle_dns.py`

- computes local Merkle root  
- fetches `_merkle.<domain>` TXT record  
- compares DNS-published root with local root  

Supports both resolver-based and direct nameserver queries. :contentReference[oaicite:3]{index=3}  


## What this enables

- compact commitment to full DNS change history  
- external publication of state (via DNS)  
- independent verification across systems  


## Boundaries

This experiment does **not**:

- sign the Merkle root  
- replace existing Ed25519 snapshot signatures  
- provide consensus or external anchoring  

Current trust still relies on signed snapshot hashes.


## Status

Experimental.

- schema and hashing rules may change  
- not intended for production use  
- no compatibility guarantees  


## Notes

This work explores extending DNSProof from:

  **individually signed events**

to:

  **structurally verifiable, append-only history**