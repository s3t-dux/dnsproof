# DNSProof

**DNSProof** is an open, reproducible, and self-hostable toolkit for running authoritative nameservers with cryptographically signed changelogs and DNSSEC support. It brings full auditability and developer-friendly control to a part of the internet that's long been opaque, centralized, and unverifiable.

## Key Features

- **Deterministic DNS change logs**  
  Track every DNS record update with deterministic, cryptographically verifiable history.

- **DNSSEC made practical**  
  Integrated DNSSEC support with automatic zone signing and key management.

- **Minimal 2-VM architecture**  
  Lightweight and production-tested setup for running your own nameservers.

- **API + CLI-based control plane**  
  Submit, verify, and sign DNS changes programmatically — ideal for GitOps and automation.

- **Built-in audit log explorer**  
  Easily inspect historical changes through a simple web UI or command line.

- **Reproducibility manifest**  
  To spin up the DNSProof CLI and backend using Docker or Nix:  
  
  [docker-nix/](./docker-nix/)

## Why DNSProof?

Most current DNS systems are either:
- **Centralized SaaS providers** (e.g., Cloudflare, Route53) that offer convenience but no visibility, or
- **Self-hosted BIND/CoreDNS setups** that are opaque, fragile, and nearly impossible to audit.

DNSProof solves this by providing:
- A semantic understanding of record changes — not just raw diffs
- Cryptographic proof of every mutation
- Full user sovereignty without third-party lock-in
- A realistic, scriptable setup that's already been battle-tested in production via the [StackDNS.io](https://stackdns.io) platform

## Project Status

DNSProof is actively evolving from StackDNS's live infrastructure. The current public release includes:

- Provisioning scripts for CoreDNS or NSD-based VMs  
- A signing and logging backend built in FastAPI (private for now)  
- A fully working CLI (`dnp.py`) for DNS record control, DNSSEC, logs, and zone management  
- Sample configuration files, demo logs, and developer documentation

## ▶ DNSProof CLI Demo (90s)

A 90-second walkthrough of the full lifecycle: config generation, nameserver provisioning, DNS record changes, DNSSEC, and verifiable logs.

[Watch: DNSProof_CLI_demo.mp4](https://storage.googleapis.com/dnsproof-assets/DNSProof_CLI_demo.mp4)

## Preview Resources

The following files are now available in this repository:

- `cli/dnp.py` — CLI entrypoint for DNS management and log verification  
- `DNSProof_CLI_demo.mp4` — 90s CLI demo showcasing the full config–deploy–verify cycle.  
- `docker-nix/` — Reproducible tools and envs with Docker and Nix  
- `examples/dns_config.yaml` — Sample configuration file  
- `examples/dnsproof.org.json` — Example zone file format  
- `examples/demo_logs.json` — Realistic signed DNS change logs  
- `examples/canonical_snapshot_demo.py` — Demonstrates canonical JSON serialization and SHA-256 hashing for DNS change snapshots  
- `examples/verify_log_offline.py` — Full offline integrity check: deterministic snapshot reconstruction + Ed25519 signature verification

These illustrate DNSProof’s focus on reproducibility, auditability, and developer-first UX.  

### Offline Log Verification  
DNSProof logs can be verified independently of the backend.  
Each DNS change is signed using Ed25519 over a deterministic, canonical snapshot:  
```json
{
  "timestamp": ...,
  "domain": ...,
  "action": ...,
  "record": ...,
  "user_id": ...,
  "ip_address": ...
}
```
The snapshot is serialized with `sort_keys=True`, hashed with SHA256, and signed.  
The resulting `snapshot_hash`, `signature`, and `public_key` are stored alongside the log entry.  
To verify a set of exported log entries:  
```bash
python examples/verify_log_offline.py examples/demo_logs.json
```
Example output:
```bash
Log ID: 511fbed5-...
[OK] Snapshot integrity verified
[OK] Signature authenticity verified
```
For readers who want to understand the hashing rule in isolation, a minimal example is available:
```bash
python examples/canonical_snapshot_demo.py
```
It demonstrates the exact canonical serialization and hashing behavior used throughout DNSProof.

This process does not require a running DNSProof backend or database.  
Verification depends only on deterministic serialization and standard Ed25519 cryptography.  

### Log Integrity & Cryptographic Guarantees

DNSProof maintains a cryptographically verifiable, append-only change log for all DNS modifications.
Each DNS update is recorded with:
- canonical JSON snapshot
- SHA-256 snapshot hash
- Ed25519 signature
- optional Merkle anchoring (Spec v1.1)
- strict key lifecycle tracking

This enables offline verification, tamper detection, and trust-minimized auditing.  

Full specification and verification instructions are documented in:

[`docs/log_integrity.md`](docs/log_integrity.md)

---

### Deterministic Zone Reconstruction

DNSProof’s signed snapshots record *how* DNS changes were made, but a verifier must also understand
*how these changes accumulate into authoritative DNS state*. To support independent auditing, the
project now includes a formal specification of “zone state” and a deterministic reconstruction model.

This document does not introduce a new algorithm; rather, it makes explicit the rules that any
verifier can use to reconstruct a zone from its full history of signed mutations—similar to how a
ledger can be replayed into an account balance.

The specification is available here:

[`docs/deterministic_zone_reconstruction.md`](docs/deterministic_zone_reconstruction.md)

---

### Experimental Merkle Log Anchoring

DNSProof also includes an experimental module exploring Merkle-based
anchoring of ordered `DNSChangeLog.snapshot_hash` values. This is not
part of the core trust model, but serves as forward-looking research on
structurally verifiable append-only histories.

The implementation and documentation are available under:
- `experiments/merkle_log.py`
- `experiments/verify_merkle_dns.py`
- `experiments/README.md`

These tools allow you to compute a local Merkle root, generate inclusion
proofs, and optionally compare the local root with a published
`_merkle.<domain>` TXT record. The experiment is intentionally isolated
from production signing logic.

---

A short video demo is also available at: [https://stackdns.io/nlnetdemo](https://stackdns.io/nlnetdemo)
