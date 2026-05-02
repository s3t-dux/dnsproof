# DNSProof

**Portable, legible, and verifiable DNS**.

DNSProof is a system and set of tools for managing DNS as a **deterministic, auditable state**, rather than an opaque control plane tied to a provider.

In conventional workflows, DNS configuration is stored and mutated inside provider systems. While changes can be applied and observed, the resulting state is not preserved in a way that allows independent reconstruction or verification.

DNSProof takes a different approach:

**DNS is treated as a state that can be reproduced, hashed, and verified independently.**

## What DNSProof enables

DNSProof makes DNS state easier to **reproduce, inspect, and verify** across environments.

In typical DNS workflows, configuration is tied to provider-specific systems. While changes can be applied and observed, there is no portable representation of state, and limited ability to reconstruct or verify it independently.  

DNSProof introduces a simple structure:

- a canonical representation of DNS state
- a recorded sequence of changes
- and a cryptographic snapshot (hash) of that state

Together, these allow DNS configurations to be:

- exported and re-applied across environments
- compared reliably
- verified independently

## Repository scope

This repository exposes the CLI (demo), verification surface, and supporting experiments of DNSProof.

Included:

- `cli/` — command-line interface for interacting with DNSProof systems (demo surface)
- `examples/` — standalone verification examples
- `experiments/` — research and prototype implementations (e.g. Merkle trees)

Not included in this repository:

- backend services for state management and logging
- frontend UI for domain and system interaction
- nameserver provisioning tooling
- full packaging and distribution configuration (e.g. `pyproject.toml`)

The public repository is intended to surface the interaction and verification model, rather than the full deployment stack.

## What DNSProof does

DNSProof defines DNS as a structured state with three properties:

### Canonical state
A complete, normalized representation of DNS records.

- Stored as structured JSON
- Deterministically serialized
- Independent of provider-specific formats

### Change history
Each DNS modification is recorded as a structured event.

- Add / update / delete operations
- Timestamped and attributable
- Produces a new state snapshot

### Verifiable snapshots
Each state can be reduced to a stable cryptographic identifier.

- Deterministic hashing (e.g. SHA-256 over normalized state)
- Snapshot comparison enables constant-time equality checks
- Changes produce new, independently verifiable states

This allows DNS state to be:
- reconstructed from history
- compared across environments
- verified without relying on the original system

## CLI usage

The dnp CLI provides an interface for interacting with DNSProof-enabled systems.

Example
```bash
# Add a DNS record
dnp add -d example.com --type A --name www --value 1.2.3.4

# View current state
dnp records -d example.com

# View DNS change logs
dnp logs-dns -d example.com

# Verify a log entry
dnp verify-log --id <log_id>

# Export portable DNS state
dnp export-domain -d example.com -o ./bundle
```
The CLI can also:
- manage DNSSEC lifecycle operations
- inspect nameserver status
- export and import portable domain bundles
- verify logs offline

## Verification
DNSProof emphasizes **independent verification of DNS state and changes**.
A DNS change produces:
- a deterministic snapshot hash
- a signed log entry
- a verifiable record of the transition

Logs can be verified:
- via API
- via CLI
- offline using exported data

The `examples/` directory includes minimal, self-contained scripts for:
- verifying DNS change logs offline
- reproducing canonical snapshot hashing behavior

These examples demonstrate the verification model without requiring a running DNSProof backend.

## Experiments
The `experiments/` directory contains prototype implementations exploring:
- Merkle tree–based commitment structures
- alternative verification models for DNS state
- efficient inclusion and consistency proofs

These are not required for core functionality, but inform the design of scalable verification mechanisms.

## Status
DNSProof is under active development.  
The current repository provides:
- a CLI for interacting with DNSProof systems (demo)
- verifiable DNS log examples
- experimental verification primitives
- reproducible manifest in [`docker-nix/`](docker-nix/)

The broader system continues to evolve alongside these components.

## Database Backend

DNSProof defaults to a local SQLite database for simple, no-setup development.  
If no `DATABASE_URL` is provided, the backend uses `DB_PATH` and creates or opens a local SQLite database file.

```env
DB_PATH=./dnsproof.db
```
For more explicit deployments, `DATABASE_URL` can be set to any supported SQLAlchemy database URL. When `DATABASE_URL` is present, it takes precedence over `DB_PATH`.
```env
# Explicit SQLite URL
DATABASE_URL=sqlite:///./dnsproof.db

# PostgreSQL URL
DATABASE_URL=postgresql+psycopg://dnsproof_user:password@127.0.0.1:5432/dnsproof
```
For PostgreSQL, create the database beforehand. DNSProof initializes its required tables on startup, but does not create the database itself.
```bash
createdb -U postgres -h 127.0.0.1 dnsproof
```
SQLite remains the recommended default for cold-start and local use. PostgreSQL is intended for more durable or multi-environment deployments.

## ▶ DNSProof CLI Demo (90s)
A short walkthrough of the DNSProof lifecycle:
- configuration generation
- nameserver provisioning
- DNS record changes
- DNSSEC operations
- verifiable change logs

[Watch: DNSProof_CLI_demo.mp4](https://storage.googleapis.com/dnsproof-assets/DNSProof_CLI_demo.mp4)

---

A short video demo is also available at: [https://stackdns.io/nlnetdemo](https://stackdns.io/nlnetdemo)
