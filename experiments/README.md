# Experiments

This directory contains experimental integrity-layer research modules
for DNSProof.

Code under `experiments/`:

-   Is **not** part of the core DNSProof trust model
-   Is not covered by API stability guarantees
-   May change without backward compatibility
-   Is intentionally isolated from production routes and signing flows

These modules evaluate potential future extensions to DNSProof's
cryptographic integrity architecture.

------------------------------------------------------------------------

# Merkle-Based DNS Change Log Anchoring (Experimental)

## Objective

DNSProof currently guarantees:

-   Deterministic canonical JSON serialization of zone state
-   Ed25519-signed DNS change events
-   Snapshot-level hash verification per mutation

This experiment evaluates an additional structural integrity layer:

> A deterministic, append-only Merkle tree constructed over ordered
> `DNSChangeLog.snapshot_hash` values.

The purpose is to explore whether DNS mutation history can be:

-   Structurally verifiable
-   Compactly anchored via a single root hash
-   Compared across independent instances
-   Optionally published via DNS (e.g., `_merkle.<domain>`)

This design follows principles used in append-only transparency logs and
Merkle-based audit systems.

------------------------------------------------------------------------

# Deterministic Ordering

Merkle leaves are derived from `DNSChangeLog.snapshot_hash`.

Ordering is strictly defined as:

ORDER BY created_at ASC, id ASC

Both fields are required to ensure deterministic ordering across
instances.

Changing the ordering rule invalidates compatibility with previously
computed roots.

------------------------------------------------------------------------

# Merkle Specification (v1.1)

## Hash Function

-   SHA256
-   Hex-encoded (lowercase)
-   UTF-8 input encoding
-   No newline or prefix characters

## Domain Separation

To prevent structural ambiguity between leaf and internal node hashes:

-   Leaf hash: sha256("leaf:" + snapshot_hash)

-   Parent hash: sha256("node:" + left_hex + right_hex)

Domain prefixes ("leaf:", "node:") ensure leaf and node namespaces are
disjoint.

## Tree Construction Rules

-   Level 0 consists of leaf hashes.
-   Each parent node is computed from adjacent pairs.
-   If a level contains an odd number of nodes, the final node is
    duplicated.
-   The Merkle root is the sole remaining node at the final level.

Tree construction is O(n) and currently performed in memory.

------------------------------------------------------------------------

# Included Modules

## `merkle_log.py`

Functions:

-   Deterministically fetch ordered `snapshot_hash` entries
-   Build full Merkle tree
-   Compute Merkle root
-   Generate inclusion proof for a given index
-   Verify inclusion proof locally

Operates exclusively on the local SQLite database.

No production APIs are modified.

------------------------------------------------------------------------

## `verify_merkle_dns.py`

Extends local Merkle root computation with DNS publication comparison.

Features:

-   Computes local Merkle root from ordered logs
-   Queries `_merkle.<domain>` TXT record
-   Supports:
    -   Recursive resolver lookup
    -   Direct authoritative nameserver query
-   Compares normalized DNS TXT value against local root

This enables external publication validation without modifying the
DNSProof signing model.

------------------------------------------------------------------------

# Trust Model Boundaries

This module does **not**:

-   Sign the Merkle root with the DNSProof signing key
-   Provide multi-party consensus or witness validation
-   Anchor roots to external timestamp authorities
-   Replace existing Ed25519 snapshot signatures

Current root publication relies on DNS integrity (DNSSEC recommended).

The Ed25519-signed snapshot hashes remain the primary cryptographic
trust anchor.

------------------------------------------------------------------------

# Research Motivation

This experiment evaluates whether DNSProof can evolve from:

Independent, signed mutation events

to:

Structurally verifiable append-only mutation history

Potential future directions include:

-   Third-party log verification
-   Root signing by active signing key
-   External anchoring (e.g., timestamp services)
-   Cross-instance state comparison
-   Public audit modes

No integration roadmap is currently committed.

------------------------------------------------------------------------

# Stability Notice

This is experimental code.

-   The Merkle specification may evolve.
-   Hash construction rules may change.
-   Data compatibility across versions is not guaranteed.
-   Production systems must not depend on this module.
