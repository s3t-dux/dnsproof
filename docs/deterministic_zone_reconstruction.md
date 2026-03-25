# Deterministic Zone Reconstruction

## Overview

DNSProof already signs and verifies individual DNS change events.  
The next step is broader: those signed changes should also make it possible to reconstruct full zone state.

This document describes that reconstruction model.

DNSProof does **not yet** expose full historical reconstruction as a user-facing feature.  
The purpose of this note is to make the underlying capability explicit: a signed mutation log can support deterministic reconstruction of authoritative DNS records.

## Why it matters

A signed log is more than an audit trail.

If mutations are ordered and applied deterministically, an independent verifier can:

- verify that a change happened,
- apply the signed change history,
- derive the expected zone state,
- compare that reconstructed state with a snapshot or published zone.

That pushes DNSProof beyond event integrity alone.  
It starts turning signed DNS history into verifiable state.

## Reconstruction model

The model is straightforward in principle:

1. Start from a known zone state.
2. Apply signed change entries in deterministic order.
3. Reconstruct the resulting zone contents.
4. Compare the result against a canonical snapshot or live zone data when needed.

Given the same starting point and the same valid mutation history, reconstruction should always produce the same zone state.

## What reconstruction requires

### Initial state

Reconstruction must begin from a known base.  
That can be either:

- an empty zone, if history starts at creation, or
- a trusted snapshot, if reconstruction starts later.

### Ordered change history

Signed mutations must be applied in a stable order, such as:

- sequence number,
- signed timestamp,
- or another monotonic ordering defined by DNSProof.

The requirement is simple: same log, same reconstruction result.

### Clear mutation semantics

Each signed entry must correspond to an unambiguous zone mutation:

- add record,
- update record,
- delete record.

Reconstruction only works if mutation handling is deterministic and canonical.

## Canonical form

Reconstruction should operate on canonical DNS data, not on incidental text formatting.

That includes stable handling of:

- names,
- TTLs,
- record types,
- RRset ordering,
- zone serialization.

Logically equivalent DNS state should reconstruct to the same canonical result.

## Verification value

Deterministic reconstruction is most useful when paired with snapshots.

A verifier can reconstruct history to a target point, derive the expected zone state, and compare it against a canonical snapshot.  
That gives DNSProof two complementary integrity checks:

- **event verification** — was this change signed and recorded?
- **state verification** — does the resulting zone state match the signed history?

## Integrity signals

Deterministic reconstruction should surface meaningful inconsistencies, including:

- missing log entries,
- invalid signatures,
- ambiguous ordering,
- conflicting mutations,
- deletion of non-existent records,
- mismatch between reconstructed state and canonical snapshot.

These are integrity failures, not just implementation details.

## Current status

DNSProof already has the pieces that point in this direction:

- signed DNS change logging,
- canonical snapshot work,
- offline log verification.

Deterministic zone reconstruction is the next step in that line of development.  
It makes explicit that authenticated DNS mutations can be used not only to prove that an event occurred, but also to reconstruct the state that event history produced.

## Bottom line

DNSProof is moving toward a stronger model of transparency:

> signed DNS history should be sufficient not only to audit changes, but also to reconstruct authoritative zone state.

That matters because it makes the system more legible to independent verification, not only to the server currently hosting the zone.