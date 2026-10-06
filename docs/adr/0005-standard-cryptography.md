# ADR 0005 — Standard cryptography only

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Application protectors frequently need authenticated encryption, hashing, KDFs and signatures. Inventing custom cryptography creates unnecessary catastrophic risk.

## Decision

Nexora Shield will not invent cryptographic primitives.

Use established, reviewed algorithms and libraries. Novelty belongs in composition, diversification and placement, not in replacing standard encryption or authentication primitives.

Cryptographic agility must be represented by versioned formats rather than hidden algorithm substitution.

## Security consequences

Security review can focus on key lifecycle, nonce use, domain separation, storage and composition instead of unreviewed ciphers.

## Compatibility consequences

Encrypted container formats must carry a version/algorithm identifier sufficient for migration.

## Alternatives considered

### Proprietary cipher for obscurity

Rejected. Obscurity may supplement but cannot substitute for cryptographic security.

## Follow-up

Phase C selects concrete primitives and libraries through a dedicated ADR after benchmarking and review.
