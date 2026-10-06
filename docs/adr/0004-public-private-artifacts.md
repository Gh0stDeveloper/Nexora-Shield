# ADR 0004 — Public/private build-artifact separation

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Nexora Shield needs mappings, seeds, transform metadata and VM/integrity information to support retrace and controlled reproducibility. Publishing those artifacts would reduce protection value.

## Decision

Every protected build has two artifact classes.

Public artifacts may contain the protected application, checksums, SBOM, non-sensitive reports and provenance.

Private artifacts may contain symbol mappings, seeds/references, transform manifests, VM maps, integrity topology and retrace metadata.

CI, logging and storage paths must treat them separately.

## Security consequences

Leakage of private artifacts is a security incident. Private material must not be embedded into the protected package or printed in normal CI logs.

## Compatibility consequences

Support tooling must identify the exact build before retracing.

## Alternatives considered

### One combined report

Rejected because access control becomes too coarse and accidental publication more likely.

## Follow-up

Phase A defines concrete report formats and storage hooks.
