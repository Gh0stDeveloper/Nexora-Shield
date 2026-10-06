# ADR 0006 — Payload-preserving ZIP rebuild and official Android signing

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Phase A must rebuild APKs before later phases can transform DEX/resources. Recompression introduces avoidable semantic/build drift, while implementing APK signing ourselves would create a high-risk cryptographic compatibility surface.

## Decision

For Phase A:

1. parse standard ZIP32 internally;
2. preserve each supported entry's compressed payload byte-for-byte;
3. rebuild deterministic local/central metadata;
4. strip stale signing metadata;
5. invoke official Android `zipalign`;
6. invoke official Android `apksigner`;
7. verify with those official tools before publication.

ZIP64 and unsupported compression methods fail explicitly.

## Security consequences

The internal parser remains small and does not depend on a decompressor for normalization.

Signing-key handling stays within the Android-supported signer path. Passwords are provided through environment-variable references rather than embedded in Nexora Shield command-line values or reports.

## Compatibility consequences

The output may have different ZIP ordering/timestamps and a new signature, but application payload bytes are preserved in Phase A.

The pipeline requires Android Build Tools for aligned/signed production output.

## Alternatives considered

### Recompress every entry

Rejected for Phase A because it creates needless binary changes, increases attack surface and makes equivalence harder to prove.

### Implement APK V1/V2/V3 signing internally

Rejected because official Android tooling already provides the canonical implementation and verification behavior.

### Depend on a general ZIP library immediately

Deferred. A dependency may be introduced later if ZIP64/advanced features justify it, but Phase A's bounded parser keeps the trusted surface explicit.

## Follow-up

Phase B may intentionally change DEX payload bytes. At that point equivalence moves from byte/content preservation to semantic validation.
