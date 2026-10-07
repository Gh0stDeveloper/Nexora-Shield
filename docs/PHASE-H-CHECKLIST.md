# Phase H — Per-Build Diversification checklist

## H.1 Seed model
- [x] Private seed type
- [x] 32-byte minimum seed strength
- [x] Debug redaction
- [x] Zeroize on drop
- [x] Application/build context
- [x] Seven independent HMAC domains
- [x] Domain-separation regression test

## H.2 Reproducible private mode
- [x] unique_build mode
- [x] Explicit build nonce
- [x] reproducible_private mode
- [x] Explicit reproduction id
- [x] Exact same-context reproducibility test
- [x] Different nonce divergence test

## H.3 Rename diversity
- [x] Dedicated rename domain
- [x] Existing RenameConfig integration
- [x] Existing compatibility rules preserved
- [x] Build-specific rename fingerprint
- [x] Different-build seed test

## H.4 Pass variants
- [x] Typed pass model
- [x] Constrained early-pass permutation
- [x] Constrained middle-pass permutation
- [x] Integrity manifest fixed last
- [x] Plan validity check
- [x] Multi-build diversity test

## H.5 CFG variants
- [x] Per-method derivation
- [x] Seeded VM block-boundary selection
- [x] Boundary padding variant
- [x] Boundary trampoline variant
- [x] Branch/handler target remapping
- [x] Post-transform VM validation
- [x] Original-vs-diversified semantic execution test

## H.6 Integrity graph topology variants
- [x] Seeded tree
- [x] Layered fanout
- [x] Seeded chain
- [x] Certificate root preserved
- [x] Package binding preserved
- [x] All node/digest data preserved
- [x] Graph root recomputed
- [x] Duplicate-edge rejection
- [x] Diversified graph validation

## H.7 String container partition variants
- [x] Min/max partition bounds
- [x] Opaque build-specific shard names
- [x] Seeded item order
- [x] Seeded partition offset
- [x] No empty emitted shards
- [x] Every logical id exactly once
- [x] Phase C ProtectedString materialization
- [x] Public shards contain opaque id + ciphertext only
- [x] Private logical lookup redacted from Debug
- [x] Cross-build partition fingerprint

## H.8 VM map variants
- [x] Dedicated VM domain
- [x] Phase G OpcodeAllocation integration
- [x] Per-build fingerprint
- [x] Cross-build allocation test

## H.9 Native generated constants
- [x] Dedicated native domain
- [x] Phase F GeneratedNativeData integration
- [x] Per-build fingerprint
- [x] Cross-build generated-data test

## H.10 Cross-build bypass regression
- [x] Seven-surface build signature
- [x] Full build fingerprint
- [x] Pairwise shared-surface analysis
- [x] Transfer basis-points metric
- [x] 32-build regression corpus
- [x] 3000 bp maximum transfer acceptance threshold
- [ ] Final dedicated CI gate

## Closure state

Phase H implementation is **IN PROGRESS**. H.1–H.10 code and tests are present. The phase is not closed until strict Rust quality, Rust 1.81 MSRV, the 32-build bypass portability gate and full Phase A–G regressions are green on the final head.
