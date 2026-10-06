# Phase A — Core Packaging checklist

Phase A establishes the first complete executable APK packaging pipeline for Nexora Shield.

## A.1 Rust workspace — DONE

Evidence:

- `crates/shield-package`;
- `crates/shield-core`;
- `crates/shield-cli`;
- workspace and lockfile updated.

## A.2 CLI skeleton — DONE

Evidence:

- `nexora-shield protect`;
- `nexora-shield inspect`;
- `nexora-shield verify`;
- `nexora-shield profiles`;
- strict option validation and explicit unsigned opt-in.

## A.3 ZIP/APK normalizer — DONE

Evidence:

- standard ZIP32 parser/writer;
- deterministic entry order and metadata;
- payload-preserving rebuild;
- stale v1/JAR signing metadata removal;
- duplicate/path-traversal/encryption/unsupported-method rejection;
- ZIP64 explicitly rejected rather than partially handled;
- malformed local/central metadata rejected.

## A.4 Manifest inspection — DONE

Evidence:

- mandatory `AndroidManifest.xml`;
- compression/size/CRC metadata;
- bounded SHA-256 for stored manifests;
- binary XML/text XML/unknown/compressed format classification.

## A.5 Multi-DEX discovery — DONE

Evidence:

- canonical `classes.dex`, `classes2.dex`, ... discovery;
- strict root-level names;
- contiguous sequence verification;
- regression test for DEX gaps.

## A.6 BuildPlan — DONE

Evidence:

- immutable build ID;
- configuration schema/profile;
- input fingerprint;
- input/output paths;
- timestamp;
- signing/alignment intent;
- expected DEX count.

## A.7 Transactional pipeline — DONE

Evidence:

- isolated sibling transaction directory;
- normalize -> content verify -> align -> sign -> package verify -> publish;
- final destination untouched until verification;
- `--force` backup/restore semantics;
- transaction cleanup.

## A.8 Public/private reports — DONE

Evidence:

- public CI-safe JSON build report;
- private operational build report;
- atomic report writes;
- no signing passwords serialized.

## A.9 apksigner/zipalign integration — DONE

Evidence:

- explicit Android Build Tools overrides;
- SDK build-tools discovery;
- `zipalign -P 16 -f 4`;
- alignment verification;
- V1/V2/V3 APK signing;
- V4 deliberately deferred as separate `.idsig` artifact;
- password environment-variable references;
- `apksigner verify --verbose --print-certs`.

## A.10 protect/inspect/verify — DONE

Evidence:

- real command execution;
- structured inspection JSON;
- structural verification;
- optional signature verification;
- production-safe signing defaults.

## Strict validation

GitHub Actions run #96, ID `37512809317`, completed successfully on the implementation branch.

Validated gates:

- [x] JSON Schema syntax;
- [x] rustfmt;
- [x] Clippy with warnings denied;
- [x] workspace unit/integration tests;
- [x] rustdoc with warnings denied;
- [x] CLI smoke tests;
- [x] RustSec audit;
- [x] synthetic multidex APK generation;
- [x] ephemeral PKCS12 generation;
- [x] deterministic APK normalization;
- [x] `zipalign` execution and verification;
- [x] V1/V2/V3 signing;
- [x] `inspect` against protected output;
- [x] `apksigner verify`;
- [x] public/private report JSON validation.

## Phase A limitations

The following are deliberately deferred and are not hidden incompleteness:

- ZIP64;
- AAB/AAR/splits;
- full binary AndroidManifest semantic decoding;
- DEX instruction parsing/rewrite;
- DEX semantic transformations;
- data encryption/RASP/VM protection.

Those belong to subsequent roadmap phases.

## Closure

**Phase A is COMPLETE.**

The implementation satisfies the Phase A exit criterion: Nexora Shield can take an APK, normalize/rebuild it without changing application payload bytes, align it with official Android tooling, sign it, verify it, inspect it and publish it transactionally.

Next milestone: **Phase B — DEX Engine**.
