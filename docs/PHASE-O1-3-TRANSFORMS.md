# Phase O.1.3 — Auditable DEX transformations (diagnostic stage)

Status: **IMPLEMENTED ON FEATURE BRANCH — EXACT-HEAD CI VERIFICATION PENDING**.

## What is integrated

- The Phase B fixed-width ASCII rename pass rewrites the actual DEX string-data
  bytes in an output DEX, recalculates SHA-1/Adler-32 and reparses/validates.
  It does not merely generate a mapping or rename report.
- The metadata pass clears DEX class source-file indexes and code debug-info
  offsets in the rebuilt bytes without changing executable instructions.
- `DexRewriteVerifier::verify` constructs a strictly bounded byte-difference
  allowlist from explicit rename and metadata reports. Every other changed byte,
  including executable instructions, table indexes and section metadata,
  causes an error. It also checks code-item identity and transformation counts.
- Multidex output reparsing checks all class ownership and canonical numbering.
  Until globally coordinated cross-DEX method/type binding and remapping exists,
  a multidex input with a class reference into another DEX is rejected for
  name rewriting rather than emitting an APK with broken links. A metadata-only
  rewrite is supported for these inputs.
- DEX string IDs directly loaded with const-string are protected against
  automatic renaming, including when a symbol shares that same string index.
- The unsigned `stage_dex` example reports verified unchanged code items, and
  Phase O CI invokes focused rename, audit, byte-tamper and cross-unit tests.

## Explicitly not covered

This is still an **unsigned diagnostic transform**, not a product-ready APK
protection executor. A fixed-length class name change might break Android
manifest references, dynamic reflection, native linking, resource XML or third-
party APIs even if DEX instructions are unchanged. End-to-end global symbol
coordination, stable symbol maps, executable transform selection, runtime
integration and Android install/launch tests are not certified by this stage.
Production `protect` therefore remains fail-closed, Phase O.1 stays OPEN, and
`v1.0.0` stays NO-GO. No release artifact is authorized by this document.
