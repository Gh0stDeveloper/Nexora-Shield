# Phase O.1.3 — Auditable DEX transformations (diagnostic stage)

Status: **PARTIAL ON FEATURE BRANCH — EXACT-HEAD CI VERIFICATION PENDING**.

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
  Class-only renames now use one owner-derived global descriptor map across all
  DEX units when linked references exist, including array type descriptors.
  Imported superclass, field-owner and method-owner type references consequently
  retain the same remapped class identity. A byte-level verifier audits every
  per-DEX patch and executable instructions remain unchanged.
- Cross-DEX **method and field** definitions and imports now use a globally
  coordinated key: declaring class + name + full parameter/return signature
  for methods; declaring class + name + field type for fields. Eligible
  direct/static/private method and field names have one deterministic rename
  across every DEX's referencing IDs. Unsafe shared string aliases fail closed.
- **Virtual/interface method renaming remains disabled** unless full override
  and Android/SDK contract resolution can be established. External and
  unresolved references retain their original identities. Metadata-only rewrite
  remains available. Class remapping rejects name collisions, protected
  runtime/JNI aliases and class-name literals. Conservative reflection mode
  skips renaming rather than assuming dynamic calls safe.
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

## O.1.3 linked-class slice — acceptance boundary

- The new `linked_classes` pass is entered only for cross-DEX-linked renames;
  it requires `rename_methods=false` and `rename_fields=false`.
- Generated class names must not capture any original global DEX string, and
  the complete output multidex set is reparsed to enforce unique ownership.
- References in DEX type IDs (including array descriptors) are remapped to
  the owner-chosen name; code items, field/method tables, and indexes remain
  byte-identical except for specifically audited fixed-width string data.
- Focused synthetic tests cover linked superclass reference rewriting,
  repeatability, method/field fail-closed and metadata/bytecode preservation.
  These are **not** Android installation tests or a proof of all Android
  runtime/linker behavior.
- Signature-bound direct/static method and field reference binding has a
  positive executable-reference fixture (invoke-static + sget) and a negative
  shared-name/selector collision fixture, plus determinism and immutable
  code-item audits. Full virtual/interface method remapping, inherited member
  dispatch and reflection compatibility still require an independently
  verified class/interface graph; the fixed-layout writer does not support
  cloning aliased string slots.
- Remaining: hierarchy-aware safe virtual/inherited method handling,
  independent retrace mapping with restricted/encrypted storage,
  manifest/resource/JNI/reflection contract checks, production executor
  integration and physical Android installation/launch matrix. No release
  gate changes.

## O.1.3 signature-bound method and field remapping (diagnostic scope)

The linked-unit planner resolves definitions by **declaring owner + complete
signature/type**, and applies the same new member name to reference-only
method/field IDs across DEX boundaries without modifying instruction opcodes,
operands or table indices. Inheritance and external class/interface resolution
are still conservative, not presumed correct. Native, reflection-observable,
Android lifecycle/Parcelable contract names and ambiguous shared string slots
cannot be renamed. Output is always staged and unsigned, not a production
protected APK.

