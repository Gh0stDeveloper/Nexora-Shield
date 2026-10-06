# Phase B — DEX Engine

## Status

**Complete and validated.**

Phase B establishes Nexora Shield's DEX analysis and conservative rewrite foundation. The implementation is intentionally fail-closed: malformed indexes, offsets, unsupported instruction encodings, invalid control-flow targets, unsafe rename candidates, and inconsistent multidex layouts are rejected instead of being silently rewritten.

## B.1 — DEX parser

Implemented in `nexora-shield-dex`:

- DEX header and integrity validation;
- string/type/proto/field/method/class tables;
- class_data and code_item parsing;
- ULEB128/SLEB128 decoding;
- MUTF-8 validation;
- instruction widths and payload decoding;
- branch target validation;
- try/catch metadata;
- string/type/field/method/proto references.

The parser works on untrusted bytes without extracting arbitrary paths or using unsafe Rust.

## B.2 — DEX writer

Phase B provides a conservative writer model:

- byte-stable round trip when no transform is requested;
- SHA-1/Adler-32 integrity regeneration;
- validated fixed-layout string replacement;
- post-write reparse and semantic validation.

Full table re-layout is deliberately not required for the Phase B rename transform: candidates must preserve encoded string length, which avoids offset churn and reduces corruption risk.

## B.3 — Validation

The validator checks:

- type descriptors;
- proto shorty descriptors;
- class ownership of encoded fields/methods;
- native/abstract method code constraints;
- method parameter/register contracts;
- structural parser invariants.

## B.4 — CFG

The control-flow graph includes:

- basic-block boundaries;
- branch/fallthrough edges;
- predecessor sets;
- exception handler edges;
- branch-target boundary validation.

## B.5 — Type analysis

A forward register dataflow analysis tracks conservative register categories:

- unknown;
- int-like;
- wide;
- reference;
- conflict.

Method parameters and receiver registers seed the entry state.

## B.6 — SSA/IR

Methods are lifted into an SSA-oriented intermediate representation with:

- blocks;
- instruction uses/defs;
- stable SSA values;
- phi nodes at joins;
- branch/reference metadata.

## B.7 — Reference graph

The graph captures relationships among:

- classes;
- types;
- fields;
- methods;
- protos;
- strings;
- call sites;
- method handles;
- code references.

## B.8 — Selector resolver

Selectors support deterministic class/member glob matching and can select:

- classes;
- methods;
- fields;
- all matching symbols.

The implementation remains compatible with the repository MSRV (Rust 1.81).

## B.9 — Rename pass

The rename pass is deterministic and conservative.

It:

- uses a per-build seed;
- maintains fixed MUTF-8/UTF-16 length;
- rejects unsafe/special names;
- avoids collisions;
- respects selector scope;
- skips names shared with unselected symbols;
- preserves Android/JVM contract names;
- integrates Reflection/JNI compatibility exclusions;
- reparses and revalidates the rewritten DEX.

## B.10 — Metadata reduction

Implemented safe metadata reduction:

- remove `source_file_idx`;
- detach `debug_info_off`;
- regenerate DEX integrity fields;
- reparse and revalidate after transformation.

## B.11 — Reflection/JNI compatibility analysis

The compatibility analyzer conservatively identifies:

- native methods;
- JNI-visible method/class names;
- reflection indicators;
- runtime string references associated with class/method/field names.

Protected string indexes are excluded from renaming.

For multidex builds, reflection evidence can trigger conservative rename suppression across the set rather than risk a cross-DEX reflective break.

## B.12 — Multidex rewrite

The multidex layer:

- accepts only canonical `classes.dex`, `classes2.dex`, ... naming;
- validates contiguous numbering;
- rejects duplicate class descriptors across DEX files;
- parses/validates every unit;
- applies compatible rewrite stages per unit;
- validates every generated DEX before returning it.

## CLI

Phase B adds:

~~~text
nexora-shield dex-inspect <classes.dex>
nexora-shield dex-roundtrip <classes.dex> --output <out.dex>
nexora-shield dex-rewrite <classes.dex> --output <out.dex> [options]
nexora-shield dex-multidex-verify <classes.dex> [classes2.dex ...]
~~~

## Strict CI gate

The permanent `Phase B DEX engine` GitHub Actions job creates deterministic golden DEX fixtures and validates:

1. targeted Phase B Rust tests;
2. parser/validator/CFG/type/SSA/reference analysis through `dex-inspect`;
3. byte-stable writer round-trip;
4. compatibility-aware renaming;
5. metadata reduction;
6. reinspection of rewritten DEX;
7. canonical multidex verification.

GitHub Actions run **#162** (ID `37522614748`) passed all Phase B gates together with Rust quality, RustSec audit, and the Phase A APK pipeline.

## Scope boundary

Phase B provides the verified DEX transformation substrate. It does not yet implement encrypted data containers, runtime decryption, RASP, native hardening, or VM virtualization; those belong to later roadmap phases.
