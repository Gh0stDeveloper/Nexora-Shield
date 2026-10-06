# Phase B — DEX Engine checklist

## B.1 DEX parser — DONE
- [x] Header/integrity parsing
- [x] ID tables
- [x] Class data/code items
- [x] LEB128/MUTF-8 validation
- [x] Instruction/payload decoding
- [x] Branch/reference validation

## B.2 DEX writer — DONE
- [x] Byte-stable round trip
- [x] Fixed-layout safe string patching
- [x] SHA-1/Adler-32 regeneration
- [x] Reparse/revalidate output

## B.3 Validation — DONE
- [x] Descriptor/proto validation
- [x] Class ownership checks
- [x] Native/abstract constraints
- [x] Register/input contract checks

## B.4 CFG — DONE
- [x] Basic blocks
- [x] Normal edges
- [x] Exception edges
- [x] Predecessors

## B.5 Type analysis — DONE
- [x] Parameter seeding
- [x] Register categories
- [x] Merge/conflict handling

## B.6 SSA/IR — DONE
- [x] SSA values
- [x] Uses/defs
- [x] Phi nodes
- [x] Block/reference metadata

## B.7 Reference graph — DONE
- [x] Class/type/field/method/proto/string nodes
- [x] Ownership/name/signature edges
- [x] Code-reference edges

## B.8 Selector resolver — DONE
- [x] Class selectors
- [x] Method selectors
- [x] Field selectors
- [x] Deterministic glob matching
- [x] Rust 1.81 compatibility

## B.9 Rename pass — DONE
- [x] Deterministic seeded names
- [x] Collision avoidance
- [x] Fixed-length safety
- [x] Contract-name exclusions
- [x] Selector-aware shared-name safety
- [x] Post-transform validation

## B.10 Metadata reduction — DONE
- [x] Source-file removal
- [x] Debug-info detachment
- [x] Integrity regeneration
- [x] Post-transform validation

## B.11 Reflection/JNI compatibility — DONE
- [x] Native method discovery
- [x] JNI name protection
- [x] Reflection evidence
- [x] Runtime string-name protection
- [x] Conservative cross-DEX policy

## B.12 Multidex rewrite — DONE
- [x] Canonical numbering
- [x] Contiguous sequence
- [x] Duplicate class rejection
- [x] Unit-by-unit parse/rewrite/validate

## CI validation

GitHub Actions run #162 (`37522614748`) completed successfully:

- [x] Rust quality
- [x] rustfmt
- [x] Clippy with `-D warnings`
- [x] workspace tests
- [x] rustdoc with warnings denied
- [x] CLI smoke
- [x] RustSec audit
- [x] Phase A APK pipeline regression
- [x] Phase B targeted tests
- [x] golden DEX generation
- [x] DEX inspection
- [x] byte-stable round trip
- [x] compatible rename
- [x] metadata reduction
- [x] multidex verification

**Phase B is complete.**
