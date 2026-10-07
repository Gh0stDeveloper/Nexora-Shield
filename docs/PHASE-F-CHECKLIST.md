# Phase F — Native Shield checklist

## F.1 Runtime crate/library
- [x] Workspace crate
- [x] rlib + cdylib
- [x] Stable runtime API version
- [x] Runtime descriptor

## F.2 JNI boundary
- [x] Minimal JNI entry points
- [x] FFI-safe primitive contract
- [x] No JNI pointer dereference
- [x] No unsafe blocks
- [x] Scoped lint exception only for JNI export attributes
- [x] Stable export names

## F.3 arm64-v8a
- [x] ABI model
- [x] Rust target mapping
- [x] Android build script
- [x] Final CI linked-library validation

## F.4 x86_64
- [x] ABI model
- [x] Rust target mapping
- [x] Android build script
- [x] Final CI linked-library validation

## F.5 Additional ABI policy
- [x] 64-bit primary defaults
- [x] Explicit 32-bit opt-in
- [x] Explicit additional-ABI allowlist
- [x] Strict ABI parser
- [x] Policy tests

## F.6 Native integrity helpers
- [x] SHA-256 digest
- [x] Constant-time comparison
- [x] Named native regions
- [x] Mutation detection
- [x] Empty-label rejection

## F.7 Generated native data
- [x] Versioned derivation domain
- [x] Build-specific output
- [x] Seed-specific output
- [x] Deterministic same-input output
- [x] No raw seed storage

## F.8 Hardening compiler flags
- [x] PIC
- [x] RELRO
- [x] NOW
- [x] GC sections
- [x] Archive-symbol hiding
- [x] Symbol stripping
- [x] Build-id disabled for reproducibility
- [x] Final ELF CI inspection

## F.9 Symbol minimization
- [x] Explicit required export list
- [x] Two-entry JNI surface
- [x] Final dynamic-symbol CI inspection

## F.10 Native fuzz/tests
- [x] Unit/regression tests
- [x] 4096-case mutation fuzz-smoke
- [x] 2048-case generated-data stability fuzz-smoke
- [x] 1024-length region stress
- [x] Final Android cross-build gate
- [x] Final reproducibility gate

## Closure state

Phase F is **COMPLETED**. F.1–F.10 are implemented. GitHub Actions run #425 (`37562726466`) passed Rust quality, RustSec, all Phase A–E regressions, Phase F host tests, Phase F Rust 1.81 MSRV, real Android arm64-v8a/x86_64 linking, ELF hardening/export inspection and byte-for-byte rebuild reproducibility.
