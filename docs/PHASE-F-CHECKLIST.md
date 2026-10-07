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
- [x] No local unsafe code
- [x] Stable export names

## F.3 arm64-v8a
- [x] ABI model
- [x] Rust target mapping
- [x] Android build script
- [ ] Final CI linked-library validation

## F.4 x86_64
- [x] ABI model
- [x] Rust target mapping
- [x] Android build script
- [ ] Final CI linked-library validation

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
- [ ] Final ELF CI inspection

## F.9 Symbol minimization
- [x] Explicit required export list
- [x] Two-entry JNI surface
- [ ] Final dynamic-symbol CI inspection

## F.10 Native fuzz/tests
- [x] Unit/regression tests
- [x] 4096-case mutation fuzz-smoke
- [x] 2048-case generated-data stability fuzz-smoke
- [x] 1024-length region stress
- [ ] Final Android cross-build gate
- [ ] Final reproducibility gate

## Closure state

Phase F implementation is **IN PROGRESS**. The portable implementation is present, but F.3/F.4/F.8/F.9/F.10 are not closed until actual Android libraries are linked and inspected by CI.
