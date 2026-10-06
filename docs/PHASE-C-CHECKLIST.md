# Phase C — Data Protection checklist

## C.1 String sensitivity model — DONE
- [x] Sensitivity levels
- [x] Context-aware classification
- [x] Explicit protect/public overrides
- [x] Runtime-contract exclusions
- [x] Redacted diagnostics
- [x] Candidate zeroization

## C.2 Authenticated encrypted containers — DONE
- [x] Versioned NSC1 format
- [x] XChaCha20-Poly1305
- [x] Authenticated context/kind/item metadata
- [x] Strict size/version parsing
- [x] Constant-time opaque-ID comparison
- [x] Tamper rejection

## C.3 Per-build key derivation — DONE
- [x] 32-byte external root material
- [x] HKDF-SHA-256
- [x] Application/build context binding
- [x] Domain separation
- [x] Per-item content keys
- [x] Per-build opaque IDs/diversification
- [x] Root-secret redaction and zeroization

## C.4 Decrypt-on-use runtime — DONE
- [x] Authenticated on-demand decrypt
- [x] Sensitive byte wrapper
- [x] Sensitive string wrapper
- [x] Redacted diagnostics
- [x] Plaintext cleanup

## C.5 Constant protection — DONE
- [x] bool
- [x] i32/i64
- [x] f32/f64
- [x] byte blobs
- [x] Stable tagged encoding
- [x] Authenticated protection
- [x] Strict decode validation

## C.6 Resource selection — DONE
- [x] Safe default surfaces
- [x] Explicit include/exclude
- [x] Size budget
- [x] Android contract exclusions
- [x] Traversal/path validation

## C.7 Resource containers — DONE
- [x] Versioned NSRB bundle
- [x] Opaque public identifiers
- [x] Per-resource authenticated containers
- [x] No plaintext paths in public bundle
- [x] Duplicate/truncation/trailing-data rejection
- [x] Decrypt round-trip

## C.8 Lifetime/caching policies — DONE
- [x] Cache disabled by default
- [x] Bounded entries
- [x] Bounded plaintext bytes
- [x] TTL expiration
- [x] LRU eviction
- [x] Explicit/runtime-drop clearing

## C.9 Private metadata — DONE
- [x] Versioned schema
- [x] String mappings
- [x] Constant mappings
- [x] Resource mappings
- [x] Exposure report support
- [x] No root/derived keys
- [x] No plaintext protected values

## C.10 Exposure benchmark — DONE
- [x] Baseline/protected occurrence counts
- [x] Critical-probe failures
- [x] Size overhead calculation
- [x] Explicit overhead budget
- [x] Probe redaction/zeroization
- [x] Probe input outside argv

## CI evidence

GitHub Actions run #216 (`37526352684`) passed:

- [x] Rust quality
- [x] rustfmt
- [x] Clippy with warnings denied
- [x] workspace tests
- [x] rustdoc with warnings denied
- [x] CLI smoke
- [x] RustSec audit
- [x] Phase A regression
- [x] Phase B regression
- [x] Phase C end-to-end data protection
- [x] tamper rejection
- [x] plaintext exposure check
- [x] per-build diversification
- [x] protected-size overhead budget
- [x] Rust 1.81 crypto tests
- [x] Rust 1.81 CLI check

**Phase C implementation is complete.**
