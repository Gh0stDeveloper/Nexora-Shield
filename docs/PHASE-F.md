# Phase F — Native Shield

## Objective

Phase F introduces a small, reproducible and auditable native runtime for Android. It does not move the entire protection system into native code. The native layer is deliberately limited to security-sensitive primitives and a minimal JNI contract.

## F.1 — Runtime crate/library

`nexora-shield-native` is a workspace crate that builds as both `rlib` and `cdylib`.

It exposes a stable runtime API version and a portable descriptor used by tests and future Android integration.

## F.2 — JNI boundary

The JNI surface is intentionally minimal and dependency-free:

- `nativeRuntimeApiVersion`;
- `nativeAbiCode`.

The boundary uses only FFI-safe raw opaque JNI handles and primitive return types. It never dereferences JNI pointers inside Rust and therefore requires no local `unsafe` block. The workspace continues to enforce `unsafe_code = "forbid"`.

## F.3 / F.4 — arm64-v8a and x86_64

These are the primary Android ABIs.

The repository includes `scripts/build-native-android.sh`, which performs actual release linking for:

- `aarch64-linux-android` → `arm64-v8a`;
- `x86_64-linux-android` → `x86_64`.

The minimum Android API is 24 unless explicitly overridden for a controlled build.

## F.5 — Additional ABI policy

32-bit ABIs are not enabled by default.

`AbiPolicy` requires both explicit 32-bit opt-in and explicit inclusion of the additional ABI. This prevents accidental expansion of the native attack and compatibility surface.

## F.6 — Native integrity helpers

`NativeRegion` and `NativeDigest` provide SHA-256 region fingerprints and constant-time digest comparison. They operate on supplied bytes and do not perform unsafe process-memory scanning.

## F.7 — Generated native data

`GeneratedNativeData` derives deterministic per-build data from build identity, a private generation seed and a versioned domain separator. The seed itself is not stored in the generated data.

## F.8 — Hardening compiler flags

Android targets use PIC, RELRO, immediate binding/NOW, section garbage collection, archive-symbol hiding, symbol stripping and a disabled ELF build-id for reproducibility.

CI inspects the produced ELF files and verifies the relevant hardening properties.

## F.9 — Symbol minimization

The required public native surface contains only the two JNI entry points defined by `REQUIRED_JNI_EXPORTS`.

CI checks that both are exported and rejects leaked Rust-mangled symbols.

## F.10 — Native fuzz/tests

The native crate includes unit/regression tests, deterministic mutation fuzz-smoke, generated-data stability fuzz-smoke, variable-length integrity stress tests, real Android cross-builds, ELF inspection and byte-for-byte reproducibility rebuild checks.

## Security boundary

Native code raises reverse-engineering and tampering cost but is not assumed to be unbreakable. It remains one layer in Nexora Shield's defense-in-depth model.

No destructive anti-analysis behavior is implemented.
