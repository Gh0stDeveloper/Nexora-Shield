# Phase F CI validation

## Final acceptance run

GitHub Actions run **#425** (ID `37562726466`) completed successfully for the final Phase F implementation head.

Validated jobs:

- Rust quality — success;
- RustSec audit — success;
- Phase A APK pipeline — success;
- Phase B DEX engine — success;
- Phase C Data Protection — success;
- Phase C Rust 1.81 MSRV — success;
- Phase D Integrity / Anti-Tamper — success;
- Phase D Rust 1.81 MSRV — success;
- Phase E RASP E.1–E.12 — success;
- Phase E RASP E.1–E.12 Rust 1.81 MSRV — success;
- Phase F Native Shield host — success;
- Phase F Native Shield Rust 1.81 MSRV — success;
- Phase F Android arm64 + x86_64 — success.

## Android native acceptance

The Android gate uses API 24 and pinned NDK `27.2.12479018`.

It performs real release linking for:

- `aarch64-linux-android` / `arm64-v8a`;
- `x86_64-linux-android` / `x86_64`.

The resulting shared libraries are inspected for architecture, GNU RELRO, NOW, disabled build-id and the required JNI export surface.

A clean second build is compared byte-for-byte against the first build for both primary ABIs.

## Safety and lint boundary

The native crate denies unsafe code globally. The only scoped lint exceptions are the two JNI `#[no_mangle]` export attributes. CI separately rejects any actual `unsafe { ... }` block under `crates/shield-native/src`.

The closure documentation commit is revalidated by CI before merge to `main`.
