# ADR 0001 — Rust core with Kotlin Android integrations

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Nexora Shield needs binary parsing, deterministic transformations, native runtimes, a CLI and first-class Android/Gradle integration. A single language would either weaken Android integration or make the transformation core harder to reuse safely.

## Decision

Use Rust for the protection core, CLI, parsers, transformation engines and memory-sensitive native components when practical.

Use Kotlin for Android-facing SDKs and the Gradle Plugin. JNI/FFI boundaries must remain narrow and versioned.

Compose Multiplatform may be used for Shield Studio later, but the UI may not contain unique security logic.

## Security consequences

Rust provides strong memory-safety defaults for parsers processing untrusted APK/AAB inputs. The workspace forbids unsafe Rust during the foundation. Future unsafe code requires isolation and a new architectural review.

FFI remains a security boundary and requires validation on both sides.

## Compatibility consequences

Android-specific behavior can follow official Kotlin/AGP APIs while the core remains usable from CLI and CI environments.

## Alternatives considered

### Kotlin-only

Good Android ergonomics but less attractive for low-level binary/native components.

### C++ core

Powerful but increases memory-safety risk for a tool that parses hostile input.

### Rust-only including Gradle

Would complicate idiomatic integration with AGP.

## Follow-up

Define a stable C/JNI boundary only when Native Shield or Gradle integration requires it.
