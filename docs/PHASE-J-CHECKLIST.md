# Phase J — Gradle Plugin checklist

## J.1 AGP integration
- [x] Gradle plugin project
- [x] Plugin id dev.nexora.shield
- [x] Application-only scope for Phase J
- [x] AGP 9.4.1 public API dependency
- [x] No deprecated Transform API

## J.2 Variant API
- [x] ApplicationAndroidComponentsExtension
- [x] onVariants registration
- [x] SingleArtifact.APK transformation
- [x] Directory artifact wiring
- [x] AGP-owned task dependencies
- [x] Real sample assembleRelease CI validation — run #760

## J.3 Release-only defaults
- [x] releaseOnly=true default
- [x] Exact variant allowlist
- [x] Debug untouched by default
- [x] Unsigned output denied by default
- [x] Explicit sample/CI unsigned override

## J.4 Config schema completion
- [x] Strict dex block
- [x] Strict budgets block
- [x] Strict compatibility block
- [x] Strict reports block
- [x] Strict signing block
- [x] Strict secrets block
- [x] Strict gradle block

## J.5 Secret providers
- [x] env: provider
- [x] file: provider
- [x] Task-execution resolution
- [x] Passwords absent from command line
- [x] Missing/unknown provider failures
- [x] Unit tests

## J.6 Reports
- [x] Public per-APK reports
- [x] Variant summary
- [x] Private report opt-in
- [x] Private path isolation

## J.7 Mapping / retrace
- [x] Per-variant mapping preservation task
- [x] R8 minification awareness
- [x] Per-variant retrace task
- [x] Android command-line Retrace integration
- [x] Explicit stack-trace input

## J.8 Build cache strategy
- [x] Disabled by default
- [x] Runtime opt-in only
- [x] Signed outputs excluded
- [x] Public/private reports excluded
- [x] Explicit cache key version

## J.9 CI examples
- [x] GitHub Actions example
- [x] Dedicated plugin build/test CI green — run #760
- [x] Full repository regression matrix green — run #760

## J.10 Sample apps
- [x] Minimal Android application
- [x] Composite plugin build
- [x] Release-only configuration
- [x] Protected sample release validated in CI — run #760

## Closure state

Phase J is **COMPLETED**. J.1–J.10 are implemented. GitHub Actions run #760 (`37581846372`) passed all 24 jobs on commit `b1e493204ce95241f3c53d4f0957a0338e984177`, including strict Rust quality, Phase A–I regressions, Gradle plugin validation, and a real AGP 9.4.1 `assembleRelease` whose APK passed through the Nexora Shield artifact transform.
