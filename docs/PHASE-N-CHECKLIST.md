# Phase N — Production Hardening checklist

> **Historical closure record:** all Phase N items below remain completed in the Phase N scope. A later production-readiness audit opened Phase O and now blocks public stable `v1.0.0` publication until O.0–O.15 release-required gates close.

## N.1 API freeze candidate
- [x] Machine-readable API contract
- [x] Stable CLI command inventory
- [x] Stable profile inventory
- [x] Gradle plugin id lock
- [x] minSdk/config schema lock
- [x] Final API freeze CI gate

## N.2 Config schema stable
- [x] Schema 1 frozen snapshot
- [x] Byte-for-byte schema drift gate
- [x] Schema const validation
- [x] Final schema CI gate

## N.3 Migration tooling
- [x] JSON migration CLI
- [x] Shield Studio YAML migration
- [x] Preserve unrelated sections
- [x] Current schema no-op
- [x] Future schema fail-closed
- [x] Final migration CI gate

## N.4 Documentation audit
- [x] Required documentation inventory
- [x] Stale README marker detection
- [x] Selected local-link validation
- [x] Final docs CI gate

## N.5 Supply-chain hardening
- [x] Minimal workflow permissions policy
- [x] CODEOWNERS for release/security surfaces
- [x] Dependabot Cargo/Gradle/Actions coverage
- [x] Workflow owner allowlist
- [x] pull_request_target rejection
- [x] write-all rejection
- [x] mutable main/master action ref rejection
- [x] network-to-shell rejection
- [x] Final supply-chain CI gate

## N.6 SBOM/provenance
- [x] CycloneDX 1.5 generator
- [x] Artifact digest manifest
- [x] Local in-toto/SLSA-compatible provenance
- [x] GitHub build-provenance attestation workflow
- [x] Final SBOM/provenance CI gate

## N.7 Signed releases
- [x] Dedicated release workflow
- [x] SHA-256 checksums
- [x] OIDC build provenance attestations
- [x] Linux/macOS/Windows release build matrix
- [x] RC/stable tag validation
- [x] Final release-workflow static gate

## N.8 Crash/retrace validation
- [x] Typed retrace argument-vector builder
- [x] No shell interpolation
- [x] Space-containing path test
- [x] Missing mapping failure test
- [x] Blank executable failure test
- [x] Final retrace regression gate

## N.9 Security review
- [x] Internal pre-release review record
- [x] Critical finding gate
- [x] High finding gate
- [x] Blocking finding gate
- [x] Final security review CI gate

## N.10 Performance review
- [x] RC budget review
- [x] Phase M budget regression
- [x] Stable device evidence explicitly required
- [x] Representative Android execution-environment measurements
- [x] Final performance review CI gate

## N.11 Compatibility review
- [x] Rust MSRV
- [x] Android minSdk
- [x] JDK/Gradle/AGP matrix
- [x] Android ABI matrix
- [x] APK/AAB/AAR/APKS matrix
- [x] Desktop OS matrix
- [x] Final compatibility CI gate

## N.12 1.0 release candidate
- [x] 1.0.0-rc.1 version synchronization
- [x] RC qualification policy
- [x] Stable qualification is stricter than RC
- [x] Final Phase N CI gate
- [x] RC qualification evidence retained (Phase N #54)

## N.13 External feedback
- [x] RC feedback issue form
- [x] Feedback status contract
- [x] Minimum independent external-assessment policy
- [x] Blocking-finding gate
- [x] Independent CodeQL assessment recorded (Phase N #54)
- [x] No blocking external finding recorded

## N.14 1.0 stable
- [x] Stable fail-closed workflow gate
- [x] Stable requires independent external assessment
- [x] Stable requires representative device measurements
- [x] Stable requires exact 1.0.0 source version
- [x] Final N.14 stable qualification CI gate
- [x] Stable release pipeline ready for v1.0.0 publication from validated main

## Closure state

Phase N is **COMPLETED — N.1–N.14**.

Final stable implementation head: `ce92ea791dc860a505658a67be1b9250105a834a`.

Final validation evidence:
- Phase N #86 (`37691051042`): **success** — 9/9 jobs passed.
- N.14 1.0 stable qualification: **success**.
- N.10 Android representative performance: **success**.
- N.13 independent CodeQL assessment: **success**.
- Rust 1.81 MSRV: **success**.
- Phase M #86: **success**.
- Phase L #92: **success**.
- Phase K #107: **success**.
- CI #1156: **success**.
- Failed jobs: **0**.

The source contract reached `1.0.0` under Phase N. **Do not create the stable tag from Phase N evidence alone.** Phase O is now the authoritative final release gate; `v1.0.0` remains blocked until O.14 approves the exact final `main` commit and O.15 is ready.
