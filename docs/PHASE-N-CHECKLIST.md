# Phase N — Production Hardening checklist

## N.1 API freeze candidate
- [x] Machine-readable API contract
- [x] Stable CLI command inventory
- [x] Stable profile inventory
- [x] Gradle plugin id lock
- [x] minSdk/config schema lock
- [ ] Final API freeze CI gate

## N.2 Config schema stable
- [x] Schema 1 frozen snapshot
- [x] Byte-for-byte schema drift gate
- [x] Schema const validation
- [ ] Final schema CI gate

## N.3 Migration tooling
- [x] JSON migration CLI
- [x] Shield Studio YAML migration
- [x] Preserve unrelated sections
- [x] Current schema no-op
- [x] Future schema fail-closed
- [ ] Final migration CI gate

## N.4 Documentation audit
- [x] Required documentation inventory
- [x] Stale README marker detection
- [x] Selected local-link validation
- [ ] Final docs CI gate

## N.5 Supply-chain hardening
- [x] Minimal workflow permissions policy
- [x] CODEOWNERS for release/security surfaces
- [x] Dependabot Cargo/Gradle/Actions coverage
- [x] Workflow owner allowlist
- [x] pull_request_target rejection
- [x] write-all rejection
- [x] mutable main/master action ref rejection
- [x] network-to-shell rejection
- [ ] Final supply-chain CI gate

## N.6 SBOM/provenance
- [x] CycloneDX 1.5 generator
- [x] Artifact digest manifest
- [x] Local in-toto/SLSA-compatible provenance
- [x] GitHub build-provenance attestation workflow
- [ ] Final SBOM/provenance CI gate

## N.7 Signed releases
- [x] Dedicated release workflow
- [x] SHA-256 checksums
- [x] OIDC build provenance attestations
- [x] Linux/macOS/Windows release build matrix
- [x] RC/stable tag validation
- [ ] Final release-workflow static gate

## N.8 Crash/retrace validation
- [x] Typed retrace argument-vector builder
- [x] No shell interpolation
- [x] Space-containing path test
- [x] Missing mapping failure test
- [x] Blank executable failure test
- [ ] Final retrace regression gate

## N.9 Security review
- [x] Internal pre-release review record
- [x] Critical finding gate
- [x] High finding gate
- [x] Blocking finding gate
- [ ] Final security review CI gate

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
- [ ] Final compatibility CI gate

## N.12 1.0 release candidate
- [x] 1.0.0-rc.1 version synchronization
- [x] RC qualification policy
- [x] Stable qualification is stricter than RC
- [ ] Final Phase N CI gate
- [ ] RC tag/release after merge to main

## N.13 External feedback
- [x] RC feedback issue form
- [x] Feedback status contract
- [x] Minimum external reviewer policy
- [x] Blocking-finding gate
- [ ] At least one real external reviewer recorded
- [ ] Blocking RC feedback resolved

## N.14 1.0 stable
- [x] Stable fail-closed workflow gate
- [x] Stable requires external feedback
- [x] Stable requires representative device measurements
- [x] Stable requires exact 1.0.0 source version
- [ ] Stable eligibility satisfied
- [ ] v1.0.0 release published

## Closure state

Phase N is **IN PROGRESS**.

N.1–N.12 implementation is being validated. N.13 and N.14 intentionally remain open until real external RC feedback and representative Android device performance evidence exist.
