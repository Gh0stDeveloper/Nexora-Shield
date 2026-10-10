# Phase O — Production Release Audit & Hardening checklist

Status: **OPEN — blocks stable v1.0.0 publication**

The checklist is intentionally strict. A checked implementation item is not enough by itself; its corresponding verification/evidence item must also be checked.

## O.0 Release freeze and baseline
- [x] Record Phase O audit baseline commit
- [x] Mark stable v1.0.0 publication blocked
- [x] Preserve Phase N historical evidence
- [x] Prevent accidental stable publication while Phase O is open
- [x] Publish P0/P1/P2 finding inventory
- [x] Define accepted-risk process for non-release-blocking P2 only
- [x] Final O.0 documentation/CI gate

## O.1 Production Protection Orchestrator
- [x] Define authoritative production stage graph
- [x] Add typed production build context
- [x] Resolve typed request configuration before mutation (O.1.1; YAML file binding remains O.5)
- [x] Resolve effective protection profile
- [ ] Integrate DEX parse/validation
- [ ] Integrate compatibility analysis
- [ ] Integrate selectors
- [ ] Integrate DEX transformation
- [ ] Integrate data/string/resource protection
- [ ] Integrate Integrity Graph creation
- [ ] Integrate RASP runtime/policy artifacts
- [ ] Integrate Native Shield where selected
- [ ] Integrate VM Shield where selected
- [ ] Integrate per-build diversity
- [ ] Integrate optional attestation binding
- [ ] Rebuild final package
- [ ] Align/sign final output
- [ ] Verify final output
- [ ] Emit executed-stage evidence
- [x] Fail closed for required unsupported stages
- [ ] CLI protect uses orchestrator
- [ ] Gradle Plugin uses orchestrator
- [ ] Shield Studio reaches same orchestrator
- [ ] Final O.1 E2E CI gate

## O.2 APK end-to-end protection
- [ ] Java golden app
- [ ] Kotlin golden app
- [ ] Compose golden app
- [ ] multidex golden app
- [ ] reflection compatibility app
- [ ] serialization compatibility app
- [ ] JNI compatibility app
- [ ] coroutines compatibility app
- [ ] R8/minified app
- [ ] representative resource-protection app
- [ ] baseline build/install/launch
- [ ] protected build/install/launch
- [ ] functional smoke before/after protection
- [ ] final DEX protected-surface assertions
- [ ] final protected-data exposure assertions
- [ ] final Integrity Graph assertions
- [ ] runtime/RASP integration assertions
- [ ] VM/native assertions where selected
- [ ] per-build diversity assertions
- [ ] signature verification
- [ ] re-sign/tamper rejection
- [ ] mapping/retrace round-trip
- [ ] protected upgrade test
- [ ] uninstall/reinstall test
- [ ] Final O.2 Android E2E gate

## O.3 AAB/APKS/dynamic-feature protection
- [ ] Define authoritative AAB protection point
- [ ] Protect base module code
- [ ] Protect supported dynamic-feature code
- [ ] Validate module-specific selectors
- [ ] Preserve resource namespaces
- [ ] Preserve bundle metadata
- [ ] Preserve baseline/startup profiles
- [ ] bundletool validation
- [ ] Build universal APKS
- [ ] Build device-targeted APKS
- [ ] Inspect delivered APK protected surfaces
- [ ] Play App Signing upload/delivery identity tests
- [ ] Split install test
- [ ] Dynamic feature install/use smoke
- [ ] Final O.3 bundle delivery gate

## O.4 AAR/library protection contract
- [ ] Define publisher guarantees
- [ ] Define consumer guarantees
- [ ] Define final-Dex protection point
- [ ] Define consumer ProGuard/R8 rules
- [ ] Define resource protection behavior
- [ ] Define mapping/retrace ownership
- [ ] Maven-local publication test
- [ ] Independent consumer project
- [ ] Final consumer APK protection assertion
- [ ] Final consumer AAB protection assertion
- [ ] Unsupported behavior fails clearly
- [ ] Final O.4 library gate

## O.5 Profiles/configuration
- [ ] Standard stage matrix
- [ ] Hardened stage matrix
- [ ] Maximum stage matrix
- [ ] Profile-specific performance budgets
- [ ] Selector defaults per profile
- [ ] Required vs optional stage semantics
- [ ] Explicit fallback policy
- [ ] Report-only/enforcement policy
- [ ] Schema tied to orchestrator
- [ ] Migration coverage
- [ ] Public report contains effective profile
- [ ] Public report contains executed controls
- [ ] Behavioral differentiation tests
- [ ] Final O.5 profile contract gate

## O.6 Governance, license and security release gates
- [ ] Select project license
- [ ] Add root LICENSE/COPYING as appropriate
- [ ] Verify third-party redistribution obligations
- [ ] Add required notices
- [ ] Verify main branch protection
- [ ] Require PRs for main
- [ ] Restrict direct pushes
- [ ] Disable force pushes
- [ ] Disable main deletion
- [ ] Require status checks
- [ ] Require review/conversation policy
- [ ] Protect release/security workflow ownership
- [ ] Define emergency override process
- [ ] Add stable tag-to-main ancestry check
- [ ] Add exact-commit required-check validation
- [ ] Add protected/immutable tag policy where available
- [ ] Add CodeQL/SARIF open-alert gate
- [ ] Critical alerts = 0
- [ ] High alerts = 0
- [ ] Blocking medium alerts = 0
- [ ] Dismissed alert rationale retained
- [ ] Update post-1.0 security support policy
- [ ] Final O.6 governance gate

## O.7 Distribution and installer trust
### Gradle Plugin
- [ ] Decide plugin distribution repository
- [ ] Add publication configuration
- [ ] Publish versioned plugin artifact
- [ ] Independent remote-coordinate consumer test
- [ ] Installation docs do not depend on includeBuild
### CLI
- [ ] Versioned Linux artifact
- [ ] Versioned macOS artifact
- [ ] Versioned Windows artifact
- [ ] Install instructions
- [ ] Upgrade instructions
- [ ] Uninstall instructions
- [ ] Checksum verification instructions
- [ ] Provenance/attestation verification instructions
### Shield Studio
- [ ] Windows installer
- [ ] Windows Authenticode signing
- [ ] Windows clean-machine install smoke
- [ ] macOS DMG/package
- [ ] macOS code signing
- [ ] macOS notarization
- [ ] macOS clean-machine install smoke
- [ ] Linux DEB
- [ ] Linux clean-machine install smoke
### Reproducible bootstrap
- [ ] Gradle Wrapper or documented/pinned equivalent
- [ ] Clean-machine build/install gate
- [ ] Final O.7 distribution gate

## O.8 Supply chain and complete SBOM
- [ ] Pin checkout action to immutable SHA
- [ ] Pin setup-java action to immutable SHA
- [ ] Pin Gradle action to immutable SHA
- [ ] Pin upload/download-artifact to immutable SHA
- [ ] Pin CodeQL action to immutable SHA
- [ ] Pin attestation action to immutable SHA
- [ ] Pin third-party Rust actions to immutable SHA
- [ ] Pin release Rust toolchain/compiler
- [ ] Retain Rust 1.81 MSRV semantic purpose
- [ ] Review all open Dependabot PRs
- [ ] RustSec passes
- [ ] Add JVM/Gradle vulnerability gate
- [ ] Generate Rust CycloneDX
- [ ] Generate Gradle Plugin CycloneDX
- [ ] Generate Shield Studio CycloneDX
- [ ] Generate aggregate product BOM
- [ ] Verify BOM against staged release files
- [ ] Reject unverified mutable binary downloads
- [ ] Re-scan network-to-shell patterns
- [ ] Final O.8 supply-chain gate

## O.9 Host/parser/crypto hardening
### Coverage-guided fuzzing
- [ ] DEX parser fuzz target
- [ ] DEX writer/verifier fuzz target
- [ ] ZIP/APK fuzz target
- [ ] AAB/APKS fuzz target
- [ ] resource container fuzz target
- [ ] config parser fuzz target
- [ ] integrity manifest fuzz target
- [ ] VM verifier fuzz target
- [ ] persistent corpus
- [ ] crash minimization
- [ ] regression corpus promotion
- [ ] scheduled extended fuzz run
- [ ] sanitizer coverage where supported
- [ ] memory/time resource limits
### Crypto/checksum cleanup
- [ ] Replace custom SHA-256 with maintained implementation
- [ ] Review/replace custom DEX SHA-1 implementation
- [ ] Review/replace custom Adler-32 implementation
- [ ] Document DEX checksum semantics
- [ ] Cryptographic misuse review
### Transaction safety
- [ ] Crash/interruption recovery design
- [ ] Stale backup recovery
- [ ] Report replacement safety
- [ ] Cross-platform rename/fsync tests
- [ ] Concurrent output collision tests
- [ ] Final O.9 hardening gate

## O.10 Android/device compatibility
- [ ] API 24 test
- [ ] Android 8 test
- [ ] Android 10 test
- [ ] Android 12 test
- [ ] Android 14 test
- [ ] Android 15 test
- [ ] Android 16 test when available
- [ ] x86_64 emulator coverage
- [ ] arm64 physical/device-farm coverage
- [ ] Pixel/AOSP device coverage
- [ ] Samsung coverage
- [ ] Xiaomi/HyperOS coverage
- [ ] additional OEM coverage
- [ ] stock RASP baseline
- [ ] developer-options baseline
- [ ] USB-debugging baseline
- [ ] emulator baseline
- [ ] rooted/modified lab baseline
- [ ] unlocked-bootloader baseline when available
- [ ] false-positive thresholds
- [ ] Final O.10 compatibility gate

## O.11 Performance/reliability/soak
- [ ] APK growth per profile
- [ ] AAB growth per profile
- [ ] cold-start budget
- [ ] warm-start budget
- [ ] startup P50/P95/P99
- [ ] memory/PSS budget
- [ ] CPU budget
- [ ] build-time budget
- [ ] VM overhead budget
- [ ] RASP overhead budget
- [ ] repeated-build soak
- [ ] large APK test
- [ ] large multidex test
- [ ] low disk-space behavior
- [ ] interrupted build behavior
- [ ] concurrent builds
- [ ] malformed input reliability
- [ ] Studio long-running operation
- [ ] Studio timeout/cancel/retry
- [ ] deterministic private rebuild
- [ ] Final O.11 reliability gate

## O.12 Documentation/public repository
- [ ] Correct README phase table
- [ ] Add Phase O release-blocked state
- [ ] Correct stable-readiness claims
- [ ] Update SECURITY.md post-1.0 wording
- [ ] Correct obsolete repository paths
- [ ] Getting Started
- [ ] Installation
- [ ] Upgrade
- [ ] Uninstall
- [ ] Release Verification
- [ ] Gradle Plugin distribution guide
- [ ] Artifact support/semantics guide
- [ ] Explicit fallback/unsupported behavior docs
- [ ] Repository description
- [ ] Repository topics
- [ ] License linked in README
- [ ] Documentation audit scans full roadmap/status table
- [ ] Documentation audit scans obsolete path markers
- [ ] Final O.12 documentation gate

## O.13 Independent human review / beta
- [ ] Select independent reviewer
- [ ] Reviewer uses distributed artifacts
- [ ] Clean installation
- [ ] Non-trivial authorized sample protection
- [ ] UX feedback
- [ ] Build integration feedback
- [ ] Security feedback
- [ ] Compatibility feedback
- [ ] All findings triaged
- [ ] Blocking findings = 0
- [ ] Retain reviewer evidence
- [ ] Security/reverse-engineering reviewer strongly preferred
- [ ] Final O.13 external review gate

## O.14 Final production audit
- [ ] Re-audit production orchestrator from zero
- [ ] Re-audit APK semantics
- [ ] Re-audit AAB/APKS semantics
- [ ] Re-audit AAR/library semantics
- [ ] Re-audit profiles/config
- [ ] Re-audit branch/tag governance
- [ ] Re-audit CodeQL/security alerts
- [ ] Re-audit dependency alerts
- [ ] Re-audit complete SBOM/provenance
- [ ] Re-audit fuzz evidence
- [ ] Re-audit device matrix
- [ ] Re-audit performance/reliability
- [ ] Re-audit installers/signing/notarization
- [ ] Re-audit documentation
- [ ] Re-audit license/notices
- [ ] Review release-relevant open issues
- [ ] Review release-relevant open PRs
- [ ] P0 open = 0
- [ ] mandatory P1 open = 0
- [ ] release-required P2 open = 0
- [ ] Final candidate all required workflows green
- [ ] Final O.14 audit approval

## O.15 Stable v1.0.0
- [ ] Freeze approved candidate
- [ ] Confirm exact main commit
- [ ] Confirm required checks on exact commit
- [ ] Confirm security alert thresholds
- [ ] Confirm license/notices
- [ ] Confirm signed/notarized distributables
- [ ] Confirm aggregate SBOM/provenance
- [ ] Confirm external feedback closed
- [ ] Create v1.0.0 from exact approved main commit
- [ ] Release workflow verifies ancestry
- [ ] Release workflow verifies exact checks/version
- [ ] Publish release artifacts
- [ ] Verify checksums from clean environment
- [ ] Verify attestations/provenance
- [ ] Post-publication clean install smoke
- [ ] Preserve immutable release evidence

## Closure state

Phase O remains **OPEN** until every release-required item above is complete.

Stable release policy:

- any open P0 = **NO-GO**;
- any mandatory open P1 = **NO-GO**;
- any unaccepted release-required P2 = **NO-GO**;
- green isolated component tests do not override an open production-path blocker.

Current decision: **NO-GO for public stable v1.0.0**.
