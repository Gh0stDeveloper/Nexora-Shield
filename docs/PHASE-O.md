# Phase O — Production Release Audit & Hardening

## Status

**OPEN — RELEASE BLOCKING**

Phase O starts after the completion of Phase N. It exists because a strict post-N production-readiness audit found gaps between the individually implemented protection engines and the actual end-user production path.

Until Phase O is closed:

- do not create or publish the stable `v1.0.0` tag;
- do not describe Nexora Shield as production-ready for external users;
- do not treat a green Phase N qualification alone as sufficient stable-release approval.

Audit baseline:

- repository: `Gh0stDeveloper/Nexora-Shield`;
- audited branch: `main`;
- audited main commit: `5ece01dfd2f07ebe1b6f5d67b845e0f1df5913aa`;
- workspace source version: `1.0.0`;
- repository CI on the audited commit: green for CI, Phase K, Phase L and Phase M;
- Phase N post-merge run #95 was still completing its final N.14 job when the audit was performed.

Phase N remains historically complete within the scope that it validated. Phase O is a new, stricter release-readiness layer and does not rewrite Phase N history.

---

## Objective

Convert Nexora Shield from a collection of validated protection engines and release gates into a production product whose **real user path** applies the documented defenses, whose release artifacts are distributable and trustworthy, and whose stable tag cannot bypass required security, compatibility, supply-chain or operational gates.

Phase O is complete only when the actual external-user workflow is proven end-to-end:

```text
user project / APK / AAB / AAR
        ↓
published Nexora Shield integration
        ↓
production protection orchestrator
        ↓
selected protection profile
        ↓
real B–I protection stages as applicable
        ↓
artifact rebuild / alignment / signing
        ↓
runtime/device validation
        ↓
release evidence
        ↓
signed/attested distributable artifact
```

A phase is not complete because the underlying crate exists or because an isolated unit/integration suite passes. The release path itself must exercise the feature.

---

## Severity model

### P0 — Stable release blocker

A P0 finding can invalidate product claims, create a legal/release-governance failure, or allow the stable release path to publish code that did not pass the intended protection/security gates.

No stable release is allowed with any P0 open.

### P1 — Production quality blocker

A P1 finding may not invalidate the core design, but it creates unacceptable supply-chain, compatibility, reliability, distribution, false-positive or operational risk for a public security product.

All mandatory P1 items must be closed before stable.

### P2 — Product/repository quality

P2 findings affect maintainability, user trust, documentation correctness, supportability or public presentation.

P2 items marked release-required must be closed before stable; remaining cosmetic P2 work may move post-1.0 only with an explicit accepted-risk record.

---

# P0 findings

## P0.1 — Production protection path does not orchestrate the protection stack

The current `nexora-shield protect` path builds a `ProtectionRequest` and calls `protect_apk()` from `shield-core`.

The audited production path performs Phase A responsibilities:

- APK structural verification;
- ZIP normalization;
- equivalence verification;
- alignment;
- signing;
- package verification;
- transactional publication;
- public/private report emission.

The audited command does **not** currently orchestrate the complete protection stack:

- Phase B DEX transformation;
- Phase C data protection;
- Phase D Integrity Graph;
- Phase E RASP integration;
- Phase F Native Shield;
- Phase G VM Shield;
- Phase H per-build diversification;
- Phase I attestation/remote-policy integration where configured.

The Gradle Plugin invokes this same `protect` command. Therefore the gap is user-visible and release-blocking.

### Required remediation

Create a production protection orchestrator with an explicit stage graph and typed stage contracts.

Minimum stage model:

1. input inspection and immutable plan;
2. configuration/profile resolution;
3. DEX discovery and parse/validate;
4. compatibility analysis;
5. selector resolution;
6. DEX transformations;
7. selected data/resource protection;
8. selective VM/native integration;
9. per-build diversity allocation;
10. integrity manifest/graph creation;
11. RASP policy/runtime integration;
12. optional attestation binding;
13. package reconstruction;
14. signing/alignment;
15. post-build verification;
16. public/private evidence emission.

The pipeline must fail closed when a requested protection cannot be safely applied.

### Exit criteria

- `protect` invokes the production orchestrator, not Phase A alone.
- Standard/Hardened/Maximum produce measurably different intended protection plans.
- E2E tests prove the final APK changed in the expected protected surfaces.
- E2E tests prove protected behavior remains functional.
- Public reports identify which protection stages actually executed.
- Requested-but-skipped critical stages fail unless an explicit policy permits fallback.
- Regression tests prove the Gradle Plugin reaches the same orchestrator.

---

## P0.2 — AAB/APKS protection path is primarily validation, not full protection

The current AAB path validates bundle structure, modules, dynamic features, optional bundletool behavior and profile-related metadata. This is valuable compatibility work, but it does not establish that the complete production protection stack is applied to code/resources that will be delivered from the bundle.

### Required remediation

Define one authoritative AAB protection strategy, for example:

- protect relevant module DEX/resources before bundle packaging; or
- transform module artifacts through supported AGP Variant APIs before the final bundle is assembled.

APKS validation must then prove that bundletool-generated delivered APKs contain the intended protected surfaces.

### Exit criteria

- base and supported dynamic-feature code passes through the production orchestrator;
- split/module identity is preserved;
- Play App Signing certificate model remains correct;
- device-targeted and universal APK Sets are generated from protected AABs;
- delivered APKs are inspected and verified for expected protection evidence;
- baseline/startup profiles and resources remain valid.

---

## P0.3 — AAR/library mode does not yet prove full protection semantics

The current AAR path verifies package structure, consumer rules, resources, metadata and baseline-profile compatibility. It does not by itself prove that protected library code is transformed at the correct point in the consuming application's DEX pipeline.

### Required remediation

Define exactly what “library protection mode” guarantees.

The design must distinguish:

- protection applied while publishing an AAR;
- consumer-side protection after library bytecode becomes application DEX;
- consumer rules required to preserve generated/runtime contracts;
- resource protection behavior;
- mapping ownership and retrace behavior.

### Exit criteria

- documentation makes no stronger claim than the implementation;
- a publishing sample and an independent consumer sample prove the complete supported behavior;
- protected code is verified in the final consuming APK/AAB;
- unsupported library transformations fail clearly instead of giving false confidence.

---

## P0.4 — Repository is public without a selected license

The repository currently has no recognized license and the README explicitly states that a final license has not been selected.

### Required remediation

Select and add a license appropriate to the intended business/distribution model.

Possible models must be decided by the project owner, not inferred by CI:

- open-source;
- source-available;
- proprietary;
- dual license;
- commercial/community split.

### Exit criteria

- root license file exists;
- README and package metadata agree with the license;
- distribution rights for bundled third-party material are verified;
- release artifacts include required notices;
- no ambiguous “public repository implies permission” state remains.

---

## P0.5 — Stable tag is not mechanically bound to validated main

The release workflow triggers from `v1.0.0`, but the tag itself must be proven to point to an approved `main` commit.

Documentation saying “create the tag from main” is not a sufficient enforcement mechanism.

### Required remediation

Stable release qualification must verify:

- the tag commit is reachable from the intended protected `main`;
- the exact tag commit has all mandatory required checks;
- the commit has the expected source version and release metadata;
- no release is created from an unmerged branch commit;
- the tag is immutable after publication.

### Exit criteria

The release workflow fails before building/publishing if tag ancestry or required-check evidence is invalid.

---

## P0.6 — CodeQL execution success is not equivalent to zero blocking findings

The current external-assessment gate treats a successful CodeQL workflow execution as assessment evidence. A CodeQL job can complete successfully while still publishing findings.

### Required remediation

Create an explicit Code Scanning/SARIF findings gate.

The release policy must define accepted thresholds. At minimum:

- critical: 0 open;
- high: 0 open;
- explicitly blocking medium findings: 0 open;
- dismissed findings require a documented reason and audit trail.

### Exit criteria

N.13/O release qualification reads finding state, not merely workflow conclusion.

---

## P0.7 — Main branch protection is not yet proven by repository evidence

The audit observed no repository rulesets. The GitHub App used for the audit could not read the classic branch-protection endpoint because administration permission was unavailable.

This does not prove classic branch protection is absent, but it means production governance is **unverified**.

### Required remediation

Verify and document repository-side enforcement for `main`.

Minimum policy:

- direct pushes restricted;
- pull request required;
- required status checks;
- stale review dismissal as appropriate;
- conversations resolved;
- force push disabled;
- deletion disabled;
- release/security workflow changes owned/reviewed;
- administrators included in policy unless an explicitly documented emergency process exists.

### Exit criteria

The final audit contains machine-readable or captured repository-setting evidence.

---

# Phase plan

## O.0 — Release freeze and audit baseline

Status: **COMPLETED** — Phase O #9 (`37710584139`) success

Authoritative O.0 evidence:
- `release/phase-o-status.json`
- `release/phase-o-findings.json`
- `release/phase-o-accepted-risks.json`
- `docs/PHASE-O0-BASELINE.md`
- `docs/PHASE-O-ACCEPTED-RISK.md`
- `scripts/release/verify-phase-o-release-freeze.py`
- `.github/workflows/phase-o.yml`

Purpose: prevent publication while remediation is in progress.

Tasks:

- record audited main SHA;
- record open P0/P1/P2 findings;
- mark `v1.0.0` stable publication as blocked;
- preserve Phase N historical evidence;
- define Phase O ownership and closure policy;
- ensure no automation can silently publish stable during Phase O.

Exit criterion:

- release status is unambiguous everywhere in documentation and CI.

---

## O.1 — Production Protection Orchestrator

Purpose: connect the implemented protection engines into the real user path.

Tasks:

- typed production stage graph;
- immutable build context;
- profile/config resolution;
- selector plan;
- DEX pipeline integration;
- data protection integration;
- integrity graph integration;
- RASP/runtime integration;
- native integration;
- VM integration;
- build-diversity integration;
- optional attestation integration;
- deterministic failure semantics;
- stage-level evidence/reporting;
- rollback-safe output publication.

Exit criterion:

- one authoritative pipeline produces the protected APK used by CLI and Gradle Plugin.

---

## O.2 — APK end-to-end protection proof

Purpose: prove the orchestrator protects real Android applications without breaking them.

Required golden matrix:

- Java;
- Kotlin;
- Compose;
- multidex;
- reflection;
- serialization;
- JNI;
- coroutines;
- representative resources;
- minified/R8;
- multiple build variants where supported.

Tests must include:

- build;
- install;
- cold launch;
- functional smoke;
- protected-surface assertions;
- signature verification;
- tamper/re-sign rejection;
- retrace/mapping behavior;
- upgrade from previous protected build;
- uninstall/reinstall.

Exit criterion:

- protected golden apps execute successfully and the final artifacts prove intended transformations.

---

## O.3 — AAB, dynamic features, splits and APKS production protection

Purpose: move bundle support from structural validation to proven delivered protection.

Tasks:

- protect base module;
- protect supported dynamic features;
- validate module-specific selectors;
- preserve resource namespaces;
- generate APK Sets with bundletool;
- validate universal and device-targeted delivery;
- Play App Signing certificate model tests;
- delivery APK protection assertions;
- baseline/startup profile compatibility;
- split install/launch tests.

Exit criterion:

- code delivered to devices from a protected AAB contains the documented protections.

---

## O.4 — AAR and library protection contract

Purpose: make library support precise and safe.

Tasks:

- define publisher vs consumer responsibilities;
- final-Dex protection point;
- consumer-rule contract;
- resource behavior;
- mapping/retrace ownership;
- independent sample consumer;
- Maven-local publication/consumption test;
- final APK/AAB protected-surface assertion.

Exit criterion:

- library users cannot mistake validation-only behavior for actual protection.

---

## O.5 — Protection profiles and configuration enforcement

Purpose: make `standard`, `hardened` and `maximum` real executable contracts.

Tasks:

- stage matrix per profile;
- overhead budgets per profile;
- selector defaults;
- required/optional stage semantics;
- unsupported-feature behavior;
- report-only vs enforcement defaults;
- migration compatibility;
- schema validation tied to orchestrator;
- public report contains effective profile and executed controls.

Exit criterion:

- profiles are behaviorally distinct, testable and accurately documented.

---

## O.6 — Release governance, licensing and security gates

Purpose: make stable release policy enforceable rather than advisory.

Tasks:

- select license;
- verify third-party notices;
- prove branch protection/rulesets;
- required checks on `main`;
- protected tag policy where available;
- tag-to-main ancestry gate;
- exact-commit required-check gate;
- CodeQL/SARIF open-finding gate;
- release approval policy;
- emergency rollback/revocation procedure;
- security-version support policy updated for post-1.0.

Exit criterion:

- a stable release cannot be published from an unapproved commit or with blocking security findings.

---

## O.7 — External distribution and installer trust

Purpose: make the product consumable by users outside the monorepo.

### Gradle Plugin

- publishable plugin metadata;
- decide Gradle Plugin Portal and/or Maven repository;
- versioned plugin coordinates;
- independent consumer project using remote coordinates;
- no `includeBuild("../../../gradle-plugin")` dependency for user documentation.

### CLI

- documented installation route;
- versioned Linux/macOS/Windows binaries;
- checksums and provenance verification instructions;
- upgrade/uninstall instructions.

### Shield Studio

- native installers;
- Windows Authenticode signing;
- macOS code signing and notarization;
- Linux package integrity/metadata;
- installer smoke tests on clean environments.

### Build reproducibility

- add/standardize Gradle Wrapper where appropriate or explicitly document/pin the external Gradle bootstrap;
- clean-machine installation tests.

Exit criterion:

- a new user can install and verify Nexora Shield without cloning the repository.

---

## O.8 — Supply-chain hardening and complete SBOM

Purpose: reduce dependency/build compromise risk.

Tasks:

- pin third-party GitHub Actions to immutable full commit SHAs;
- record human-readable version comments;
- pin release compiler/toolchain instead of floating `stable`;
- triage every Dependabot PR;
- preserve the Rust 1.81 MSRV gate instead of auto-upgrading its purpose;
- RustSec gate;
- JVM/Gradle vulnerability scanning;
- Rust CycloneDX;
- Gradle Plugin CycloneDX;
- Shield Studio CycloneDX;
- aggregate release BOM;
- verify release artifact dependency inventory;
- review build scripts for network-to-shell, mutable downloads and unverified binary fetches.

Exit criterion:

- the full shipped product, not only Cargo, has traceable dependency/provenance evidence.

---

## O.9 — Parser, cryptography and host-safety hardening

Purpose: strengthen Nexora Shield against hostile or malformed inputs.

### Coverage-guided fuzzing

Add real persistent fuzz targets for:

- DEX reader/writer/verifier;
- ZIP/APK parser;
- AAB/APKS parser;
- resource container parser;
- configuration parser;
- integrity manifest parser;
- VM bytecode verifier.

Requirements:

- persistent corpus;
- crash minimization;
- regression promotion;
- scheduled long-running fuzz jobs;
- sanitizer use where supported;
- explicit resource limits to detect memory/time denial-of-service behavior.

### Cryptographic primitive cleanup

Replace unnecessary hand-written cryptographic implementations with maintained libraries.

Specific audited candidates:

- custom SHA-256 in `shield-package/src/hash.rs`;
- custom SHA-1 in DEX checksum handling where a vetted implementation can preserve format semantics;
- Adler-32 may use a maintained checksum implementation if practical.

DEX-required SHA-1 is a format checksum/signature field, not a claim of modern collision resistance.

### Transaction safety

Harden:

- output overwrite recovery after process/machine interruption;
- stale backup handling;
- report replacement semantics;
- fsync/rename behavior by platform;
- concurrent build collisions.

Exit criterion:

- malformed inputs cannot trivially panic/crash the host process and transactional interruption tests preserve recoverability.

---

## O.10 — Android compatibility and physical-device matrix

Purpose: validate actual Android behavior beyond one representative emulator.

Minimum target matrix:

- API 24 / Android 7;
- Android 8;
- Android 10;
- Android 12;
- Android 14;
- Android 15;
- Android 16 where tooling/image availability permits.

Architectures:

- x86_64 CI emulator;
- arm64 real device/device farm.

Required physical/OEM coverage when resources permit:

- Pixel/AOSP reference;
- Samsung;
- Xiaomi/HyperOS or equivalent heavily customized OEM;
- Motorola or another distinct vendor.

RASP environments:

- stock;
- developer options;
- USB debugging;
- emulator;
- rooted/modified laboratory device;
- unlocked bootloader where safely available.

Exit criterion:

- no release-blocking functional regression or unacceptable false-positive rate across the supported matrix.

---

## O.11 — Production performance, reliability and soak qualification

Purpose: extend N.10 from representative performance to production confidence.

Measure by profile:

- APK/AAB size growth;
- cold start;
- warm start;
- P50/P95/P99 where meaningful;
- memory/PSS;
- CPU;
- build time;
- VM overhead;
- RASP overhead;
- repeated builds;
- long-running Studio/CLI operations.

Reliability:

- repeated protect runs;
- interrupted build recovery;
- concurrent project builds;
- low disk-space behavior;
- malformed input behavior;
- large APK/multidex behavior;
- Studio timeout/cancel/retry;
- deterministic private reproducible mode.

Exit criterion:

- all supported profiles have explicit budgets and no release-blocking reliability regression.

---

## O.12 — Documentation and public repository correctness

Purpose: make public claims match actual behavior.

Required corrections include:

- remove stale README phase statuses;
- add Phase O release-blocked status;
- update Security Policy from “pre-1.0” wording;
- fix obsolete repository paths in `REPOSITORY-CONVENTIONS.md`;
- add Getting Started;
- add Installation;
- add Upgrade/Uninstall;
- add Release Verification;
- explain plugin distribution;
- explain supported artifact semantics;
- explain unsupported/fallback behavior;
- add repository description/topics;
- add license;
- ensure docs audit checks the entire supported status table, not isolated markers.

Exit criterion:

- no known contradiction between implementation, roadmap, README, release process and security policy.

---

## O.13 — Real external review and controlled beta

Purpose: supplement automated analysis with independent human use.

Requirements:

- at least one technically independent reviewer/tester;
- reviewer uses distributed artifacts, not a developer checkout;
- clean installation;
- protect a non-trivial authorized sample;
- report UX/build/security/compatibility findings;
- triage every finding;
- zero unresolved blocking findings.

Strongly preferred:

- one Android build/tooling reviewer;
- one security/reverse-engineering reviewer.

Exit criterion:

- retained human feedback evidence and resolved blockers.

---

## O.14 — Final production audit

Purpose: perform a new audit from zero after remediation.

Audit must re-check:

- production orchestration;
- artifact semantics;
- release governance;
- repository protection;
- CodeQL/security alerts;
- dependency alerts;
- SBOM/provenance;
- fuzz results;
- device matrix;
- performance;
- installer trust;
- documentation;
- license;
- open issues/PRs relevant to release;
- stable tag ancestry controls.

No prior Phase N/O result may be assumed valid without revalidation when the relevant implementation changed.

Exit criterion:

- zero open P0;
- zero mandatory open P1;
- no undisclosed release-required P2;
- all required CI/release gates green on the final candidate commit.

---

## O.15 — Stable 1.0 publication

Purpose: publish only after O.14 approves the exact commit.

Required sequence:

1. freeze final candidate;
2. run complete required checks;
3. confirm branch/tag governance;
4. confirm security-alert thresholds;
5. confirm license/notices;
6. confirm signed/notarized distributables;
7. confirm aggregate SBOM/provenance;
8. confirm external feedback closure;
9. create `v1.0.0` on the exact approved `main` commit;
10. release workflow revalidates ancestry/checks/version;
11. publish artifacts;
12. verify release attestations/checksums from a clean environment;
13. perform post-publication install smoke;
14. preserve release evidence.

Exit criterion:

- `v1.0.0` is public, verifiable, installable and tied to the exact audited commit.

---

# Cross-cutting engineering rules

## No false confidence

A successful validation command must never be represented as proof that a protection was applied unless evidence from the final artifact demonstrates it.

## Fail closed

When a configured protection cannot be safely applied, the default is a build failure. Any fallback must be explicit, profile-defined and observable in reports.

## One production path

CLI, Gradle Plugin and Shield Studio must converge on the same production orchestrator. They may provide different UX surfaces, but must not implement divergent protection semantics.

## Evidence from final artifacts

Security claims must be validated against the final output artifact that users receive, not only intermediate structures.

## Regressions are permanent

Every confirmed parser crash, bypass, false positive, packaging breakage or release-governance defect becomes a retained regression test/gate when it can be safely automated.

## User-controlled device assumption

No documentation may claim that client-side protection is unbreakable. Defense-in-depth raises attacker cost and detects defined classes of modification; it does not create an absolute trust boundary on an attacker-controlled device.

---

# Phase O release gate

Stable publication is prohibited until all of the following are true:

- O.0–O.15 checklist release-required items are complete;
- production `protect` applies the documented protection stack;
- APK/AAB/AAR claims match real final-artifact behavior;
- license is selected;
- main/tag governance is verified and enforced;
- CodeQL/blocking security findings are explicitly gated;
- user-facing distribution is installable and signed/notarized where required;
- complete supply-chain evidence exists;
- coverage-guided fuzzing has no unresolved release-blocking crash;
- supported Android compatibility matrix passes;
- real external feedback has no blocking finding;
- final production audit approves the exact stable commit.

**Current release decision: NO-GO for public stable `v1.0.0` until Phase O closes.**
