# Production Readiness Audit — Post Phase N

## Executive summary

A strict post-Phase-N audit was performed against `main` at commit:

`5ece01dfd2f07ebe1b6f5d67b845e0f1df5913aa`

The project has strong internal engineering in many areas: Rust quality gates, Rust 1.81 MSRV, RustSec, package parsing validation, secrets handling, Android representative performance, SBOM/provenance, GitHub attestations, CodeQL execution, repack/re-sign tests, build diversity and Security Lab regression evidence.

However, the project is **not yet approved for external stable production** because the audit found a critical gap between isolated engine implementation and the actual user-facing production protection path.

The primary finding is that the current `nexora-shield protect` path invokes the Phase A packaging pipeline and does not yet orchestrate the documented B–I protection layers into the final APK. The Gradle Plugin invokes that same command.

Phase O was created to resolve these findings before `v1.0.0`.

---

## Audited evidence

### Repository state

- public repository;
- default branch: `main`;
- audited commit: `5ece01dfd2f07ebe1b6f5d67b845e0f1df5913aa`;
- repository license: not selected/recognized;
- repository rulesets observed by audit: none;
- classic branch-protection endpoint: unreadable by the connected GitHub App because administration permission is unavailable;
- GitHub Releases at audit time: none;
- stable `v1.0.0` not published.

### Post-merge automation observed

On the audited main commit:

- CI #1165: success;
- Phase K #111: success;
- Phase L #96: success;
- Phase M #90: success;
- Phase N #95: all base jobs successful while final N.14 remained queued at the final audit read;
- Dependabot update discovery jobs: successful.

### Open dependency-update PRs observed

At audit time, Dependabot had opened updates including:

- GitHub CodeQL Action v3 → v4;
- Gradle Actions v4 → v6;
- upload-artifact v4 → v6;
- download-artifact v5 → v7;
- Rust toolchain action update;
- JUnit updates;
- Zeroize;
- ChaCha20Poly1305;
- SnakeYAML;
- Compose;
- SHA-2;
- HMAC;
- HKDF.

These updates are not automatically classified as vulnerabilities. They require intentional triage. The declared Rust 1.81 MSRV gate must not be semantically destroyed by an automated toolchain-version bump.

---

# Findings

## Finding A — Critical: production protect command is Phase A packaging only

### Evidence

The CLI dispatcher maps:

`protect → run_protect()`.

The audited `run_protect()` builds `ProtectionRequest` and invokes:

`protect_apk(&request)`.

The audited `protect_apk()` performs:

- package input validation;
- APK structure verification;
- normalization;
- normalized-content equivalence verification;
- optional zipalign;
- optional apksigner signing;
- output structure verification;
- transactional output publication;
- public/private build reports.

The command itself prints:

`Nexora Shield Phase A protection pipeline: OK`.

### Impact

The real command users invoke does not establish that the final artifact received:

- DEX rename/metadata/IR transformations;
- protected strings/constants/resources;
- Integrity Graph;
- RASP/runtime integration;
- Native Shield;
- VM Shield;
- per-build diversity;
- attestation binding.

The profile name alone does not prove these stages executed.

### Severity

**P0 / Critical release blocker.**

---

## Finding B — Critical: Gradle Plugin inherits the same production-path gap

### Evidence

`NexoraShieldApkTransformTask` constructs an argument vector containing:

- configured CLI executable;
- `protect`;
- input APK;
- output APK;
- profile;
- minSdk;
- signing/report parameters.

It therefore reaches the same audited `protect` command.

### Impact

A user applying `dev.nexora.shield` can receive an artifact that passed the packaging pipeline without the complete documented protection stack.

### Severity

**P0.**

---

## Finding C — Critical: AAB/APKS support does not yet prove delivered full-stack protection

### Evidence

The audited bundle task runs:

- `aab-verify`;
- optional `bundletool-validate`;
- structural module inspection;
- dynamic-feature counting;
- baseline-profile inspection.

### Impact

Structural validity does not prove that code delivered from the bundle passed the complete production protection orchestrator.

### Severity

**P0 until product claims and implementation are aligned.**

---

## Finding D — Critical: AAR mode is contract/validation-oriented

### Evidence

The audited AAR task validates:

- package structure;
- consumer rule entries;
- resources;
- resource symbols;
- AAR metadata;
- baseline/startup profiles.

### Impact

This is useful compatibility validation but does not prove application-level DEX protection of library code in the consuming app.

### Severity

**P0 if advertised as full library protection; otherwise must be explicitly scoped.**

---

## Finding E — Public repository has no selected license

### Evidence

- repository metadata has no recognized license;
- README states that a final repository license has not been selected;
- no root license file was found in the audited tree.

### Impact

External users do not have a clear legal grant defining use, modification or redistribution rights.

### Severity

**P0 legal/distribution blocker.**

---

## Finding F — Stable tag origin is documented but not sufficiently enforced

### Evidence

The release workflow is tag-triggered. The release documentation requires `v1.0.0` to be created from validated `main`, but the audit did not identify a strong release step that proves the tag commit is an approved main commit with all required exact-commit checks.

### Impact

A release tag could potentially trigger publication from an unintended commit.

### Severity

**P0 release-governance blocker.**

---

## Finding G — CodeQL success can coexist with findings

### Evidence

The N.13 workflow initializes and analyzes CodeQL and records successful job execution as external-assessment evidence.

### Impact

Workflow `success` means the analysis executed, not that blocking findings are zero.

### Severity

**P0 for stable security qualification.**

---

## Finding H — Main protection cannot be independently confirmed by this audit

### Evidence

- repository rulesets endpoint returned an empty ruleset list;
- classic branch-protection read returned 403 because the connected GitHub integration lacks the required administration access.

### Impact

The audit cannot prove that direct pushes, force pushes, branch deletion or unreviewed changes are prevented.

### Severity

**P0 until verified.**

---

## Finding I — User distribution is incomplete

### Gradle Plugin

Samples use composite-build inclusion via `includeBuild`; no production plugin-publication configuration was identified.

### Shield Studio

The release workflow creates platform packages, but no Windows Authenticode or macOS code-signing/notarization path was identified.

### CLI

Release staging exists, but clean external installation/update/uninstall workflows need to be treated as product gates.

### Severity

**P1.**

---

## Finding J — GitHub Actions references are version tags, not immutable SHAs

Observed workflow references include version tags such as:

- `actions/checkout@v5`;
- `actions/setup-java@v5`;
- `gradle/actions/setup-gradle@v4`;
- `github/codeql-action/*@v3`;
- other tagged third-party actions.

### Impact

Tags are easier to read but are mutable supply-chain references.

### Severity

**P1.**

---

## Finding K — Release toolchain uses floating stable Rust in places

### Impact

A future stable compiler can change release behavior without source changes.

### Severity

**P1 reproducibility.**

---

## Finding L — SBOM coverage is Rust-centric

### Evidence

The audited Phase N SBOM generation is based on Cargo metadata.

### Impact

Shield Studio and the Gradle Plugin introduce Kotlin/JVM/Gradle dependency graphs that need release-level dependency inventory and vulnerability scanning.

### Severity

**P1.**

---

## Finding M — Security Lab fuzzing is deterministic mutation smoke, not coverage-guided fuzzing

### Evidence

The audited `FuzzFarm` applies deterministic:

- bit flips;
- truncation;
- appended bytes;
- prefix reversal;

and tracks panics with `catch_unwind`.

### Positive value

This is useful and should remain as a quick regression gate.

### Gap

It is not a replacement for long-running, corpus-guided fuzzing of hostile APK/DEX/ZIP/config/VM inputs.

### Severity

**P1.**

---

## Finding N — Hand-written SHA implementations exist

### Evidence

- `shield-package/src/hash.rs` contains an internal SHA-256 implementation;
- DEX checksum handling contains internal SHA-1 and Adler-32 implementations.

### Impact

This increases maintenance/audit burden and conflicts with the project's own policy to prefer established cryptographic implementations.

DEX SHA-1 is required by the file format, but the implementation itself does not need to be custom.

### Severity

**P1.**

---

## Finding O — Transaction recovery is not fully crash-safe

### Evidence

The audited output replacement logic renames the previous output to a backup, renames the new output into place and removes the backup. Tests cover normal overwrite behavior.

The audit did not find recovery tests for process/machine termination between those steps.

The report writer removes an existing destination before renaming the temporary file.

### Impact

A hard interruption can leave stale backup/temp state or a missing expected output/report.

### Severity

**P1 reliability.**

---

## Finding P — Android compatibility matrix is narrower than the documented target

### Positive progress

N.10 now performs genuine baseline/protected execution measurements on a representative Android emulator and verifies that the measured protected APK matches Nexora Shield's own output report.

### Remaining gap

The broader documented support matrix includes older Android APIs, arm64 physical devices and OEM variations that are not equivalent to one x86_64 ATD environment.

RASP false positives are especially sensitive to device/OEM differences.

### Severity

**P1.**

---

## Finding Q — Documentation contradictions remain despite docs gate

Examples observed:

- README upper sections state Phase N/1.0 readiness while its roadmap table still marks later phases as Next/Planned;
- Security Policy still uses pre-1.0 support wording;
- repository-conventions documentation contains obsolete paths/names.

### Impact

Users can receive conflicting statements about maturity and support.

### Severity

**P2, release-required.**

---

## Finding R — Public repository metadata is incomplete

Observed repository metadata included no description, no topics and no recognized license.

### Severity

**P2 except license, which is P0.**

---

# Improvements confirmed since earlier audits

The post-N audit confirms meaningful improvements that should be preserved.

## CI and language quality

- strict Rust formatting/lint/test gates;
- declared Rust 1.81 MSRV validation;
- RustSec dependency audit;
- workspace unsafe-code policy;
- Clippy restrictions against common panic patterns in production code.

## APK/package safety

- strict ZIP metadata parsing;
- duplicate entry rejection;
- traversal/absolute/backslash path rejection;
- unsupported/encrypted entry rejection;
- ZIP64 fail-closed behavior where unsupported;
- local/central metadata validation;
- deterministic normalization.

## Secrets/build integration

- Gradle secret references use `env:` or `file:` providers;
- passwords are passed to apksigner through environment references rather than raw command-line values;
- signing output is verified;
- cache behavior is restricted when secret/per-build inputs are present.

## Studio safety

- bounded project traversal;
- symlink-conscious project discovery;
- command argument vectors rather than shell-string interpolation;
- command timeout;
- bounded captured output;
- report size bound;
- private-report fields rejected by public report viewer.

## Adversarial/security regression

- re-sign testing with independent identities;
- repack/tamper rejection tests;
- cross-build diversity/portability tests;
- versioned Security Lab corpus;
- deterministic fuzz-smoke;
- security scoring methodology.

## Phase N release engineering

- synchronized source version;
- API/schema freeze;
- migration tooling;
- N.10 representative Android measurements;
- CycloneDX generation for Rust;
- provenance generation;
- GitHub build attestations;
- multi-platform release build structure;
- CodeQL execution;
- stable qualification policy.

These improvements are not discarded by Phase O. Phase O turns them into a coherent external production path.

---

# Release recommendation

## Current decision

**NO-GO for public stable `v1.0.0`.**

The stable tag should remain unpublished until Phase O closes.

## First implementation priority

The first engineering work should be:

1. O.0 release freeze;
2. O.1 production protection orchestrator;
3. O.2 APK E2E proof;
4. O.5 profile enforcement.

This closes the largest gap: making the product actually execute the protection architecture that the repository already contains.

## Final approval rule

Only O.14 may issue the final production approval for O.15 stable publication.

No previous green run, checklist closure or component-level test is allowed to override an unresolved production-path P0.
