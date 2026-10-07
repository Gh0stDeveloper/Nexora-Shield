# Phase N — Production Hardening

## Objective

Phase N converts the completed protection platform into a release-qualified 1.0 product.

The phase separates **release engineering** from feature development. A build is not considered stable merely because it compiles: public contracts, migration behavior, supply-chain controls, provenance, retrace, security, performance and compatibility all have explicit gates.

The 1.0 line was qualified first as **1.0.0-rc.1**. Phase N #54 (run `37686651703`) passed all nine jobs on head `d101cb457556ca077020ab1932f6632d8d55d0a1`, including representative Android performance and independent CodeQL assessment. The source is now promoted to **1.0.0** for final N.14 stable qualification.

## N.1 — API freeze candidate

The frozen public surface is recorded in `release/api-surface-v1.json`.

The contract covers:

- configuration schema version;
- Android minimum SDK;
- Gradle plugin id;
- stable CLI commands;
- protection profiles;
- supported artifact families.

`scripts/release/verify-api-freeze.py` cross-checks the manifest against the real CLI dispatcher, `shield-core`, the Gradle Plugin and active schema.

Breaking changes require an explicit post-1.0 compatibility decision instead of silently mutating this contract.

## N.2 — Config schema stable

Schema 1 is frozen byte-for-byte in:

- `schemas/nexora-shield.schema.json`
- `schemas/nexora-shield.schema.v1.json`

CI compares both files exactly. Any incompatible schema change must create a new schema version and migration path.

## N.3 — Migration tooling

Two migration surfaces exist:

1. `nexora-shield-release config-migrate-json` for machine-readable JSON configurations;
2. Shield Studio `ConfigMigration` for YAML configuration loaded through SnakeYAML.

Current schema 1 is a no-op. Legacy flat configuration is migrated to schema 1 while unrelated advanced sections are retained. Future unknown schemas fail closed.

## N.4 — Documentation audit

The documentation audit verifies required release/security/compatibility documents, selected local links and stale phase/version markers in the README.

## N.5 — Supply-chain hardening

Production hardening includes explicit workflow permissions, CODEOWNERS, Dependabot coverage, Rust lockfile enforcement, an action-owner allowlist, rejection of `pull_request_target`, rejection of `write-all`, rejection of mutable action refs and rejection of network-to-shell patterns.

Write permissions are reserved for the dedicated release workflow.

## N.6 — SBOM and provenance

CI generates a CycloneDX 1.5 SBOM from locked Cargo metadata.

Release artifacts also receive:

- SHA-256 checksums;
- local in-toto/SLSA-compatible provenance;
- GitHub build-provenance attestation through OIDC.

## N.7 — Signed releases

`.github/workflows/release.yml` is the only workflow allowed release write permissions.

Release artifacts are built on Linux, macOS and Windows, staged deterministically, checksummed and attested before a GitHub Release is created.

RC tags use `v1.0.0-rc.N`. Stable uses `v1.0.0`.

## N.8 — Crash and retrace validation

Gradle retrace uses a dedicated argument-vector builder with no shell interpolation.

Tests cover paths with spaces, missing mappings, invalid executable inputs and exact mapping/stacktrace ordering.

## N.9 — Security review

The internal pre-release security review is recorded in:

- `release/security-review.json`;
- `docs/PHASE-N-SECURITY-REVIEW.md`.

No critical, high or blocking finding remains open.

## N.10 — Performance review

N.10 is complete.

Phase N #54 measured baseline and genuinely protected APKs on Android 15 / API 35 x86_64 ATD with 5 warmups + 20 measured runs per variant.

The gate verifies:

- startup p50/p95;
- median PSS;
- signed APK size;
- distinct baseline/protected SHA-256;
- protected APK identity against the authoritative Nexora Shield public report.

The configured budget passed. Full evidence is in `release/performance-review.json` and `docs/PHASE-N-PERFORMANCE-REVIEW.md`.

## N.11 — Compatibility review

The 1.0 compatibility contract includes:

- Rust MSRV 1.81;
- Android minSdk 24;
- JDK 17;
- Gradle 9.7.0;
- Android Gradle Plugin 9.4.1;
- arm64-v8a and x86_64;
- APK, AAB, AAR and APKS;
- Linux, macOS and Windows desktop targets.

## N.12 — 1.0 release candidate

RC qualification is complete.

Phase N #54 passed 9/9 jobs, including N.10 performance, N.13 CodeQL, MSRV, SBOM/provenance, migration/retrace and inherited Phase M/K/L regressions.

The RC qualification evidence is retained even when a prerelease tag is not distributed. Stable cannot bypass RC-equivalent qualification.

## N.13 — External assessment and feedback

N.13 is complete under the machine-enforced release policy.

The required independent external assessment is GitHub CodeQL:

- provider: `github-codeql`;
- Phase N #54;
- run `37686651703`;
- job `N.13 independent external assessment`;
- conclusion: `success`.

The evidence is recorded in `release/feedback-status.json`.

Human RC feedback remains supported through `docs/RC-FEEDBACK.md` and the issue form. Human feedback is supplementary; if a blocking external finding is recorded, stable must fail closed until it is resolved.

## N.14 — 1.0 stable

The source version is now exactly `1.0.0`.

Stable qualification requires all of the following in the same final release line:

- API/schema/migration/documentation/supply-chain gates green;
- SBOM/provenance gate green;
- security and compatibility reviews green;
- N.10 Android performance green;
- N.13 CodeQL external assessment green;
- no blocking external finding;
- Rust 1.81 MSRV green;
- inherited Phase M/K/L regressions green;
- exact synchronized `1.0.0` source version.

The stable tag `v1.0.0` must be created only from the validated `main` commit. The release workflow then builds Linux/macOS/Windows artifacts, checksums them, emits SBOM/provenance attestations and publishes the stable GitHub Release.


## Closure status

**COMPLETED — N.1–N.14**

Final stable implementation head: `ce92ea791dc860a505658a67be1b9250105a834a`.

Validated by:
- Phase N #86 (`37691051042`): 9/9 jobs successful;
- N.14 stable qualification: successful;
- N.10 Android performance: successful;
- N.13 CodeQL external assessment: successful;
- Rust 1.81 MSRV: successful;
- Phase M #86, Phase L #92, Phase K #107: successful;
- CI #1156: successful;
- zero failed jobs.

The repository source is finalized at `1.0.0`. Stable GitHub Release publication is intentionally performed after merge from the validated `main` commit so the release tag cannot point at an unmerged feature branch.
