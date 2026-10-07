# Phase N — Production Hardening

## Objective

Phase N converts the completed protection platform into a release-qualified 1.0 product.

The phase separates **release engineering** from feature development. A build is not considered stable merely because it compiles: public contracts, migration behavior, supply-chain controls, provenance, retrace, security, performance and compatibility all have explicit gates.

The 1.0 release line starts at **1.0.0-rc.1**. Stable `1.0.0` is intentionally blocked until real external RC feedback and representative Android device performance evidence exist.

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

The release source of truth is:

- `README.md`
- `SECURITY.md`
- `docs/ROADMAP.md`
- `docs/CONFIGURATION.md`
- this Phase N document;
- API/release/security/performance/compatibility review documents.

## N.5 — Supply-chain hardening

Production hardening includes:

- explicit workflow permissions;
- CODEOWNERS coverage for security/release surfaces;
- Dependabot coverage for Cargo, Gradle and GitHub Actions;
- Rust lockfile enforcement;
- workflow action-owner allowlist;
- rejection of `pull_request_target`;
- rejection of `permissions: write-all`;
- rejection of mutable `@main` / `@master` action refs;
- rejection of network-to-shell patterns;
- write permissions reserved for the dedicated release workflow.

The policy is enforced by `scripts/release/verify-supply-chain.py`.

## N.6 — SBOM and provenance

CI generates a CycloneDX 1.5 SBOM from locked Cargo metadata.

Release artifacts also receive:

- SHA-256 checksums;
- local in-toto/SLSA-compatible provenance statement;
- GitHub artifact build-provenance attestation using OIDC.

The local provenance file supplements, but does not replace, GitHub's signed attestation.

## N.7 — Signed releases

`.github/workflows/release.yml` is the only workflow allowed release write permissions.

Release artifacts are built on Linux, macOS and Windows, collected with SHA-256 checksums and attested using GitHub's build-provenance attestation service before a GitHub Release is created.

RC tags use `v1.0.0-rc.N`. Stable uses `v1.0.0`.

## N.8 — Crash and retrace validation

Gradle retrace now uses a dedicated argument-vector builder. Shell interpolation is not used.

Tests cover:

- paths containing spaces;
- missing mappings;
- missing/invalid executable inputs;
- exact mapping + stacktrace ordering.

Release qualification runs the Gradle Plugin test suite.

## N.9 — Security review

The internal pre-release security review is recorded in:

- `release/security-review.json`
- `docs/PHASE-N-SECURITY-REVIEW.md`

No critical/high/blocking finding may remain open for RC qualification. External feedback remains a separate N.13 gate.

## N.10 — Performance review

The RC performance review reuses the Phase M budget engine and verifies deterministic performance/size budget logic.

Stable remains blocked until representative Android device measurements record:

- startup p50/p95;
- memory delta;
- final protected APK/AAB size delta.

This distinction prevents CI-host timings from being presented as Android runtime measurements.

## N.11 — Compatibility review

`release/compatibility-matrix.json` freezes the 1.0 candidate compatibility targets:

- Rust MSRV 1.81;
- Android minSdk 24;
- JDK 17;
- Gradle 9.7.0;
- Android Gradle Plugin 9.4.1;
- arm64-v8a and x86_64 native ABIs;
- APK, AAB, AAR and APKS;
- Linux, macOS and Windows desktop release targets.

## N.12 — 1.0 release candidate

The repository version is synchronized at `1.0.0-rc.1` for Rust, Gradle Plugin and Shield Studio.

RC qualification requires N.1–N.11 plus all inherited Phase M/L/K and repository CI regressions.

## N.13 — External feedback

External feedback is not fabricated or inferred from internal CI.

The project provides:

- a dedicated GitHub issue form;
- `docs/RC-FEEDBACK.md`;
- `release/feedback-status.json`;
- a minimum-external-reviewer policy.

The stable gate remains closed while external reviewer count is below policy or blocking feedback remains open.

## N.14 — 1.0 stable

Stable release is intentionally unavailable until all of the following are true:

- RC is published and tested;
- external feedback requirement is satisfied;
- no blocking feedback remains;
- representative device performance evidence is complete;
- source version is updated from `1.0.0-rc.N` to `1.0.0`;
- the complete release qualification workflow is green.

The release workflow fails closed if a `v1.0.0` tag is attempted before these conditions are met.
