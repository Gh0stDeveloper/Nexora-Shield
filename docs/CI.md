# Continuous Integration

## Purpose

CI is a security boundary for Nexora Shield. A failed quality/security gate must not be interpreted as a protected/releasable build.

## Phase 0 workflow

`.github/workflows/ci.yml` runs two jobs.

### Rust quality

- JSON schema syntax validation;
- `cargo fmt --check`;
- Clippy for all workspace targets/features with warnings denied;
- workspace tests;
- rustdoc with warnings denied;
- CLI metadata smoke tests.

### RustSec audit

The committed `Cargo.lock` is checked against the RustSec advisory database.

## Permissions

The workflow uses read-only repository contents permission. Additional write scopes must be introduced only for a concrete requirement and reviewed.

## Concurrency

Superseded runs on the same ref are cancelled to avoid wasting runner capacity.

## Branch policy target

Once repository settings are configured, `main` should require:

- pull request review as appropriate for the team size;
- successful CI;
- resolved conversations;
- no force pushes;
- no deletion.

Repository settings are administrative state and are not represented by source files alone.

## Security constraints

CI must never print:

- signing passwords;
- seeds;
- private mappings;
- decrypted protected content;
- production tokens.

Fork-originated PRs must not receive production secrets.

## Future gates

Later phases add:

- fuzz smoke tests;
- Android golden-app builds;
- APK/AAB validation;
- emulator/device smoke tests;
- adversarial regression;
- performance budgets;
- SBOM/provenance;
- release signature verification.

## Failure policy

A failed step is actionable. Security checks are not silently skipped to obtain a green badge. Temporary exceptions require a documented reason, owner and expiry.
