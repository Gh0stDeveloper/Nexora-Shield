# Phase 0 — Foundation checklist

This file maps every Phase 0 roadmap item to repository evidence.

## 0.1 Vision — DONE

Evidence:

- `README.md`
- explicit goals, non-goals and security principles;
- protection profiles and project scope.

## 0.2 Threat Model — DONE

Evidence:

- `docs/THREAT-MODEL.md`;
- adversaries T0–T5;
- assets;
- trust boundaries;
- threats;
- invariants;
- non-goals.

## 0.3 Architecture — DONE

Evidence:

- `docs/ARCHITECTURE.md`;
- module boundaries;
- transactional pipeline;
- DEX IR direction;
- runtime;
- artifact separation;
- compatibility model.

## 0.4 Configuration Spec — DONE

Evidence:

- `docs/CONFIGURATION.md`;
- `schemas/nexora-shield.schema.json`;
- `examples/nexora-shield.yml`;
- schema version 1;
- profiles;
- selectors;
- budgets and secret references.

## 0.5 Security Design — DONE

Evidence:

- `docs/SECURITY-DESIGN.md`;
- integrity graph;
- RASP evidence model;
- risk engine;
- Native/VM Shield direction;
- per-build diversity;
- secret-handling rules.

## 0.6 Test Strategy — DONE

Evidence:

- `docs/TESTING.md`;
- correctness, compatibility, performance and adversarial testing;
- fuzzing;
- golden apps;
- Android matrix;
- release/security gates.

## 0.7 Repository Structure — DONE

Evidence:

- Cargo workspace;
- `crates/shield-core`;
- `crates/shield-cli`;
- `docs/REPOSITORY-CONVENTIONS.md`;
- `.editorconfig`;
- `.gitignore`;
- `CONTRIBUTING.md`;
- `CODEOWNERS`;
- locked dependency graph.

The workspace intentionally creates only crates with Phase 0 code. Planned crates are introduced in their corresponding phases.

## 0.8 CI Baseline — DONE when latest workflow is green

Evidence:

- `.github/workflows/ci.yml`;
- Rust formatting gate;
- Clippy with warnings denied;
- workspace tests;
- rustdoc warnings denied;
- CLI smoke test;
- JSON schema syntax validation;
- RustSec dependency audit;
- Dependabot configuration.

## 0.9 ADR Baseline — DONE

Evidence:

- `docs/adr/README.md`;
- ADR 0001: Rust core + Kotlin integrations;
- ADR 0002: versioned declarative configuration;
- ADR 0003: defense in depth + per-build diversity;
- ADR 0004: public/private artifact separation;
- ADR 0005: standard cryptography only.

## 0.10 Security Policy — DONE

Evidence:

- `SECURITY.md`;
- vulnerability scope;
- severity;
- reporting requirements;
- safe-research boundary;
- security promise policy.

## Exit criteria

- [x] coherent architecture/security/config/test documentation;
- [x] initial compilable Rust workspace created;
- [x] automated format/lint/test/doc/audit pipeline defined;
- [x] security disclosure policy established;
- [x] ADR process established;
- [ ] latest CI execution verified green.

Phase 0 becomes fully CLOSED only after the CI checkbox above is backed by a successful GitHub Actions run on the Phase 0 branch.
