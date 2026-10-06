# ADR 0002 — Versioned declarative configuration

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Protection behavior must be auditable and reproducible. Hidden defaults or ad-hoc CLI flags make security reviews difficult and cause configuration drift.

## Decision

The canonical protection configuration is declarative YAML validated against a versioned schema. Schema version 1 begins in Phase 0.

CLI flags may override non-secret operational values, but the resolved configuration must be represented in the BuildPlan.

Secrets are referenced by identifier and are never embedded directly in configuration.

## Security consequences

Versioned configuration makes security changes reviewable and prevents silent reinterpretation of old configuration.

Unknown top-level keys should fail validation once the corresponding subsystem schema is strict.

## Compatibility consequences

Breaking configuration changes require a schema-version increment and migration guidance.

## Alternatives considered

### CLI-only configuration

Rejected because it is difficult to review, reproduce and integrate consistently in Gradle/CI.

### Kotlin DSL as the only format

Rejected because standalone CLI and non-Gradle workflows need the same contract.

## Follow-up

Tighten currently open subsystem objects in the JSON Schema as their implementation phases begin.
