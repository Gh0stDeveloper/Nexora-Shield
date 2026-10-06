# ADR 0003 — Defense in depth and per-build diversity

- Status: Accepted
- Date: 2026-10-06
- Owners: Gh0stDeveloper

## Context

Android executes on a device that may be controlled by an adversary. A fixed anti-tamper check, fixed VM opcode map or fixed obfuscation recipe becomes a reusable bypass target.

## Decision

Nexora Shield must combine independent layers and support controlled per-build diversity.

No layer may be documented or implemented as an absolute trust anchor on a hostile device.

Diversity must be reproducible only when private build material is supplied explicitly.

## Security consequences

A bypass against one layer or build should not automatically neutralize the rest. Security regression tests must measure bypass portability across builds.

Diversity is not a replacement for sound cryptography or backend authorization.

## Compatibility consequences

Build outputs are intentionally not byte-identical by default. Crash retrace and analysis require the correct private build manifest.

## Alternatives considered

### Fixed deterministic protector

Rejected because it enables cheap signature-based tooling against every protected build.

### Random transformations with no reproducibility

Rejected because production incidents would be difficult to diagnose.

## Follow-up

Phase H implements and benchmarks concrete diversity mechanisms.
