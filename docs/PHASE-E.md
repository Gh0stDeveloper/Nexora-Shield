# Phase E — RASP

## Objective

Phase E adds a portable Runtime Application Self-Protection evidence layer on top of the integrity primitives delivered in Phase D.

The design is evidence-first. Platform-specific adapters observe runtime state and submit normalized observations. The portable Rust core converts those observations into deterministic, auditable signals. Response policy and risk correlation are intentionally separate so a single detector cannot become a fragile central kill switch.

## Part 1 scope — E.1 to E.4

### E.1 — Signal API

Implemented in `nexora-shield-rasp::signal`.

Properties:

- typed categories, sources, severity and evidence strength;
- structured evidence details;
- deterministic duplicate suppression;
- category and maximum-severity summaries;
- no destructive action or process termination in the signal layer.

### E.2 — Debug evidence

`DebugEvaluator` consumes normalized debug observations:

- application debuggable state;
- debugger-connected state;
- wait-for-debugger state;
- JDWP transport evidence;
- non-zero tracer PID evidence.

A debuggable application flag is informational by itself. Stronger observations are emitted independently so later policy can correlate evidence instead of treating one weak signal as definitive.

### E.3 — Instrumentation evidence

`InstrumentationEvaluator` models independent runtime instrumentation evidence:

- runtime agent presence;
- instrumentation bridge presence;
- unexpected class-loader evidence;
- protected method-dispatch changes;
- runtime agent count.

### E.4 — Hook / injection evidence

`HookInjectionEvaluator` models:

- inline-hook evidence;
- imported-function target redirection;
- writable+executable mappings;
- protected code-page digest mismatch;
- unexpected injected-library count.

The portable core does not perform privileged scanning. Android/native collectors are adapters; the core validates and correlates their normalized observations. Native collection/hardening is expanded in Phase F.

## Security boundary

RASP signals are evidence, not proof that client-side software is impossible to bypass. The system raises attack cost through multiple independent signals, later risk fusion, policy compilation and per-build diversity.

## Remaining Phase E work

E.5–E.12 remain open after this part:

- modified-system evidence;
- emulator evidence;
- integrity evidence fusion;
- risk engine;
- policy compiler;
- responses;
- report-only mode;
- false-positive lab.
