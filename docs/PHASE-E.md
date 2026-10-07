# Phase E — RASP

## Objective

Phase E adds a portable Runtime Application Self-Protection evidence layer on top of the integrity primitives delivered in Phase D.

The design is evidence-first. Platform-specific adapters observe runtime state and submit normalized observations. The portable Rust core converts those observations into deterministic, auditable signals. Response policy and risk correlation are intentionally separate so a single detector cannot become a fragile central kill switch.

## Implemented scope — E.1 to E.7

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

### E.5 — Modified-system evidence

`ModifiedSystemEvaluator` consumes normalized platform evidence for:

- unlocked bootloader state;
- verified-boot state outside the expected green state;
- permissive SELinux state;
- writable protected system partitions;
- root-management artifacts;
- unexpected privileged-binary artifacts.

Signals are independent. An unlocked bootloader or artifact count is not treated as conclusive compromise by itself.

### E.6 — Emulator evidence

`EmulatorEvaluator` distinguishes weak environmental hints from stronger virtualization evidence:

- generic build profile;
- emulator-like device profile;
- QEMU transport evidence;
- hypervisor artifacts;
- sparse sensor profile;
- missing telephony characteristics.

Generic, sensor and telephony hints intentionally remain low-severity/weak evidence. Later risk policy must correlate them instead of blocking legitimate devices on a single heuristic.

### E.7 — Integrity evidence fusion

`IntegritySignalFusion` converts Phase D `IntegrityVerdict` failures into the common RASP signal model.

Properties:

- clean integrity verdicts emit no suspicious RASP signal;
- each integrity failure remains independently addressable;
- missing evidence is strong rather than falsely represented as an observed digest mismatch;
- cryptographic/content mismatches are represented as definitive evidence;
- failure category and node label are retained for audit;
- expected and observed digest material is not copied into RASP signal details.

This keeps Phase D as the source of truth for integrity while allowing E.8 Risk Engine to correlate integrity failures with runtime evidence.

## Security boundary

RASP signals are evidence, not proof that client-side software is impossible to bypass. The system raises attack cost through multiple independent signals, later risk fusion, policy compilation and per-build diversity.

## Remaining Phase E work

E.8–E.12 remain open:

- risk engine;
- policy compiler;
- responses;
- report-only mode;
- false-positive lab.
