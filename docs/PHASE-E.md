# Phase E — RASP

## Objective

Phase E adds a portable Runtime Application Self-Protection evidence layer on top of the integrity primitives delivered in Phase D.

The design is evidence-first. Platform-specific adapters observe runtime state and submit normalized observations. The portable Rust core converts those observations into deterministic, auditable signals. Response policy and risk correlation are intentionally separate so a single detector cannot become a fragile central kill switch.

## Implemented scope — E.1 to E.12

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

### E.8 — Risk Engine

`RiskEngine` performs deterministic weighted correlation over the typed signal set.

The engine:

- assigns points from signal severity and evidence strength;
- adds a bounded cross-category correlation bonus only when strong evidence exists;
- elevates critical+definitive evidence directly to critical risk;
- caps weak-only evidence at observed risk;
- caps weak/moderate-only evidence at elevated risk;
- emits auditable reasons explaining how the final level was produced.

The default thresholds are intentionally separated from signal generation and can be validated by the policy compiler.

### E.9 — Policy compiler

`CompiledPolicy::compile` validates the complete RASP policy before it can be used.

It rejects:

- zero or non-increasing thresholds;
- missing responses for any risk level;
- policies whose response becomes less restrictive as risk rises.

The configuration schema now exposes a strict `rasp.thresholds` and `rasp.responses` surface with unknown fields rejected.

### E.10 — Responses

`ResponseEngine` converts a risk assessment into a deterministic response decision.

Supported responses are deliberately non-destructive:

- continue;
- report;
- require reverification;
- deny a sensitive operation.

The RASP core does not terminate processes, corrupt data, delete files or perform stealth/destructive countermeasures.

### E.11 — Report-only mode

`PolicyMode::ReportOnly` preserves the configured policy decision for audit while constraining the effective response to at most `report`.

That means:

- clean/observed flows remain unchanged;
- elevated/high/critical risk is still calculated normally;
- configured blocking responses remain visible in the decision record;
- the effective runtime action never exceeds `report`.

This allows teams to deploy RASP telemetry before enforcement without silently changing risk semantics.

### E.12 — False-positive lab

`FalsePositiveLab` runs deterministic acceptance cases against a compiled policy and verifies two independent ceilings:

- maximum acceptable risk level;
- maximum acceptable effective response.

The baseline matrix covers clean production, debuggable-only, weak emulator hints, unlocked-bootloader-only, root-artifact-only and QEMU-only profiles. A dedicated regression test also verifies that the lab fails when a case exceeds its declared ceiling.

This is a portable Phase E false-positive gate. Broader physical-device, modified-environment and performance matrices remain part of Phase M Security Lab.

## Security boundary

RASP signals are evidence, not proof that client-side software is impossible to bypass. The system raises attack cost through multiple independent signals, later risk fusion, policy compilation and per-build diversity.

## Closure state

E.1–E.12 are implemented. Final closure requires the complete GitHub Actions acceptance matrix to pass on the final branch head, including Rust quality, RustSec, Phase A–D regressions, Phase E tests and Rust 1.81 MSRV validation.
