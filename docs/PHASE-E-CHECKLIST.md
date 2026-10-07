# Phase E — RASP checklist

## E.1 Signal API
- [x] Typed signal category
- [x] Typed signal source
- [x] Severity and evidence strength
- [x] Structured details
- [x] Duplicate suppression
- [x] Deterministic summaries

## E.2 Debug evidence
- [x] Debuggable configuration evidence
- [x] Debugger connection evidence
- [x] Wait-for-debugger evidence
- [x] JDWP evidence
- [x] Tracer PID evidence
- [x] Clean-observation test

## E.3 Instrumentation evidence
- [x] Runtime-agent evidence
- [x] Instrumentation-bridge evidence
- [x] Unexpected class-loader evidence
- [x] Method-dispatch evidence
- [x] Agent-count evidence
- [x] Independent-cause tests

## E.4 Hook / injection evidence
- [x] Inline-hook evidence
- [x] Import-target redirection evidence
- [x] Writable+executable mapping evidence
- [x] Code-page mismatch evidence
- [x] Injected-library evidence
- [x] Independent-cause tests

## E.5 Modified-system evidence
- [ ] Pending

## E.6 Emulator evidence
- [ ] Pending

## E.7 Integrity evidence fusion
- [ ] Pending

## E.8 Risk Engine
- [ ] Pending

## E.9 Policy compiler
- [ ] Pending

## E.10 Responses
- [ ] Pending

## E.11 Report-only mode
- [ ] Pending

## E.12 False-positive lab
- [ ] Pending

## Closure state

Phase E is **IN PROGRESS**. Part 1 implements E.1–E.4 only. The phase must not be marked complete until E.5–E.12, full CI, documentation and the final false-positive acceptance gate are complete.
