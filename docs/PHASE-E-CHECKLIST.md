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
- [x] Bootloader-state evidence
- [x] Verified-boot evidence
- [x] SELinux-state evidence
- [x] Writable-system evidence
- [x] Root-management artifact evidence
- [x] Privileged-binary artifact evidence
- [x] Clean-observation test

## E.6 Emulator evidence
- [x] Generic-build weak evidence
- [x] Emulator device-profile evidence
- [x] QEMU transport evidence
- [x] Hypervisor artifact evidence
- [x] Sparse-sensor weak evidence
- [x] Missing-telephony weak evidence
- [x] Weak/strong separation tests
- [x] Clean-observation test

## E.7 Integrity evidence fusion
- [x] Phase D verdict adapter
- [x] Clean-verdict path
- [x] Independent failure preservation
- [x] Severity translation
- [x] Missing-evidence handling
- [x] Integrity source attribution
- [x] No digest leakage into RASP details

## E.8 Risk Engine
- [x] Deterministic weighted scoring
- [x] Risk levels
- [x] Cross-category correlation
- [x] Critical definitive floor
- [x] Weak-evidence escalation cap
- [x] Moderate-evidence escalation cap
- [x] Auditable risk reasons
- [x] Empty/weak/strong/critical tests

## E.9 Policy compiler
- [x] Typed policy specification
- [x] Strict threshold validation
- [x] Complete response mapping validation
- [x] Monotonic response enforcement
- [x] Fail-closed missing-response behavior
- [x] Strict JSON schema surface
- [x] Invalid-policy tests

## E.10 Responses
- [x] Continue response
- [x] Report response
- [x] Require-reverification response
- [x] Deny-sensitive-operation response
- [x] No destructive process-control action
- [x] Deterministic decision record
- [x] Policy-to-response integration test

## E.11 Report-only mode
- [ ] Pending

## E.12 False-positive lab
- [ ] Pending

## Closure state

Phase E is **IN PROGRESS**. E.1–E.10 are implemented. E.1–E.7 were closed by CI #304. The phase must not be marked complete until E.11–E.12, full CI, documentation and the final false-positive acceptance gate are complete.
