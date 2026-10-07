# Phase L — Shield Studio checklist

## L.1 Compose Multiplatform shell
- [x] Standalone Compose Multiplatform desktop project
- [x] Structured navigation for all Studio capabilities
- [x] Dark professional desktop shell
- [x] JVM 17 toolchain target
- [ ] Final compile/test gate

## L.2 Project import
- [x] Safe directory import
- [x] Gradle Android project discovery
- [x] Existing Nexora Shield configuration discovery
- [x] Artifact/report/mapping discovery
- [x] Bounded project traversal
- [ ] Final project-import tests

## L.3 Profile editor
- [x] standard/hardened/maximum profile editing
- [x] application id and minSdk editing
- [x] schema-aware configuration load/save
- [x] unknown configuration sections preserved
- [x] validation before write
- [ ] Final configuration round-trip tests

## L.4 Selector editor
- [x] Named selector groups
- [x] include patterns
- [x] exclude patterns
- [x] duplicate/blank normalization
- [x] persisted YAML representation
- [ ] Final selector tests

## L.5 Security report
- [x] Public report loader
- [x] build/profile/hash/signing summary
- [x] pipeline-stage presentation
- [x] malformed/private report rejection boundary
- [ ] Final report parsing tests

## L.6 Performance budget UI
- [x] APK growth budget
- [x] startup P50/P95 budgets
- [x] memory budget
- [x] VM-method budget
- [x] build-time budget
- [x] fail/warn/adaptive policy selection
- [x] measured APK growth evaluation
- [ ] Final budget tests

## L.7 Build console
- [x] Direct ProcessBuilder execution without shell interpolation
- [x] bounded captured output
- [x] Gradle task execution
- [x] Nexora Shield CLI smoke execution
- [x] asynchronous UI execution
- [ ] Final command runner tests

## L.8 Artifact verification
- [x] APK verification
- [x] AAB verification
- [x] AAR verification
- [x] APK Set verification
- [x] unsupported artifact rejection
- [ ] Final verification-routing tests

## L.9 Mapping/retrace UI
- [x] mapping.txt selection
- [x] stacktrace selection
- [x] direct retrace execution
- [x] retraced output viewer
- [ ] Final retrace routing tests

## L.10 Secure secret-provider integration
- [x] environment references
- [x] file references
- [x] external-provider status
- [x] secret values never rendered
- [x] raw secret entry intentionally absent
- [ ] Final secret-reference tests

## Closure state

Phase L is **IN PROGRESS** until Studio compilation, service tests and the repository regression CI pass on the final branch head.
