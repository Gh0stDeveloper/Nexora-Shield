# Phase L — Shield Studio checklist

## L.1 Compose Multiplatform shell
- [x] Standalone Compose Multiplatform desktop project
- [x] Structured navigation for all Studio capabilities
- [x] Dark professional desktop shell
- [x] JVM 17 toolchain target
- [x] Final compile/test gate

## L.2 Project import
- [x] Safe directory import
- [x] Gradle Android project discovery
- [x] Existing Nexora Shield configuration discovery
- [x] Artifact/report/mapping discovery
- [x] Bounded project traversal
- [x] Final project-import tests

## L.3 Profile editor
- [x] standard/hardened/maximum profile editing
- [x] application id and minSdk editing
- [x] schema-aware configuration load/save
- [x] unknown configuration sections preserved
- [x] validation before write
- [x] Final configuration round-trip tests

## L.4 Selector editor
- [x] Named selector groups
- [x] include patterns
- [x] exclude patterns
- [x] duplicate/blank normalization
- [x] persisted YAML representation
- [x] Final selector tests

## L.5 Security report
- [x] Public report loader
- [x] build/profile/hash/signing summary
- [x] pipeline-stage presentation
- [x] malformed/private report rejection boundary
- [x] Final report parsing tests

## L.6 Performance budget UI
- [x] APK growth budget
- [x] startup P50/P95 budgets
- [x] memory budget
- [x] VM-method budget
- [x] build-time budget
- [x] fail/warn/adaptive policy selection
- [x] measured APK growth evaluation
- [x] Final budget tests

## L.7 Build console
- [x] Direct ProcessBuilder execution without shell interpolation
- [x] bounded captured output
- [x] Gradle task execution
- [x] Nexora Shield CLI smoke execution
- [x] asynchronous UI execution
- [x] Final command runner tests

## L.8 Artifact verification
- [x] APK verification
- [x] AAB verification
- [x] AAR verification
- [x] APK Set verification
- [x] unsupported artifact rejection
- [x] Final verification-routing tests

## L.9 Mapping/retrace UI
- [x] mapping.txt selection
- [x] stacktrace selection
- [x] direct retrace execution
- [x] retraced output viewer
- [x] Final retrace routing tests

## L.10 Secure secret-provider integration
- [x] environment references
- [x] file references
- [x] external-provider status
- [x] secret values never rendered
- [x] raw secret entry intentionally absent
- [x] Final secret-reference tests

## Closure state

Phase L is **COMPLETED**. L.1–L.10 are implemented and their acceptance gates passed on the validated implementation head.

Validated by GitHub Actions:
- Phase L run #18 (`37591538497`): **success**
- CI run #889 (`37591538479`): **success**
- Phase K regression run #35 (`37591538494`): **success**

The validated implementation head is `cae761c471deb8284c111927380ca9b4b55b5b1f`.
