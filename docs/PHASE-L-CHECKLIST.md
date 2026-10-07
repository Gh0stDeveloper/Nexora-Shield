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

## L.11 Nexora Shield design system & visual identity
- [x] Dedicated dark product color system
- [x] Typography hierarchy
- [x] Branded surfaces and borders
- [x] Semantic success/warning/error states
- [x] Reusable panel/metric/status/empty-state components
- [x] Consistent product iconography
- [ ] Final Compose compile gate

## L.12 Dashboard & information architecture
- [x] Dashboard as default landing screen
- [x] Workspace/Policy/Operations/Security navigation groups
- [x] Project readiness summary
- [x] Protection/profile/module/artifact metrics
- [x] Contextual quick actions
- [ ] Final navigation compile gate

## L.13 End-user workflow UX
- [x] Consistent page hierarchy
- [x] Contextual primary/secondary actions
- [x] Guided empty states
- [x] Structured project/report/policy panels
- [x] Dedicated command/retrace console surface
- [x] Selectable hashes, paths and output
- [ ] Final workflow UI gate

## L.14 Responsive desktop & accessibility
- [x] Minimum viewport policy
- [x] Compact navigation breakpoint
- [x] Compact content breakpoint
- [x] Centralized UX policy
- [x] UX policy unit tests
- [x] Text/icon status in addition to color
- [x] Accessible navigation descriptions
- [ ] Final accessibility/responsive compile gate

## L.15 Final polish & distribution presentation
- [x] Branded application shell
- [x] Native task-specific file dialogs
- [x] Consistent Windows/macOS/Linux distribution metadata
- [x] No regression to secret handling boundaries
- [x] No regression to direct argument-vector execution
- [ ] Final Studio test gate
- [ ] Final Phase K regression gate
- [ ] Final repository CI gate

## Closure state

Phase L core L.1–L.10 is **COMPLETED**. UX polish L.11–L.15 is **IN VALIDATION** until its final Compose, Studio-test and regression gates pass.

Validated by GitHub Actions:
- Phase L run #20 (`37591941642`): **success**
- CI run #891 (`37591941514`): **success**
- Phase K regression run #36 (`37591941555`): **success**

The validated implementation head is `7e9d149e72885263b183f71e907d3ef6482a4e4a`.
