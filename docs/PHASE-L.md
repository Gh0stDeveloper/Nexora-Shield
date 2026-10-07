# Phase L — Shield Studio

## Objective

Shield Studio is the desktop UX layer for Nexora Shield. It does not replace the CLI or Gradle plugin and does not introduce a second protection engine. Every build, verification and retrace action is delegated to the existing authoritative tooling.

The Studio is implemented as a standalone Compose Multiplatform desktop application under `studio/`.

## Architecture

The Studio is split into three boundaries:

1. **UI state** — Compose screens and user-editable non-secret configuration.
2. **Document/services** — project import, YAML configuration round-tripping, report loading, budget evaluation and secret-reference inspection.
3. **Authoritative tools** — direct child-process invocation of `nexora-shield`, Gradle and Retrace.

No action is executed through a shell command string. Arguments are passed as a vector to `ProcessBuilder`.

## L.1 — Compose Multiplatform shell

The desktop target provides a single-window shell with dedicated sections for project configuration, selectors, reports, budgets, build execution, artifact verification, retrace and secret-provider status.

Kotlin and Compose versions are pinned in `studio/build.gradle.kts`. Native distribution metadata is defined for macOS, Windows and Debian-compatible Linux.

## L.2 — Project import

Project import:

- resolves the selected root through `toRealPath()`;
- does not follow symbolic links during traversal;
- limits traversal depth and collected entries;
- detects Gradle settings/modules;
- discovers existing `nexora-shield.yml` / `nexora-shield.yaml`;
- finds recent Android artifacts, public reports and mapping files.

Import never executes Gradle scripts.

## L.3 — Profile editor

Studio edits:

- schema version 1;
- application id;
- minSdk;
- standard/hardened/maximum profile.

The YAML codec preserves unknown sections so advanced configuration authored outside Studio is not silently discarded. Writes are atomic through a temporary sibling file.

## L.4 — Selector editor

Named selector groups expose include/exclude patterns. Blank entries and duplicates are normalized before persistence.

## L.5 — Security report

Only the public build-report contract is displayed. Studio parses a bounded JSON file and exposes build id, profile, input/output hashes and sizes, signing/alignment state, DEX count and pipeline stages.

Private `.nshield` metadata is intentionally not rendered.

## L.6 — Performance budget UI

Studio edits the schema-supported budgets:

- APK growth;
- startup P50/P95;
- memory;
- VM method count;
- build time;
- fail/warn/adaptive policy.

When a public report is loaded, output growth is measured against the configured APK growth budget.

## L.7 — Build console

The build console supports:

- Gradle task execution inside the imported project;
- Nexora Shield CLI version/smoke invocation;
- bounded output capture;
- cancellation-safe coroutine execution.

Studio does not concatenate shell commands and does not echo inherited environment values.

## L.8 — Artifact verification

Verification routes by artifact format:

- APK → `verify`;
- AAB → `aab-verify`;
- AAR → `aar-verify`;
- APKS → `apks-verify`.

Unsupported extensions fail closed before process execution.

## L.9 — Mapping/retrace UI

Retrace accepts explicit mapping and stacktrace files, invokes Retrace directly and displays only command output. It does not copy mappings into public locations.

## L.10 — Secure secret-provider integration

Studio manages references, not secret values.

Supported local availability checks:

- `env:NAME`;
- `file:path`.

References delegated to CI, file-descriptor, OS-keychain or external-KMS providers are represented as external and never resolved by Studio.

The UI intentionally contains no raw-secret text field.

## Closure requirement

Phase L is complete only when:

1. Studio compiles on the pinned desktop toolchain;
2. project import is covered by tests;
3. config editing round-trips without losing unrelated sections;
4. selectors and budgets persist correctly;
5. public reports are parsed safely;
6. process execution never relies on shell interpolation;
7. artifact verification routing is tested;
8. secret values are never exposed by the model/UI;
9. repository CI remains green.

## Closure status

**COMPLETED**

All Phase L closure requirements were satisfied on the validated implementation head:

- Compose Multiplatform desktop compilation passed;
- project import, configuration round-trip, selectors, reports and performance-budget services are covered by tests;
- Gradle, artifact verification and Retrace use explicit argument vectors rather than shell interpolation;
- APK/AAB/AAR/APKS routing and unsupported-artifact rejection are tested;
- secret-provider handling exposes references/status only and never renders raw secret material;
- Phase L run #20 (`37591941642`), CI run #891 (`37591941514`) and Phase K regression #36 (`37591941555`) all passed.

Validated implementation head: `7e9d149e72885263b183f71e907d3ef6482a4e4a`.

The next roadmap phase is **Phase M — Security Lab**.
