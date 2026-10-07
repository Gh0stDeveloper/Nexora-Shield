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

## L.11 — Nexora Shield design system & visual identity

Shield Studio uses a dedicated dark product theme instead of raw Material defaults. The design system defines brand colors, typography, elevated/muted surfaces, borders, semantic success/warning/error tones, reusable panels, metric cards, status pills, empty states and a dedicated console surface.

Iconography is consistent and functional. Navigation and primary actions pair icons with explicit text where space allows.

## L.12 — Dashboard & information architecture

Studio opens on a dashboard rather than a raw project form. The dashboard exposes:

- active protection profile;
- module, selector and artifact counts;
- release-readiness indicators;
- current project paths;
- contextual quick actions.

Navigation is grouped by Workspace, Policy, Operations and Security so users do not need to understand the internal implementation architecture before operating the tool.

## L.13 — End-user workflow UX

Each screen uses a consistent page-header → status → task-panel hierarchy. Primary operations are promoted into contextual action areas; secondary actions remain outlined. Empty states explain what is missing and what the user should do next.

Build and Retrace output are visually isolated in a console surface, while long paths and hashes remain selectable.

## L.14 — Responsive desktop & accessibility

The window has an explicit minimum usable viewport. Navigation collapses to icon-only mode at a tested breakpoint while the content layout uses a separate compact breakpoint.

The UX policy is centralized and unit tested. Navigation icons expose descriptions, headings use semantic heading metadata, status is always conveyed by text/icon in addition to color, and native controls retain keyboard focus behavior.

## L.15 — Final polish & distribution presentation

Native project/file dialogs have task-specific titles and filters. Product branding, window sizing, installer metadata and platform distribution targets remain consistent across Windows MSI, macOS DMG and Debian DEB builds.

The final polish must not weaken any existing Phase L security boundary.

## UX polish acceptance requirement

L.11–L.15 are complete only when:

1. the branded Compose desktop shell compiles;
2. Studio service tests and UX policy tests pass;
3. the UI remains usable at the declared minimum viewport;
4. compact navigation/content breakpoints are deterministic;
5. success/error/working feedback is semantic and text-backed;
6. no raw secret-value input is introduced;
7. Phase K regression remains green;
8. repository CI remains green.

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

**COMPLETED — L.1–L.15**

All Phase L core and UX polish closure requirements were satisfied on the validated implementation head:

- Compose Multiplatform desktop compilation passed;
- project import, configuration round-trip, selectors, reports and performance-budget services are covered by tests;
- Gradle, artifact verification and Retrace use explicit argument vectors rather than shell interpolation;
- APK/AAB/AAR/APKS routing and unsupported-artifact rejection are tested;
- secret-provider handling exposes references/status only and never renders raw secret material;
- Phase L run #35 (`37601597136`) passed Compose compilation and all Studio service/UX policy tests;
- Phase K regression run #50 (`37601597546`) passed;
- CI run #929 (`37601597217`) passed all 24 jobs with zero failures.

Validated implementation head: `6e5ed0ba67dc73bf56c36f47cac758106aa6a43d`.

Phase L is formally complete through L.15. The next roadmap phase is **Phase M — Security Lab**.
