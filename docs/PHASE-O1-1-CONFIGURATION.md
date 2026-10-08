# Phase O.1.1 — Effective policy resolution and input safety

Status: **IMPLEMENTED ON FEATURE BRANCH — CI VERIFICATION REQUIRED**.

## Acceptance criteria

1. Effective policy computed from immutable `ProtectionProfile` plus typed
   `ProductionOverrides` before reading or writing APK artifacts.
2. Mandatory Standard/Hardened/Maximum controls cannot be disabled.
3. Selecting an optional control upgrades its stage to `Required` with
   `NotIntegrated` status until an actual executor provides final evidence.
4. Duplicate/contradictory flags fail explicitly (no silent last-wins).
5. Output, reports, keystore and explicit tool paths are checked for canonical
   collisions, Unix hardlink aliases and directory destinations.
6. Signing cannot be simultaneously requested and explicitly suppressed;
   production signing policy requires minSdk 24+ and v2/v3.
7. `--plan-only` never writes protected output or report artifacts; full
   `protect` remains blocked while mandatory B–I stages are absent.
8. CLI integration and focused core/E2E tests run in Phase O workflow,
   alongside Rust formatting, Clippy and workspace tests.

## Supported CLI syntax

```sh
nexora-shield protect app.apk --output app-protected.apk \
  --profile standard --unsigned --no-align --plan-only \
  --enable-control vm-shield --enable-control attestation
```

Control names: `data-protection`, `native-shield`, `vm-shield`,
`diversity`, `integrity-graph`, `rasp-runtime`, `attestation`.
`--disable-control` is available for optional controls only.

**No protected APK is produced while the production executor is incomplete.**
Avoid enabling `legacyPhaseAOnly` for production distributions.

## Deliberately outstanding (O.5)

The canonical declarative YAML schema does not yet feed this resolver.
Config-file parsing, schema-version migration, full selector/resource/crypto
settings, budget enforcement and user-level YAML/CLI override precedence
are separate O.5 acceptance gates. Do not claim YAML-configured full
protection based on these typed CLI selections.

The shipped declarative example has been updated to match the present v1
JSON Schema vocabulary; it remains **illustrative and non-executable** until
the O.5 YAML parser and schema-to-policy mapping are implemented. On Windows,
canonical path alias checks apply, but hardlink file-ID equivalence requires a
separate portable metadata integration; this is a recorded limitation rather
than a claimed cross-platform guarantee.
