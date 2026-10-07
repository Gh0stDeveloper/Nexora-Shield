# Nexora Shield Studio

Desktop control surface for Nexora Shield.

Studio is a UX layer over the existing CLI, Gradle plugin and Retrace tooling. It does not implement an independent protection engine.

## Product UX

Shield Studio is designed as an end-user security product rather than a build-tool demo.

The desktop experience includes:

- a Nexora Shield design system with dedicated colors, typography and surface hierarchy;
- a dashboard with protection readiness, project metrics and contextual quick actions;
- grouped navigation for Workspace, Policy, Operations and Security;
- responsive compact navigation for narrower desktop windows;
- semantic success, warning, working and error states that never rely on color alone;
- guided empty states instead of blank technical screens;
- dedicated console presentation for Gradle, verifier and Retrace output;
- reference-only secret-provider UI with no raw-secret editor.

The minimum supported Studio viewport is 980x680. Windows wider than the defined navigation breakpoint use the full labeled sidebar; narrower windows use a compact icon-based layout.


## Development

Requirements:

- JDK 17+
- Gradle 9.7+
- `nexora-shield` available on PATH or configured in Studio

Run:

```bash
gradle -p studio run
```

Tests:

```bash
gradle -p studio desktopTest
```

Compile:

```bash
gradle -p studio compileKotlinDesktop
```

## Security boundary

Studio persists references to secrets, never resolved secret values. Environment/file references are checked for availability without rendering their contents. External CI/KMS/keychain references remain opaque.
