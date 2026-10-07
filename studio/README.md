# Nexora Shield Studio

Desktop control surface for Nexora Shield.

Studio is a UX layer over the existing CLI, Gradle plugin and Retrace tooling. It does not implement an independent protection engine.

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
