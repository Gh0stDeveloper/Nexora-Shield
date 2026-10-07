# Nexora Shield 1.0 API stability

The 1.0 candidate public contract is machine-readable in `../release/api-surface-v1.json`.

## Frozen for 1.0

The following are compatibility-sensitive:

- configuration schema 1;
- Gradle plugin id `dev.nexora.shield`;
- minimum Android SDK 24;
- CLI commands listed by the API contract;
- profiles `standard`, `hardened`, `maximum`;
- artifact families APK, AAB, AAR and APKS.

## Compatibility rule

Patch releases must not remove or silently reinterpret a frozen 1.0 surface.

New optional behavior may be added when existing valid configuration remains valid and behavior is backwards-compatible.

Breaking changes require a new contract/schema/version with documented migration.

## Configuration schema

`nexora-shield.schema.v1.json` is immutable for the 1.0 line. Do not edit schema 1 to represent a breaking semantic change. Create schema 2 and a tested migration instead.

## CLI

Existing stable commands may gain optional flags. Existing flags must retain their meaning for the 1.0 line unless a security issue requires fail-closed behavior; such changes require release notes.

## Gradle Plugin and Studio

The Gradle Plugin and Shield Studio are clients of the same protection engine. They do not define alternative security semantics. Public configuration written by Studio must remain schema-compatible with the CLI/Gradle contract.
