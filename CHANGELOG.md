# Changelog

All notable changes to Nexora Shield are documented here.

## [1.0.0] — Stable

### Production qualification

- API and config schema 1 frozen for the 1.0 contract;
- migration tooling validated for JSON and Shield Studio YAML;
- supply-chain policy, CODEOWNERS and dependency automation enforced;
- CycloneDX SBOM, checksums and provenance pipeline enabled;
- release artifacts prepared for Linux, macOS and Windows;
- crash/retrace regression coverage completed;
- internal security and compatibility reviews completed;
- N.10 representative Android performance gate completed on Android 15 / API 35 x86_64 ATD;
- N.13 independent GitHub CodeQL assessment completed;
- Rust 1.81 MSRV and inherited Phase M/K/L regressions validated.

### Protection platform

- APK/AAB/AAR/APKS protection and verification pipeline;
- DEX analysis/rewrite engine;
- protected data containers;
- integrity graph and anti-tamper controls;
- RASP and risk-policy engine;
- Native Shield;
- VM Shield;
- per-build diversification;
- optional attestation/remote policy;
- Gradle Plugin;
- Shield Studio desktop UX;
- Security Lab regression corpus.

### Publication

The source is promoted to `1.0.0`. Stable publication is permitted only after the final N.14 qualification workflow is green on the release commit and the `v1.0.0` tag is created from validated `main`.

## [1.0.0-rc.1] — Release candidate

The RC qualification line is retained as the pre-stable evidence baseline. Phase N #54 (run `37686651703`) passed all release-qualification jobs before the source was promoted to stable.
