# Phase O.1 — Production Protection Orchestrator

Status: **IN PROGRESS — NOT PRODUCTION READY**. Stable `v1.0.0` remains **NO-GO**.

## Implemented in the first O.1 pass

- Ordered, typed 18-stage protection graph in `crates/shield-core/src/production.rs`.
- Read-only, typed `ProductionBuildContext` includes the input SHA-256, DEX count, resolved profile, output path and stage requirements.
- The planner rejects malformed/DEX-less APK inputs, same-file outputs, unapproved overwrites, unsigned-output ambiguity and conflicting report paths before producing a plan.
- Stage requirements are distinct from stage integration. `ReadOnlyPlanning` **does not** claim that a defense has executed.
- A mandatory-stage readiness check fails closed and lists missing production integrations.
- Unit tests enforce ordering, profile distinctions and refusal to report readiness when a required stage is not wired.

## Authoritative order

1. Input inspection
2. Request/configuration resolution
3. DEX parse/validate
4. Compatibility
5. Selector resolution
6. DEX transformation
7. Data protection
8. Native Shield (when selected or Maximum)
9. VM Shield (when selected or Maximum)
10. Per-build diversity
11. Integrity Graph
12. RASP runtime
13. Attestation (when selected)
14. Package rebuild
15. Alignment
16. Signing
17. Final artifact verification
18. Executed-stage evidence

The matrix is an initial implementation contract, not final profile policy. Phase O.5 must confirm defaults, explicit opt-ins, fallback semantics and budgets. A `WhenSelected` control must become mandatory whenever actually selected.

## Remaining production blockers

- DEX discovery/parse of real APK content, compatibility and selectors must be connected.
- DEX/data/resources, native, VM, integrity, RASP, diversity and attestation must be applied to the final package, not just standalone fixtures.
- Archive rebuild, signature, runtime smoke, rollback safety and evidence tied to final bytes are not integrated.
- `nexora-shield protect` still executes the historical Phase A packaging path. The Gradle Plugin and Studio are **not** yet connected to this new contract. These are critical P0 gaps.
- The source/input digest must be checked again immediately before execution to prevent a post-plan substitution (TOCTOU).
- Signed output verification and representative Android E2E tests remain pending.

**O.1 is NOT complete.** The checklist records only the stage graph and typed context as completed. No stable-release approval is implied.

## Second engineering pass — real DEX preflight

The read-only CLI option `protect ... --plan-only` now invokes the same typed production build context and inspects actual canonical DEX contents from the input APK. The core checks:

- the inspected input SHA-256 before and after DEX inspection;
- bounds of 64 MiB per DEX and 256 MiB combined decoded DEX sizes;
- canonical DEX sequencing with the established `MultiDexSet` parser and validator;
- duplicate class descriptors across DEX units;
- per-unit compatibility/reflection and JNI/native findings;
- default selector resolution and eligible classes/methods/fields;
- missing mandatory production stages, explicitly reported as **NotIntegrated**.

The option does not create an output APK or reports, does not sign, and reports `Production ready: false`. It is a preflight diagnostic, not an implementation of the complete `protect` production path.

Current limit: this first read-only reader supports **stored (ZIP method 0) DEX only**. A DEX stored in ZIP Deflate (method 8) is rejected, not silently excluded. Support for bounded decompression and production transformations is still required.

The Phase O workflow now checks representative *synthetic* two-DEX APKs, malformed DEX, deflated DEX and cross-DEX duplicate classes. Synthetic APK fixtures are not Android emulator/device installation evidence.

The existing packaging-only `protect` command remains unchanged for historical Phase A test compatibility and is **not an approved full-protection operation**. Until it is replaced with the executed orchestrator and final-output evidence, P0.1 remains open.

## Third engineering pass — executable DEX-only diagnostic staging

Added a deterministic ZIP32 repacker capable of replacing an explicit list of
stored DEX entries without changing the identities of other APK contents. The
new `ProductionBuildContext::stage_dex_rewrite` executes the existing
`MultiDexSet::rewrite` engine with real compatible renaming and source/debug
metadata reduction, then independently validates:

- the source SHA-256 snapshot and CRC-32 of original DEX entries;
- conservative multidex reflection behavior;
- non-empty DEX byte changes (no-op requests are rejected);
- the count of all resulting DEX entries;
- ZIP32 structure and entry inventory after reconstruction;
- CRC-32 and exact byte identity of transformed entries;
- identity of non-transformed entry CRC, uncompressed size and method;
- reparsing/revalidating every DEX from the rebuilt APK;
- removal of obsolete v1 signature entries.

This produces an **unsigned diagnostic staging APK only**. The test driver
`cargo run -p nexora-shield-core --example stage_dex -- <input> <new-staging>`
is a development/E2E harness and is NOT a production protection endpoint.
Synthetic golden DEX tests assert actual bytes changed and untouched manifest
bytes survived rebuilding.

### Critical P0.1 containment change

The user-facing `protect` command now calls `protect_production_apk`.
It checks the input and the mandatory 18-stage graph, and **rejects** production
requests when required stages remain missing. It never silently falls back
to Phase A normalization, nor does it publish a supposedly protected APK.
`protect --plan-only` continues to provide a no-output diagnostic view.

Historical CI and the Phase J sample use an **explicit** packaging-only
compatibility mode: `package-apk` in the CLI and
`nexoraShield.legacyPhaseAOnly.set(true)` in the *sample* Gradle build.
The Gradle Plugin's default is `legacyPhaseAOnly=false`, so a release build
cannot silently produce Phase A-only output under the full protection label.

The developer must consciously request Phase A packaging; neither this mode
nor the staging harness is an accepted production-protected artifact. The
Phase O gate verifies `protect` exits non-zero and produces no output.

### Still release blocking

The executed B–I pipeline needs end-to-end runtime binding, license/policy
verification, generated RASP/native/VM/integrity/data artifacts, selective
config, final signing, certificate-rooted runtime validation, trusted reports,
install/launch tests and cross-integration evidence. The current immutable
stage graph correctly advertises these as unintegrated.

**O.1 is NOT complete; the staged diagnostic does not close its outstanding
mandatory work. Phase O / stable remains NO-GO.**
