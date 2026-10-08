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
