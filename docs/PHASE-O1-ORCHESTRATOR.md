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
