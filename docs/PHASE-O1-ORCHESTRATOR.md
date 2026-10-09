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
- `nexora-shield protect` now executes only the production entry point and refuses incomplete builds. A distinct `package-apk` operation preserves explicitly requested Phase A packaging for tests. The production Gradle Plugin also defaults to the fail-closed command; Studio preflight can inspect the same contract, but full production execution remains unavailable.
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

Historical limit (first pass, now superseded by the sixth pass): the reader originally accepted only ZIP STORE DEX. The current preflight and unsigned staging also support bounded ZIP DEFLATE DEX decoding; see below. Production transformations and Android runtime evidence remain required.

The Phase O workflow now checks representative *synthetic* two-DEX APKs, malformed DEX, valid/invalid deflated DEX and cross-DEX duplicate classes. Synthetic APK fixtures are not Android emulator/device installation evidence.

Historical Phase A compatibility now requires explicitly calling `package-apk`. Production `protect` never reports a packaging-only artifact as protected. The executed production orchestrator and final-output evidence remain incomplete, so P0.1 stays open.

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

## Fourth engineering pass — transaction isolation, truthful readiness and Studio routing

- ZIP32 reconstruction now **exclusively creates** its destination. It refuses
  preexisting files and symlinks and removes partial output following write
  failures. Guard/file declaration order ensures cleanup also works on Windows.
- The staging API rejects normalized source/output aliases, including
  `./`, `../` and symlinked parent directory forms. Regression tests cover
  existing output preservation, symlink targets, missing replacements and
  staged-path collisions.
- Required-stage readiness no longer excludes operations merely because they
  were `ReadOnlyPlanning`: **every required stage must be
  `ProductionIntegrated`**, and the executor still independently refuses
  release until it has implemented real artifact publication.
- `DiagnosticOnly` describes DEX validation, compatibility, selectors,
  rewriting, rebuild and ZIP verification. It explicitly does **not** mean
  embedded application protection. Production stages such as RASP, native/VM,
  data protection and integrity remain `NotIntegrated`.
- Studio now invokes `protect --plan-only` from its build console using
  the configured profile. This is a diagnostic that creates no APK. Studio
  public-report views also distinguish Phase A packaging-only results from
  actual production-protection claims.
- Phase O CI covers three resolved profile matrices, ZIP CRC corruption,
  source/output aliases, no-output/no-report production failure, staged DEX
  validation and Studio JVM tests.

### Why the release remains blocked

No production artifact may be claimed until the app-facing runtime loader,
method/data transforms, RASP, Integrity Graph, native/VM execution, diversity,
optional attestation binding and Android final signature/install tests are
wired and verified together. A passing diagnostic ZIP test or Compose desktop
test does not satisfy these product-level requirements.

## Fifth hardening pass — raw payload equivalence proof

The ZIP normalizer and the O.1 unsigned staging validator now check the **exact
compressed payload bytes** for all untouched entries in fixed 64 KiB chunks.
Prior checks compared only CRC-32, uncompressed size and compression method,
which cannot establish payload identity under a CRC collision or forged central
directory metadata. The stronger check applies to stored and DEFLATE copied
entries without decompressing them. A regression test mutates an entry's bytes
while deliberately leaving its central-directory CRC and size unchanged.

This improvement does **not** mean DEFLATE-compressed `classes*.dex` can be
decoded or rewritten; preflight still rejects compressed DEX. It also does not
substitute for a runtime-capable B–I executor, signing or Android device
evidence. O.1 remains **OPEN** and `v1.0.0` remains **NO-GO**.

## Sixth hardening pass — bounded ZIP DEFLATE DEX decoding

The preflight and unsigned diagnostic DEX staging now decode canonical DEX
entries stored using ZIP method 0 (STORE) **or method 8 (raw DEFLATE)** through
the maintained pure-Rust `miniz_oxide` inflater. Each read enforces declared
uncompressed size, a maximum compressed-input budget, the per-DEX/aggregate
decoded budgets and CRC-32 verification; corrupt DEFLATE and oversized metadata
are rejected. Diagnostic rewrites convert replaced DEX entries to STORE while
preserving other APK payloads byte-for-byte.

Synthetic tests exercise valid compressed DEX, corrupt DEFLATE, an over-limit
declared size, the rebuilt DEX bytes and preservation of the manifest. These
are not installable Android app tests. DEFLATE support is a necessary staging
feature, **not** evidence of B–I protection, signing, runtime injection or an
approved stable release. O.1 remains **OPEN**; final production executor and
runtime installation proof are still required.

## Subphase O.1.1 — Frozen request policy and collision-proof planning

The production request now resolves `EffectiveProductionPolicy` before APK
parsing, transformations, report writes, alignment or signing. The typed
`ProductionOverrides` set is explicit; duplicate CLI overrides are rejected.
All selected optional controls become **required**, not silently best-effort.
A request attempting to disable a profile-mandatory control is rejected before
opening the input APK.

Current minimum mandatory set:
- Standard: integrity graph plus the core inspect/configure/DEX/rebuild/verify/evidence stages.
- Hardened: adds data protection, per-build diversity and RASP runtime.
- Maximum: adds Native Shield and VM Shield to the hardened requirements.
- Optional native/VM/attestation/data/diversity/RASP controls are promoted to
  mandatory if explicitly enabled; required controls never accept disable.

`protect --plan-only --enable-control vm-shield` prints the immutable
effective selections and mandatory-stage graph. Both production entry points
use the same resolver. `package-apk` refuses production-control overrides.
No new output is created by policy planning; the incomplete production
executor continues to fail closed.

Filesystem planning also rejects clobber aliases involving source, output,
reports, signing keystore and explicitly supplied Build Tools. This includes
canonicalized paths and Unix hardlinks, along with directory destinations.
Configured signing is validated for usable v2/v3 policy, supported minSdk and
non-secret keystore/password-reference availability.

**Scope boundary:** The canonical YAML schema and `examples/nexora-shield.yml`
are not yet bound to the Rust planner. File-backed YAML parsing, versioned
migration, budget and behavioral policy enforcement remain tracked for O.5.
This subphase establishes the **typed request-to-effective-policy contract**,
not a claim of implemented runtime protections or complete YAML support.

## O.1.3 — compiled Android resource table inspection (read-only)

Added a bounded `resources.arsc` structural analyzer alongside the binary
XML inspector. The diagnostic APK compatibility gate now decodes the global
string pool and package type/key pools, verifies package/type-spec/type chunk
boundaries, validates ordinary/sparse/16-bit entry offset tables, verifies
typed string indices, and rejects malformed or unsupported resource layouts.
Any compiled resource string matching a proposed renamed DEX symbol blocks the
rename **before** unsigned APK staging. No-change resource tables are copied
byte-for-byte; fixture tests verify the exact original payload survives.

This is **NOT** a resource-table linker, serializer or a remapper: resource IDs,
string indices, references and compiled XML are never modified. Unknown ARSC
package extensions currently **fail closed** under class/name renaming; they
are not evidence of malicious input. Testing uses synthetic ZIP fixtures, not
real installable Android apps. Class names referenced indirectly, including
runtime reflection/JNI, remain guarded or unsupported. A successful structure
scan must not be described as a complete Android compatibility contract.

**Pending in O.1.3:** atomic Binary XML + ARSC rewriting with identifier
stability, certified JNI coupling, real-device Android install/launch tests,
and final integrated production stages. The PR stays open, `main` remains
unchanged, O.1 stays OPEN, and stable `v1.0.0` stays NO-GO.
