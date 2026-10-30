# O.1 execution audit and remaining production work

Status: **OPEN — O.1 NOT CLOSED; stable v1.0.0 NO-GO**.

The [delivered diversity/private reproduction increment](PHASE-O1-DIVERSITY-RUNTIME.md)
adds executing DEX/data/VM/native/graph variation to the eligible runtime path.
Its scope supersedes historical missing-diversity findings below; full production
closure remains outstanding.

The [raw asset runtime increment](PHASE-O1-ASSET-RUNTIME.md) supersedes the
missing raw-asset loader finding below for its explicitly eligible API-28+ path.

The [encrypted constant runtime increment](PHASE-O1-CONSTANT-RUNTIME.md) adds
eligible primitive literal getters; its evidence and limits supersede the
constant-specific missing-integration findings below.

Current startup graph/RASP implementation and remaining limitations are recorded
in [O.1 signed guard runtime](PHASE-O1-GUARD-RUNTIME.md). Historical missing-loader
findings below do not describe that new eligible slice; full production closure
requirements remain outstanding.

This audit records the previous frozen-selection/input-snapshot increment.
The subsequent runtime increment verified upstream HEAD
`f4409a62d7234b785886feaa505048ee5cdcf270` before edits and is recorded in
[O.1 Android runtime](PHASE-O1-RUNTIME.md). That document supersedes the
data/native/VM "no injected loader" findings below for its narrow eligible
method slice only. The production closure boundaries remain open.

## Baseline and scope

The Ghost Developer connection resolved PR #35 and the branch
`feat/phase-o1-orchestrator-contracts` to
`4199ca8bf024470e608da0c0f475af21b159914b` before edits. All 380 downloaded
source files were checked against their Git blob SHA-1 identities.
No O.2–O.15 implementation, merge, tag or release is included in this change.
`release/phase-o-status.json` and all production integration statuses remain
unchanged. An all-green component run does not close O.1.

## Changes in this increment

1. `ProductionBuildContext::prepare_with_selection` clones the immutable
   include/exclude policy together with resolved profile controls and binds
   absolute input/output paths. Production calls and CLI planning use it.
   Editing the caller's policy later cannot change the context.
2. Preflight and actual DEX staging share global selector resolution. Staging
   passes the resulting definition IDs to `MultiDexSet::rewrite_selected`.
   Per-execution selector overrides are rejected instead of silently replacing
   the reviewed policy. The DEX entry points reject invalid/reference-only IDs,
   incorrect unit counts and simultaneous selector rules/resolved selections.
3. Independent and linked-unit renaming consume that same selection. Imported
   references to selected owners are updated to retain binding, while excluded
   consumer definitions keep their original names. Linked virtual-family
   consistency, JNI/reflection guards and byte-level rewrite audits still apply.
4. Debug/source metadata stripping now respects selected class/method ownership.
   A code item also owned by an unselected method is retained conservatively.
   An entirely excluded, unlinked DEX retains its bytes exactly.
5. `InputSnapshot` copies source bytes from one open file descriptor into an
   exclusively allocated temporary directory. The copy is bounded by ZIP32's
   size limit and authenticated against the planned SHA-256 before use.
   DEX extraction, Android contract linking, rebuilding and comparison all read
   the same captured copy. Unix directory/file modes are 0700/0600. RAII removes
   the temporary copy on normal success/error paths. Windows permissions are
   inherited from the host; equivalent private ACL qualification is pending.
   This prevents mutable-source ABA substitution from mixing reads; it does
   not claim crash recovery, protection from a compromised build user or
   durable transaction recovery. Persistent source changes still reject output.
6. The existing JNI test's truncating ELF64 offset cast is replaced by a checked
   conversion. No lint or validator is disabled. The original Rust quality
   failure is visible in CI run `41014649333`, job `123928181143`.

## Tests and evidence boundaries

New retained regressions cover:

- mutation of source bytes after snapshot capture and rejection of a stale hash;
- Unix private permissions and temporary-directory cleanup;
- cloning the selector policy, then mutating the caller before actual staging;
- final staged APK hash equality and byte-identical preservation of excluded DEX;
- execution-time override rejection with no output;
- source substitution rejection with no output;
- selected owner method/field imports versus excluded consumer definitions;
- repeatable selected transforms, invalid unit counts and reference-only IDs.

Local verification completed before publication:

| Check | Result |
| --- | --- |
| Workspace tests | 223 passed, 0 failed, 0 ignored; 46 test/doc-test binaries |
| Rustfmt | Passed |
| Strict workspace/all-target Clippy | Passed with `-D warnings` |
| Phase O DEX job run scripts | All 17 executable steps passed locally, including existing adversarial fixtures |
| Release freeze validator | Passed; open / no-go / 18 release blockers retained |
| Documentation validator | Passed |
| Android installation/start/function E2E | Not executed; no complete production runtime executor or Android device/emulator available |

The first full workspace attempt encountered local shared-target Rust metadata
resolution errors. A complete fresh target-directory rebuild with two jobs
passed. The final pass is recorded above; the failed attempt is not counted
as a successful test execution.

Commands used for local verification:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --target-dir /tmp/nexora-clean-tests -j 2
python scripts/release/verify-phase-o-release-freeze.py
python scripts/release/verify-docs.py
```

Initial local verification used Ubuntu Rust 1.91.1. GitHub's floating `stable`
compiler was 1.99.1. Its additional Clippy rules detected an unnecessary format
comma and an empty-collection assertion form, both corrected without suppressing
rules. Rust 1.99.1 was then installed locally and strict all-target Clippy and
Rustfmt passed on the corrected source. Local results are not a substitute
for all required checks on the published commit. Phase O now explicitly runs
the snapshot and frozen-selection regressions in its DEX preflight job, as
well as retaining the complete pre-existing negative/adversarial checks.

All APK fixtures exercised by these new tests are **synthetic and unsigned**.
They do not demonstrate Android installation, startup, behavior equivalence,
or final embedded security controls. No production APK hash exists to report.

## Individual subphase status

| Subphase | Current verified scope | Closure boundary |
| --- | --- | --- |
| O.1.1 configuration/preflight | Typed profile controls, mandatory-control enforcement, path checks; this increment freezes selectors and captures input bytes | Typed contract only; full production execution still open |
| O.1.2 DEX preflight | Bounded parsing, canonical multidex, compatibility and global include/exclude resolution | Diagnostic contract only; production runtime proof still open |
| O.1.3 DEX transforms | Real fixed-layout byte transformations, linked owners, restricted compiled-resource linking, encrypted retrace sidecar, selected execution | OPEN; not a signed, behavior-qualified production integration |
| Parent O.1 | 18-stage contract and fail-closed public path | OPEN; the remaining required stages below have no final-artifact proof |

## Remaining mandatory integrations

| Work | Source evidence / missing integration | Required proof |
| --- | --- | --- |
| DEX production execution | `shield-core/src/production.rs` still deliberately rejects output after readiness validation | ART-compatible transforms, Android/JNI/reflection/serialization contracts and representative functional differential execution |
| Data protection | `shield-crypto` provides host container/key/decrypt APIs; no injected Android loader or transformed call sites invoke them | Selected literals/constants/resources absent in ordinary APK extraction and correctly decrypted when the app uses them |
| Native Shield | `shield-native/src/jni_bridge.rs` exports runtime version/ABI queries only; core does not embed or invoke security helpers | ABI-qualified library packaging and actual protected calls on Android |
| VM Shield | `shield-vm` has host lowering/interpreter APIs; no APK method replacement or JNI host bridge calls the interpreter | Selected original methods replaced, executed through the VM, and behavior compared on Android |
| Diversification | Core has no production dependency on `shield-diversity` | Variations in the delivered DEX/runtime/data/graph, plus private reproducibility |
| Integrity Graph | Core has no production dependency on `shield-integrity` or Android checker injection | Package/certificate and transformed DEX/resource/native coverage, with a signature-cycle-free commitment model and tamper detection inside the app |
| RASP | `shield-rasp` evaluates supplied observations; core does not inject an Android collector/startup hook | Real observations, response policy, report-only behavior and normal-environment false-positive results |
| Optional attestation | Core has no APK/runtime dependency on `shield-attestation` | Signed public-key verification, remote response binding and offline degradation; server secrets excluded from the APK |
| Rebuild/sign/verify | Diagnostic staging and Phase A tool integrations exist separately; production does not publish their combination | Reconstructed final APK, zipalign, signature/certificate checks and install/start/function evidence |
| Final evidence | Existing public success reports describe Phase A packaging; staging hash describes unsigned diagnostics | Actual executed controls/profile/tool versions and verification results bound to final signed APK hash |
| CLI/Gradle/Studio | CLI protect and default Gradle reject incomplete production; Studio exposes preflight | Same working production executor from every entry point, with no legacy fallback |

These are implementation and validation blockers, not documentation items that
can be waived. No stage is promoted to `ProductionIntegrated` by this increment.
The full requested O.1 completion has **not** been achieved.
