# O.1 functional Android runtime slice

Status: **OPEN — partial integration, production graph incomplete; NO-GO**.

The [encrypted constant runtime increment](PHASE-O1-CONSTANT-RUNTIME.md) adds
eligible primitive literal getters; its evidence and limits supersede the
constant-specific missing-integration findings below.

The subsequent [signed startup graph and Android RASP increment](PHASE-O1-GUARD-RUNTIME.md)
supersedes the "no new integration" findings below for its explicitly eligible
APK slice. The complete production executor and parent O.1 remain open.

## Scope and decisions

This increment starts from verified branch HEAD
`f4409a62d7234b785886feaa505048ee5cdcf270` on PR #35.
It changes O.1 only. It creates no release, tag, merge or stable approval.
`release/phase-o-status.json` and stage integration statuses remain unchanged.

`ProductionBuildContext::prepare_android_runtime` consumes the frozen
selection and hash-validated private input snapshot. The compiled manifest
must contain the same package identity and an unambiguous numeric minSdk
of at least 24. Every selected method must satisfy the contract below;
one incompatible selection rejects the entire request. The runtime identity
also includes the original APK SHA-256.

| Selected method | Accepted behavior | Actual final-APK execution |
| --- | --- | --- |
| static unsynchronized `()Ljava/lang/String;` | Sole const-string / return-object pair, same register, no handlers or selected annotations | Original method calls injected helper; native runtime authenticates/decrypts its XChaCha20-Poly1305 container; helper interns the result |
| static `(I...I)I`, at most 16 arguments | Bounded pure integer operations, forward branches, no host calls, fields, objects, division, exceptions or loops | Original body is removed; JNI decodes the encrypted allocated opcode stream and executes the existing Rust VM |

Class names, method names/prototypes/flags and excluded members remain in
place. Smali 3.0.9 performs DEX table rebuilding rather than ad hoc index
patches. Its complete dependency inventory is pinned by SHA-256. Reassembly
must reproduce the planned declarations/instructions when independently
disassembled. Every resulting DEX is reparsed and validated together.
Untouched entries retain their original compressed payload bytes. A helper
namespace collision, unsupported input ABI, existing output or unplanned
Smali change rejects staging.

This integrates an actual native data/VM bridge. It does **not** implement
general native AOT translation of Java methods, Java object/exception VM
hosting or a general reflection/JNI compatibility qualification. Those
remain production blockers.

## Key and library binding

The private root file is 32 bytes with Unix private permissions.
A build-private `.nshield-private` file holds split client key shares,
build identity and authenticated ciphertext. Both shares necessarily ship
in the native runtime; their splitting prevents the original root sequence
from appearing directly but is **not** a hardware-backed secret or a
guarantee against static/dynamic reverse engineering. The APK exposure probe
is limited to the selected fixture's plaintext and original root bytes.
No attestation/server private key is used or embedded.

Build configuration is ignored by Git, created exclusively with mode 0600
and never uploaded. Root/serialized configuration buffers are zeroized.
The build script uses ciphertext as byte data so corruption tests exercise
the shipped container rather than only a host-side representation.
JNI failures raise SecurityException instead of returning successful dummy
values. Library binding and container authentication run before the first
protected call through the injected helper's class initializer.

The native build requires NDK 27.3.13750724 and Android API 24 linkers.
Both arm64-v8a and x86_64 libraries must have the exact required JNI export
set and the selected runtime fingerprint. A mismatched build or host glibc
library is rejected before APK output. This fingerprint binds planned
artifacts; it is **not** a complete Integrity Graph or certificate-rooted
anti-repackaging defense.

## Rebuilding and evidence

`rewrite_with_additions` extends the existing exclusive ZIP32 writer with
explicit additions, rejecting unsafe names, signature additions and entry
collisions. Staging adds the helper DEX and both native libraries, strips
obsolete signatures, and verifies exact generated/preserved entry contents.
Partial outputs are removed on verification failure.

The internal `stage_android_runtime` example exposes separate prepare/stage
operations. It prints `production_protected=false` and cannot publish the
planned production output. CLI protect, default Gradle and Studio continue
to use their fail-closed production/preflight paths; no legacy fallback is
introduced. Routing these clients to a complete working executor is pending.

The qualification scripts separately align/sign the installable test
fixtures with an ephemeral test key, then verify signature, 16 KiB ZIP
alignment and unchanged payload contents. The public JSON evidence contains
the checked-out source commit, exact signed APK SHA-256 identities, actual
selected string/VM counts, executed control names, tool versions, native
hashes and device results when available. Only this JSON is uploaded;
private configuration, key material, keystore and APKs are excluded.

## Verification retained in source

- Rust tests exercise authenticated string decoding including NUL/Unicode,
  actual VM execution and wrapping overflow, wrong slot/type/arity,
  wrong build/key, ciphertext tamper and unsupported host/loop operations.
- Core regressions check exact method replacement and refusal of ambiguous
  or annotated methods. ZIP tests check additions, preservation, path
  traversal, signature injection and collisions.
- The JVM harness invokes the real JNI exports, compares integer vectors
  and interned Unicode strings, then loads a corrupted library in a fresh
  JVM and requires authenticated rejection.
- Negative APK integration checks use a real compiled manifest: mismatched
  package, minSdk 23, instance method, missing/duplicate selector,
  wrong native build and already-bound helper namespace must produce no output.
- The Android gate installs baseline, runtime and corrupted-runtime signed
  APKs, pulls each installed APK and compares its SHA-256 to the verified
  artifact, then starts the Activity. Baseline/runtime must report equivalent
  string/overflow behavior; tamper must cause SecurityException (directly or
  as the class-initializer cause). Unrelated exceptions fail the gate.

Local validation passed: 229 workspace tests with all features, strict
all-target/all-feature Clippy on Rust 1.99.1, Rustfmt, Rust 1.81 core/example
compilation with JNI enabled, both Android native builds, real Smali
round-trip/rebuilt APK, JVM positive/tamper execution, and final alignment/
signature/exposure checks. Documentation and release-freeze validation are
also required before publishing the commit. The local environment has no
`/dev/kvm`; local Android installation/startup was **not executed**.

The new Phase O job `O.1 Android string JNI VM qualification` runs the
device checks without an emulator-availability skip. Its uploaded
`o1-android-runtime-evidence` is valid Android evidence only if the exact
commit's job completes and `android_execution` equals `passed`.
A declared workflow is not a recorded passing execution.

## Closure boundaries

| Area | State after this increment |
| --- | --- |
| O.1.1 | Frozen context/policy/input contract retained; full profile execution open |
| O.1.2 | Real preflight/selectors retained; complete Android compatibility matrix open |
| O.1.3 | Existing transforms plus eligible real call-site replacement; representative production equivalence open |
| Data / Native / VM | Functional eligible string/int slice; resources/constants, broader JNI/VM/native contracts open |
| Diversification | Runtime opcode allocation is build-derived; complete delivered-surface diversification/private reproducibility open |
| Integrity Graph / RASP / optional attestation | No new integration or closure claim |
| Rebuild / align / sign / final evidence | Real qualification fixtures; full production transaction/report integration open |
| CLI / Gradle / Studio | No silent fallback; complete shared production executor open |
| Parent O.1 | **OPEN**; no stage promoted to ProductionIntegrated |

Next required work is the complete runtime/control graph, resource/constant
access rewriting, certificate-safe integrity design, actual Android RASP
observations/policies and optional signed attestation/offline degradation,
followed by shared production publication and representative functional
coverage. No O.2–O.15 implementation is included.
