# O.1 signed startup Integrity Graph and Android RASP

Status: **partial runtime integration — O.1 OPEN; stable v1.0.0 NO-GO**.

This increment starts from verified branch HEAD
`42e13f7ff22e656f48f2340b9351dbc28e4820b2` on PR #35.
It adds an executing guard to the existing eligible string/integer runtime.
It does not implement O.2 or promote any complete production stage.

## Signature-cycle-free package graph

1. Provision an independent Ed25519 build signing key, the intended APK
   certificate SHA-256, and the RASP mode before compiling native libraries.
   The graph key is never derived from the client encryption root; exact
   reuse is rejected. Unix private-file checks apply to both private keys.
2. Embed only the public verification key and a binding of certificate,
   version and RASP policy in the native runtime. These participate in the
   runtime fingerprint, so changing them requires matching rebuilt libraries.
3. Replace eligible method bodies, append the helper/provider DEX, and
   structurally add a non-exported startup provider to the compiled manifest.
4. Build the existing IntegrityManifest/IntegrityGraph over the final
   uncompressed DEX bytes (including regions), compiled manifest, resources,
   other entries and both complete native libraries. Include package/version
   and the exact current signer binding.
5. Sign that graph and its runtime policy with the independent build key.
   Store its detached envelope at `assets/nexora-shield/guard.v1`.
6. Align/sign the APK. These operations preserve the graph-covered payload
   bytes. Verify the APK signature and final artifact hash separately.

The envelope excludes itself from its inventory; its detached Ed25519
signature authenticates it. Native verification uses the already compiled
public key. The APK signature block and obsolete/current v1 signature
entries are not recursively fingerprinted; Android PackageManager supplies
the actual installed current certificate. Consequently no final APK hash
must be inserted into a DEX that would change that same hash.

The server/attestation signing domain is not used here. The build-private
graph key never enters native configuration or the APK. This is an
application-level trust anchor, not hardware-backed protection against an
attacker who can replace the verifier itself.

## Actual Android execution

The injected provider invokes a JNI startup entry using its real Context.
The native adapter reads ApplicationInfo.sourceDir and PackageManager,
including API-28+ current signers or the API-24 legacy signature interface.
Split APKs and multiple current signers are rejected by this narrow path.

The runtime verifies the signed envelope, exact entry inventory, all graph
checks, package/version/current certificate, build identity and pinned policy
binding. Added, missing or modified covered entries fail verification.
RASP report-only mode does not suppress integrity failures.

Every selected JNI string/VM operation requires successful guard startup
when the guard is configured. Removing the provider therefore cannot turn
the protected calls into an unguarded success.

The platform adapter collects actual debugger-connected/waiting state,
ApplicationInfo's debuggable flag, /proc/self/status TracerPid, Build
fingerprint/model emulator indicators, and a bounded set of known injected
library names from /proc/self/maps. The existing Debug/Emulator/Hook
evaluators, RiskEngine and ResponseEngine determine the response.
Protected calls recheck the observed RASP state. Report-only caps the
effective response at reporting; enforcing mode denies an operation
requiring reverification or denial. There is no dummy successful return.
Unavailable/malformed observations fail instead of being called clean.

No generalized inline-hook scanner, root/OEM certification, complete
instrumentation collector or physical-device false-positive claim is made.

## Structural and eligibility boundaries

The manifest writer appends string slots and resource-map bindings, preserving
every original string index and XML node byte sequence. Original attributes,
components and resource references are not reconstructed from text.
UTF-8/UTF-16 pool tests compare the original nodes and indices after injection.

Current guard eligibility requires the default Application and factory,
a single default unlocked process, no custom backup/instrumentation startup,
no ambiguous existing provider priority, and an unstyled manifest pool.
Namespace collisions and unsupported early-entry contracts reject the build.
Selected operations before provider initialization are deliberately refused.
A custom Application/factory requires a separately verified early-entry binder;
this increment does not silently claim that compatibility.

Limits include 64 MiB per decoded entry, 256 MiB combined guarded payload,
4 MiB signed-envelope encoding, 4,096 artifacts and 8,192 graph nodes.
Runtime evidence is limited to the single APK, not APK splits or memory pages.

## Verification

Retained tests cover envelope tamper/wrong key/circular inclusion, binary XML
preservation/refusal, independent signing-key enforcement and the actual
graph verifier over reconstructed and signed APKs. A non-ASCII 64-byte
certificate digest now returns an error rather than panicking during slicing.

The qualification harness builds both report-only and enforcing policy images
and libraries. For each mode it creates eleven signed APK cases:

- original baseline and valid guarded output;
- encrypted native-container corruption;
- graph-signature corruption and missing graph;
- resource corruption;
- executable-valid DEX modification (checksums refreshed);
- native-file modification;
- provider removal;
- an unplanned extra entry;
- unchanged payloads signed by a different APK key.

Host checks verify the exact APK bytes and signer observations and exercise
normal/critical RASP response contracts. The Android gate must independently
install each APK, pull it and compare its final hash, start it, require the
expected security/functional result and observe actual RASP status in the
valid app. An unrelated launch failure is not accepted as tamper detection.

Local verification passed 233 workspace tests with all features, strict
Clippy, Rustfmt, Rust 1.81 workspace/all-feature compilation, both Android
ABIs, Smali round-trip, signed APK verification and the eleven-case host
matrix in both RASP modes. The local machine has no KVM device; Android
installation/startup requires the exact-head Phase O job. Only its two
public evidence JSON files are uploaded, never the private keys, keystores,
password files, native configurations or certificates.

Ed25519 uses ed25519-dalek 2.2.0 strict verification. Cargo.lock retains
base64ct 1.6.0 for the Rust 1.81 resolver; the newer optional PKCS#8 dependency
manifest required Edition 2024. The MSRV check and RustSec gate remain enabled.

## Remaining O.1 closure work

The full public executor still fails closed. This qualification driver
does not replace the missing shared CLI/Gradle/Studio production transaction.
Selected constant/resource encryption and runtime access rewriting,
broader Native/VM contracts, complete delivered-surface diversification,
optional remote attestation and final production reporting/publication
remain open. The existing stage integration flags and release NO-GO remain
unchanged. O.2 must not start on the strength of this partial integration.
