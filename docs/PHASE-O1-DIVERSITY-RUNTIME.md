# O.1 delivered runtime diversity and private reproduction

Status: **partial Android integration; O.1 OPEN; stable v1.0.0 NO-GO**.

Starting branch HEAD, verified through the Ghost Developer connection:
`56a04ae194d1f171a9d28ee057ee56dda37e4845`, PR #35,
`feat/phase-o1-orchestrator-contracts`. This increment extends the existing
[data/assets](PHASE-O1-ASSET-RUNTIME.md) and [signed guard/RASP](PHASE-O1-GUARD-RUNTIME.md)
paths. It does not change production readiness flags or begin O.2.

## Materialized surfaces

The typed `prepare_android_runtime_with_diversity` API derives a SeedDeriver
from independent private seed material, build/application identity, the frozen
input APK SHA-256 and explicit unique/private-reproduction mode. The plan owns
its allocations; later changes to the caller's file cannot change them.

- Method and asset slot permutations change the actual DEX-to-native bindings.
  Original Android class/member names and signatures remain unchanged.
- A domain-separated public commitment extends the build identity used by
  KeySchedule, producing different authenticated strings/constants/resources
  and VM payloads for a different unique nonce.
- NativeConstantVariant material changes the native key-share representation;
  it participates in actual root reconstruction during decryption.
- CfgVariantPlan changes eligible lowered integer VM code with verified forward
  padding/trampolines. VmMapVariant allocates the actual executable opcode map.
  The transformed instructions, map and stream are encrypted into the library
  used by the final APK. Unsupported/cyclic/over-budget programs still fail.
- IntegrityTopologyPlan produces the signed certificate-rooted tree and changes
  redundant check assignments. Every expected package/certificate/DEX/resource/
  native node is reconstructed independently during manifest validation.

These are delivered-byte changes and executing calls, not metadata-only plans.
No general class rename, arbitrary Java object VM/native translation or complete
Phase H pass/shard materialization is claimed.

## Integrity invariants

Canonical manifests retain exact graph equality and their legacy JSON shape.
The optional `certificate_tree` topology permits edge variation while requiring
identical canonical identity/artifact nodes, one certificate root, package-first
trust, a complete rooted tree, valid graph digest and exact redundant coverage.
Graph validation now also rejects disconnected cycles and unreachable nodes;
ordinary valid multi-parent DAGs remain supported by the graph API.
Signature verification, certificate binding, package/build matching, exact APK
inventory, RASP policies and all previous tamper checks remain mandatory.

## Private inputs and reproduction boundary

The private seed must differ from client encryption and graph-signing material;
exact role reuse is rejected. It never enters RuntimeImage, APK, public reports
or compiler arguments. SeedDeriver/private seed and owned domain-key buffers
are zeroized. Only commitments, counts and digests are public.

The internal qualification example accepts `--diversity-file <path>` before
`--asset` and guard options. The file must be a regular Unix-private file with
ignored `.nshield-private` suffix: six bytes `NSDV1\0`, one mode byte (0 unique,
1 reproducible private), 32 seed bytes, and a nonempty UTF-8 mode identifier of
at most 256 bytes without NUL. The test generator provisions independent CSPRNG
material and fresh unique nonces. This is not a public YAML/CLI configuration
binding or a replacement for O.5.

Private reproduction requires the retained original APK, root/seed/mode inputs,
independent graph key, signer, policy and the pinned source/toolchain/build recipe.
The qualified Linux recipe retains workspace/dependency layout, Rust 1.99.1,
NDK 27.3.13750724 and Smali 3.0.9. Arbitrary cross-OS/path reproducibility is
not certified. Reusing a unique nonce deliberately reproduces its deterministic
allocation; callers must provision a fresh nonce for a new unique build.

The pinned assembler runs with one worker: parallel helper assembly was observed
to produce different DEX layouts for identical input. Native caches are scoped
by complete private-image SHA-256 and ABI, and compiled library ABI/fingerprint
is checked before copying. A stale ARM image encountered during validation was
rejected by the existing staging validator; no validator was relaxed.

## Retained proof

The qualification job independently plans/builds two private copies and one unique
variant for each RASP mode. It requires:

1. identical private RuntimeImage values, independently built ABI libraries,
   reconstructed APK bytes and final aligned/signed APK bytes;
2. different delivered source/helper DEX, encrypted asset, both native libraries,
   actual graph edges and redundant assignment lists for the unique variant;
3. authenticated executable VM inspection, showing a materialized CFG, a changed
   actual opcode map and opcode stream; no original VM values/instructions leak;
4. every planned encrypted runtime payload present in each final native library;
5. absence of raw private seed, mode identifiers, root and graph key from APK payloads;
6. signature/alignment/payload verification bound to final signed APK hashes;
7. fourteen Android cases per RASP mode, including valid private and unique builds,
   baseline, cross-build native substitution and every previous tamper case.

The app checks both VM branch outcomes, wrapping overflow, Unicode string
interning, five primitive constants and selected/unselected assets. Installed APKs
are pulled and hash-compared before launch. Both valid protected variants must
verify the guard and evaluate actual RASP observations. Missing evidence, unrelated
exceptions or an incomplete case inventory fail the gate.

Unit/regression checks cover 32 unique allocations, private repetition, CFG/VM
semantics, malformed VM maps, graph cycles/bindings, malformed/private option files
and key-role reuse. Full workspace tests, strict Clippy, formatting, Rust 1.81,
signed host matrices, docs and release-freeze checks run before publication.
Local Android installation is unavailable without KVM; exact-commit Phase O
Android evidence is required. Only the two public JSON evidence files are uploaded.

## Remaining closure work

The public production entry point remains fail-closed. Complete CLI/Gradle/Studio
orchestration, combined O.1.3 transforms/retrace, broader JNI/reflection/resources/
Native/VM compatibility, optional signed remote attestation/offline behavior and
representative full-profile execution remain open. A passing eligible runtime
qualification does not close O.1.1/O.1.2/O.1.3 or the parent O.1.
