# O.1 raw asset runtime integration

Status: **partial Android integration; O.1 OPEN; stable v1.0.0 NO-GO**.

The [delivered diversity/private reproduction increment](PHASE-O1-DIVERSITY-RUNTIME.md)
adds executing DEX/data/VM/native/graph variation to the eligible runtime path.
Its scope supersedes historical missing-diversity findings below; full production
closure remains outstanding.

The Ghost Developer branch HEAD was verified as
`a7ee49ddb5239a56c4db7c860fb9b6d4d8f58a0e` before this increment.
It extends the [constant runtime](PHASE-O1-CONSTANT-RUNTIME.md) and the
[signed guard/RASP runtime](PHASE-O1-GUARD-RUNTIME.md).

## Actual data flow

`AndroidRuntimePlan::with_protected_assets` accepts an explicit list of raw
`assets/` entries. It reads the frozen input snapshot, encrypts them using the
existing ResourceBundle/KeySchedule engine, and replaces the actual APK entries.
Each encrypted bundle is bound by path, slot and SHA-256 in authenticated native
metadata. No plaintext resource or second plaintext copy is embedded in the native
image. The signed Integrity Graph covers both encrypted assets and metadata-bearing
libraries after rebuilding.

All direct `AssetManager.open(String)` and `open(String,int)` calls in every DEX
unit are rewritten to the generated helper, retaining register and range layouts.
The frozen DEX invocation count must equal the actual rewritten count, and the
complete Smali round-trip plus final multidex validation remain mandatory.
The native entry point opens the actual asset through the supplied AssetManager,
reads it within a fixed budget, closes the Android stream even after errors,
verifies the metadata binding, and invokes ResourceBundle decryption. Unselected
paths return their original Android stream. Existing Android I/O exceptions are
preserved; authentication/guard failures raise SecurityException.

Selected plaintext is returned through the shipped ResourceInputStream, which
preserves mark/reset, EOF, zero-length reads, negative skip and closed-stream
behavior for the qualified platform contract. Its close operation overwrites the
owned plaintext array. Rust plaintext buffers are zeroized. Plaintext returned to
the app remains observable; this is not hardware-backed resource secrecy.

## Strict eligibility

This asset path requires a compiled minSdk of at least 28. Android 24-27 have a
different AssetInputStream implementation and are not silently assumed compatible.
The original data/VM slice retains its separate API-24 contract. Platform behavior
was checked against the primary Android AssetManager sources:
[API 28](https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r3/core/java/android/content/res/AssetManager.java)
and [API 35](https://android.googlesource.com/platform/prebuilts/fullsdk/sources/+/refs/heads/androidx-constraintlayout-release/android-35/android/content/res/AssetManager.java).

Limits: 1 MiB per selected plaintext asset, bounded encrypted reads, raw assets
only, and no reserved guard namespace. Missing/duplicate assets and compiled
resources are rejected. Existing native libraries, reflective/dynamic calls,
AssetInputStream casts, non-open/list AssetManager APIs, and foreign/dynamic asset
manager construction are conservatively rejected because their access contracts
have not been integrated. A request is rejected as a whole; no partial APK or
private configuration is published on eligibility failure.

This does not implement `res/raw`, Resources.openRawResource, compiled XML/table
resource encryption, asset file descriptors, WebView/NDK asset loading or arbitrary
resource-provider compatibility. Those remain part of the production closure work.

## Retained verification

- Unit tests exercise actual bundle decryption, binary/NUL payloads, wrong slot,
  path/build/key binding, duplicate/path refusal, ciphertext substitution/tamper,
  and both direct/range access rewrite forms.
- The installable fixture reads selected and unselected assets through both open
  overloads, compares SHA-256 digests and exercises mark/reset, negative skip,
  reads across chunks, EOF, zero-length reads and closed-stream behavior.
- The exposure probe requires the selected plaintext in the baseline and rejects
  it in every final APK payload, including native libraries.
- The guard matrix adds an independently signed encrypted-asset corruption case,
  for twelve APKs per RASP mode. The actual final protected APK must still install,
  pass its startup guard, execute strings/constants/VM/assets and return its success
  marker. Unrelated crashes never count as protected behavior.
- Public evidence includes actual protected-resource counts and hashes of the final
  signed APKs. Only JSON reports are uploaded; private configurations/keys/keystores
  and APKs remain excluded.

Local verification includes 237 all-feature workspace tests, strict Clippy,
Rust 1.81 workspace/all-feature compilation, both Android ABI builds, pinned Smali
round-trip, real JNI regression execution, alignment/signature verification and
both host guard matrices. Android installation/startup must pass on the exact
commit in the non-skipping Phase O job; local KVM is unavailable.

The complete profile executor, broader Native/VM and resource compatibility,
delivered diversification/private reproducibility, optional attestation and shared
CLI/Gradle/Studio production transaction remain open. No stage is promoted to
ProductionIntegrated; O.2 has not started and global NO-GO is unchanged.
