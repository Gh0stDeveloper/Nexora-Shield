# O.1 shared experimental APK transaction

Status: **eligible integrated execution; O.1 OPEN; stable v1.0.0 NO-GO**.

Starting HEAD verified through Ghost Developer:
`94a987fe5a88d2e865409e7735e2c7b9e5d4cdf5`, branch
`feat/phase-o1-orchestrator-contracts`, PR #35. This increment stays in O.1.

## Executing transaction

The common `shield-core::protect_integrated_apk` executor now owns:

1. Effective profile/control resolution, separate DEX/runtime selectors and
   disjoint output/key/tool paths, with unavailable selected controls rejected.
2. A private hash-bound APK snapshot and resolved method indices before renaming.
3. Real selected DEX renaming/metadata reduction with Android/JNI/reflection/
   resource checks. Private seed allocation drives renaming. No-op transforms
   and skipped requested renaming fail the transaction.
4. Runtime method replacement, data/asset encryption, eligible VM lowering,
   executable diversity and independent signed Integrity Graph/RASP binding.
5. Real native compilation for ARM64/x86_64, owned by core without a shell
   recipe. Source and complete private image fingerprints, ELF machine type,
   runtime commitment and every planned ciphertext are checked before use.
6. Verified Smali assembly/round-trip, helper/provider injection, reconstruction,
   alignment, signing, actual signer verification and final signed alignment.
7. Verification of the signed final APK by the real runtime graph verifier,
   host RASP response contracts, native payload binding and selected string
   exposure checks including DEX modified UTF-8 and UTF-16 encodings.
8. Independent-key retrace encryption bound to the final signed APK hash,
   followed by grouped APK/report/map publication with rollback on failure.

Runtime indices are frozen from the original parsed DEX. The verified fixed-layout
rewrite preserves those IDs; selection does not depend on obsolete renamed names.
The fixture renames Probe, retains contractual public members, then applies the
selected runtime transformations to its original methods.

The graph covers exact payload inventory and expected certificate identity,
independently of the APK signing block. Final whole-APK hashes belong in external
reports/retrace sidecars, avoiding circular signing/hash dependencies.

Private workspaces/configurations use Unix 0700/0600 creation. Source/config/ABI
partitioned native caches also require private directories. Cargo intermediate
outputs stay there; compiler wrappers and ambient flags are reset to the pinned
recipe. Proxy/CA authentication remains inherited. Bounded tool diagnostics are
withheld from public errors. Failed rollback retains recovery backups.

Composition exposed a real resource-reader defect: AAPT2's canonical header-only
empty global string pool was rejected. The reader now accepts precisely that
bounded empty layout. Nonempty truncation, corrupt offsets/styles and existing
adversarial cases remain rejected. See Android's separate stringCount=0 handling:
[AOSP ResourceTypes.cpp](https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/ResourceTypes.cpp).

## Shared frontends

CLI opt-in:

```sh
nexora-shield protect input.apk --output protected.apk --profile maximum \
  --engine-config /private/build/engine.nshield-private \
  --keystore /private/signing/test.p12 --alias test \
  --ks-pass-env NEXORA_SHIELD_SIGNING_PASSWORD --min-sdk 28 \
  --public-report protected.json
```

The private schema-1 JSON file denies unknown fields and contains references,
not inline key bytes. It requires an ignored `.nshield-private` suffix, Unix
private regular-file permissions, a 64 KiB bound and absolute referenced paths.

| Fields | Contract |
| --- | --- |
| `application_id`, `build_id`, `controls` | Exact Android package, ordinary build ID, explicit enabled controls; mandatory profile defaults remain authoritative |
| `runtime_methods` | Nonempty bounded class-descriptor#member-glob list; every match must be eligible |
| `assets` | Explicit raw assets; empty means no asset selected |
| `root_key_file`, `graph_key_file`, `diversity_file` | Independent private inputs; diversity retains the NSDV1 private format |
| `signer_sha256`, `rasp_mode` | Exact single signer digest and report-only/enforce mode |
| `dex` | rename/strip_metadata flags and nonempty selectors, each with kind/class/optional member/optional exclude |
| `tools` | java, smali_directory, cargo, rustc, native_source, ndk_directory, native_cache |
| `retrace_key_file`, `retrace_output` | Both required with renaming; independent 32-byte private root and external encrypted map destination |

Controls can be empty for Maximum. This experimental recipe requires all six
Data/Native/VM/Diversity/Integrity/RASP controls enabled. Standard/Hardened must
explicitly select the additional controls or are refused; default subset recipes
still need integration/qualification. No control is silently enabled or omitted.
Selected attestation is rejected before construction. Alignment, signing and
public evidence are mandatory. Legacy private JSON reports are refused; retrace
uses its own encrypted output. All key roles are checked for exact material reuse.

Gradle exposes `nexoraShield.engineConfig.set(file(...))`. The actual APK task
calls the same CLI/core executor, requires signing/alignment/public reports,
refuses legacy mode and disables up-to-date/build-cache reuse. Existing reports
survive a failed integrated transaction.

Studio exposes APK/configuration/keystore selection, alias and password environment
variable name, and invokes the same executor through IntegratedProtectionService.
There is no raw password editor. The report viewer retains the experimental scope.

## Verification boundary

The Phase O Android job keeps the earlier 28 runtime cases and adds:

- Four actual CLI-engine APK cases per RASP mode: baseline, integrated valid,
  native modification and provider removal.
- Actual plugin-adapter and Studio-service executions, followed by Android
  installation/pull/hash/launch checks of both resulting APKs.
- Five cause-specific configuration/eligibility rejections per mode.
- A real failed signing after success, proving prior APK/report/map preservation,
  then exact private reproduction of the whole transaction.
- Independent final-signed-APK retrace authentication and raw private key/seed/
  mode absence checks against decoded public payloads.

A complete successful job therefore has **38 Android executions**. Missing cases,
wrong exceptions, changed hashes or missing graph/RASP execution fail the gate.
Dedicated Kotlin integratedEngineTest tasks require actual fixture/CLI inputs;
ordinary unit tasks exclude that tag. Required E2E tasks prohibit cache reuse.

Only six public JSON qualification reports are uploaded. They bind source commit,
worktree status, engine report and exact installed APK hashes to device outcomes.
The engine's own report records `android_execution: not-run`; the external
qualification records device observations after installation/launch. No build-only
constructor reports an Android success. No APK, private image, keystore or key is
uploaded by this gate.

Signer observation is tested with official Build Tools 35 and 37. The latter
labels its single v3 certificate `V3.0 Signer:` instead of `Signer #1`.
The reader requires exactly one explicit signer count and one complete certificate
digest in either exact layout, then compares it with the guard-bound certificate.
Duplicate digests/counts, extra signers, rotation, stamps and unknown layouts are
rejected. CI installs both versions: CLI uses explicit 35 paths, while the real
frontend adapters exercise SDK discovery with 37 available. Dedicated frontend
tests expose the CLI's sanitized error so tool format failures remain diagnosable.

## Remaining closure work

Global readiness is unchanged: production_protected=false, scope
`o1-integrated-experimental`, stable NO-GO. Ordinary protect without the explicit
private engine configuration remains fail-closed. O.1.1/O.1.2/O.1.3 and O.1 stay open.

The build recipe is Linux x86_64, Rust 1.99.1, Smali 3.0.9, NDK 27.3.13750724 and
verified official Android tools. Runtime libraries cover ARM64/x86_64; functional
device qualification covers API 35 x86_64. All existing method/native/reflection/
resource/asset/fixed-layout restrictions remain enforced. General object/instance
VM translation, arbitrary resource/native relinking, default profile subsets,
optional signed remote attestation/offline behavior and broader real application
compatibility remain open. No O.2 or later implementation is included.
