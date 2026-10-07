# Phase K — AAB / AAR / Splits

## Objective

Phase K extends Nexora Shield beyond a single APK artifact and establishes compatibility contracts for Android App Bundles, bundletool-generated APK Sets, dynamic features, Play App Signing and publishable Android libraries.

The phase does not reinterpret every ZIP as an APK. Each Android package format has a dedicated model and validation path.

## K.1 — AAB parser/model

`nexora-shield-package` contains a dedicated AAB model.

The parser discovers:

- `BundleConfig.pb`;
- the base module;
- feature modules through their module manifest path;
- per-module `classes*.dex`;
- per-module `resources.pb`;
- resource and asset entries;
- native ABI directories;
- bundle metadata;
- compiled Baseline Profile artifacts.

AAB DEX numbering is validated independently inside each module.

The structural verifier requires `BundleConfig.pb`, a base-module manifest and canonical DEX numbering for every discovered module.

## K.2 — bundletool validation

Official bundletool is the semantic authority for Android App Bundle validation and split generation.

The repository pins:

- bundletool 1.18.3;
- SHA-256 `a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29`.

`scripts/fetch-bundletool.sh` downloads the exact release over HTTPS and rejects a digest mismatch.

The Rust `Bundletool` wrapper supports:

- bundle validation;
- default APK Set generation;
- universal APK Set generation;
- local-testing mode;
- explicit APK-set signing inputs.

Password values are supplied through password files rather than raw command-line values.

## K.3 — Dynamic features

The AAB model treats every non-base module with a valid module manifest as a feature module.

The integration sample contains an on-demand `feature-payments` dynamic feature with its own namespace, resources, manifest and code.

The Phase K AAB gate requires the final App Bundle to contain exactly the expected feature module and validates it with official bundletool.

## K.4 — Split APK testing

`ApkSetInspection` models bundletool `.apks` containers.

It validates:

- `toc.pb`;
- presence of APK artifacts;
- split APKs;
- standalone APKs;
- universal APKs;
- instant/system/asset-slice categories when present.

CI builds both a default local-testing APK Set and a universal APK Set from the real sample AAB.

## K.5 — Play App Signing compatibility

Nexora Shield distinguishes two identities:

1. upload certificate — signs the AAB uploaded to Play;
2. delivery/app-signing certificate — signs APKs installed on user devices.

`PlayAppSigningConfig` never treats the upload certificate as an implicit runtime trust root. Phase D `CertificateBinding` is constructed from Play delivery signers and optional delivery signing lineage.

This avoids a false integrity failure after Google Play re-signs delivery APKs.

The integration sample signs its AAB with an ephemeral upload key and verifies that upload signature before bundletool processing.

## K.6 — AAR consumer rules

`AarInspection` validates the publishable Android library contract:

- `AndroidManifest.xml`;
- `classes.jar`;
- consumer ProGuard/R8 rules;
- AAR metadata;
- resources;
- JNI ABI directories;
- resource symbols when emitted;
- Baseline/Startup Profile entries.

The library integration sample packages explicit consumer rules and K fails when library mode requires rules but none are present.

## K.7 — Library protection mode

Phase K adds `com.android.library` support to `dev.nexora.shield`.

The mode is deliberately format-correct:

- an AAR contains JVM bytecode in `classes.jar`, not final DEX;
- Nexora Shield therefore does not claim DEX/VM transformations were executed inside a standalone AAR;
- the plugin validates and preserves the library's protection/consumer contract;
- DEX/VM/RASP application layers become available after D8/R8 when the library is consumed by a Nexora-protected application.

Generating a non-standard AAR containing arbitrary final DEX is explicitly avoided.

## K.8 — Resource namespaces

Library resources remain namespaced by AGP.

Phase K validates that the AAR carries resources and resource symbols/metadata and that an independent application can compile against the published Maven artifact.

Dynamic-feature resources are also validated independently in the AAB module layout.

## K.9 — Baseline Profiles interaction

Phase K detects:

- library source profile entries in AAR;
- compiled `baseline.prof` / `baseline.profm` entries in AAB modules.

The integration gates verify that protection/validation orchestration does not discard those artifacts.

Nexora Shield does not rewrite compiled profile bytecode metadata itself in Phase K.

## K.10 — Publishing tests

The publishing gate is intentionally cross-build:

1. a real `com.android.library` project builds and validates its release AAR;
2. the release component is published into a temporary Maven repository;
3. a separate Android application resolves the artifact by Maven coordinates;
4. that application builds a minified release;
5. consumer rules and namespaced resources therefore have to survive the publication boundary.

This is stricter than a `project(":library")` dependency test.

## Gradle integration

For applications, Phase J's APK transform remains unchanged. Phase K adds a per-variant AAB validation task using `SingleArtifact.BUNDLE`.

For libraries, the plugin uses `LibraryAndroidComponentsExtension` and validates `SingleArtifact.AAR`.

Defaults remain release-only.

## Security boundary

AAB/AAR support is packaging compatibility, not a new cryptographic primitive.

- bundletool validation cannot prove application logic is impossible to reverse engineer;
- Play App Signing requires configuring the delivery certificate, not trusting an upload certificate at runtime;
- consumer ProGuard rules are compatibility/protection hints, not secrets;
- a library becomes DEX only in the consuming Android application build.

## Closure requirement

Phase K is complete only when:

1. K.1–K.10 code and tests are integrated;
2. Rust quality and Rust 1.81 MSRV pass;
3. official pinned bundletool validates the real AAB;
4. a real dynamic feature survives bundle packaging;
5. default and universal APK Sets pass validation;
6. upload signing works without confusing upload and Play delivery identities;
7. a real AAR contains its consumer rules/resources/profile contract;
8. the AAR publishes to Maven and an independent minified app consumes it;
9. Phase A–J regressions remain green on the final head.

## Closure status

**COMPLETED**

All Phase K closure requirements were satisfied before merge:

- Phase K GitHub Actions run #25 (`37588269683`) completed successfully;
- general CI run #849 (`37588269688`) completed successfully;
- strict AAB upload-signature verification passed using the CI upload keystore as the explicit trust anchor;
- real AAB validation, dynamic-feature counting, default/universal APK Set generation, AAR publication/consumer validation and profile/resource preservation all passed;
- PR #13 was merged into `main` as `7211607b34cc320dd80e52e523f41f364cfe2e77`.

The next roadmap phase is **Phase L — Shield Studio**.
