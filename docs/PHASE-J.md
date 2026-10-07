# Phase J — Gradle Plugin

## Objective

Phase J removes the manual APK post-processing step for Android application projects.

The plugin id is dev.nexora.shield. It integrates with Android Gradle Plugin through the public Variant API and transforms SingleArtifact.APK in the selected variants.

Current compatibility target:

- Android Gradle Plugin 9.4.1;
- Gradle 9.6.x;
- JDK 17;
- Android application modules.

AAR/library protection remains Phase K scope.

## J.1 — AGP integration

NexoraShieldPlugin requires com.android.application to be applied first.

The plugin obtains ApplicationAndroidComponentsExtension and registers variant-aware protection tasks. It does not use deprecated Transform APIs or internal AGP classes.

## J.2 — Variant API

Each selected application variant receives a NexoraShieldApkTransformTask wired to SingleArtifact.APK using wiredWithDirectories(...).toTransform(...).

AGP therefore owns task ordering and artifact dependencies. Running assembleRelease produces the transformed APK artifact without a separate manual shell pipeline.

Non-APK metadata in the APK artifact directory is preserved.

## J.3 — Release-only defaults

releaseOnly defaults to true.

Debug and other non-release variants remain untouched unless the application explicitly opts in. An optional variants allowlist can restrict exact variant names.

Unsigned protected output is denied by default. CI/sample builds must explicitly opt into allowUnsigned=true when no release keystore is used.

## J.4 — Config schema completion

The root JSON Schema is strict for previously lax blocks:

- dex;
- budgets;
- compatibility;
- reports;
- signing;
- secrets.

A strict gradle block now models Phase J options including variants, signing references, mapping/retrace and cache controls.

## J.5 — Secret providers

SecretResolver supports env: and file: references.

Password values are resolved only during task execution and injected into the child shield-cli process as environment variables. They are not placed in command-line arguments or generated public reports.

The provider surface is intentionally narrow in J. External KMS and OS keychain integrations remain future provider adapters.

## J.6 — Reports

Each protected APK can emit a public report. The Gradle task also emits variant-summary.json.

Public reports live under build/reports/nexora-shield/<variant>/.

Private reports are opt-in and isolated under build/nexora-shield/private/<variant>/.

## J.7 — Mapping / Retrace

For R8-minified variants, Phase J preserves the AGP mapping.txt into a stable per-variant archive.

The retrace task uses the Android command-line Retrace executable and writes its result into the public report directory.

The plugin does not implement an incomplete proprietary retrace algorithm.

## J.8 — Build cache strategy

NexoraShieldApkTransformTask is disabled from caching by default.

Runtime cache opt-in is accepted only for the narrow reproducible case where:

- buildCacheEnabled=true;
- output is explicitly unsigned;
- no signing keystore is configured;
- public reports are disabled;
- private reports are disabled.

This prevents secret rotation, signing state or path-bearing reports from becoming invisible cache inputs.

## J.9 — CI examples

examples/ci/nexora-shield-gradle.yml provides a GitHub Actions reference flow with JDK, Gradle, CLI build, release build and public-report publication.

The main repository CI adds dedicated plugin and sample-app gates.

## J.10 — Sample apps

samples/gradle-plugin/basic-app is a minimal Android application using the composite-build form of the Nexora Shield Gradle plugin.

Its release build is intentionally unsigned and unaligned for repository CI so the integration test does not require production signing material.

## Security boundary

The Gradle plugin is orchestration. It does not turn build-time secrets into runtime secrets and it does not make Android client code uninspectable.

The plugin deliberately avoids logging raw secret values. Production release signing remains an explicit external trust boundary.
