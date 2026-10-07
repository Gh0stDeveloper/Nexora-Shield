# Phase J basic Android sample

This sample proves that an Android application can activate Nexora Shield from Gradle without a manual APK post-processing pipeline.

The sample intentionally uses AGP 9.4.1, Gradle 9.6.x, JDK 17, the dev.nexora.shield plugin, release-only protection, unsigned output for CI only, and public reports.

For production, replace allowUnsigned=true with explicit signing configuration and env: or file: secret references.
