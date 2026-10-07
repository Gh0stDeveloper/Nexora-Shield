# Nexora Shield 1.0 — compatibility review

> **Post-Phase-N audit clarification:** this is the Phase N declared compatibility contract. Phase O requires broader real-device/API/OEM validation before stable production approval, so this matrix must not be interpreted as proof that every listed environment has already passed full-stack O.1 production protection.

The machine-readable compatibility contract is `../release/compatibility-matrix.json`.

## 1.0 stable matrix

| Surface | Supported stable contract |
| --- | --- |
| Rust | MSRV 1.81 |
| Android | minSdk 24+ |
| JDK | 17 |
| Gradle | 9.7.0 |
| Android Gradle Plugin | 9.4.1 |
| Native ABIs | arm64-v8a, x86_64 |
| Android artifacts | APK, AAB, AAR, APKS |
| Shield Studio | Linux, macOS, Windows |

CI must retain the existing Android native ABI tests, package-model regressions, Gradle sample integration and Shield Studio compile/tests.

Support outside this matrix is best-effort until explicitly promoted into the compatibility contract.
