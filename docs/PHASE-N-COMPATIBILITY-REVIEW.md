# Nexora Shield 1.0 RC — compatibility review

The machine-readable compatibility contract is `../release/compatibility-matrix.json`.

## 1.0 candidate matrix

| Surface | Supported candidate |
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
