# Phase K — AAB / AAR / Splits checklist

## K.1 AAB parser/model
- [x] Dedicated AAB inspection model
- [x] BundleConfig.pb detection
- [x] Base-module detection
- [x] Per-module DEX discovery
- [x] Canonical per-module multidex validation
- [x] resources.pb/resources/assets/native ABI discovery
- [x] Bundle metadata discovery
- [x] Structural regression fixtures

## K.2 bundletool validation
- [x] bundletool 1.18.3 pinned
- [x] SHA-256 pinned and verified
- [x] Official validate wrapper
- [x] Official build-apks wrapper
- [x] Default/universal modes
- [x] Password-file signing inputs
- [x] Final real-AAB bundletool gate

## K.3 Dynamic features
- [x] Feature modules represented in AAB model
- [x] On-demand feature sample
- [x] Feature-local namespace/resources/code
- [x] Final bundle feature-count gate

## K.4 Split APK testing
- [x] APK Set model
- [x] toc.pb validation
- [x] Split/standalone/universal classification
- [x] Default APK Set CI flow
- [x] Universal APK Set CI flow
- [x] Final real bundletool split gate

## K.5 Play App Signing compatibility
- [x] Upload certificate modeled separately
- [x] Delivery certificate set
- [x] Delivery signing lineage
- [x] Upload certificate excluded from runtime binding by default
- [x] Upload-signed AAB sample
- [x] Final upload-signing integration gate

## K.6 AAR consumer rules
- [x] AAR structural model
- [x] Consumer-rule discovery
- [x] Library sample consumer rules
- [x] Library mode can require consumer rules
- [x] Final AAR gate

## K.7 Library protection mode
- [x] com.android.library plugin support
- [x] Library Variant API
- [x] SingleArtifact.AAR validation
- [x] Release-only defaults
- [x] Standard-AAR/D8-Dex boundary documented
- [x] Final library Gradle gate

## K.8 Resource namespaces
- [x] AAR resource contract inspection
- [x] Dynamic-feature resources
- [x] Independent Maven consumer sample
- [x] Final consumer compilation gate

## K.9 Baseline profiles interaction
- [x] AAB compiled profile detection
- [x] AAR source profile detection
- [x] App Baseline Profile sample
- [x] Library Baseline Profile sample
- [x] Final profile-preservation gate

## K.10 Publishing tests
- [x] Maven publication sample
- [x] Temporary Maven repository
- [x] Independent consumer project
- [x] Minified consumer release
- [x] Final publishing/consumer CI gate

## Closure state

Phase K is **COMPLETED**. K.1–K.10 are implemented and all final acceptance gates passed on the final branch head before merge.

Validated by GitHub Actions:
- Phase K run #25 (`37588269683`): **success**
- CI run #849 (`37588269688`): **success**
- `K.1-K.5 AAB bundletool splits Play signing`: **success**
- `K.6-K.10 AAR publishing and consumer`: **success**
- `K.1-K.9 package models`: **success**
- `K package models Rust 1.81 MSRV`: **success**

PR #13 was merged into `main` with merge commit `7211607b34cc320dd80e52e523f41f364cfe2e77`.
