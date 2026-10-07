use nexora_shield_native::{
    Abi, AbiDecision, AbiPolicy, ExportPolicy, GeneratedNativeData, HardeningProfile,
    NativeError, NativeRegion, NativeRuntimeDescriptor, NATIVE_RUNTIME_API_VERSION,
    PRIMARY_ANDROID_ABIS, REQUIRED_JNI_EXPORTS,
};
use std::str::FromStr;

#[test]
fn runtime_descriptor_has_stable_api_version() {
    let descriptor = NativeRuntimeDescriptor::current();
    assert_eq!(descriptor.api_version, NATIVE_RUNTIME_API_VERSION);
    assert_eq!(descriptor.crate_version, env!("CARGO_PKG_VERSION"));
    assert_ne!(descriptor.target_arch, "");
}

#[test]
fn primary_android_abis_are_arm64_and_x86_64() {
    assert_eq!(PRIMARY_ANDROID_ABIS, [Abi::Arm64V8a, Abi::X86_64]);
    assert_eq!(Abi::Arm64V8a.android_name(), "arm64-v8a");
    assert_eq!(Abi::Arm64V8a.rust_target(), "aarch64-linux-android");
    assert_eq!(Abi::X86_64.android_name(), "x86_64");
    assert_eq!(Abi::X86_64.rust_target(), "x86_64-linux-android");
}

#[test]
fn default_abi_policy_rejects_32_bit_fallbacks() {
    let policy = AbiPolicy::default();
    assert_eq!(policy.decision(Abi::Arm64V8a), AbiDecision::Primary);
    assert_eq!(policy.decision(Abi::X86_64), AbiDecision::Primary);
    assert_eq!(policy.decision(Abi::ArmeabiV7a), AbiDecision::Rejected);
    assert_eq!(policy.decision(Abi::X86), AbiDecision::Rejected);
}

#[test]
fn additional_abis_require_explicit_32_bit_policy() {
    let denied = AbiPolicy::with_additional(false, [Abi::ArmeabiV7a]);
    assert!(!denied.allows(Abi::ArmeabiV7a));

    let allowed = AbiPolicy::with_additional(true, [Abi::ArmeabiV7a]);
    assert!(allowed.allow_32_bit());
    assert_eq!(
        allowed.decision(Abi::ArmeabiV7a),
        AbiDecision::AdditionalAllowed
    );
    assert_eq!(allowed.decision(Abi::X86), AbiDecision::Rejected);
}

#[test]
fn abi_parser_is_strict() {
    assert_eq!(Abi::from_str("arm64-v8a"), Ok(Abi::Arm64V8a));
    assert_eq!(Abi::from_str("x86_64"), Ok(Abi::X86_64));
    assert!(matches!(
        Abi::from_str("mips"),
        Err(NativeError::UnsupportedAbi(_))
    ));
}

#[test]
fn native_region_detects_mutation() -> Result<(), NativeError> {
    let clean = b"native-code-region-v1";
    let region = NativeRegion::new(".text:critical", clean)?;

    let clean_check = region.verify(clean);
    assert!(clean_check.matched);

    let tampered_check = region.verify(b"native-code-region-v2");
    assert!(!tampered_check.matched);
    assert_ne!(clean_check.observed, tampered_check.observed);
    Ok(())
}

#[test]
fn native_region_rejects_empty_label() {
    assert_eq!(
        NativeRegion::new("  ", b"bytes"),
        Err(NativeError::EmptyRegionLabel)
    );
}

#[test]
fn generated_native_data_is_deterministic_and_build_specific() -> Result<(), NativeError> {
    let first = GeneratedNativeData::derive("release-100", b"private-seed-a")?;
    let same = GeneratedNativeData::derive("release-100", b"private-seed-a")?;
    let different_build = GeneratedNativeData::derive("release-101", b"private-seed-a")?;
    let different_seed = GeneratedNativeData::derive("release-100", b"private-seed-b")?;

    assert_eq!(first, same);
    assert_ne!(first, different_build);
    assert_ne!(first, different_seed);
    Ok(())
}

#[test]
fn generated_native_data_rejects_missing_inputs() {
    assert_eq!(
        GeneratedNativeData::derive("", b"seed"),
        Err(NativeError::EmptyBuildId)
    );
    assert_eq!(
        GeneratedNativeData::derive("build", b""),
        Err(NativeError::EmptySeed)
    );
}

#[test]
fn production_hardening_profile_is_complete() {
    assert!(HardeningProfile::production().is_production_hardened());
}

#[test]
fn export_policy_contains_only_required_jni_surface() {
    assert_eq!(ExportPolicy::required(), &REQUIRED_JNI_EXPORTS);
    assert_eq!(ExportPolicy::required().len(), 2);
    for symbol in REQUIRED_JNI_EXPORTS {
        assert!(ExportPolicy::is_required(symbol));
    }
    assert!(!ExportPolicy::is_required("internal_secret_helper"));
}
