pub const REQUIRED_JNI_EXPORTS: [&str; 2] = [
    "Java_dev_nexora_shield_NativeShield_nativeRuntimeApiVersion",
    "Java_dev_nexora_shield_NativeShield_nativeAbiCode",
];

pub const RUNTIME_JNI_EXPORTS: [&str; 4] = [
    "Java_dev_nexora_shield_NativeShield_nBind",
    "Java_dev_nexora_shield_NativeShield_nInt",
    "Java_dev_nexora_shield_NativeShield_nString",
    "Java_dev_nexora_shield_NativeShield_nStart",
];

#[derive(Debug, Default, Clone, Copy)]
pub struct ExportPolicy;

impl ExportPolicy {
    #[must_use]
    pub fn is_required(symbol: &str) -> bool {
        REQUIRED_JNI_EXPORTS.contains(&symbol)
    }

    #[must_use]
    pub fn required() -> &'static [&'static str] {
        &REQUIRED_JNI_EXPORTS
    }
}
