use crate::abi::Abi;
use jni::objects::JClass;
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::ptr;

#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nativeRuntimeVersion(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    match env.new_string(env!("CARGO_PKG_VERSION")) {
        Ok(value) => value.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nativeAbiCode(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    abi_code_for_target()
}

const fn abi_code_for_target() -> jint {
    #[cfg(target_arch = "aarch64")]
    {
        return abi_code(Abi::Arm64V8a);
    }
    #[cfg(target_arch = "x86_64")]
    {
        return abi_code(Abi::X86_64);
    }
    #[cfg(target_arch = "arm")]
    {
        return abi_code(Abi::ArmeabiV7a);
    }
    #[cfg(target_arch = "x86")]
    {
        return abi_code(Abi::X86);
    }
    #[allow(unreachable_code)]
    0
}

const fn abi_code(abi: Abi) -> jint {
    match abi {
        Abi::Arm64V8a => 64,
        Abi::X86_64 => 65,
        Abi::ArmeabiV7a => 32,
        Abi::X86 => 33,
    }
}
