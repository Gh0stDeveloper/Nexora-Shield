use crate::abi::Abi;
use crate::runtime::NATIVE_RUNTIME_API_VERSION;
use core::ffi::c_void;

type JInt = i32;
type JniEnv = *mut c_void;
type JClass = *mut c_void;

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nativeRuntimeApiVersion(
    _env: JniEnv,
    _class: JClass,
) -> JInt {
    i32::try_from(NATIVE_RUNTIME_API_VERSION).unwrap_or(i32::MAX)
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nativeAbiCode(
    _env: JniEnv,
    _class: JClass,
) -> JInt {
    abi_code_for_target()
}

const fn abi_code_for_target() -> JInt {
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

const fn abi_code(abi: Abi) -> JInt {
    match abi {
        Abi::Arm64V8a => 64,
        Abi::X86_64 => 65,
        Abi::ArmeabiV7a => 32,
        Abi::X86 => 33,
    }
}
