//! JNI owns Android references; all cryptography and VM execution stay in safe Rust.
use crate::{RuntimeError, RuntimeImage};
#[path = "runtime_guard_jni.rs"]
mod guard;
use jni::{
    objects::{JClass, JIntArray, JString},
    sys::{jint, jstring},
    JNIEnv,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::OnceLock,
};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/runtime_image.rs"));
}
static IMAGE: OnceLock<Option<RuntimeImage>> = OnceLock::new();

fn image() -> Result<&'static RuntimeImage, RuntimeError> {
    IMAGE
        .get_or_init(embedded::image)
        .as_ref()
        .ok_or(RuntimeError("runtime image is not configured"))
}

fn reject(env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(true) {
        return;
    }
    let _ = env.throw_new(
        "java/lang/SecurityException",
        "Nexora runtime rejected the operation",
    );
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nBind(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    expected: JString<'_>,
) {
    let valid = env.get_string(&expected).is_ok_and(|value| {
        value
            .to_str()
            .is_ok_and(|value| value == std::hint::black_box(embedded::COMMITMENT))
    }) && image().and_then(RuntimeImage::authenticate).is_ok();
    if !valid {
        reject(&mut env);
    }
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nString(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    slot: jint,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| {
        guard::check(&mut env)?;
        let slot = u32::try_from(slot).map_err(|_| RuntimeError("invalid runtime slot"))?;
        image()?.decrypt_string(slot)
    }));
    if let Ok(Ok(plaintext)) = result {
        if let Ok(value) = env.new_string(plaintext.as_str()) {
            return value.into_raw();
        }
    }
    reject(&mut env);
    std::ptr::null_mut()
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nInt(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    slot: jint,
    arguments: JIntArray<'_>,
) -> jint {
    let result = (|| {
        guard::check(&mut env)?;
        let slot = u32::try_from(slot).map_err(|_| RuntimeError("invalid runtime slot"))?;
        let length = env
            .get_array_length(&arguments)
            .map_err(|_| RuntimeError("invalid VM arguments"))?;
        let length = usize::try_from(length).map_err(|_| RuntimeError("invalid VM arguments"))?;
        if length > 16 {
            return Err(RuntimeError("too many VM arguments"));
        }
        let mut args = vec![0; length];
        env.get_int_array_region(&arguments, 0, &mut args)
            .map_err(|_| RuntimeError("invalid VM arguments"))?;
        catch_unwind(AssertUnwindSafe(|| image()?.execute_int_vm(slot, &args)))
            .map_err(|_| RuntimeError("VM execution boundary rejected"))?
    })();
    if let Ok(value) = result {
        value
    } else {
        reject(&mut env);
        0
    }
}
