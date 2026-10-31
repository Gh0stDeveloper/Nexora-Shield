//! Bounded access to the actual encrypted asset supplied by Android AssetManager.
use super::{guard, image, reject};
use crate::RuntimeError;
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroizing;

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nOpenAsset(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    manager: JObject<'_>,
    name: JString<'_>,
    mode: jint,
) -> jobject {
    let result = catch_unwind(AssertUnwindSafe(|| {
        open_asset(&mut env, &manager, &name, mode)
    }));
    if let Ok(Ok(object)) = result {
        return object;
    }
    reject(&mut env);
    std::ptr::null_mut()
}
fn open_asset(
    env: &mut JNIEnv<'_>,
    manager: &JObject<'_>,
    name: &JString<'_>,
    mode: jint,
) -> Result<jobject, RuntimeError> {
    guard::check(env)?;
    if manager.is_null() || name.is_null() {
        let _ = env.throw_new(
            "java/lang/NullPointerException",
            "asset manager and name are required",
        );
        return Err(RuntimeError("null asset argument"));
    }
    let filename: String = env
        .get_string(name)
        .map_err(|_| RuntimeError("invalid asset name"))?
        .into();
    let path = format!("assets/{filename}");
    let slot = image()?.resource_slot(&path)?;
    let stream = env
        .call_method(
            manager,
            "open",
            "(Ljava/lang/String;I)Ljava/io/InputStream;",
            &[JValue::Object(name), JValue::Int(mode)],
        )
        .and_then(jni::objects::JValueGen::l)
        .map_err(|_| RuntimeError("Android asset open failed"))?;
    let Some(slot) = slot else {
        return Ok(stream.into_raw());
    };
    let result = read_stream(env, &stream);
    // Always release the actual AssetInputStream, including a bounded-read failure.
    let pending = if env.exception_check().unwrap_or(true) {
        let exception = env
            .exception_occurred()
            .map_err(|_| RuntimeError("asset exception unavailable"))?;
        env.exception_clear()
            .map_err(|_| RuntimeError("asset exception clear failed"))?;
        Some(exception)
    } else {
        None
    };
    let close = env.call_method(&stream, "close", "()V", &[]);
    if let Some(exception) = pending {
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
        }
        let _ = env.throw(exception);
    }
    let encoded = result?;
    close.map_err(|_| RuntimeError("Android asset close failed"))?;
    let plaintext = image()?.decrypt_resource(slot, &encoded)?;
    let array = env
        .byte_array_from_slice(plaintext.as_slice())
        .map_err(|_| RuntimeError("asset result allocation failed"))?;
    let object = env
        .new_object(
            "dev/nexora/shield/ResourceInputStream",
            "([B)V",
            &[JValue::Object(&array)],
        )
        .map_err(|_| RuntimeError("asset stream allocation failed"))?;
    Ok(object.into_raw())
}
fn read_stream(
    env: &mut JNIEnv<'_>,
    stream: &JObject<'_>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let buffer = env
        .new_byte_array(4096)
        .map_err(|_| RuntimeError("asset buffer allocation failed"))?;
    let mut encoded = Zeroizing::new(Vec::new());
    loop {
        let count = env
            .call_method(stream, "read", "([B)I", &[JValue::Object(&buffer)])
            .and_then(jni::objects::JValueGen::i)
            .map_err(|_| RuntimeError("Android asset read failed"))?;
        if count == -1 {
            break;
        }
        let count =
            usize::try_from(count).map_err(|_| RuntimeError("invalid asset read result"))?;
        if count == 0 || count > 4096 || encoded.len() + count > 1024 * 1024 + 4096 {
            return Err(RuntimeError("asset read budget exceeded"));
        }
        let chunk = env
            .convert_byte_array(&buffer)
            .map_err(|_| RuntimeError("asset byte copy failed"))?;
        encoded.extend_from_slice(&chunk[..count]);
    }
    Ok(encoded)
}
