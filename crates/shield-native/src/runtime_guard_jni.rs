use super::{image, reject};
use crate::{RuntimeApkGuard, RuntimeError};
use jni::{
    objects::{JByteArray, JClass, JObject, JObjectArray, JString, JValue},
    sys::jint,
    JNIEnv,
};
use nexora_shield_integrity::{CertificateObservation, PackageObservation, Sha256Digest};
use nexora_shield_rasp::{
    DebugObservation, EmulatorObservation, HookInjectionObservation, PolicyMode, RaspResponse,
    ResponseDecision, RiskLevel,
};
use std::{io::Read, path::Path, sync::OnceLock};

struct ActiveGuard {
    guard: RuntimeApkGuard,
    debuggable: bool,
    emulator: EmulatorObservation,
}
static GUARD: OnceLock<ActiveGuard> = OnceLock::new();
type Result<T> = std::result::Result<T, RuntimeError>;
fn failed() -> RuntimeError {
    RuntimeError("Android guard observation or verification failed")
}

pub(super) fn check(env: &mut JNIEnv<'_>) -> Result<()> {
    if image()?.guard_key.is_none() {
        return Ok(());
    }
    let guard = GUARD
        .get()
        .ok_or(RuntimeError("APK guard was not initialized"))?;
    let decision = decision(env, guard)?;
    if matches!(
        decision.effective_response,
        RaspResponse::RequireReverification | RaspResponse::DenySensitiveOperation
    ) {
        return Err(RuntimeError("RASP denied the protected operation"));
    }
    Ok(())
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_dev_nexora_shield_NativeShield_nStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) -> jint {
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| start(&mut env, &context)));
    if let Ok(Ok(status)) = result {
        status
    } else {
        reject(&mut env);
        -1
    }
}

fn start(env: &mut JNIEnv<'_>, context: &JObject<'_>) -> Result<i32> {
    let active = collect_and_verify(env, context)?;
    let result = decision(env, &active)?;
    if matches!(
        result.effective_response,
        RaspResponse::RequireReverification | RaspResponse::DenySensitiveOperation
    ) {
        return Err(RuntimeError("RASP requires reverification or denial"));
    }
    GUARD
        .set(active)
        .map_err(|_| RuntimeError("APK guard already initialized"))?;
    let level = match result.risk_level {
        RiskLevel::Clean => 0,
        RiskLevel::Observed => 1,
        RiskLevel::Elevated => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    };
    let signals = i32::try_from(result.signals_evaluated).map_err(|_| failed())?;
    Ok((1 << 25)
        | if result.policy_mode == PolicyMode::ReportOnly {
            1 << 24
        } else {
            0
        }
        | (level << 16)
        | signals)
}

fn collect_and_verify(env: &mut JNIEnv<'_>, context: &JObject<'_>) -> Result<ActiveGuard> {
    let package = string_call(env, context, "getPackageName")?;
    let info = env
        .call_method(
            context,
            "getApplicationInfo",
            "()Landroid/content/pm/ApplicationInfo;",
            &[],
        )
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let path = string_field(env, &info, "sourceDir")?;
    let splits = env
        .get_field(&info, "splitSourceDirs", "[Ljava/lang/String;")
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    if !splits.is_null()
        && env
            .get_array_length(&JObjectArray::from(splits))
            .map_err(|_| failed())?
            != 0
    {
        return Err(RuntimeError(
            "split APK guard requires split-aware protection",
        ));
    }
    let flags = env
        .get_field(&info, "flags", "I")
        .and_then(jni::objects::JValueOwned::i)
        .map_err(|_| failed())?;
    let sdk = env
        .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
        .and_then(jni::objects::JValueOwned::i)
        .map_err(|_| failed())?;
    let manager = env
        .call_method(
            context,
            "getPackageManager",
            "()Landroid/content/pm/PackageManager;",
            &[],
        )
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let name = JObject::from(env.new_string(&package).map_err(|_| failed())?);
    let package_info = env
        .call_method(
            &manager,
            "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
            &[
                JValue::Object(&name),
                JValue::Int(if sdk >= 28 { 0x0800_0000 } else { 0x40 }),
            ],
        )
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let certificate = observe_signer(env, &package_info, sdk)?;
    let version = if sdk >= 28 {
        u64::try_from(
            env.call_method(&package_info, "getLongVersionCode", "()J", &[])
                .and_then(jni::objects::JValueOwned::j)
                .map_err(|_| failed())?,
        )
        .map_err(|_| failed())?
    } else {
        u64::from(u32::from_ne_bytes(
            env.get_field(&package_info, "versionCode", "I")
                .and_then(jni::objects::JValueOwned::i)
                .map_err(|_| failed())?
                .to_ne_bytes(),
        ))
    };
    let package = PackageObservation::new(package, version, None).map_err(|_| failed())?;
    let guard = RuntimeApkGuard::verify(Path::new(&path), image()?, certificate, package)?;
    let fingerprint = build_field(env, "FINGERPRINT")?.to_ascii_lowercase();
    let model = build_field(env, "MODEL")?.to_ascii_lowercase();
    let emulator = EmulatorObservation {
        generic_build_profile: fingerprint.contains("generic"),
        emulator_device_profile: ["sdk_", "gphone", "emulator"]
            .iter()
            .any(|value| model.contains(value) || fingerprint.contains(value)),
        ..EmulatorObservation::default()
    };
    Ok(ActiveGuard {
        guard,
        debuggable: flags & 2 != 0,
        emulator,
    })
}

fn decision(env: &mut JNIEnv<'_>, active: &ActiveGuard) -> Result<ResponseDecision> {
    let status = proc_text("/proc/self/status", 64 * 1024)?;
    let tracer = status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .ok_or_else(failed)?
        .trim()
        .parse::<u32>()
        .map_err(|_| failed())?;
    let connected = env
        .call_static_method("android/os/Debug", "isDebuggerConnected", "()Z", &[])
        .and_then(jni::objects::JValueOwned::z)
        .map_err(|_| failed())?;
    let waiting = env
        .call_static_method("android/os/Debug", "waitingForDebugger", "()Z", &[])
        .and_then(jni::objects::JValueOwned::z)
        .map_err(|_| failed())?;
    let debug = DebugObservation {
        application_debuggable: active.debuggable,
        debugger_connected: connected,
        waiting_for_debugger: waiting,
        tracer_pid: Some(tracer),
        ..DebugObservation::default()
    };
    let maps = proc_text("/proc/self/maps", 4 * 1024 * 1024)?.to_ascii_lowercase();
    let count = [
        "frida-agent",
        "libfrida-gadget",
        "libxposed_art",
        "libsubstrate",
    ]
    .iter()
    .filter(|name| maps.contains(**name))
    .count();
    let hooks = HookInjectionObservation {
        injected_library_count: u16::try_from(count).map_err(|_| failed())?,
        ..HookInjectionObservation::default()
    };
    Ok(active.guard.evaluate(&debug, &active.emulator, &hooks))
}
fn proc_text(path: &str, limit: u64) -> Result<String> {
    let file = std::fs::File::open(path).map_err(|_| failed())?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failed())?;
    if u64::try_from(bytes.len()).map_err(|_| failed())? > limit {
        return Err(failed());
    }
    String::from_utf8(bytes).map_err(|_| failed())
}
fn string_call(env: &mut JNIEnv<'_>, object: &JObject<'_>, method: &str) -> Result<String> {
    let value = env
        .call_method(object, method, "()Ljava/lang/String;", &[])
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let text = JString::from(value);
    let value = env.get_string(&text).map_err(|_| failed())?;
    value.to_str().map(str::to_owned).map_err(|_| failed())
}
fn string_field(env: &mut JNIEnv<'_>, object: &JObject<'_>, field: &str) -> Result<String> {
    let value = env
        .get_field(object, field, "Ljava/lang/String;")
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let text = JString::from(value);
    let value = env.get_string(&text).map_err(|_| failed())?;
    value.to_str().map(str::to_owned).map_err(|_| failed())
}
fn build_field(env: &mut JNIEnv<'_>, field: &str) -> Result<String> {
    let value = env
        .get_static_field("android/os/Build", field, "Ljava/lang/String;")
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let text = JString::from(value);
    let value = env.get_string(&text).map_err(|_| failed())?;
    value.to_str().map(str::to_owned).map_err(|_| failed())
}

fn observe_signer(
    env: &mut JNIEnv<'_>,
    package_info: &JObject<'_>,
    sdk: i32,
) -> Result<CertificateObservation> {
    let signatures = if sdk >= 28 {
        let signing = env
            .get_field(
                package_info,
                "signingInfo",
                "Landroid/content/pm/SigningInfo;",
            )
            .and_then(jni::objects::JValueOwned::l)
            .map_err(|_| failed())?;
        env.call_method(
            signing,
            "getApkContentsSigners",
            "()[Landroid/content/pm/Signature;",
            &[],
        )
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?
    } else {
        env.get_field(
            package_info,
            "signatures",
            "[Landroid/content/pm/Signature;",
        )
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?
    };
    let signatures = JObjectArray::from(signatures);
    if env.get_array_length(&signatures).map_err(|_| failed())? != 1 {
        return Err(failed());
    }
    let signer = env
        .get_object_array_element(&signatures, 0)
        .map_err(|_| failed())?;
    let der = env
        .call_method(signer, "toByteArray", "()[B", &[])
        .and_then(jni::objects::JValueOwned::l)
        .map_err(|_| failed())?;
    let der = env
        .convert_byte_array(JByteArray::from(der))
        .map_err(|_| failed())?;
    if der.len() > 65536 {
        return Err(failed());
    }
    CertificateObservation::new([Sha256Digest::of(&der)], []).map_err(|_| failed())
}
