use nexora_shield_crypto::BuildIdentity;
use nexora_shield_native::RuntimeImage;
use nexora_shield_vm::{ConstantPool, VmInstruction as I, VmMethod, VmRegister as R};

fn image() -> Result<RuntimeImage, Box<dyn std::error::Error>> {
    Ok(RuntimeImage::new(
        &[42; 32],
        BuildIdentity::new("dev.nexora.runtime", "test-build")?,
    )?)
}
fn method() -> VmMethod {
    VmMethod {
        method_idx: 0,
        register_count: 3,
        parameter_registers: vec![R(1), R(2)],
        constants: ConstantPool::default(),
        handlers: vec![],
        instructions: vec![
            I::Add {
                dst: R(0),
                left: R(1),
                right: R(2),
            },
            I::Return { src: R(0) },
        ],
    }
}

#[test]
fn runtime_image_authenticates_string_and_executes_actual_vm_bytecode(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut image = image()?;
    image.protect_string(0, "protected probe \0 فارسی 🔒")?;
    image.protect_int_vm(1, &method())?;
    assert_eq!(
        image.decrypt_string(0)?.as_str(),
        "protected probe \0 فارسی 🔒"
    );
    for (a, b) in [(1, 2), (i32::MAX, 1), (i32::MIN, -1), (-18, 9)] {
        assert_eq!(image.execute_int_vm(1, &[a, b])?, a.wrapping_add(b));
    }
    assert!(image.execute_int_vm(0, &[]).is_err());
    assert!(image.decrypt_string(1).is_err());
    assert!(image.execute_int_vm(1, &[1]).is_err());
    assert!(image.decrypt_string(u32::MAX).is_err());
    assert!(!serde_json::to_vec(&image)?
        .windows(b"protected probe".len())
        .any(|w| w == b"protected probe"));
    assert!(!format!("{image:?}").contains("42"));
    Ok(())
}

#[test]
fn runtime_image_rejects_tamper_wrong_build_key_and_duplicate_slot(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut original = image()?;
    original.protect_string(0, "secret")?;
    assert!(original.protect_string(0, "duplicate").is_err());
    let mut bad = original.clone();
    bad.entries[0].ciphertext[90] ^= 1;
    assert!(bad.decrypt_string(0).is_err());
    bad = original.clone();
    bad.build_id.push('x');
    assert!(bad.decrypt_string(0).is_err());
    bad = original;
    bad.key_share_a[0] ^= 1;
    assert!(bad.decrypt_string(0).is_err());
    Ok(())
}

#[test]
fn runtime_vm_refuses_host_operations_and_unbounded_loops() -> Result<(), Box<dyn std::error::Error>>
{
    let mut image = image()?;
    let mut invalid = method();
    invalid.instructions[0] = I::Jump { target: 0 };
    assert!(image.protect_int_vm(0, &invalid).is_err());
    invalid = method();
    invalid.instructions[0] = I::Call {
        dst: Some(R(0)),
        method: 1,
        args: vec![],
    };
    assert!(image.protect_int_vm(0, &invalid).is_err());
    assert_eq!(image.entries.len(), 0);
    Ok(())
}

#[test]
fn runtime_constant_engine_preserves_integer_and_float_bits_and_rejects_tamper(
) -> Result<(), Box<dyn std::error::Error>> {
    use nexora_shield_crypto::ConstantValue;
    let cases = [
        (ConstantValue::Bool(true), 1),
        (
            ConstantValue::I32(-19),
            u64::from(u32::from_le_bytes((-19i32).to_le_bytes())),
        ),
        (ConstantValue::I64(i64::MIN), 1u64 << 63),
        (ConstantValue::F32(-0.0), u64::from((-0.0f32).to_bits())),
        (ConstantValue::F64(2.5), (2.5f64).to_bits()),
    ];
    let mut runtime = image()?;
    for (index, (value, bits)) in cases.iter().enumerate() {
        let slot = u32::try_from(index)?;
        runtime.protect_constant(slot, value)?;
        assert_eq!(runtime.constant_bits(slot)?, *bits);
        assert!(runtime.decrypt_string(slot).is_err());
        assert!(runtime.execute_int_vm(slot, &[]).is_err());
    }
    assert!(runtime
        .protect_constant(71, &ConstantValue::Bytes(vec![1, 2, 3]))
        .is_err());
    assert!(runtime
        .protect_constant(0, &ConstantValue::Bool(false))
        .is_err());
    runtime.entries[0].ciphertext[90] ^= 1;
    assert!(runtime.constant_bits(0).is_err());
    Ok(())
}

#[test]
fn runtime_assets_bind_actual_bundle_path_build_and_slot() -> Result<(), Box<dyn std::error::Error>>
{
    let mut image = RuntimeImage::new(
        &[31; 32],
        BuildIdentity::new("dev.nexora.assets", "build-a")?,
    )?;
    let data = b"asset-private-\0\xff-payload".to_vec();
    let bundle = image.protect_resource(256, "assets/data.bin", data.clone())?;
    assert!(!bundle.windows(data.len()).any(|w| w == data));
    assert_eq!(image.resource_slot("assets/data.bin")?, Some(256));
    assert_eq!(image.resource_slot("assets/other.bin")?, None);
    assert_eq!(image.decrypt_resource(256, &bundle)?.as_slice(), data);
    assert!(image
        .protect_resource(257, "assets/data.bin", data.clone())
        .is_err());
    assert!(image
        .protect_resource(257, "resources.arsc", data.clone())
        .is_err());
    assert!(image
        .protect_resource(257, "assets/../bad", data.clone())
        .is_err());
    let mut corrupt = bundle.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(image.decrypt_resource(256, &corrupt).is_err());
    assert!(image.decrypt_resource(0, &bundle).is_err());
    let other = image.protect_resource(257, "assets/other.bin", data)?;
    assert!(image.decrypt_resource(256, &other).is_err());
    let mut wrong_build = image.clone();
    wrong_build.build_id = "wrong-build".into();
    assert!(wrong_build.decrypt_resource(256, &bundle).is_err());
    let mut wrong_key = image.clone();
    wrong_key.key_share_b[0] ^= 1;
    assert!(wrong_key.decrypt_resource(256, &bundle).is_err());
    let empty = image.protect_resource(258, "assets/empty.bin", Vec::new())?;
    assert_eq!(image.decrypt_resource(258, &empty)?.as_slice(), b"");
    assert!(image
        .protect_resource(259, "assets/oversized.bin", vec![1; 1024 * 1024 + 1])
        .is_err());
    image.authenticate()?;
    Ok(())
}

#[test]
fn explicit_runtime_vm_map_rejects_foreign_build_and_broken_decode_without_partial_entries(
) -> Result<(), Box<dyn std::error::Error>> {
    use nexora_shield_vm::OpcodeAllocation;
    let mut image = image()?;
    let foreign = OpcodeAllocation::derive("foreign-build", &[63; 32])?;
    assert!(image
        .protect_int_vm_with_allocation(0, &method(), foreign)
        .is_err());
    assert_eq!(image.entries.len(), 0);
    let allocation = OpcodeAllocation::derive(&image.build_id, &[63; 32])?;
    let mut encoded = serde_json::to_value(&allocation)?;
    encoded["decode"] = serde_json::json!({});
    let malformed = serde_json::from_value(encoded)?;
    assert!(image
        .protect_int_vm_with_allocation(0, &method(), malformed)
        .is_err());
    assert_eq!(image.entries.len(), 0);
    image.protect_int_vm_with_allocation(0, &method(), allocation)?;
    assert_eq!(image.execute_int_vm(0, &[i32::MAX, 1])?, i32::MIN);
    let stats = image.int_vm_evidence(0)?;
    assert_eq!(stats.instruction_count, 2);
    assert_eq!(stats.opcode_map_sha256.len(), 64);
    assert_eq!(stats.opcode_stream_sha256.len(), 64);
    assert!(image.int_vm_evidence(99).is_err());
    Ok(())
}
