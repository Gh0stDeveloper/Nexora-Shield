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
