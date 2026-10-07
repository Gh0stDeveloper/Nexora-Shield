mod common;

use common::{add_dex, branch_dex};
use nexora_shield_vm::{
    DexLowerer, EligibilityPolicy, ExecutionConfig, Interpreter, NullHost, VmValue,
};

#[test]
fn differential_add_matches_reference_for_4096_cases() -> Result<(), Box<dyn std::error::Error>> {
    let method = DexLowerer::lower(&add_dex(), 0, EligibilityPolicy::default())?;
    let mut host = NullHost;
    let mut state = 0x4e45_584f_5241_4744_u64;

    for _ in 0..4_096 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let left = i32::from_le_bytes(
            u32::try_from(state & u64::from(u32::MAX))
                .unwrap_or(0)
                .to_le_bytes(),
        );
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let right = i32::from_le_bytes(
            u32::try_from(state & u64::from(u32::MAX))
                .unwrap_or(0)
                .to_le_bytes(),
        );

        let expected = left.wrapping_add(right);
        let actual = Interpreter::execute(
            &method,
            &[VmValue::Int(left), VmValue::Int(right)],
            &mut host,
            ExecutionConfig::default(),
        )?
        .value;
        assert_eq!(actual, VmValue::Int(expected));
    }
    Ok(())
}

#[test]
fn differential_branch_matches_reference_for_boundary_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let method = DexLowerer::lower(&branch_dex(), 0, EligibilityPolicy::default())?;
    let mut host = NullHost;

    for condition in [i32::MIN, -1, 0, 1, i32::MAX] {
        let when_nonzero = 11;
        let when_zero = 22;
        let expected = if condition == 0 {
            when_zero
        } else {
            when_nonzero
        };
        let actual = Interpreter::execute(
            &method,
            &[
                VmValue::Int(condition),
                VmValue::Int(when_nonzero),
                VmValue::Int(when_zero),
            ],
            &mut host,
            ExecutionConfig::default(),
        )?
        .value;
        assert_eq!(actual, VmValue::Int(expected));
    }
    Ok(())
}
