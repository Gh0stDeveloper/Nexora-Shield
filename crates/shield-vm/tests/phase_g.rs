mod common;

use common::{add_dex, unsupported_dex};
use nexora_shield_vm::{
    BranchCondition, ConstantPool, DexLowerer, EligibilityAnalyzer, EligibilityPolicy,
    ExecutionConfig, Interpreter, MetadataSealer, NullHost, OpcodeAllocation, OpcodeStream,
    PerformanceEstimator, SelectionPlanner, VmConstant, VmExceptionHandler, VmInstruction,
    VmMethod, VmRegister, VmSelectionConfig, VmSelectionMode, VmSelector, VmValue,
};
use std::collections::BTreeSet;

#[test]
fn eligibility_accepts_supported_integer_method() {
    let dex = add_dex();
    let report = EligibilityAnalyzer::analyze(&dex, 0, EligibilityPolicy::default());
    assert!(report.eligible);
    assert_eq!(report.instruction_count, 2);
    assert_eq!(report.register_count, 3);
}

#[test]
fn eligibility_rejects_unsupported_dex_opcode() {
    let dex = unsupported_dex();
    let report = EligibilityAnalyzer::analyze(&dex, 0, EligibilityPolicy::default());
    assert!(!report.eligible);
    assert!(!report.reasons.is_empty());
}

#[test]
fn lowering_and_interpreter_preserve_add_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let dex = add_dex();
    let method = DexLowerer::lower(&dex, 0, EligibilityPolicy::default())?;
    let mut host = NullHost;

    for left in [-2_147_483_648_i32, -100, -1, 0, 1, 99, 2_147_483_647] {
        for right in [-100_i32, -1, 0, 1, 100] {
            let result = Interpreter::execute(
                &method,
                &[VmValue::Int(left), VmValue::Int(right)],
                &mut host,
                ExecutionConfig::default(),
            )?;
            assert_eq!(result.value, VmValue::Int(left.wrapping_add(right)));
        }
    }
    Ok(())
}

#[test]
fn opcode_allocation_changes_per_build_without_changing_semantics(
) -> Result<(), Box<dyn std::error::Error>> {
    let method = DexLowerer::lower(&add_dex(), 0, EligibilityPolicy::default())?;
    let first = OpcodeAllocation::derive("build-a", b"private-seed")?;
    let second = OpcodeAllocation::derive("build-b", b"private-seed")?;
    let first_stream = OpcodeStream::encode(&method.instructions, &first)?;
    let second_stream = OpcodeStream::encode(&method.instructions, &second)?;

    assert_ne!(first.fingerprint(), second.fingerprint());
    assert_ne!(first_stream, second_stream);
    assert_eq!(
        first_stream.semantics(&first)?,
        second_stream.semantics(&second)?
    );
    Ok(())
}

#[test]
fn metadata_seal_rejects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let method = DexLowerer::lower(&add_dex(), 0, EligibilityPolicy::default())?;
    let allocation = OpcodeAllocation::derive("seal-build", b"seed")?;
    let metadata = nexora_shield_vm::VmMetadata::from_method(&method, &allocation)?;
    let sealed = MetadataSealer::seal(&metadata, b"metadata-key")?;
    assert_eq!(MetadataSealer::verify(&sealed, b"metadata-key")?, metadata);

    let mut tampered = sealed;
    tampered.payload[0] ^= 1;
    assert!(MetadataSealer::verify(&tampered, b"metadata-key").is_err());
    Ok(())
}

#[test]
fn arithmetic_exception_handler_preserves_control_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut constants = ConstantPool::default();
    let fallback = constants.intern(VmConstant::Int(-1))?;
    let method = VmMethod {
        method_idx: 7,
        register_count: 3,
        parameter_registers: vec![VmRegister(0), VmRegister(1)],
        instructions: vec![
            VmInstruction::Div {
                dst: VmRegister(2),
                left: VmRegister(0),
                right: VmRegister(1),
            },
            VmInstruction::Return { src: VmRegister(2) },
            VmInstruction::LoadConst {
                dst: VmRegister(2),
                constant: fallback,
            },
            VmInstruction::Return { src: VmRegister(2) },
        ],
        constants,
        handlers: vec![VmExceptionHandler {
            start: 0,
            end: 1,
            target: 2,
            type_name: Some("Ljava/lang/ArithmeticException;".to_owned()),
            exception_register: None,
        }],
    };

    let mut host = NullHost;
    let result = Interpreter::execute(
        &method,
        &[VmValue::Int(10), VmValue::Int(0)],
        &mut host,
        ExecutionConfig::default(),
    )?;
    assert_eq!(result.value, VmValue::Int(-1));
    Ok(())
}

#[test]
fn branch_conditions_are_explicit_in_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut constants = ConstantPool::default();
    let one = constants.intern(VmConstant::Int(1))?;
    let zero = constants.intern(VmConstant::Int(0))?;
    let method = VmMethod {
        method_idx: 8,
        register_count: 2,
        parameter_registers: vec![VmRegister(0)],
        instructions: vec![
            VmInstruction::Branch {
                condition: BranchCondition::EqZero,
                left: VmRegister(0),
                right: None,
                target: 3,
            },
            VmInstruction::LoadConst {
                dst: VmRegister(1),
                constant: one,
            },
            VmInstruction::Return { src: VmRegister(1) },
            VmInstruction::LoadConst {
                dst: VmRegister(1),
                constant: zero,
            },
            VmInstruction::Return { src: VmRegister(1) },
        ],
        constants,
        handlers: Vec::new(),
    };

    let mut host = NullHost;
    assert_eq!(
        Interpreter::execute(
            &method,
            &[VmValue::Int(0)],
            &mut host,
            ExecutionConfig::default(),
        )?
        .value,
        VmValue::Int(0)
    );
    assert_eq!(
        Interpreter::execute(
            &method,
            &[VmValue::Int(3)],
            &mut host,
            ExecutionConfig::default(),
        )?
        .value,
        VmValue::Int(1)
    );
    Ok(())
}

#[test]
fn performance_estimator_accounts_for_host_boundaries() {
    let method = VmMethod {
        method_idx: 9,
        register_count: 1,
        parameter_registers: Vec::new(),
        instructions: vec![
            VmInstruction::LoadField {
                dst: VmRegister(0),
                object: None,
                field: 1,
            },
            VmInstruction::Call {
                dst: Some(VmRegister(0)),
                method: 2,
                args: vec![VmRegister(0)],
            },
            VmInstruction::Return { src: VmRegister(0) },
        ],
        constants: ConstantPool::default(),
        handlers: Vec::new(),
    };
    let estimate = PerformanceEstimator::estimate(&method);
    assert_eq!(estimate.host_boundary_count, 2);
    assert!(estimate.weighted_cost > 3);
}

#[test]
fn config_and_annotation_selection_are_both_supported(
) -> Result<(), Box<dyn std::error::Error>> {
    let dex = add_dex();
    let annotated = BTreeSet::from([0_u32]);
    let config = VmSelectionConfig {
        enabled: true,
        mode: VmSelectionMode::ConfigAndAnnotation,
        selectors: vec![VmSelector {
            class_pattern: "LTest;".to_owned(),
            method_pattern: "add".to_owned(),
        }],
        annotation_descriptor: "Ldev/nexora/shield/Virtualize;".to_owned(),
    };
    let plan = SelectionPlanner::plan(&dex, &annotated, &config)?;
    assert_eq!(plan.selected_methods, BTreeSet::from([0_u32]));
    assert_eq!(plan.selected_by_config, BTreeSet::from([0_u32]));
    assert_eq!(plan.selected_by_annotation, BTreeSet::from([0_u32]));
    Ok(())
}
