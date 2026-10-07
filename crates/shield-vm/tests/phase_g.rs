mod common;

use common::{add_dex, orphan_move_result_dex, unsupported_dex};
use nexora_shield_vm::{
    BranchCondition, ConstantPool, DexLowerer, EligibilityAnalyzer, EligibilityPolicy,
    ExecutionConfig, Interpreter, MetadataSealer, NullHost, OpcodeAllocation, OpcodeStream,
    PerformanceEstimator, SelectionPlanner, VmConstant, VmError, VmException, VmExceptionHandler,
    VmHost, VmInstruction, VmMethod, VmRegister, VmSelectionConfig, VmSelectionMode, VmSelector,
    VmValue,
};
use std::collections::{BTreeMap, BTreeSet};

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
fn eligibility_rejects_orphan_move_result() {
    let dex = orphan_move_result_dex();
    let report = EligibilityAnalyzer::analyze(&dex, 0, EligibilityPolicy::default());
    assert!(!report.eligible);
    assert!(report.reasons.iter().any(|reason| matches!(
        reason,
        nexora_shield_vm::EligibilityReason::OrphanMoveResult { .. }
    )));
}

#[test]
fn lowering_and_interpreter_preserve_add_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let dex = add_dex();
    let method = DexLowerer::lower(&dex, 0, EligibilityPolicy::default())?;
    let mut host = NullHost;

    for left in [-2_147_483_648_i32, -100, -1, 0, 1, 99, 2_147_483_647] {
        for right in [-100_i32, -1, 0, 1, 100] {
            let allocation = OpcodeAllocation::derive("execute-build", b"execute-seed")?;
            let stream = OpcodeStream::encode(&method.instructions, &allocation)?;
            let result = Interpreter::execute_stream(
                &method,
                &stream,
                &allocation,
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
    assert_eq!(first_stream.decode(&first)?, method.instructions);
    assert_eq!(second_stream.decode(&second)?, method.instructions);

    let mut truncated = first_stream.clone();
    truncated.bytes.pop();
    assert!(truncated.decode(&first).is_err());
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
    let stream = OpcodeStream::encode(&method.instructions, &allocation)?;
    let wrong_allocation = OpcodeAllocation::derive("other-build", b"seed")?;
    assert_eq!(
        MetadataSealer::verify_program(&sealed, b"metadata-key", &stream, &allocation)?,
        metadata
    );

    assert_eq!(
        MetadataSealer::verify_program(
            &sealed,
            b"metadata-key",
            &stream,
            &wrong_allocation
        ),
        Err(VmError::OpcodeFingerprintMismatch)
    );

    let mut tampered_method = method.clone();
    tampered_method.parameter_registers.reverse();
    assert_eq!(
        MetadataSealer::verify_executable(
            &sealed,
            b"metadata-key",
            &tampered_method,
            &stream,
            &allocation
        ),
        Err(VmError::MetadataSealMismatch)
    );

    let mut tampered_metadata = sealed.clone();
    tampered_metadata.payload[0] ^= 1;
    assert!(MetadataSealer::verify(&tampered_metadata, b"metadata-key").is_err());

    let mut tampered_stream = stream;
    tampered_stream.bytes[0] ^= 1;
    assert_eq!(
        MetadataSealer::verify_program(&sealed, b"metadata-key", &tampered_stream, &allocation),
        Err(VmError::BytecodeDigestMismatch)
    );
    Ok(())
}

#[test]
fn arithmetic_exception_handler_preserves_control_flow() -> Result<(), Box<dyn std::error::Error>> {
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
fn config_and_annotation_selection_are_both_supported() -> Result<(), Box<dyn std::error::Error>> {
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

#[derive(Debug, Default)]
struct MemoryHost {
    fields: BTreeMap<u32, VmValue>,
}

impl VmHost for MemoryHost {
    fn load_field(
        &mut self,
        _object: Option<&VmValue>,
        field: u32,
        _constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException> {
        Ok(self.fields.get(&field).cloned().unwrap_or(VmValue::Null))
    }

    fn store_field(
        &mut self,
        _object: Option<&VmValue>,
        field: u32,
        value: &VmValue,
        _constants: &ConstantPool,
    ) -> std::result::Result<(), VmException> {
        self.fields.insert(field, value.clone());
        Ok(())
    }

    fn call(
        &mut self,
        method: u32,
        args: &[VmValue],
        _constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException> {
        if method == 7 {
            let value = args
                .first()
                .and_then(|value| value.as_int().ok())
                .unwrap_or_default();
            Ok(VmValue::Int(value.wrapping_mul(2)))
        } else if method == 99 {
            Err(VmException {
                type_name: Some("LTest/ChildException;".to_owned()),
                value: VmValue::Ref(99),
            })
        } else {
            Err(VmException {
                type_name: Some("LTest/UnknownMethod;".to_owned()),
                value: VmValue::Null,
            })
        }
    }

    fn exception_matches(
        &self,
        expected: &str,
        actual: Option<&str>,
        _constants: &ConstantPool,
    ) -> bool {
        actual == Some(expected)
            || (expected == "LTest/BaseException;" && actual == Some("LTest/ChildException;"))
    }
}

#[test]
fn calls_and_fields_use_explicit_host_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let method = VmMethod {
        method_idx: 10,
        register_count: 2,
        parameter_registers: Vec::new(),
        instructions: vec![
            VmInstruction::LoadField {
                dst: VmRegister(0),
                object: None,
                field: 1,
            },
            VmInstruction::Call {
                dst: Some(VmRegister(1)),
                method: 7,
                args: vec![VmRegister(0)],
            },
            VmInstruction::StoreField {
                object: None,
                field: 1,
                src: VmRegister(1),
            },
            VmInstruction::Return { src: VmRegister(1) },
        ],
        constants: ConstantPool::default(),
        handlers: Vec::new(),
    };
    let mut host = MemoryHost {
        fields: BTreeMap::from([(1, VmValue::Int(21))]),
    };

    let result = Interpreter::execute(&method, &[], &mut host, ExecutionConfig::default())?;
    assert_eq!(result.value, VmValue::Int(42));
    assert_eq!(host.fields.get(&1), Some(&VmValue::Int(42)));
    Ok(())
}

#[test]
fn interpreter_step_limit_stops_non_terminating_programs() {
    let method = VmMethod {
        method_idx: 11,
        register_count: 0,
        parameter_registers: Vec::new(),
        instructions: vec![VmInstruction::Jump { target: 0 }],
        constants: ConstantPool::default(),
        handlers: Vec::new(),
    };
    let mut host = NullHost;

    let result = Interpreter::execute(&method, &[], &mut host, ExecutionConfig { step_limit: 16 });
    assert_eq!(result, Err(VmError::StepLimitExceeded { limit: 16 }));
}

#[test]
fn typed_handler_uses_host_assignability_rules() -> Result<(), Box<dyn std::error::Error>> {
    let mut constants = ConstantPool::default();
    let fallback = constants.intern(VmConstant::Int(77))?;
    let method = VmMethod {
        method_idx: 12,
        register_count: 2,
        parameter_registers: Vec::new(),
        instructions: vec![
            VmInstruction::Call {
                dst: None,
                method: 99,
                args: Vec::new(),
            },
            VmInstruction::ReturnVoid,
            VmInstruction::LoadConst {
                dst: VmRegister(0),
                constant: fallback,
            },
            VmInstruction::Return { src: VmRegister(0) },
        ],
        constants,
        handlers: vec![VmExceptionHandler {
            start: 0,
            end: 1,
            target: 2,
            type_name: Some("LTest/BaseException;".to_owned()),
            exception_register: Some(VmRegister(1)),
        }],
    };
    let mut host = MemoryHost::default();

    let result = Interpreter::execute(&method, &[], &mut host, ExecutionConfig::default())?;
    assert_eq!(result.value, VmValue::Int(77));
    Ok(())
}


#[test]
fn sealed_execution_debug_redacts_key() -> Result<(), Box<dyn std::error::Error>> {
    let method = DexLowerer::lower(&add_dex(), 0, EligibilityPolicy::default())?;
    let allocation = OpcodeAllocation::derive("debug-redaction", b"seed")?;
    let stream = OpcodeStream::encode(&method.instructions, &allocation)?;
    let metadata = nexora_shield_vm::VmMetadata::from_method(&method, &allocation)?;
    let sealed = MetadataSealer::seal(&metadata, b"super-secret-vm-key")?;
    let protected = SealedExecution::new(
        &method,
        &stream,
        &allocation,
        &sealed,
        b"super-secret-vm-key",
    );

    let debug = format!("{protected:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("super-secret-vm-key"));
    Ok(())
}
