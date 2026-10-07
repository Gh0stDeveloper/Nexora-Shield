use nexora_shield_vm::{MetadataSealer, OpcodeAllocation, VmMetadata, VmSecurityBenchmark};

#[test]
fn opcode_maps_are_diverse_across_32_builds() -> Result<(), Box<dyn std::error::Error>> {
    let build_ids = (0..32)
        .map(|index| format!("security-build-{index}"))
        .collect::<Vec<_>>();
    let report = VmSecurityBenchmark::opcode_diversity(b"private-security-seed", &build_ids)?;

    assert_eq!(report.builds, 32);
    assert_eq!(report.unique_opcode_maps, 32);
    assert!(report.maximum_transfer_basis_points <= 3_000);
    Ok(())
}

#[test]
fn wrong_metadata_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let allocation = OpcodeAllocation::derive("metadata-build", b"seed-a")?;
    let metadata = VmMetadata {
        version: 1,
        method_idx: 17,
        register_count: 4,
        instruction_count: 9,
        handler_count: 1,
        constant_pool_digest: [3; 32],
        control_metadata_digest: [5; 32],
        opcode_fingerprint: allocation.fingerprint(),
        bytecode_digest: [4; 32],
    };
    let sealed = MetadataSealer::seal(&metadata, b"key-a")?;
    assert!(MetadataSealer::verify(&sealed, b"key-b").is_err());
    Ok(())
}
