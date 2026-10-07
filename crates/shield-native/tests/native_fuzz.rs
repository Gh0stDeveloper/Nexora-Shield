use nexora_shield_native::{GeneratedNativeData, NativeError, NativeRegion};

fn next_state(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn fuzz_native_region_mutations_never_match_original() -> Result<(), NativeError> {
    let original = (0_u16..=255)
        .map(|value| u8::try_from(value).unwrap_or(0))
        .collect::<Vec<_>>();
    let region = NativeRegion::new("fuzz-region", &original)?;
    let mut state = 0x4e45_584f_5241_4655_u64;

    for _ in 0..4_096 {
        let mut mutated = original.clone();
        let state_value = next_state(&mut state);
        let length = u64::try_from(mutated.len()).unwrap_or(u64::MAX);
        let index = usize::try_from(state_value % length).unwrap_or(0);
        let delta = u8::try_from((state_value >> 32) & 0xff)
            .unwrap_or(1)
            .max(1);
        mutated[index] ^= delta;
        assert!(!region.verify(&mutated).matched);
    }

    Ok(())
}

#[test]
fn fuzz_generated_data_is_stable_for_many_inputs() -> Result<(), NativeError> {
    for index in 0_u32..2_048 {
        let build_id = format!("fuzz-build-{index}");
        let seed = index.to_le_bytes();
        let first = GeneratedNativeData::derive(&build_id, &seed)?;
        let second = GeneratedNativeData::derive(&build_id, &seed)?;
        assert_eq!(first, second);
    }
    Ok(())
}

#[test]
fn fuzz_region_lengths_are_handled_without_panics() -> Result<(), NativeError> {
    for len in 0_usize..1_024 {
        let bytes = vec![0xa5; len];
        let region = NativeRegion::new(format!("len-{len}"), &bytes)?;
        assert!(region.verify(&bytes).matched);
    }
    Ok(())
}
