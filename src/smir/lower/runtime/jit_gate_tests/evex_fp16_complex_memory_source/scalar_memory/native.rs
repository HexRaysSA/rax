use super::*;
use crate::smir::lower::runtime::ExecMem;

#[test]
fn native_scalar_fp16_complex_memory_matches_interpretation_faults_and_bit_zero_suppression() {
    if !std::is_x86_feature_detected!("avx512f")
        || !std::is_x86_feature_detected!("avx512bw")
        || !std::is_x86_feature_detected!("avx512fp16")
    {
        eprintln!(
            "skipping native scalar FP16 complex memory differential: \
             host lacks AVX-512F/BW/FP16"
        );
        return;
    }

    // Scalar AVX-512-FP16 does not require AVX-512VL. Every operation and
    // mask control is crossed with all four guest LLIG images, including
    // 11b. The host memory replay must canonicalize these ignored bits.
    let mut cases = Vec::new();
    for operation in ComplexOperation::ALL {
        for ll in 0..=3 {
            for (control_index, control) in MaskControl::ALL.into_iter().enumerate() {
                cases.push(ScalarComplexMemoryCase {
                    operation,
                    source1: [1, 17, 30][control_index],
                    ll,
                    control,
                });
            }
        }
    }
    assert_eq!(cases.len(), 4 * 4 * 3);
    assert!(cases.iter().any(|case| case.ll == 3));

    let mut successes = 0usize;
    let mut faults = 0usize;
    let mut suppressions = 0usize;
    for (ordinal, case) in cases.into_iter().enumerate() {
        for level in [OptLevel::O0, OptLevel::O2] {
            let function = optimize(lift_scalar_case(case), level);
            let (code, entry) = lower_scalar(&function, case);
            let exec =
                ExecMem::new(&code).unwrap_or_else(|error| panic!("{level:?} {case:?}: {error:?}"));
            let pair = PAIR_CORPUS[ordinal % PAIR_CORPUS.len()];
            let value = [u64::from(pair), 0, 0, 0, 0, 0, 0, 0];
            let bytes = memory_bytes(value);

            let mut registers = scalar_initial_registers(case, ordinal);
            if case.mask() != 0 {
                registers.k[usize::from(case.mask())] = (1 << 42) | 1;
            }
            let mut context = LaneMemoryContext {
                base: 0x2000,
                value: bytes,
                fail_address: None,
                calls: 0,
                addresses: [0; 16],
            };
            registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
            registers.load_fn = lane_load_helper as *const () as usize as u64;
            let mut expected = scalar_interpreter_success(&function, &registers, value, case);

            exec.run(entry, &mut registers);
            expected.host_mxcsr = registers.host_mxcsr;
            assert_eq!(registers, expected, "{level:?} {case:?}: success");
            assert_eq!(context.calls, 1, "{level:?} {case:?}: success");
            assert_eq!(context.addresses[0], 0x2000, "{level:?} {case:?}");
            successes += 1;

            let mut registers = scalar_initial_registers(case, ordinal ^ 0x55);
            if case.mask() != 0 {
                registers.k[usize::from(case.mask())] = (1 << 42) | 1;
            }
            let mut context = LaneMemoryContext {
                base: 0x2000,
                value: bytes,
                fail_address: Some(0x2000),
                calls: 0,
                addresses: [0; 16],
            };
            registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
            registers.load_fn = lane_load_helper as *const () as usize as u64;
            let mut expected = registers;
            expected.exit_pc = PC;

            exec.run(entry, &mut registers);
            expected.host_mxcsr = registers.host_mxcsr;
            assert_eq!(
                registers, expected,
                "{level:?} {case:?}: helper fault committed state"
            );
            assert_eq!(context.calls, 1, "{level:?} {case:?}: fault");
            assert_eq!(context.addresses[0], 0x2000, "{level:?} {case:?}: fault");
            faults += 1;

            if case.mask() != 0 {
                let mut registers = scalar_initial_registers(case, ordinal ^ 0xAA);
                registers.k[usize::from(case.mask())] = 1 << 42;
                let mut context = LaneMemoryContext {
                    base: 0x2000,
                    value: bytes,
                    fail_address: Some(0x2000),
                    calls: 0,
                    addresses: [0; 16],
                };
                registers.ctx = (&mut context as *mut LaneMemoryContext) as u64;
                registers.load_fn = lane_load_helper as *const () as usize as u64;
                let mut expected = scalar_interpreter_success(&function, &registers, value, case);

                exec.run(entry, &mut registers);
                expected.host_mxcsr = registers.host_mxcsr;
                assert_eq!(
                    registers, expected,
                    "{level:?} {case:?}: inactive mask changed state"
                );
                assert_eq!(
                    context.calls, 0,
                    "{level:?} {case:?}: inactive mask called helper"
                );
                suppressions += 1;
            }
        }
    }
    assert_eq!(successes, 4 * 4 * 3 * 2);
    assert_eq!(faults, successes);
    assert_eq!(suppressions, 4 * 4 * 2 * 2);
}
