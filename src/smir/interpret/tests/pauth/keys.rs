//! Independent distinct-key vectors prevent shared dispatch from hiding swaps.

use super::*;

#[test]
fn pauth_direct_smir_and_native_select_each_distinct_key_from_independent_vectors() {
    // Unmodified pinned QEMU primitive, data=0, modifier=1, (lo,hi)=(1,2),
    // (3,4), (5,6), (7,8), (9,10), respectively. Reproduce with:
    // python3 tools/pauth-reference/verify.py --cases 1024 --seed 0x5c0fed --known-key-vectors
    // Arm's 48-bit, TBI-disabled layout selects MAC[63:48] except bit 55;
    // PACGA selects MAC[63:32] with the low 32 bits zero.
    let vectors = [
        (
            PauthAlgorithm::Qarma5,
            [
                0xd7b3_0472_52bb_635b,
                0xd295_5ae2_8126_4245,
                0xdab0_f4ca_806d_f928,
                0x257e_5286_75e5_0bc5,
                0x83f8_5d4c_dc39_fc3e,
            ],
        ),
        (
            PauthAlgorithm::Qarma3,
            [
                0xfa51_63e0_c3e5_62fd,
                0x8ec1_9274_5ecf_1080,
                0x6082_f095_2c7b_2278,
                0xdbdb_7e4d_c256_8d99,
                0xc6f7_bbb4_009a_5ec5,
            ],
        ),
    ];
    let mut comparisons = 0;
    for (algorithm, macs) in vectors {
        for (index, mac) in macs.into_iter().enumerate() {
            let raw = if index == 4 {
                0x9ac1_3000
            } else {
                0xdac1_0020 | ((index as u32) << 10)
            };
            let expected_value = mac
                & if index == 4 {
                    0xffff_ffff_0000_0000
                } else {
                    0xff7f_0000_0000_0000
                };
            let mut direct = cpu(raw, algorithm, PauthProfile::FpacCombine, true);
            direct.set_pauth_keys(PauthKeys {
                ia: PauthKey { lo: 1, hi: 2 },
                ib: PauthKey { lo: 3, hi: 4 },
                da: PauthKey { lo: 5, hi: 6 },
                db: PauthKey { lo: 7, hi: 8 },
                ga: PauthKey { lo: 9, hi: 10 },
            });
            direct.set_x(0, 0);
            direct.set_x(1, 1);
            let initial = snapshot(&direct);
            direct.step().unwrap();
            assert_eq!(direct.get_x(0), expected_value, "{algorithm:?} key={index}");
            let expected = snapshot(&direct);
            for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                let mut function = function(&[raw], direct.config().features);
                optimize_function(&mut function, level);
                let mut context = context(&initial);
                let result = SmirInterpreter::new().execute_block(
                    &mut context,
                    &mut FlatMemory::new(0x10000),
                    &function.blocks[0],
                );
                assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
                let ArchRegState::Aarch64(state) = context.arch_regs else {
                    panic!()
                };
                assert_eq!(state.x[0], expected_value);
                assert_eq!(
                    crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
                    crate::codec::serialize(&expected).unwrap()
                );
                comparisons += 1;
                #[cfg(all(
                    feature = "smir-jit",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                {
                    use crate::smir::lower::SmirLowerer;
                    use crate::smir::lower::runtime::{
                        Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem,
                    };
                    function.blocks[0].terminator = Terminator::Return { values: vec![] };
                    #[cfg(target_arch = "aarch64")]
                    let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
                    #[cfg(target_arch = "x86_64")]
                    let mut lowerer = crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
                    lowerer.set_pauth_helpers(true);
                    let lowered = lowerer.lower_function(&function).unwrap();
                    let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
                    let mut memory = FlatMemory::new(0x10000);
                    let mut runtime = Aarch64PauthRuntime::new(
                        Aarch64RegState::from_cpu_state(&initial).unwrap(),
                        &mut memory,
                    )
                    .unwrap();
                    runtime
                        .run(&mut Aarch64GuestRegs::default(), |registers| {
                            #[cfg(target_arch = "aarch64")]
                            executable.run_aarch64_identity(lowered.entry_offset, registers);
                            #[cfg(target_arch = "x86_64")]
                            executable.run_aarch64(lowered.entry_offset, registers);
                        })
                        .unwrap();
                    assert_eq!(runtime.registers.x[0], expected_value);
                    assert_eq!(runtime.retired, 1);
                    assert_eq!(
                        crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap())
                            .unwrap(),
                        crate::codec::serialize(&expected).unwrap()
                    );
                    comparisons += 1;
                }
            }
        }
    }
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    assert_eq!(comparisons, 60);
    #[cfg(not(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    assert_eq!(comparisons, 30);
}
