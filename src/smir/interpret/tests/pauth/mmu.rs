//! Real page-table translation and exact fault transport through both planes.

use super::*;
use crate::isa::arm::aarch64::Aarch64MemoryBridge;
use crate::isa::arm::common::memory::ArmMemory as ArmMemoryTrait;

fn translated_cpu(pointer: u64, descriptor: u64, el0: bool, alignment: bool) -> AArch64Cpu {
    let mut memory = ArmMemory::new(0, 0x100000);
    for (base, next) in [(0x10000, 0x20000), (0x20000, 0x30000), (0x30000, 0x40000)] {
        memory.write_u64(base, next | 3).unwrap();
    }
    memory.write_u64(0x40008, 0x81000 | 0x443).unwrap(); // VA 0x1000, code.
    memory.write_u64(0x40020, descriptor).unwrap(); // VA 0x4000, data.
    memory.write_u32(0x81000, 0xf820_0406).unwrap(); // LDRAA X6,[X0].
    memory.write_u64(0x90000, 0x1122_3344_5566_7788).unwrap();
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            features: ArmFeatures::armv8_5_base(),
            gic_config: None,
            ..Default::default()
        },
        Box::new(memory),
    );
    let mut system = cpu.export_sregs();
    system.ttbr0_el1 = 0x10000;
    system.mair_el1 = 0xff;
    cpu.import_sregs(&system).unwrap();
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 = 1 | (1 << 10) | (1 << 16) | (1 << 17);
    controls.hcr_el2 = (1 << 31) | (1 << 40) | (1 << 41);
    controls.sctlr[1] = 1 | (1 << 27) | (u64::from(alignment) << 1);
    controls.tcr[1] = 16 | (16 << 16) | (5 << 32);
    if pointer >> 56 != 0 {
        controls.tcr[1] |= 1 << 37;
    }
    cpu.set_pauth_controls(controls).unwrap();
    cpu.set_pstate_bits(0xa000_00c0 | if el0 { 0 } else { 5 })
        .unwrap();
    cpu.set_current_sp(0x3000);
    let mut keys = cpu.pauth_keys();
    keys.da = PauthKey {
        lo: u64::MAX,
        hi: 0x0123_4567_89ab_cdef,
    };
    cpu.set_pauth_keys(keys);
    cpu.set_x(
        0,
        controls.layout(pointer, true).sign(
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
            pointer,
            0,
            keys.da,
        ),
    );
    cpu.set_x(6, 0xdead_beef_cafe_f00d);
    cpu.set_pc(PC);
    cpu
}

#[test]
fn pauth_smir_and_native_mmu_bridge_preserves_precise_load_faults_and_state() {
    use crate::smir::lower::SmirLowerer;
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};
    let mut comparisons = 0;
    for (pointer, descriptor, el0, alignment) in [
        (0x4000, 0x90000 | 0x443, false, false), // Read succeeds.
        (0x4000, 0, false, false),               // Translation fault at L3.
        (0x4000, 0x90000 | 0x043, false, false), // Access-flag fault at L3.
        (0x4000, 0x90000 | 0x403, true, false),  // EL0 permission fault.
        (0x4001, 0x90000 | 0x443, false, true),  // Alignment before translation.
        (0x4ffc, 0x90000 | 0x443, false, false), // Second page is unmapped.
        (0xab00_0000_0000_4000, 0x90000 | 0x443, false, false),
        (0xab00_0000_0000_4000, 0, false, false),
        (0xab00_0000_0000_4ffc, 0x90000 | 0x443, false, false),
    ] {
        let mut direct = translated_cpu(pointer, descriptor, el0, alignment);
        let initial = snapshot(&direct);
        let expected_exit = direct.step();
        let expected = snapshot(&direct);
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut function = function(&[0xf820_0406], direct.config().features);
            optimize_function(&mut function, level);
            let mut context = context(&initial);
            let mut cpu = translated_cpu(pointer, descriptor, el0, alignment);
            let mut generic = FlatMemory::new(0); // No generic memory ops in this function.
            let mut memory = Aarch64MemoryBridge::new(&mut cpu, &mut generic);
            let result = SmirInterpreter::new().execute_block(
                &mut context,
                &mut memory,
                &function.blocks[0],
            );
            assert_exit(&expected_exit, &result, pointer, level);
            let ArchRegState::Aarch64(state) = &context.arch_regs else {
                panic!()
            };
            assert_eq!(
                crate::codec::serialize(&state.to_cpu_state().unwrap()).unwrap(),
                crate::codec::serialize(&expected).unwrap()
            );
            assert_eq!(context.insn_count, u64::from(expected_exit.is_ok()));
            comparisons += 1;

            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            {
                function.blocks[0].terminator = Terminator::Return { values: vec![] };
                #[cfg(target_arch = "aarch64")]
                let mut lowerer = crate::smir::lower::aarch64::Aarch64Lowerer::new();
                #[cfg(target_arch = "x86_64")]
                let mut lowerer = crate::smir::lower::cross::aarch64_guest_to_x86_64_host::Aarch64X86_64Lowerer::new();
                lowerer.set_pauth_helpers(true);
                let lowered = lowerer.lower_function(&function).unwrap();
                let executable = ExecMem::new(&lowerer.finalize().unwrap()).unwrap();
                let mut runtime = Aarch64PauthRuntime::new(
                    Aarch64RegState::from_cpu_state(&initial).unwrap(),
                    &mut memory,
                )
                .unwrap();
                let native_exit = runtime.run(&mut Aarch64GuestRegs::default(), |registers| {
                    #[cfg(target_arch = "aarch64")]
                    executable.run_aarch64_identity(lowered.entry_offset, registers);
                    #[cfg(target_arch = "x86_64")]
                    executable.run_aarch64(lowered.entry_offset, registers);
                });
                let result = match native_exit {
                    Ok(()) => BlockResult::Exit(ExitReason::Halt),
                    Err(error) => BlockResult::Exit(error),
                };
                assert_exit(&expected_exit, &result, pointer, level);
                assert_eq!(runtime.retired, u64::from(expected_exit.is_ok()));
                assert_eq!(
                    crate::codec::serialize(&runtime.registers.to_cpu_state().unwrap()).unwrap(),
                    crate::codec::serialize(&expected).unwrap()
                );
                comparisons += 1;
            }
        }
    }
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    assert_eq!(comparisons, 54);
    #[cfg(not(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    assert_eq!(comparisons, 27);
}

fn assert_exit(
    expected: &Result<crate::isa::arm::common::cpu::CpuExit, ArmError>,
    result: &BlockResult,
    pointer: u64,
    level: OptLevel,
) {
    match expected {
        Ok(_) => assert!(matches!(result, BlockResult::Exit(ExitReason::Halt))),
        Err(ArmError::MemoryError(expected)) => {
            let BlockResult::Exit(ExitReason::Aarch64Fault {
                pc: PC,
                error: ArmError::MemoryError(actual),
            }) = result
            else {
                panic!("{pointer:#x} {level:?}: {result:?}; expected {expected:?}");
            };
            assert_eq!(actual.address, expected.address);
            assert_eq!(actual.access, expected.access);
            assert_eq!(actual.fault_type, expected.fault_type);
            assert_eq!(actual.stage2, expected.stage2);
        }
        Err(error) => panic!("unexpected direct error {error:?}"),
    }
}
