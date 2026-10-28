//! FPEN transitions must preserve the interpreter's precise FP-access trap.

use std::sync::Arc;

use crate::isa::arm::aarch64::cpu::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::cpu::{ArmCpu, CpuExit};
use crate::isa::arm::common::memory::FlatMemory;

const ENTRY: u64 = 0x1000;
const VECTOR_PC: u64 = ENTRY + 4;
const EXIT_PC: u64 = ENTRY + 16;

fn vector_loop_cpu(el: u8) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config::default(),
        Box::new(FlatMemory::new(0, 0x10000)),
    );
    let program = [
        0x9100_0400u32, // ADD X0, X0, #1
        0x4e22_8420,    // ADD V0.16B, V1.16B, V2.16B
        0xf100_0803,    // SUBS X3, X0, #2: architectural destination
        0x54ff_ffa3,    // B.LO ENTRY
        0xd420_0000,    // BRK #0: native interpreter frontier
    ];
    let bytes: Vec<_> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    cpu.write_memory(ENTRY, &bytes).unwrap();
    cpu.set_pc(ENTRY);
    cpu.current_el = el;
    cpu.sysregs.el1.vbar = 0x8000;
    cpu.set_x(0, 1);
    cpu.set_simd(0, 0xa5a5_a5a5_a5a5_a5a5);
    cpu.set_simd(1, u128::MAX);
    cpu.set_simd(2, 0x0101_0101_0101_0101_0101_0101_0101_0101);
    cpu
}

#[test]
fn cached_fp_regions_observe_every_fpen_transition_at_el0_and_el1() {
    // Arm CPACR_EL1.FPEN: 00/10 trap EL0 and EL1; 01 traps only EL0;
    // 11 enables access at both levels. ESR_EL1.EC for this trap is 0x07.
    for el in [0, 1] {
        for fpen in 0..=3u64 {
            let mut cpu = vector_loop_cpu(el);
            let region = Arc::new(cpu.jit_compile_region().expect("enabled vector loop"));
            assert!(region.uses_fp);
            let enabled_key = (ENTRY, cpu.jit_mode_tag());
            cpu.jit.cache.insert(enabled_key, Some(region.clone()));
            cpu.sysregs.el1.cpacr = (cpu.sysregs.el1.cpacr & !(3 << 20)) | (fpen << 20);
            let permitted = fpen == 3 || (el == 1 && fpen == 1);
            let initial_vector = cpu.get_simd(0);

            if permitted {
                assert!(cpu.jit_run_region(&region));
                assert_eq!(cpu.get_pc(), EXIT_PC);
                assert_eq!(cpu.get_x(0), 2);
                assert_eq!(cpu.get_simd(0), 0);
            } else {
                assert!(!cpu.jit_run_region(&region), "EL{el}, FPEN={fpen:02b}");
                assert!(cpu.jit_lookup(ENTRY).is_none(), "EL{el}, FPEN={fpen:02b}");
                assert!(
                    cpu.jit_compile_region().is_none(),
                    "EL{el}, FPEN={fpen:02b}"
                );
                assert_eq!(cpu.get_pc(), ENTRY);
                assert_eq!(cpu.get_x(0), 1);
                assert_eq!(cpu.get_simd(0), initial_vector);

                assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
                assert_eq!(cpu.get_pc(), VECTOR_PC);
                assert_eq!(cpu.get_x(0), 2);
                assert_eq!(cpu.get_simd(0), initial_vector);
                assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
                assert_eq!(cpu.sysregs.el1.elr, VECTOR_PC);
                assert_eq!((cpu.sysregs.el1.esr >> 26) & 0x3f, 0x07);
                assert_eq!(cpu.instruction_count(), 1);
                assert_eq!(cpu.get_x(0), 2);
                assert_eq!(cpu.get_simd(0), initial_vector);
            }
        }
    }
}

#[test]
fn restoring_fpen_reuses_the_enabled_cache_key() {
    let mut cpu = vector_loop_cpu(1);
    let enabled_tag = cpu.jit_mode_tag();
    let region = Arc::new(cpu.jit_compile_region().unwrap());
    cpu.jit
        .cache
        .insert((ENTRY, enabled_tag), Some(region.clone()));
    cpu.sysregs.el1.cpacr &= !(3 << 20);
    let disabled_tag = cpu.jit_mode_tag();
    assert_ne!(disabled_tag, enabled_tag);
    assert!(cpu.jit_lookup(ENTRY).is_none());
    cpu.jit.cache.insert((ENTRY, disabled_tag), None);
    cpu.sysregs.el1.cpacr |= 3 << 20;
    assert_eq!(cpu.jit_mode_tag(), enabled_tag);
    assert!(Arc::ptr_eq(&cpu.jit_lookup(ENTRY).unwrap(), &region));
}

#[test]
fn integer_regions_remain_native_when_fpen_disables_vectors() {
    for el in [0, 1] {
        for fpen in 0..=3u64 {
            let mut cpu = vector_loop_cpu(el);
            cpu.write_memory(VECTOR_PC, &0xd503_201fu32.to_le_bytes())
                .unwrap(); // NOP replaces the vector instruction.
            cpu.sysregs.el1.cpacr = (cpu.sysregs.el1.cpacr & !(3 << 20)) | (fpen << 20);
            let region = cpu.jit_compile_region().expect("integer loop");
            assert!(!region.uses_fp);
            assert!(cpu.jit_run_region(&region));
            assert_eq!(cpu.get_pc(), EXIT_PC);
            assert_eq!(cpu.get_x(0), 2);
        }
    }
}
