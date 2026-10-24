//! Arm CheckSPAlignment uses SA0 at EL0 and SA at higher exception levels.

use super::*;

const ACCESSES: &[(u32, &str)] = &[
    (0xf94003e0, "ldr x0, [sp]"),
    (0xf90003e0, "str x0, [sp]"),
    (0xf84003e0, "ldur x0, [sp]"),
    (0xf80003e0, "stur x0, [sp]"),
    (0xf8400be0, "ldtr x0, [sp]"),
    (0xf8000be0, "sttr x0, [sp]"),
    (0xa94007e0, "ldp x0, x1, [sp]"),
    (0xa90007e0, "stp x0, x1, [sp]"),
    (0x3dc003e0, "ldr q0, [sp]"),
    (0x3d8003e0, "str q0, [sp]"),
    (0xc8dfffe0, "ldar x0, [sp]"),
    (0xc89fffe0, "stlr x0, [sp]"),
    (0xc85f7fe0, "ldxr x0, [sp]"),
    (0xc8027fe0, "stxr w2, x0, [sp]"),
    (0xf82083e1, "swp x0, x1, [sp]"),
    (0xc8a07fe1, "cas x0, x1, [sp]"),
    (0xf8bfc3e0, "ldapr x0, [sp]"),
    (0xa400a3e0, "ld1b {z0.b}, p0/z, [sp]"),
    (0xe400e3e0, "st1b {z0.b}, p0, [sp]"),
    (0x858043e0, "ldr z0, [sp]"),
    (0xe58043e0, "str z0, [sp]"),
    (0x858003e0, "ldr p0, [sp]"),
    (0xe58003e0, "str p0, [sp]"),
];

fn stack_cpu(instruction: u32, el: u8, controls: u64, sp: u64) -> AArch64Cpu {
    let mut memory = FlatMemory::new(0, 0x10000);
    memory.write_u32(0, instruction).unwrap();
    let config = AArch64Config {
        initial_el: el,
        ..AArch64Config::v9_0()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    let mut regs = cpu.export_sregs();
    regs.sctlr_el1 = controls;
    regs.vbar_el1 = 0x8000;
    cpu.import_sregs(&regs).unwrap();
    cpu.set_current_sp(sp);
    cpu.set_pc(0);
    cpu.set_sve_pred(0, 0xffff);
    cpu
}

#[test]
fn sa_and_sa0_select_the_current_exception_level_independently() {
    for &(instruction, name) in ACCESSES {
        for el in [0, 1] {
            for controls in [0, 1 << 3, 1 << 4, (1 << 3) | (1 << 4)] {
                for sp in [0x1000, 0x1008] {
                    let mut cpu = stack_cpu(instruction, el, controls, sp);
                    let enabled = controls & (if el == 0 { 1 << 4 } else { 1 << 3 }) != 0;
                    let expected_fault = enabled && sp & 15 != 0;
                    let result = cpu.step();
                    assert_eq!(
                        result.is_err(),
                        expected_fault,
                        "{name} EL{el} controls={controls:#x} SP={sp:#x}: {result:?}"
                    );
                    if expected_fault {
                        assert!(matches!(result, Err(ArmError::MemoryError(info))
                            if info.fault_type == MemoryFaultType::SpAlignment));
                        assert_eq!(cpu.get_pc(), 0);
                        assert_eq!(cpu.current_sp(), sp);
                    }
                }
            }
        }
    }
}

#[test]
fn stack_alignment_has_its_own_exception_class_and_preserves_far() {
    for el in [0, 1] {
        let mut cpu = stack_cpu(0xf94003e0, el, (1 << 3) | (1 << 4), 0x1008);
        let mut regs = cpu.export_sregs();
        regs.far_el1 = 0x12345678;
        cpu.import_sregs(&regs).unwrap();
        cpu.step_system().unwrap();
        let regs = cpu.export_sregs();
        assert_eq!((regs.esr_el1 >> 26) & 0x3f, 0x26);
        assert_eq!(regs.esr_el1 & 0x1ffffff, 0);
        assert_eq!(regs.elr_el1, 0);
        assert_eq!(regs.far_el1, 0x12345678);
    }
}

#[test]
fn stack_alignment_checks_the_base_before_adding_the_offset() {
    // LDR X0, [SP, #8]: an aligned effective address cannot repair a bad SP.
    let mut cpu = stack_cpu(0xf94007e0, 1, 1 << 3, 0x1008);
    assert!(cpu.step().is_err());
    // The effective address need not be 16-byte aligned when the SP is.
    let mut cpu = stack_cpu(0xf94007e0, 1, 1 << 3, 0x1000);
    cpu.step().unwrap();
}
