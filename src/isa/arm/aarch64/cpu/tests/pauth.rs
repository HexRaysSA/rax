//! Feature-disabled pointer-authentication instructions preserve precise state.

use super::*;

#[test]
fn pauth_data_processing_requires_its_feature() {
    for opcode in 0..=17u32 {
        let insn = 0xdac1_0000 | (opcode << 10) | (31 << 5);
        let mut cpu = create_cpu_with_insn(insn);
        cpu.set_x(0, 0xfeed_beef_1234_5678);
        assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(word)) if word == insn));
        assert_eq!(cpu.get_x(0), 0xfeed_beef_1234_5678);
        assert_eq!(cpu.get_pc(), 0);
    }
    let mut cpu = create_cpu_with_insn(0x9ac1_3000);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::UndefinedInstruction(0x9ac1_3000))
    ));
    assert_eq!(cpu.get_pc(), 0);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn pauth_native_regions_decline_without_executing_a_prefix() {
    for word in [0xd71f_081f_u32, 0xd61f_081f, 0xf820_17e6, 0xd69f_0bff] {
        let mut memory = FlatMemory::new(0, 0x1000);
        memory.write(0, &0x9100_0400_u32.to_le_bytes()).unwrap(); // ADD X0, X0, #1
        memory.write(4, &word.to_le_bytes()).unwrap();
        let mut cpu = AArch64Cpu::new(
            AArch64Config {
                features: ArmFeatures::armv8_3_base(),
                ..AArch64Config::default()
            },
            Box::new(memory),
        );
        cpu.set_x(0, 5);
        cpu.set_pc(0);
        assert!(cpu.jit_compile_region().is_none(), "{word:#010x}");
        assert_eq!(cpu.get_x(0), 5);
        assert_eq!(cpu.get_pc(), 0);
    }
}

#[test]
fn pauth_hint_is_nop_without_feature_and_overlap_is_undefined() {
    let mut cpu = create_cpu_with_insn(0xd503_20ff);
    cpu.set_x(30, 0xabcd_0000_1234_5670);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(30), 0xabcd_0000_1234_5670);
    let mut cpu = create_cpu_with_insn(0xf820_0c00);
    cpu.config.features |= ArmFeatures::PACA;
    cpu.set_x(0, 0x800);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::UndefinedInstruction(0xf820_0c00))
    ));
    assert_eq!(cpu.get_x(0), 0x800);
    assert_eq!(cpu.get_pc(), 0);
}
