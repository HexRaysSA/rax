//! PAC placement, translation, TBI/TBID and alignment use the same VHE regime.

use super::*;
use crate::isa::arm::aarch64::pauth::{PauthKey, PauthKeyKind};
use crate::isa::arm::common::cpu::AccessType;

pub(super) fn host_cpu(el: u8) -> AArch64Cpu {
    let mut memory = FlatMemory::new(0, 0x100000);
    for (base, next) in [
        (0x10000, 0x20000),
        (0x20000, 0x30000),
        (0x30000, 0x40000),
        (0x50000, 0x60000),
        (0x60000, 0x70000),
        (0x70000, 0xa0000),
    ] {
        memory.write_u64(base, next | 3).unwrap();
    }
    memory.write_u64(0x40000, 0x80000 | 0x443).unwrap();
    memory.write_u64(0xa0000, 0x90000 | 0x443).unwrap();
    memory.write_u64(0x80000, 0x0123_4567_89ab_cdef).unwrap();
    memory.write_u64(0x90000, 0xfedc_ba98_7654_3210).unwrap();
    memory.write_u32(0x80020, 0xf820_0402).unwrap(); // LDRAA X2,[X0]
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            initial_el: el,
            features: ArmFeatures::armv8_5_base() | ArmFeatures::VHE,
            gic_config: None,
            ..Default::default()
        },
        Box::new(memory),
    );
    cpu.sysregs.el1.ttbr0 = 0xe0000; // Deliberately invalid EL1 mapping.
    cpu.sysregs.el2.ttbr0 = 0x10000;
    cpu.sysregs.el2.ttbr1 = 0x50000;
    cpu.sysregs.el2.mair = 0xff;
    let mut controls = cpu.pauth_controls();
    controls.scr_el3 = 1 | (1 << 10) | (1 << 16) | (1 << 17);
    controls.hcr_el2 = (1 << 34) | (1 << 27) | (1 << 31) | (1 << 40) | (1 << 41);
    controls.sctlr[2] = 1 | (1 << 27); // MMU + data key A.
    controls.tcr[2] = 16 | (16 << 16) | (2 << 30) | (5 << 32) | (1 << 37) | (1 << 38);
    cpu.set_pauth_controls(controls).unwrap();
    let mut keys = cpu.pauth_keys();
    keys.da = PauthKey {
        lo: 0x1234,
        hi: 0x5678,
    };
    cpu.set_pauth_keys(keys);
    cpu.set_pc(0x20);
    cpu
}

#[test]
fn pauth_regime_vhe_el0_and_el2_use_el2_roots_for_keyed_lower_and_upper_loads() {
    for el in [0, 2] {
        for (pointer, expected) in [
            (0xab00_0000_0000_0000, 0x0123_4567_89ab_cdef),
            (0xabff_0000_0000_0000, 0xfedc_ba98_7654_3210),
        ] {
            let mut cpu = host_cpu(el);
            assert_eq!(cpu.pauth_controls().regime_el(), 2);
            assert_eq!(cpu.mem_read_u64(pointer).unwrap(), expected);
            let signed = cpu
                .pauth_value(pointer, 0, PauthKeyKind::Da, false, false)
                .unwrap();
            cpu.set_x(0, signed);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(2), expected);
        }
    }
}

#[test]
fn pauth_regime_vhe_instruction_tbi_and_tbid_use_el2_controls() {
    let mut cpu = host_cpu(0);
    cpu.memory.write_u32(0x80020, 0xd503_201f).unwrap();
    cpu.set_pc(0xab00_0000_0000_0020);
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    let mut controls = cpu.pauth_controls();
    controls.tcr[2] |= 1 << 51;
    cpu.set_pauth_controls(controls).unwrap();
    cpu.set_pc(0xab00_0000_0000_0020);
    assert!(
        matches!(cpu.step(), Err(ArmError::MemoryError(info)) if info.access == AccessType::InstructionFetch)
    );
    assert_eq!(
        cpu.mem_read_u64(0xab00_0000_0000_0000).unwrap(),
        0x0123_4567_89ab_cdef
    );
}

#[test]
fn pauth_regime_vhe_alignment_reads_effective_el2_sctlr() {
    let mut cpu = host_cpu(0);
    let mut controls = cpu.pauth_controls();
    controls.sctlr[2] |= sctlr::A | sctlr::SA0;
    cpu.set_pauth_controls(controls).unwrap();
    assert!(
        matches!(cpu.mem_read_u64(1), Err(ArmError::MemoryError(info)) if info.fault_type == MemoryFaultType::Alignment)
    );
    cpu.set_current_sp(8);
    assert!(
        matches!(cpu.checked_sp(AccessType::Read), Err(ArmError::MemoryError(info)) if info.fault_type == MemoryFaultType::SpAlignment)
    );
}

#[test]
fn pauth_regime_single_range_el2_el3_rejects_signed_ttbr1_addresses() {
    for el in [2, 3] {
        let mut cpu = host_cpu(el);
        let mut controls = cpu.pauth_controls();
        controls.hcr_el2 &= !(1 << 34);
        controls.sctlr[el as usize] = 1;
        controls.tcr[el as usize] = 16 | (5 << 16) | (1 << 20);
        cpu.set_pauth_controls(controls).unwrap();
        assert!(!cpu.pauth_controls().two_ranges());
        assert_eq!(
            cpu.effective_data_address(0xabff_ffff_0000_0000, el),
            0x00ff_ffff_0000_0000
        );
        assert!(
            matches!(cpu.mem_read_u64(0xffff_0000_0000_0000), Err(ArmError::MemoryError(info)) if info.fault_type == MemoryFaultType::AddressSize)
        );
    }
}
