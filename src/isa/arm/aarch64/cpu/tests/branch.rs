//! tests::branch tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

// -------------------------------------------------------------------------
// Data Processing Immediate - PC-relative addressing
// -------------------------------------------------------------------------

#[test]
fn test_adr() {
    // ADR X0, #0x100 (PC + 0x100)
    // ADR: [0 immlo[1:0] 10000 immhi[18:0] Rd[4:0]]
    // PC=0, imm=0x100 -> immhi=0x40, immlo=0
    let insn = 0x10000800; // ADR X0, #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(0), 0x100);
    assert_eq!(cpu.get_pc(), 4);
}
#[test]
fn test_adrp() {
    // ADRP X1, #0x1000 (page-aligned, PC + 0x1000)
    // ADRP: [1 immlo[1:0] 10000 immhi[18:0] Rd[4:0]]
    let insn = 0x90000001; // ADRP X1, #0 (current page)
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(1), 0); // Page of PC=0
    assert_eq!(cpu.get_pc(), 4);
}
// -------------------------------------------------------------------------
// Branch Instructions - Conditional
// -------------------------------------------------------------------------

#[test]
fn test_b_cond_taken() {
    // B.EQ #0x100 (taken when Z=1)
    let insn = 0x54000800; // B.EQ #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(true);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x100);
}
#[test]
fn test_b_cond_not_taken() {
    // B.EQ #0x100 (not taken when Z=0)
    let insn = 0x54000800; // B.EQ #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(false);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4); // Falls through
}
#[test]
fn test_b_ne() {
    // B.NE #0x20
    let insn = 0x54000101; // B.NE #0x20
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_z(false);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x20);
}
// -------------------------------------------------------------------------
// Branch Instructions - Unconditional
// -------------------------------------------------------------------------

#[test]
fn test_b() {
    // B #0x1000
    let insn = 0x14000400; // B #0x1000
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x1000);
}
#[test]
fn test_b_negative() {
    // B #-0x100 (backward branch)
    // imm26 = -0x40 (in instruction words) = 0x3FFFFC0
    let insn = 0x17FFFFC0; // B #-0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_pc(0x1000);
    write_insn(&mut cpu, 0x1000, insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0xF00);
}
#[test]
fn test_bl() {
    // BL #0x100 (saves return address in X30)
    let insn = 0x94000040; // BL #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x100);
    assert_eq!(cpu.get_x(30), 4); // Return address
}
// -------------------------------------------------------------------------
// Branch Instructions - Compare and Branch
// -------------------------------------------------------------------------

#[test]
fn test_cbz_taken() {
    // CBZ X0, #0x100
    let insn = 0xB4000800; // CBZ X0, #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x100);
}
#[test]
fn test_cbz_not_taken() {
    // CBZ X0, #0x100
    let insn = 0xB4000800; // CBZ X0, #0x100
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 1);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4);
}
#[test]
fn test_cbnz_taken() {
    // CBNZ X1, #0x80
    let insn = 0xB5000401; // CBNZ X1, #0x80
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(1, 0x1234);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x80);
}
#[test]
fn test_cbz_32bit() {
    // CBZ W0, #0x20
    let insn = 0x34000100; // CBZ W0, #0x20
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0xFFFF_FFFF_0000_0000); // Upper bits set but W0 is 0
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x20);
}
// -------------------------------------------------------------------------
// Branch Instructions - Test and Branch
// -------------------------------------------------------------------------

#[test]
fn test_tbz_taken() {
    // TBZ X0, #0, #0x40 (branch if bit 0 is 0)
    let insn = 0x36000200; // TBZ X0, #0, #0x40
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0xFFFE); // Bit 0 is 0
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x40);
}
#[test]
fn test_tbz_not_taken() {
    // TBZ X0, #0, #0x40
    let insn = 0x36000200; // TBZ X0, #0, #0x40
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0xFFFF); // Bit 0 is 1
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 4);
}
#[test]
fn test_tbnz_taken() {
    // TBNZ X0, #4, #0x80 (branch if bit 4 is 1)
    let insn = 0x37200400; // TBNZ X0, #4, #0x80
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x10); // Bit 4 is 1
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x80);
}
#[test]
fn test_tbz_high_bit() {
    // TBZ X0, #63, #0x20 (test highest bit)
    let insn = 0xB6F80100; // TBZ X0, #63, #0x20
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(0, 0x7FFF_FFFF_FFFF_FFFF); // Bit 63 is 0
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x20);
}
#[test]
fn test_blr() {
    // BLR X5
    let insn = 0xD63F00A0; // BLR X5
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(5, 0x4000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x4000);
    assert_eq!(cpu.get_x(30), 4); // Return address
}
#[test]
fn test_ret() {
    // RET (uses X30 by default)
    let insn = 0xD65F03C0; // RET
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(30, 0x8000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x8000);
}
#[test]
fn test_ret_xn() {
    // RET X5
    let insn = 0xD65F00A0; // RET X5
    let mut cpu = create_cpu_with_insn(insn);
    cpu.set_x(5, 0x3000);
    cpu.step().unwrap();
    assert_eq!(cpu.get_pc(), 0x3000);
}

// -------------------------------------------------------------------------
// FEAT_PAuth branches (register). Encodings from the Apple LLVM assembler
// (`clang -arch arm64e`); the implementation's PAC algorithm leaves
// pointers unchanged, so the authenticated target is the register value.
// -------------------------------------------------------------------------

fn pauth_cpu_with_insn(insn: u32) -> AArch64Cpu {
    use crate::isa::arm::common::features::ArmFeatures;
    use crate::isa::arm::common::memory::FlatMemory;
    let config = AArch64Config {
        features: ArmFeatures::armv8_3_base(),
        ..AArch64Config::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000_0000)));
    cpu.write_memory(0, &insn.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn test_pauth_branches_jump_to_the_register() {
    // (insn, Rn, links)
    let cases: [(u32, u8, bool); 8] = [
        (0xd71f0822, 1, false), // braa x1, x2
        (0xd71f0c7f, 3, false), // brab x3, sp
        (0xd61f089f, 4, false), // braaz x4
        (0xd61f0cbf, 5, false), // brabz x5
        (0xd73f08c7, 6, true),  // blraa x6, x7
        (0xd73f0d09, 8, true),  // blrab x8, x9
        (0xd63f095f, 10, true), // blraaz x10
        (0xd63f0d7f, 11, true), // blrabz x11
    ];
    for (insn, rn, links) in cases {
        let mut cpu = pauth_cpu_with_insn(insn);
        cpu.set_x(rn, 0x4000);
        cpu.set_x(30, 0x1234);
        // Modifiers that must not affect the target.
        cpu.set_x(2, 0xdead_beef);
        cpu.set_x(7, 0xfeed);
        cpu.set_x(9, 0x77);
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{insn:#010x}");
        assert_eq!(cpu.get_pc(), 0x4000, "{insn:#010x}");
        assert_eq!(
            cpu.get_x(30),
            if links { 4 } else { 0x1234 },
            "{insn:#010x}"
        );
    }
}

#[test]
fn test_pauth_returns_use_the_link_register() {
    for insn in [0xd65f0bffu32, 0xd65f0fff] {
        // retaa, retab
        let mut cpu = pauth_cpu_with_insn(insn);
        cpu.set_x(30, 0x8888);
        cpu.step().unwrap();
        assert_eq!(cpu.get_pc(), 0x8888, "{insn:#010x}");
    }
}

#[test]
fn test_pauth_eret_is_undefined_at_el0() {
    for insn in [0xd69f0bffu32, 0xd69f0fff] {
        // eretaa, eretab
        let mut cpu = pauth_cpu_with_insn(insn);
        cpu.enter_el0();
        assert!(
            matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(0))),
            "{insn:#010x}"
        );
    }
}

#[test]
fn test_pauth_branch_reserved_forms_are_undefined() {
    for insn in [
        0xd61f0880u32, // braaz x4 with Rm != 11111
        0xd63f0940,    // blraaz x10 with Rm != 11111
        0xd65f0be0,    // retaa with Rn != 11111
        0xd65f0bfe,    // retaa with Rm != 11111
        0xd69f0be0,    // eretaa with Rn != 11111
        0xd61f1080,    // op3 = 000100
    ] {
        let mut cpu = pauth_cpu_with_insn(insn);
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))),
            "{insn:#010x}"
        );
    }
}

#[test]
fn test_pauth_branches_need_feat_pauth() {
    for insn in [
        0xd71f0822u32,
        0xd61f089f,
        0xd63f095f,
        0xd65f0bff,
        0xd65f0fff,
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.set_x(1, 0x4000);
        assert!(
            matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))),
            "{insn:#010x} executed without FEAT_PAuth"
        );
    }
}
