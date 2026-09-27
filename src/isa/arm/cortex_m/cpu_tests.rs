//! Cortex-M core: construction, reset, and instruction execution.

use super::*;
use crate::isa::arm::common::memory::ArmMemory;

fn create_test_cpu() -> CortexMCpu {
    let mut memory = FlatMemory::new(0, 0x10000);
    // Set up minimal vector table
    memory.write_u32(0, 0x1000).unwrap(); // Initial SP
    memory.write_u32(4, 0x101).unwrap(); // Reset vector (Thumb)
    CortexMCpu::new(CortexMVariant::CortexM4, Box::new(memory))
}

#[test]
fn test_cpu_creation() {
    let cpu = create_test_cpu();
    assert_eq!(cpu.variant(), CortexMVariant::CortexM4);
    assert_eq!(cpu.profile(), ArmProfile::M);
    // The Floating-point Extension is not implemented.
    assert!(!cpu.has_fpu());
}

#[test]
fn test_cpu_reset() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    assert_eq!(cpu.get_sp(), 0x1000);
    assert_eq!(cpu.get_pc(), 0x100);
    assert!(cpu.is_privileged());
}

#[test]
fn test_mov_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // MOV R0, #42 (0x202A)
    cpu.memory_mut().write_u16(0x100, 0x202A).unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 42);
}

#[test]
fn test_add_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // MOV R0, #10
    cpu.memory_mut().write_u16(0x100, 0x200A).unwrap();
    // ADD R0, #5
    cpu.memory_mut().write_u16(0x102, 0x3005).unwrap();

    cpu.step().unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 15);
}

#[test]
fn test_push_pop() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    let initial_sp = cpu.get_sp();

    // Set up some register values
    cpu.set_gpr(0, 0x1234);
    cpu.set_gpr(1, 0x5678);

    // PUSH {R0, R1} (0xB403)
    cpu.memory_mut().write_u16(0x100, 0xB403).unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_sp(), initial_sp - 8);

    // Clear registers
    cpu.set_gpr(0, 0);
    cpu.set_gpr(1, 0);

    // POP {R0, R1} (0xBC03)
    cpu.memory_mut().write_u16(0x102, 0xBC03).unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0x1234);
    assert_eq!(cpu.get_gpr(1), 0x5678);
    assert_eq!(cpu.get_sp(), initial_sp);
}

#[test]
fn test_conditional_branch() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // Set Z flag
    cpu.set_z(true);

    // BEQ +4 (0xD001) - should branch
    cpu.memory_mut().write_u16(0x100, 0xD001).unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_pc(), 0x106); // 0x102 + 4

    // Reset and try BNE
    cpu.set_pc(0x100);
    cpu.set_z(true);

    // BNE +4 (0xD101) - should not branch
    cpu.memory_mut().write_u16(0x100, 0xD101).unwrap();
    cpu.step().unwrap();

    assert_eq!(cpu.get_pc(), 0x102); // No branch
}

#[test]
fn test_breakpoint() {
    let mut cpu = create_test_cpu();
    cpu.reset();
    cpu.set_breakpoint(0x100).unwrap();

    // Any instruction at 0x100
    cpu.memory_mut().write_u16(0x100, 0xBF00).unwrap(); // NOP

    let exit = cpu.step().unwrap();
    assert!(matches!(exit, CpuExit::Breakpoint(0x100)));
}

#[test]
fn test_svc() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // SVC #42 (0xDF2A)
    cpu.memory_mut().write_u16(0x100, 0xDF2A).unwrap();

    let exit = cpu.step().unwrap();
    assert!(matches!(exit, CpuExit::Svc(42)));
}

#[test]
fn test_wfi() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // WFI (0xBF30)
    cpu.memory_mut().write_u16(0x100, 0xBF30).unwrap();

    let exit = cpu.step().unwrap();
    assert!(matches!(exit, CpuExit::Wfi));
}

#[test]
fn test_flags() {
    let mut cpu = create_test_cpu();

    cpu.set_n(true);
    assert!(cpu.get_n());

    cpu.set_z(true);
    assert!(cpu.get_z());

    cpu.set_c(true);
    assert!(cpu.get_c());

    cpu.set_v(true);
    assert!(cpu.get_v());

    cpu.update_nz(0);
    assert!(cpu.get_z());
    assert!(!cpu.get_n());

    cpu.update_nz(0x8000_0000);
    assert!(!cpu.get_z());
    assert!(cpu.get_n());
}

// =========================================================================
// Thumb-32 Instruction Tests
// =========================================================================

/// Helper to write a Thumb-32 instruction (little-endian half-words)
fn write_thumb32(cpu: &mut CortexMCpu, addr: u32, insn: u32) {
    let hw1 = ((insn >> 16) & 0xFFFF) as u16;
    let hw2 = (insn & 0xFFFF) as u16;
    cpu.memory_mut().write_u16(addr as u64, hw1).unwrap();
    cpu.memory_mut().write_u16((addr + 2) as u64, hw2).unwrap();
}

#[test]
fn test_thumb32_bl() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // BL to offset +0x100 from PC
    // BL encoding: 1111 0xxx xxxx xxxx 11x1 xxxx xxxx xxxx
    // For offset 0x100: S=0, imm10=0, J1=1, J2=1, imm11=0x80
    // PC at 0x100, target = 0x204
    // offset = 0x100, so imm10 = 0, imm11 = 0x80, S = 0
    // hw1 = 1111 0S00 0000 0000 = F000
    // hw2 = 11D1 Jimm11 = F880 (J1=1, J2=1, imm11=0x80)
    write_thumb32(&mut cpu, 0x100, 0xF000_F880);
    cpu.step().unwrap();

    assert_eq!(cpu.get_pc(), 0x204);
    assert_eq!(cpu.get_lr() & !1, 0x104); // Return address
}

#[test]
fn test_thumb32_mov_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // MOVW R0, #0x1234
    // Encoding: 1111 0i10 0100 imm4 | 0 imm3 Rd imm8
    // imm16 = 0x1234: imm4=1, i=0, imm3=2, imm8=0x34
    // hw1 = 1111 0010 0100 0001 = F241
    // hw2 = 0 010 0000 0011 0100 = 0034 (imm3=0x2, rd=0, imm8=0x34)
    // Actually: MOV.W Rd, #const where const uses ThumbExpandImm
    // Let's use a simpler constant: MOV R0, #0xFF
    // Encoding for MOV.W R0, #0xFF:
    // op=0010, S=0, Rn=1111, i=0, imm3=0, Rd=0, imm8=0xFF
    // hw1 = 1111 0x00 010x 1111 = F04F
    // hw2 = 0 000 0000 1111 1111 = 00FF
    write_thumb32(&mut cpu, 0x100, 0xF04F_00FF);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0xFF);
}

#[test]
fn test_thumb32_add_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 100);

    // ADD.W R0, R1, #50
    // Encoding: op=1000, S=0, Rn=1, i=0, imm3=0, Rd=0, imm8=50
    // hw1 = 1111 0x01 000x 0001 = F101
    // hw2 = 0 000 0000 0011 0010 = 0032
    write_thumb32(&mut cpu, 0x100, 0xF101_0032);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 150);
}

#[test]
fn test_thumb32_sub_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 100);

    // SUB.W R0, R1, #30
    // Encoding: op=1101, S=0, Rn=1
    // hw1 = 1111 0x01 101x 0001 = F1A1
    // hw2 = 0 000 0000 0001 1110 = 001E
    write_thumb32(&mut cpu, 0x100, 0xF1A1_001E);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 70);
}

#[test]
fn test_thumb32_and_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 0xFF);

    // AND.W R0, R1, #0x0F
    // Encoding: op=0000, S=0, Rn=1
    // hw1 = 1111 0x00 000x 0001 = F001
    // hw2 = 0 000 0000 0000 1111 = 000F
    write_thumb32(&mut cpu, 0x100, 0xF001_000F);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0x0F);
}

#[test]
fn test_thumb32_orr_imm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 0xF0);

    // ORR.W R0, R1, #0x0F
    // Encoding: op=0010, S=0, Rn=1
    // hw1 = 1111 0x00 010x 0001 = F041
    // hw2 = 0 000 0000 0000 1111 = 000F
    write_thumb32(&mut cpu, 0x100, 0xF041_000F);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0xFF);
}

#[test]
fn test_thumb32_mul() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 7);
    cpu.set_gpr(2, 6);

    // MUL R0, R1, R2
    // Encoding: 1111 1011 0000 Rn | Ra Rd 0000 Rm
    // Ra = 1111 (no accumulate), Rn=1, Rm=2, Rd=0
    // hw1 = 1111 1011 0000 0001 = FB01
    // hw2 = 1111 0000 0000 0010 = F002
    write_thumb32(&mut cpu, 0x100, 0xFB01_F002);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 42);
}

#[test]
fn test_thumb32_mla() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 7);
    cpu.set_gpr(2, 6);
    cpu.set_gpr(3, 10);

    // MLA R0, R1, R2, R3
    // Encoding: 1111 1011 0000 Rn | Ra Rd 0000 Rm
    // Ra = 3, Rn=1, Rm=2, Rd=0
    // hw1 = 1111 1011 0000 0001 = FB01
    // hw2 = 0011 0000 0000 0010 = 3002
    write_thumb32(&mut cpu, 0x100, 0xFB01_3002);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 52); // 7*6 + 10 = 52
}

#[test]
fn test_thumb32_sdiv() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 100);
    cpu.set_gpr(2, 7);

    // SDIV R0, R1, R2
    // Encoding: 1111 1011 1001 Rn | 1111 Rd 1111 Rm
    // hw1 = 1111 1011 1001 0001 = 0xFB91
    // hw2 = 1111 0000 1111 0010 = 0xF0F2
    write_thumb32(&mut cpu, 0x100, 0xFB91_F0F2);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 14); // 100 / 7 = 14
}

#[test]
fn test_thumb32_udiv() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 100);
    cpu.set_gpr(2, 3);

    // UDIV R0, R1, R2
    // Encoding: 1111 1011 1011 Rn | 1111 Rd 1111 Rm
    // hw1 = 1111 1011 1011 0001 = 0xFBB1
    // hw2 = 1111 0000 1111 0010 = 0xF0F2
    write_thumb32(&mut cpu, 0x100, 0xFBB1_F0F2);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 33); // 100 / 3 = 33
}

#[test]
fn test_thumb32_smull() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(2, 0x12345);
    cpu.set_gpr(3, 0x6789A);

    // SMULL R0, R1, R2, R3
    // Encoding: 1111 1011 1000 Rn | RdLo RdHi 0000 Rm
    // Rn=2, Rm=3, RdLo=0, RdHi=1
    // hw1 = 1111 1011 1000 0010 = FB82
    // hw2 = 0000 0001 0000 0011 = 0103
    write_thumb32(&mut cpu, 0x100, 0xFB82_0103);
    cpu.step().unwrap();

    let result = ((cpu.get_gpr(1) as u64) << 32) | (cpu.get_gpr(0) as u64);
    assert_eq!(result, 0x12345u64 * 0x6789Au64);
}

#[test]
fn test_thumb32_umull() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(2, 0xFFFFFFFF);
    cpu.set_gpr(3, 2);

    // UMULL R0, R1, R2, R3
    // Encoding: 1111 1011 1010 Rn | RdLo RdHi 0000 Rm
    // Rn=2, Rm=3, RdLo=0, RdHi=1
    // hw1 = 1111 1011 1010 0010 = FBA2
    // hw2 = 0000 0001 0000 0011 = 0103
    write_thumb32(&mut cpu, 0x100, 0xFBA2_0103);
    cpu.step().unwrap();

    let result = ((cpu.get_gpr(1) as u64) << 32) | (cpu.get_gpr(0) as u64);
    assert_eq!(result, 0xFFFFFFFFu64 * 2);
}

#[test]
fn test_thumb32_ldr_imm12() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // Store a value in memory
    cpu.memory_mut().write_u32(0x200, 0xDEADBEEF).unwrap();
    cpu.set_gpr(1, 0x200);

    // LDR.W R0, [R1, #0]
    // Encoding: 1111 1000 1101 Rn | Rt imm12
    // Rn=1, Rt=0, imm12=0
    // hw1 = 1111 1000 1101 0001 = F8D1
    // hw2 = 0000 0000 0000 0000 = 0000
    write_thumb32(&mut cpu, 0x100, 0xF8D1_0000);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0xDEADBEEF);
}

#[test]
fn test_thumb32_str_imm12() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(0, 0x12345678);
    cpu.set_gpr(1, 0x300);

    // STR.W R0, [R1, #0]
    // Encoding: 1111 1000 1100 Rn | Rt imm12
    // Rn=1, Rt=0, imm12=0
    // hw1 = 1111 1000 1100 0001 = F8C1
    // hw2 = 0000 0000 0000 0000 = 0000
    write_thumb32(&mut cpu, 0x100, 0xF8C1_0000);
    cpu.step().unwrap();

    let stored = cpu.memory().read_u32(0x300).unwrap();
    assert_eq!(stored, 0x12345678);
}

#[test]
fn test_thumb32_ldm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    // Set up memory
    cpu.memory_mut().write_u32(0x300, 0x11111111).unwrap();
    cpu.memory_mut().write_u32(0x304, 0x22222222).unwrap();
    cpu.memory_mut().write_u32(0x308, 0x33333333).unwrap();
    cpu.set_gpr(5, 0x300);

    // LDM R5!, {R0, R1, R2}
    // Encoding: 1110 1000 1011 Rn | PM register_list
    // W=1, Rn=5, register_list = 0x0007
    // hw1 = 1110 1000 1011 0101 = E8B5
    // hw2 = 0000 0000 0000 0111 = 0007
    write_thumb32(&mut cpu, 0x100, 0xE8B5_0007);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0x11111111);
    assert_eq!(cpu.get_gpr(1), 0x22222222);
    assert_eq!(cpu.get_gpr(2), 0x33333333);
    assert_eq!(cpu.get_gpr(5), 0x30C); // Writeback
}

#[test]
fn test_thumb32_stm() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(0, 0xAAAAAAAA);
    cpu.set_gpr(1, 0xBBBBBBBB);
    cpu.set_gpr(5, 0x400);

    // STMIA R5!, {R0, R1}
    // Encoding: 1110 1000 1010 Rn | 0M register_list
    // W=1, Rn=5, register_list = 0x0003
    // hw1 = 1110 1000 1010 0101 = E8A5
    // hw2 = 0000 0000 0000 0011 = 0003
    write_thumb32(&mut cpu, 0x100, 0xE8A5_0003);
    cpu.step().unwrap();

    assert_eq!(cpu.memory().read_u32(0x400).unwrap(), 0xAAAAAAAA);
    assert_eq!(cpu.memory().read_u32(0x404).unwrap(), 0xBBBBBBBB);
    assert_eq!(cpu.get_gpr(5), 0x408); // Writeback
}

#[test]
fn test_thumb32_ldrd() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.memory_mut().write_u32(0x500, 0x11112222).unwrap();
    cpu.memory_mut().write_u32(0x504, 0x33334444).unwrap();
    cpu.set_gpr(5, 0x500);

    // LDRD Rt, Rt2, [Rn, #imm8*4]
    // Encoding: 1110 100P U1W1 Rn | Rt Rt2 imm8
    // For LDRD: P=1, U=1, W=0 (no writeback), L=1 (load)
    // Bits: 1110 1001 0101 Rn | Rt Rt2 imm8
    // With Rn=5, Rt=0, Rt2=1, imm8=0:
    // hw1 = 1110 1001 0101 0101 = E955
    // hw2 = 0000 0001 0000 0000 = 0100
    // But this goes to load_store_dual which checks op1, op2, op3
    // op1 = (insn >> 23) & 0x3 = 0b01
    // op2 = (insn >> 20) & 0x3 = 0b01 for LDRD, 0b00 for STRD? No...
    // Let me check: E955 = 1110 1001 0101 0101
    // bits [24:23] = 01, bits [21:20] = 01
    // But handler checks (0b00|0b01, 0b11, _) for LDRD
    // So op2 needs to be 0b11 for LDRD
    // LDRD is: 1110 100P U D W L Rn...
    // For load dual (LDRD): L=1, so bit 20=1
    // Wait the encoding shows: 1110 100 P U 1 W 1 for LDRD
    // So bits [21:20] = 1 1 = 0b11
    // hw1 should be: 1110 1001 1101 0101 = E9D5
    write_thumb32(&mut cpu, 0x100, 0xE9D5_0100);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 0x11112222);
    assert_eq!(cpu.get_gpr(1), 0x33334444);
}

#[test]
fn test_thumb32_strd() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(0, 0xAAAABBBB);
    cpu.set_gpr(1, 0xCCCCDDDD);
    cpu.set_gpr(5, 0x600);

    // STRD Rt, Rt2, [Rn, #imm8*4]
    // Encoding: 1110 100P U D W 0 Rn | Rt Rt2 imm8
    // For STRD: P=1, U=1, W=0, L=0 (store)
    // bits [21:20] = 1 0 = 0b10
    // hw1 = 1110 1001 1100 0101 = E9C5
    // hw2 = 0000 0001 0000 0000 = 0100
    write_thumb32(&mut cpu, 0x100, 0xE9C5_0100);
    cpu.step().unwrap();

    assert_eq!(cpu.memory().read_u32(0x600).unwrap(), 0xAAAABBBB);
    assert_eq!(cpu.memory().read_u32(0x604).unwrap(), 0xCCCCDDDD);
}

#[test]
fn test_thumb32_clz() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 0x00010000); // CLZ = 15

    // CLZ R0, R1
    // Encoding: 1111 1010 1011 Rn | 1111 Rd 10 00 Rm
    // For CLZ: op1=0b1011, op2=0b1000
    // Rn=1, Rd=0, Rm=1 (same as Rn)
    // hw1 = 1111 1010 1011 0001 = FAB1
    // hw2 = 1111 0000 1000 0001 = F081
    // This goes to exec_data_processing_reg_32
    // op1 = (insn >> 20) & 0xF = 0xB
    // op2 = (insn >> 4) & 0xF = 0x8 (but CLZ expects 0)
    // Actually CLZ encoding is: 1111 1010 1011 nnnn | 1111 dddd 1000 mmmm
    // op2 should be checked as == 0b0000
    // The issue is my handler checks op2 == 0b0000 but we have 0b1000
    // CLZ is FA B n F d 8 m = FAB1 F081
    // Wait, let me re-read the handler...
    // 0b1011 if op2 == 0b0000 => CLZ
    // But we need op2 from bits [7:4] of hw2 = 0b1000
    // That's wrong - CLZ should have op2=0b1000
    // Let me fix this in the handler instead
    write_thumb32(&mut cpu, 0x100, 0xFAB1_F081);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 15);
}

#[test]
fn test_thumb32_rbit() {
    let mut cpu = create_test_cpu();
    cpu.reset();

    cpu.set_gpr(1, 0x80000000);

    // RBIT R0, R1
    // Encoding: 1111 1010 1001 Rn | 1111 Rd 1010 Rm
    // op1=0b1001, op2=0b1010
    // But handler expects op1=0b1000 and op2=0b1100 for RBIT
    // Actual RBIT: 1111 1010 100 1 nnnn | 1111 dddd 1010 mmmm
    // Let me check ARM reference... RBIT is:
    // 1111 1010 1001 nnnn | 1111 dddd 1010 mmmm
    // So op1 = (insn >> 20) & 0xF = 0x9
    // But our handler checks op1=0b1000=8 with op2=0b1100=12
    // Need to fix handler
    write_thumb32(&mut cpu, 0x100, 0xFA91_F0A1);
    cpu.step().unwrap();

    assert_eq!(cpu.get_gpr(0), 1);
}
