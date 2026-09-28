//! RIP-relative memory operands of VEX-encoded instructions.
//!
//! In 64-bit mode ModR/M `mod=00 rm=101` addresses `RIP + disp32`, where RIP
//! is the address of the *next* instruction (Intel SDM Vol. 2A section
//! 2.2.1.6). The next instruction starts after any trailing immediate, and
//! whether a VEX opcode has one depends on its map and opcode: every 0F3A
//! opcode has an imm8, the 0F map only at 70-73 and C2/C4-C6, and the 0F38
//! map never. Each case places its operand at an address computed from the
//! complete encoded length, surrounded by distinct bytes, so an operand read
//! one byte early or late produces a different value (or #GP for an aligned
//! operand). Encodings were produced by `llvm-mc -triple=x86_64
//! -show-encoding`.

use crate::common::*;
use rax::vm::vcpu::Registers;
use vm_memory::{Bytes, GuestAddress};

/// 32-byte-aligned operand address.
const TARGET: u64 = 0x3000;

/// `head` runs through the ModR/M byte (`mod=00 rm=101`); `imm` is the
/// trailing immediate. The disp32 is chosen so the operand is `TARGET`.
fn rip_code(head: &[u8], imm: &[u8]) -> Vec<u8> {
    let len = (head.len() + 4 + imm.len()) as u64;
    let disp = TARGET.wrapping_sub(CODE_ADDR + len) as u32;
    let mut code = head.to_vec();
    code.extend_from_slice(&disp.to_le_bytes());
    code.extend_from_slice(imm);
    code.push(0xF4); // HLT
    code
}

/// Runs `code` with the 0x40.. byte ramp around `TARGET` (bytes 0x3F and
/// 0x80 flank it, so a one-byte shift in either direction is visible).
fn run(code: &[u8], initial: Registers) -> Registers {
    let (mut vcpu, mem) = setup_vm(code, Some(initial));
    let ramp: Vec<u8> = (0x3F..=0x80).collect();
    mem.write_slice(&ramp, GuestAddress(TARGET - 1)).unwrap();
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert_eq!(
        regs.rip,
        CODE_ADDR + code.len() as u64,
        "{code:02X?}: stopped at the HLT"
    );
    regs
}

/// The 16-byte ramp chunk starting `offset` bytes past `TARGET`, as XMM qwords.
fn ramp128(offset: u8) -> [u64; 2] {
    let byte = |i: u8| u64::from(0x40 + offset + i);
    let qword = |base: u8| (0..8).fold(0, |acc, i| acc | (byte(base + i) << (8 * i)));
    [qword(0), qword(8)]
}

#[test]
fn vex2_0f_aligned_load_without_immediate() {
    // VMOVAPS xmm0, [rip+disp32] - VEX.128.0F.WIG 28 /r
    let code = rip_code(&[0xC5, 0xF8, 0x28, 0x05], &[]);
    let regs = run(&code, Registers::default());
    assert_eq!(regs.xmm[0], ramp128(0));
}

#[test]
fn vex2_0f_256_bit_source_without_immediate() {
    // VPADDD ymm2, ymm1, [rip+disp32] - VEX.256.66.0F.WIG FE /r, ymm1 = 0
    let code = rip_code(&[0xC5, 0xF5, 0xFE, 0x15], &[]);
    let regs = run(&code, Registers::default());
    assert_eq!(regs.xmm[2], ramp128(0));
    assert_eq!(regs.ymm_high[2], ramp128(16));
}

#[test]
fn vex3_0f_source_without_immediate() {
    // {vex3} VPXOR ymm9, ymm1, [rip+disp32] - VEX.256.66.0F.WIG EF /r, ymm1 = 0
    let code = rip_code(&[0xC4, 0x61, 0x75, 0xEF, 0x0D], &[]);
    let regs = run(&code, Registers::default());
    assert_eq!(regs.xmm[9], ramp128(0));
    assert_eq!(regs.ymm_high[9], ramp128(16));
}

#[test]
fn vex3_0f38_shuffle_mask_without_immediate() {
    // VPSHUFB ymm2, ymm1, [rip+disp32] - VEX.256.66.0F38.WIG 00 /r. Mask byte
    // i is 0x40 + i: bit 7 clear and index i mod 16, the identity per lane.
    let code = rip_code(&[0xC4, 0xE2, 0x75, 0x00, 0x15], &[]);
    let mut initial = Registers::default();
    initial.xmm[1] = [0xA7A6_A5A4_A3A2_A1A0, 0xAFAE_ADAC_ABAA_A9A8];
    initial.ymm_high[1] = [0xB7B6_B5B4_B3B2_B1B0, 0xBFBE_BDBC_BBBA_B9B8];
    let regs = run(&code, initial.clone());
    assert_eq!(regs.xmm[2], initial.xmm[1]);
    assert_eq!(regs.ymm_high[2], initial.ymm_high[1]);
}

#[test]
fn vex3_0f38_gpr_source_without_immediate() {
    // ANDN eax, ebx, [rip+disp32] - VEX.LZ.0F38.W0 F2 /r, ebx = 0
    let code = rip_code(&[0xC4, 0xE2, 0x60, 0xF2, 0x05], &[]);
    let mut initial = Registers::default();
    initial.rax = u64::MAX;
    let regs = run(&code, initial);
    assert_eq!(regs.rax, 0x4342_4140);
}

#[test]
fn vex3_0f3a_source_with_immediate() {
    // VPALIGNR ymm2, ymm1, [rip+disp32], 0 - VEX.256.66.0F3A.WIG 0F /r ib:
    // a zero shift selects the memory operand in each lane.
    let code = rip_code(&[0xC4, 0xE3, 0x75, 0x0F, 0x15], &[0x00]);
    let regs = run(&code, Registers::default());
    assert_eq!(regs.xmm[2], ramp128(0));
    assert_eq!(regs.ymm_high[2], ramp128(16));
}

#[test]
fn vex3_0f3a_gpr_source_with_immediate() {
    // RORX ecx, [rip+disp32], 8 - VEX.LZ.F2.0F3A.W0 F0 /r ib
    let code = rip_code(&[0xC4, 0xE3, 0x7B, 0xF0, 0x0D], &[0x08]);
    let mut initial = Registers::default();
    initial.rcx = u64::MAX;
    let regs = run(&code, initial);
    // ROR(0x43424140, 8) = 0x40434241, zero-extended into RCX.
    assert_eq!(regs.rcx, 0x4043_4241);
}

#[test]
fn vex_0f_sources_with_immediate() {
    // VPSHUFD xmm3, [rip+disp32], 0xE4 - VEX.128.66.0F.WIG 70 /r ib (identity),
    // in both the two- and three-byte VEX forms.
    for head in [
        &[0xC5, 0xF9, 0x70, 0x1D][..],
        &[0xC4, 0xE1, 0x79, 0x70, 0x1D],
    ] {
        let code = rip_code(head, &[0xE4]);
        let regs = run(&code, Registers::default());
        assert_eq!(regs.xmm[3], ramp128(0), "{code:02X?}");
    }

    // VSHUFPS xmm5, xmm4, [rip+disp32], 0x44 - VEX.128.0F.WIG C6 /r ib:
    // dwords {xmm4[0], xmm4[1], m[0], m[1]}.
    let code = rip_code(&[0xC5, 0xD8, 0xC6, 0x2D], &[0x44]);
    let mut initial = Registers::default();
    initial.xmm[4] = [0x1111_1111_2222_2222, 0x3333_3333_4444_4444];
    let regs = run(&code, initial);
    assert_eq!(regs.xmm[5], [0x1111_1111_2222_2222, ramp128(0)[0]]);
}
