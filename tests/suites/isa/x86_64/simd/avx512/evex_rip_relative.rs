//! RIP-relative memory operands of EVEX-encoded instructions.
//!
//! In 64-bit mode ModR/M `mod=00 rm=101` addresses `RIP + disp32`, where RIP
//! is the address of the *next* instruction (Intel SDM Vol. 2A section
//! 2.2.1.6), after any trailing immediate: every 0F3A opcode has an imm8,
//! the 0F map only at 70-73 and C2/C4-C6, and the 0F38 map and the
//! AVX512-FP16 maps 5 and 6 never. Each case places its operand at an address
//! computed from the complete encoded length, surrounded by distinct bytes, so
//! an operand read one byte early or late produces a different value.
//! Encodings were produced by `llvm-mc -triple=x86_64 -show-encoding`.

use crate::common::*;
use rax::vm::vcpu::Registers;
use vm_memory::{Bytes, GuestAddress};

/// 64-byte-aligned operand address.
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

/// The 64 bytes at `TARGET`: 0x40, 0x41, ..., 0x7F.
fn ramp() -> [u8; 64] {
    std::array::from_fn(|i| 0x40 + i as u8)
}

/// Runs `code` with the ramp at `TARGET`, flanked by 0x3F and 0x80 so a
/// one-byte shift in either direction is visible.
fn run(code: &[u8], initial: Registers) -> Registers {
    let (mut vcpu, mem) = setup_vm(code, Some(initial));
    let bytes: Vec<u8> = (0x3F..=0x80).collect();
    mem.write_slice(&bytes, GuestAddress(TARGET - 1)).unwrap();
    let regs = run_until_hlt(&mut vcpu).unwrap();
    assert_eq!(
        regs.rip,
        CODE_ADDR + code.len() as u64,
        "{code:02X?}: stopped at the HLT"
    );
    regs
}

fn qwords(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(8)
        .map(|q| u64::from_le_bytes(q.try_into().unwrap()))
        .collect()
}

/// ZMM register `r` (0-15) as bytes.
fn zmm(regs: &Registers, r: usize) -> [u8; 64] {
    let q = [
        regs.xmm[r][0],
        regs.xmm[r][1],
        regs.ymm_high[r][0],
        regs.ymm_high[r][1],
        regs.zmm_high[r][0],
        regs.zmm_high[r][1],
        regs.zmm_high[r][2],
        regs.zmm_high[r][3],
    ];
    let mut out = [0u8; 64];
    for (i, v) in q.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn set_zmm(regs: &mut Registers, r: usize, bytes: &[u8; 64]) {
    let q = qwords(bytes);
    regs.xmm[r] = [q[0], q[1]];
    regs.ymm_high[r] = [q[2], q[3]];
    regs.zmm_high[r] = [q[4], q[5], q[6], q[7]];
}

#[test]
fn evex_0f_load_without_immediate() {
    // VMOVDQU32 zmm1, [rip+disp32] - EVEX.512.F3.0F.W0 6F /r
    let code = rip_code(&[0x62, 0xF1, 0x7E, 0x48, 0x6F, 0x0D], &[]);
    let regs = run(&code, Registers::default());
    assert_eq!(zmm(&regs, 1), ramp());
}

#[test]
fn evex_0f_sources_with_immediate() {
    // VPSHUFD zmm1, [rip+disp32], 0xE4 - EVEX.512.66.0F.W0 70 /r ib (identity)
    let code = rip_code(&[0x62, 0xF1, 0x7D, 0x48, 0x70, 0x0D], &[0xE4]);
    let regs = run(&code, Registers::default());
    assert_eq!(zmm(&regs, 1), ramp(), "VPSHUFD");

    // VPSRLDQ zmm1, [rip+disp32], 0 - EVEX.512.66.0F.WIG 73 /3 ib
    let code = rip_code(&[0x62, 0xF1, 0x75, 0x48, 0x73, 0x1D], &[0x00]);
    let regs = run(&code, Registers::default());
    assert_eq!(zmm(&regs, 1), ramp(), "VPSRLDQ");
}

#[test]
fn evex_0f_compare_with_immediate() {
    // VCMPPS k1, zmm0, [rip+disp32], 0 (EQ_OQ) - EVEX.512.0F.W0 C2 /r ib.
    // The ramp's dwords are finite, so each equals itself.
    let code = rip_code(&[0x62, 0xF1, 0x7C, 0x48, 0xC2, 0x0D], &[0x00]);
    let mut initial = Registers::default();
    set_zmm(&mut initial, 0, &ramp());
    let regs = run(&code, initial);
    assert_eq!(regs.k[1], 0xFFFF);
}

#[test]
fn evex_0f_compare_without_immediate() {
    // VPCMPEQD k1, zmm0, [rip+disp32] - EVEX.512.66.0F.W0 76 /r
    let code = rip_code(&[0x62, 0xF1, 0x7D, 0x48, 0x76, 0x0D], &[]);
    let mut initial = Registers::default();
    set_zmm(&mut initial, 0, &ramp());
    let regs = run(&code, initial);
    assert_eq!(regs.k[1], 0xFFFF);
}

#[test]
fn evex_0f38_source_without_immediate() {
    // VPERMD zmm1, zmm2, [rip+disp32] - EVEX.512.66.0F38.W0 36 /r, with
    // the identity permutation in zmm2.
    let code = rip_code(&[0x62, 0xF2, 0x6D, 0x48, 0x36, 0x0D], &[]);
    let mut initial = Registers::default();
    let identity: [u8; 64] = std::array::from_fn(|i| if i % 4 == 0 { (i / 4) as u8 } else { 0 });
    set_zmm(&mut initial, 2, &identity);
    let regs = run(&code, initial);
    assert_eq!(zmm(&regs, 1), ramp());
}

#[test]
fn evex_0f3a_sources_with_immediate() {
    // VPTERNLOGD zmm1, zmm2, [rip+disp32], 0xAA - EVEX.512.66.0F3A.W0 25 /r
    // ib: truth table 0xAA selects the third (memory) operand.
    let code = rip_code(&[0x62, 0xF3, 0x6D, 0x48, 0x25, 0x0D], &[0xAA]);
    let regs = run(&code, Registers::default());
    assert_eq!(zmm(&regs, 1), ramp(), "VPTERNLOGD");

    // VPCMPD k1, zmm0, [rip+disp32], 0 (EQ) - EVEX.512.66.0F3A.W0 1F /r ib
    let code = rip_code(&[0x62, 0xF3, 0x7D, 0x48, 0x1F, 0x0D], &[0x00]);
    let mut initial = Registers::default();
    set_zmm(&mut initial, 0, &ramp());
    let regs = run(&code, initial);
    assert_eq!(regs.k[1], 0xFFFF, "VPCMPD");
}
