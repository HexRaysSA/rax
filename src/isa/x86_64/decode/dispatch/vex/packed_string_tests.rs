//! Direct AVX packed-string regressions, including the installed glibc failure.

use crate::isa::x86_64::cpu::X86_64Vcpu;
use crate::vm::vcpu::VCpu;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const CODE: u64 = 0x1000;
const STATUS: u64 = 0x8D5;

fn cpu(code: &[u8]) -> X86_64Vcpu {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    memory.write_slice(code, GuestAddress(CODE)).unwrap();
    let mut cpu = X86_64Vcpu::new(0, memory);
    cpu.sregs.efer = 1 << 10;
    cpu.sregs.cr0 |= 1;
    cpu.sregs.cs.l = true;
    cpu.sregs.cs.db = false;
    cpu.regs.rip = CODE;
    cpu.regs.rflags = 0xCD7;
    cpu.regs.rcx = u64::MAX;
    for register in 0..16 {
        cpu.regs.xmm[register] = [
            0x4142_4344_0000_807F ^ register as u64,
            0xFFFE_0102_0304_0506,
        ];
        cpu.regs.ymm_high[register] = [0xAAAA_5555_0123_4567; 2];
        cpu.regs.zmm_high[register] = [0x1234_5678_ABCD_EF00; 4];
    }
    cpu
}

fn encoding(opcode: u8, w: bool, first: u8, second: u8, imm: u8) -> [u8; 6] {
    [
        0xC4,
        0xE3 ^ (u8::from(first >= 8) << 7) ^ (u8::from(second >= 8) << 5),
        0x79 | (u8::from(w) << 7),
        opcode,
        0xC0 | ((first & 7) << 3) | (second & 7),
        imm,
    ]
}

#[test]
fn vex_packed_string_installed_glibc_comparison_matches_native_control() {
    // Measured libc bytes at file offset 0x159F43: VPCMPISTRI xmm0,xmm1,0x1A.
    // Independent native execution reports ECX=16 and status flags 0xC0.
    let code = [0xC4, 0xE3, 0x79, 0x63, 0xC1, 0x1A];
    let mut cpu = cpu(&code);
    cpu.regs.xmm[0] = [
        u64::from_le_bytes(*b"installe"),
        u64::from_le_bytes(*b"d\0\0\0\0\0\0\0"),
    ];
    cpu.regs.xmm[1] = cpu.regs.xmm[0];
    let before = cpu.regs.clone();
    assert!(cpu.step().unwrap().is_none());
    assert_eq!(cpu.regs.rcx, 16);
    assert_eq!(cpu.regs.rflags, (before.rflags & !STATUS) | 0xC0);
    assert_eq!(cpu.regs.xmm, before.xmm);
    assert_eq!(cpu.regs.ymm_high, before.ymm_high);
    assert_eq!(cpu.regs.zmm_high, before.zmm_high);
    assert_eq!(cpu.regs.rip, CODE + code.len() as u64);
}

#[test]
fn vex_packed_strings_match_legacy_controls_and_preserve_sources() {
    for opcode in 0x60..=0x63 {
        for w in [false, true] {
            for (first, second) in [(0, 1), (9, 10), (0, 0), (1, 0), (15, 15)] {
                for imm in 0..=u8::MAX {
                    let code = encoding(opcode, w, first, second, imm);
                    let rex = 0x40
                        | (u8::from(w) << 3)
                        | (u8::from(first >= 8) << 2)
                        | u8::from(second >= 8);
                    let legacy = [0x66, rex, 0x0F, 0x3A, opcode, code[4], imm];
                    let mut avx = cpu(&code);
                    let mut sse = cpu(&legacy);
                    avx.regs.rax = 0xFFFF_FFFF_0000_0000;
                    avx.regs.rdx = 0x1234_5678_8000_0000;
                    sse.regs.rax = avx.regs.rax;
                    sse.regs.rdx = avx.regs.rdx;
                    let before = avx.regs.clone();
                    assert!(sse.step().unwrap().is_none());
                    assert!(avx.step().unwrap().is_none(), "{code:02X?}");
                    assert_eq!(avx.regs.xmm, sse.regs.xmm, "{code:02X?}");
                    assert_eq!(avx.regs.rcx, sse.regs.rcx, "{code:02X?}");
                    assert_eq!(avx.regs.rflags, sse.regs.rflags, "{code:02X?}");
                    for register in 0..16 {
                        let mask_destination = opcode & 1 == 0 && register == 0;
                        assert_eq!(
                            avx.regs.ymm_high[register],
                            if mask_destination {
                                [0; 2]
                            } else {
                                before.ymm_high[register]
                            }
                        );
                        assert_eq!(
                            avx.regs.zmm_high[register],
                            if mask_destination {
                                [0; 4]
                            } else {
                                before.zmm_high[register]
                            }
                        );
                    }
                    assert_eq!(avx.regs.rip, CODE + code.len() as u64);
                }
            }
        }
    }
}

#[test]
fn vex_packed_string_mask_clears_upper_bits_even_when_low_result_is_unchanged() {
    let mut cpu = cpu(&encoding(0x60, false, 1, 2, 0));
    cpu.regs.rax = 0;
    cpu.regs.rdx = 0;
    cpu.regs.xmm[0] = [0; 2];
    cpu.regs.ymm_high[0] = [0; 2];
    assert!(cpu.step().unwrap().is_none());
    assert_eq!(cpu.regs.xmm[0], [0; 2]);
    assert_eq!(cpu.regs.ymm_high[0], [0; 2]);
    assert_eq!(cpu.regs.zmm_high[0], [0; 4]);
}

#[test]
fn vex_packed_string_rip_relative_memory_includes_immediate_and_allows_unaligned_data() {
    let mut code = vec![0xC4, 0xE3, 0x79, 0x63, 0x05];
    code.extend_from_slice(&(0x3003i32 - (CODE as i32 + 10)).to_le_bytes());
    code.push(0x1A);
    let mut cpu = cpu(&code);
    let data = [0x4141_4141_4141_4141u64, 0x0041_4141_4141_4141];
    cpu.regs.xmm[0] = data;
    cpu.write_mem(0x3003, data[0], 8).unwrap();
    cpu.write_mem(0x300B, data[1], 8).unwrap();
    assert!(cpu.step().unwrap().is_none());
    assert_eq!(cpu.regs.rcx, 16);
    assert_eq!(cpu.regs.rflags & STATUS, 0xC0);
    assert_eq!(cpu.regs.rip, CODE + 10);
}

#[test]
fn vex_packed_string_late_memory_fault_preserves_destinations_and_flags() {
    for opcode in 0x60..=0x63 {
        let mut cpu = cpu(&[0xC4, 0xE3, 0x79, opcode, 0x08, 0]);
        cpu.regs.rax = 0xFFF8;
        cpu.write_mem(0xFFF8, 0x1234, 8).unwrap();
        let before = cpu.regs.clone();
        assert!(cpu.step().is_err());
        assert_eq!(cpu.regs.rip, before.rip);
        assert_eq!(cpu.regs.rcx, before.rcx);
        assert_eq!(cpu.regs.rflags, before.rflags);
        assert_eq!(cpu.regs.xmm, before.xmm);
        assert_eq!(cpu.regs.ymm_high, before.ymm_high);
        assert_eq!(cpu.regs.zmm_high, before.zmm_high);
    }
}

#[test]
fn vex_packed_string_reserved_encodings_raise_ud_before_operand_access() {
    for opcode in 0x60..=0x63 {
        for prefix in [0x7D, 0x71, 0x78, 0x7A, 0x7B] {
            let mut cpu = cpu(&[0xC4, 0xE3, prefix, opcode, 0x08, 0]);
            cpu.regs.rax = 0x20000;
            let before = cpu.regs.clone();
            let error = cpu
                .step()
                .expect_err("reserved packed-string encoding must #UD");
            assert!(
                format!("{error:?}").contains("IDT entry 6 not present"),
                "{error:?}"
            );
            assert_eq!(cpu.regs.rip, before.rip);
            assert_eq!(cpu.regs.rcx, before.rcx);
            assert_eq!(cpu.regs.rflags, before.rflags);
            assert_eq!(cpu.regs.xmm, before.xmm);
            assert_eq!(cpu.regs.ymm_high, before.ymm_high);
            assert_eq!(cpu.regs.zmm_high, before.zmm_high);
        }
    }
}

#[test]
fn vex_packed_string_compatibility_mode_ignores_w_for_explicit_lengths() {
    for opcode in [0x60, 0x61] {
        let mut outputs = Vec::new();
        for w in [false, true] {
            let mut cpu = cpu(&encoding(opcode, w, 1, 2, 0x08));
            cpu.sregs.cs.l = false;
            cpu.sregs.cs.db = true;
            cpu.regs.rax = 0xFFFF_FFFF_0000_0000;
            cpu.regs.rdx = 0x1234_5678_0000_0000;
            assert!(cpu.step().unwrap().is_none());
            outputs.push((cpu.regs.xmm[0], cpu.regs.rcx, cpu.regs.rflags));
        }
        assert_eq!(outputs[0], outputs[1]);
        assert_eq!(outputs[0].2 & STATUS, 0x8C1);
    }
}

#[test]
fn vex_packed_string_rejects_forbidden_legacy_prefixes_before_operand_access() {
    for prefix in [0x66, 0xF0, 0xF2, 0xF3, 0x48] {
        let mut cpu = cpu(&[prefix, 0xC4, 0xE3, 0x79, 0x63, 0x08, 0x1A]);
        cpu.regs.rax = 0x20000;
        let before = cpu.regs.clone();
        let error = cpu.step().expect_err("forbidden VEX prefix must #UD");
        assert!(
            format!("{error:?}").contains("IDT entry 6 not present"),
            "{error:?}"
        );
        assert_eq!(cpu.regs.rip, before.rip);
        assert_eq!(cpu.regs.rcx, before.rcx);
        assert_eq!(cpu.regs.rflags, before.rflags);
        assert_eq!(cpu.regs.xmm, before.xmm);
        assert_eq!(cpu.regs.ymm_high, before.ymm_high);
        assert_eq!(cpu.regs.zmm_high, before.zmm_high);
    }
}
