//! Regression tests: the SSE2 shift-by-immediate groups (`66 0F 71/72/73`)
//! must apply REX.B to their ModR/M.rm register, and reject memory forms.
//!
//! Intel SDM Vol. 2B (PSRLW/PSRLD/PSRLQ, PSRAW/PSRAD, PSLLW/PSLLD/PSLLQ,
//! PSRLDQ, PSLLDQ) encodes `xmm1, imm8` as `66 0F 71..73 /n ib` with operand
//! encoding "MI": the register is ModR/M.r/m, which REX.B extends to
//! xmm8-xmm15. Vol. 2 Appendix A, Table A-6 defines groups 12, 13, and 14
//! only for `mod = 11B`; the memory forms are reserved (#UD). For the MMX
//! forms (`NP 0F 71..73`), REX.B is ignored: there are only mm0-mm7.
//!
//! The direct interpreter used ModR/M.rm without REX.B, so `psrld $24,
//! %xmm9` shifted xmm1 instead: clang's vectorized byte extraction
//! (`psrld $0x18, %xmm9; packuswb ...`) then produced wrong bytes (found by
//! the morok corpus program `cf_duff_device_parser` under rax-user).
//! Expected values below follow the SDM's per-element definitions, computed
//! independently of the emulator.

use crate::common::*;

const A: u128 = 0xfedc_ba98_7654_3210_8001_7fff_0123_4567;
const SENTINEL: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;

/// Applies `f` to each `bits`-wide element of `v`.
fn lanes(v: u128, bits: u32, f: impl Fn(u128) -> u128) -> u128 {
    let mask = (1u128 << bits) - 1;
    (0..128 / bits).fold(0, |acc, i| {
        acc | ((f((v >> (i * bits)) & mask) & mask) << (i * bits))
    })
}

/// Sign-extends a `bits`-wide element to i128.
fn sext(x: u128, bits: u32) -> i128 {
    ((x << (128 - bits)) as i128) >> (128 - bits)
}

/// The SDM result of group `opcode` (0x71..0x73), operation `/op`, count
/// `imm` on `v`.
fn expected(opcode: u8, op: u8, imm: u8, v: u128) -> u128 {
    let n = u32::from(imm);
    let bits = match opcode {
        0x71 => 16,
        0x72 => 32,
        _ => 64,
    };
    match (opcode, op) {
        (_, 2) => lanes(v, bits, |x| if n >= bits { 0 } else { x >> n }),
        (_, 6) => lanes(v, bits, |x| if n >= bits { 0 } else { x << n }),
        (0x71 | 0x72, 4) => lanes(v, bits, |x| (sext(x, bits) >> n.min(bits - 1)) as u128),
        (0x73, 3) => {
            if n >= 16 {
                0
            } else {
                v >> (8 * n)
            }
        }
        (0x73, 7) => {
            if n >= 16 {
                0
            } else {
                v << (8 * n)
            }
        }
        _ => unreachable!(),
    }
}

/// Runs `prefix 0F opcode modrm imm` on xmm registers preset to `A` (the
/// target) and `SENTINEL` (every other register), returning the registers.
fn run(bytes: &[u8], target: usize) -> Registers {
    let mut code = bytes.to_vec();
    code.push(0xf4);
    let (mut vcpu, mem) = setup_vm(&code, None);
    for i in 0..16 {
        set_xmm(&mem, &mut vcpu, i, if i == target { A } else { SENTINEL });
    }
    run_until_hlt(&mut vcpu).unwrap()
}

const FORMS: [(u8, u8, &str); 10] = [
    (0x71, 2, "PSRLW"),
    (0x71, 4, "PSRAW"),
    (0x71, 6, "PSLLW"),
    (0x72, 2, "PSRLD"),
    (0x72, 4, "PSRAD"),
    (0x72, 6, "PSLLD"),
    (0x73, 2, "PSRLQ"),
    (0x73, 3, "PSRLDQ"),
    (0x73, 6, "PSLLQ"),
    (0x73, 7, "PSLLDQ"),
];

#[test]
fn rex_b_selects_xmm8_to_xmm15() {
    for (opcode, op, name) in FORMS {
        for reg in [8usize, 9, 15] {
            for imm in [0u8, 1, 7, 15, 24, 31, 63, 200] {
                let modrm = 0xc0 | (op << 3) | (reg as u8 & 7);
                let regs = run(&[0x66, 0x41, 0x0f, opcode, modrm, imm], reg);
                let want = expected(opcode, op, imm, A);
                assert_eq!(
                    get_xmm(&regs, reg),
                    want,
                    "{name} xmm{reg}, {imm}: got {:#034x}, want {want:#034x}",
                    get_xmm(&regs, reg)
                );
                for other in (0..16).filter(|&i| i != reg) {
                    assert_eq!(
                        get_xmm(&regs, other),
                        SENTINEL,
                        "{name} xmm{reg}, {imm} changed xmm{other}"
                    );
                }
            }
        }
    }
}

#[test]
fn without_rex_b_the_low_register_is_shifted() {
    // REX with W/R/X but not B (0x4e) still names xmm0-xmm7.
    for (opcode, op, name) in FORMS {
        let modrm = 0xc0 | (op << 3) | 3;
        let regs = run(&[0x66, 0x4e, 0x0f, opcode, modrm, 5], 3);
        assert_eq!(get_xmm(&regs, 3), expected(opcode, op, 5, A), "{name} xmm3");
        assert_eq!(get_xmm(&regs, 11), SENTINEL, "{name} must not touch xmm11");
    }
}

/// Single-steps `code` and asserts that it raised #UD (the harness's IDT
/// sends vector 6 to `INT_HANDLER_ADDR`).
fn assert_ud(code: &[u8]) {
    let (mut vcpu, _mem) = setup_vm(code, None);
    let exit = vcpu
        .step()
        .expect("a reserved encoding must not be a host error");
    assert!(exit.is_none(), "{code:02x?}: expected #UD, got {exit:?}");
    assert_eq!(
        vcpu.get_regs().unwrap().rip,
        INT_HANDLER_ADDR,
        "{code:02x?}: expected #UD"
    );
}

#[test]
fn memory_forms_are_reserved() {
    for (opcode, op, _) in FORMS {
        // mod = 00, 01, 10 with r/m = [rax] (plus a disp8 / disp32).
        assert_ud(&[0x66, 0x0f, opcode, op << 3, 0x05, 0xf4]);
        assert_ud(&[0x66, 0x0f, opcode, 0x40 | (op << 3), 0x10, 0x05, 0xf4]);
        assert_ud(&[
            0x66,
            0x41,
            0x0f,
            opcode,
            0x80 | (op << 3),
            0,
            0,
            0,
            0,
            0x05,
            0xf4,
        ]);
        if op != 3 && op != 7 {
            // The MMX forms are register-only too.
            assert_ud(&[0x0f, opcode, op << 3, 0x05, 0xf4]);
        }
    }
}

#[test]
fn mmx_forms_ignore_rex_b() {
    // 41 0F 72 D1 04 is PSRLD mm1, 4: REX.B does not extend MMX registers.
    let code = [
        0x0f, 0x6f, 0x0c, 0x25, 0x00, 0x20, 0x00, 0x00, // MOVQ MM1, [0x2000]
        0x41, 0x0f, 0x72, 0xd1, 0x04, // PSRLD MM1, 4 (with REX.B)
        0x0f, 0x7f, 0x0c, 0x25, 0x10, 0x20, 0x00, 0x00, // MOVQ [0x2010], MM1
        0xf4,
    ];
    let (mut vcpu, mem) = setup_vm(&code, None);
    write_mem_at_u64(&mem, 0x2000, 0x8765_4321_1234_5678);
    run_until_hlt(&mut vcpu).unwrap();
    assert_eq!(read_mem_at_u64(&mem, 0x2010), 0x0876_5432_0123_4567);
}
