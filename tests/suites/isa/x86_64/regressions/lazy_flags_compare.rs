//! Regression tests: compares that write EFLAGS directly must discard pending
//! lazy flags.
//!
//! Bug: UCOMISS/UCOMISD, FCOMI/FCOMIP/FUCOMI/FUCOMIP, and PTEST wrote ZF, PF,
//! and CF into RFLAGS without clearing the lazy-flags state of the preceding
//! arithmetic instruction, so the next flag reader (SETcc, Jcc, CMOVcc,
//! PUSHF) recomputed the stale arithmetic flags instead. Compiled
//! floating-point code (`if (x == y)`, musl's `printf("%f")` digit loop)
//! took the wrong branch.
//!
//! Expected flags come from the Intel SDM Vol. 2: UCOMISD/UCOMISS
//! ("OF, AF, SF := 0" and the ZF/PF/CF result table), FCOMI/FCOMIP/FUCOMI/
//! FUCOMIP Table 3-31 ("set the OF, SF, and AF flags to zero"), and PTEST
//! ("The OF, AF, PF, SF flags are cleared and the ZF, CF flags are set").
//! Encodings were produced with `llvm-mc -triple=x86_64 -show-encoding`.

use crate::common::*;

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const STATUS: u64 = CF | PF | AF | ZF | SF | OF;

/// `mov edx, 0 ; sub edx, 1`: leaves lazy flags CF=PF=AF=SF=1, ZF=OF=0,
/// the complement of every expectation below in at least one flag.
const LAZY_SUB: [u8; 8] = [0xBA, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEA, 0x01];

/// Runs `setup`, [`LAZY_SUB`], `compare`, then `sete bl ; setp cl ; setb dl ;
/// hlt`, and returns the status flags and the three SETcc results.
fn flags_after(setup: &[u8], compare: &[u8]) -> (u64, [u64; 3]) {
    let mut code = setup.to_vec();
    code.extend_from_slice(&LAZY_SUB);
    code.extend_from_slice(compare);
    code.extend_from_slice(&[
        0x0F, 0x94, 0xC3, // sete bl
        0x0F, 0x9A, 0xC1, // setp cl
        0x0F, 0x92, 0xC2, // setb dl
        0xF4, // hlt
    ]);
    let (mut vcpu, _) = setup_vm(&code, None);
    run_until_hlt(&mut vcpu).unwrap();
    let regs = vcpu.get_regs().unwrap();
    (
        regs.rflags & STATUS,
        [regs.rbx & 0xFF, regs.rcx & 0xFF, regs.rdx & 0xFF],
    )
}

/// `mov rax, a ; movq xmm0, rax ; mov rax, b ; movq xmm1, rax`.
fn load_xmm0_xmm1(a: u64, b: u64) -> Vec<u8> {
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&a.to_le_bytes());
    code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC0, 0x48, 0xB8]);
    code.extend_from_slice(&b.to_le_bytes());
    code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC8]);
    code
}

fn assert_flags(what: &str, got: (u64, [u64; 3]), want: u64) {
    let setcc = [
        u64::from(want & ZF != 0),
        u64::from(want & PF != 0),
        u64::from(want & CF != 0),
    ];
    assert_eq!(
        got,
        (want, setcc),
        "{what}: (status flags, [sete, setp, setb])"
    );
}

const UCOMISD: [u8; 4] = [0x66, 0x0F, 0x2E, 0xC1];
const UCOMISS: [u8; 3] = [0x0F, 0x2E, 0xC1];

#[test]
fn ucomisd_flags_replace_pending_lazy_flags() {
    let one = 1.0f64.to_bits();
    let two = 2.0f64.to_bits();
    let nan = f64::NAN.to_bits();
    for (what, a, b, want) in [
        ("equal", one, one, ZF),
        ("greater", two, one, 0),
        ("less", one, two, CF),
        ("unordered", nan, one, ZF | PF | CF),
    ] {
        assert_flags(what, flags_after(&load_xmm0_xmm1(a, b), &UCOMISD), want);
    }
}

#[test]
fn ucomiss_flags_replace_pending_lazy_flags() {
    let f = |x: f32| u64::from(x.to_bits());
    for (what, a, b, want) in [
        ("equal", f(1.0), f(1.0), ZF),
        ("greater", f(2.0), f(1.0), 0),
        ("less", f(1.0), f(2.0), CF),
        ("unordered", f(f32::NAN), f(1.0), ZF | PF | CF),
    ] {
        assert_flags(what, flags_after(&load_xmm0_xmm1(a, b), &UCOMISS), want);
    }
}

const FLDZ: [u8; 2] = [0xD9, 0xEE];
const FLD1: [u8; 2] = [0xD9, 0xE8];

#[test]
fn x87_compare_to_eflags_replaces_pending_lazy_flags() {
    // Operands are pushed ST(1) first: ST(0) is the second push.
    let cases: [(&str, [[u8; 2]; 2], [u8; 2], u64); 4] = [
        ("fcomi 0 = 0", [FLDZ, FLDZ], [0xDB, 0xF1], ZF),
        ("fucomi 1 > 0", [FLDZ, FLD1], [0xDB, 0xE9], 0),
        ("fcomip 0 < 1", [FLD1, FLDZ], [0xDF, 0xF1], CF),
        ("fucomip 0 = 0", [FLDZ, FLDZ], [0xDF, 0xE9], ZF),
    ];
    for (what, pushes, compare, want) in cases {
        assert_flags(what, flags_after(&pushes.concat(), &compare), want);
    }
}

#[test]
fn ptest_flags_replace_pending_lazy_flags() {
    const PTEST: [u8; 5] = [0x66, 0x0F, 0x38, 0x17, 0xC1];
    for (what, dst, src, want) in [
        // ZF: (src AND dst) == 0; CF: (src AND NOT dst) == 0.
        ("both zero", 0, 0, ZF | CF),
        ("src within dst", u64::MAX, 1, CF),
        ("src outside dst", 1, 2, ZF),
        ("overlap and outside", 1, 3, 0),
    ] {
        assert_flags(what, flags_after(&load_xmm0_xmm1(dst, src), &PTEST), want);
    }
}
