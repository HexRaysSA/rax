//! End-to-end AArch64-on-AArch64 SMIR JIT: lift real AArch64 machine code to
//! SMIR, lower it with the native `Aarch64Lowerer` (identity register map), map
//! it W^X, and execute it on the host through `ExecMem::run_aarch64_identity`.
//!
//! Until now the native AArch64 lowerer was only validated as *bytes* against a
//! QEMU oracle (`tests/suites/differential/arm/aarch64.rs`) — never actually
//! executed. These tests run
//! the lowered code on real hardware and check architectural results, proving
//! the lift → lower → W^X-map → run → marshal-back pipeline.
//!
//! Gated to aarch64 hosts with the `smir-jit` feature (the executor only exists
//! there). Register-only blocks for now (the clobber-safe core); memory/FP/
//! native-exit modes land with the lowerer ABI work.
#![cfg(all(feature = "smir-jit", target_arch = "aarch64", target_os = "linux"))]

use std::collections::HashMap;

use rax::smir::ir::ops::OpKind;
use rax::smir::ir::types::{
    Address, ArchReg, ArmReg, FunctionId, MemWidth, SignExtend, SourceArch, VReg,
};
use rax::smir::ir::{FunctionBuilder, Terminator};
use rax::smir::lift::aarch64::Aarch64Lifter;
use rax::smir::lift::{LiftContext, SmirLifter};
use rax::smir::lower::SmirLowerer;
use rax::smir::lower::aarch64::{Aarch64Lowerer, uses_aarch64_fp_trampoline};
use rax::smir::lower::runtime::{Aarch64GuestRegs, ExecMem};

use rax::isa::arm::{AArch64Config, AArch64Cpu, ArmCpu, CpuExit, FlatMemory};

fn xr(n: u8) -> VReg {
    VReg::Arch(ArchReg::Arm(ArmReg::X(n)))
}

/// Lift `insns` (consecutive 4-byte AArch64 words) into one straight-line SMIR
/// block, lower it natively, execute it over `regs`, and write results back.
fn jit_run(insns: &[u32], regs: &mut Aarch64GuestRegs) -> Result<(), String> {
    let mut lifter = Aarch64Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch64);
    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    for (i, &insn) in insns.iter().enumerate() {
        let pc = (i * 4) as u64;
        let lifted = lifter
            .lift_insn(pc, &insn.to_le_bytes(), &mut ctx)
            .map_err(|e| format!("lift #{i} ({insn:#010x}) failed: {e:?}"))?;
        for op in lifted.ops {
            builder.push_op(op.guest_pc, op.kind);
        }
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut lowerer = Aarch64Lowerer::new();
    let result = lowerer
        .lower_function(&func)
        .map_err(|e| format!("lower failed: {e:?}"))?;
    let code = lowerer
        .finalize()
        .map_err(|e| format!("finalize failed: {e:?}"))?;
    let mem = ExecMem::new(&code).map_err(|e| format!("exec map failed: {e:?}"))?;
    if uses_aarch64_fp_trampoline(&func) {
        mem.run_aarch64_identity_fp(result.entry_offset, regs);
    } else {
        mem.run_aarch64_identity(result.entry_offset, regs);
    }
    Ok(())
}

fn run(insns: &[u32], setup: impl FnOnce(&mut Aarch64GuestRegs)) -> Aarch64GuestRegs {
    let mut regs = Aarch64GuestRegs::default();
    setup(&mut regs);
    jit_run(insns, &mut regs).expect("jit_run");
    regs
}

fn code_bytes_with_ret(insns: &[u32]) -> Vec<u8> {
    let mut code = Vec::with_capacity((insns.len() + 1) * 4);
    for &insn in insns {
        code.extend_from_slice(&insn.to_le_bytes());
    }
    code.extend_from_slice(&0xd65f_03c0u32.to_le_bytes()); // ret
    code
}

fn raw_native_run(insns: &[u32], setup: impl FnOnce(&mut Aarch64GuestRegs)) -> Aarch64GuestRegs {
    let code = code_bytes_with_ret(insns);
    let mem = ExecMem::new(&code).expect("raw native map");
    let mut regs = Aarch64GuestRegs::default();
    setup(&mut regs);
    mem.run_aarch64_identity(0, &mut regs);
    regs
}

fn raw_native_run_fp(insns: &[u32], setup: impl FnOnce(&mut Aarch64GuestRegs)) -> Aarch64GuestRegs {
    let code = code_bytes_with_ret(insns);
    let mem = ExecMem::new(&code).expect("raw native fp map");
    let mut regs = Aarch64GuestRegs::default();
    setup(&mut regs);
    mem.run_aarch64_identity_fp(0, &mut regs);
    regs
}

#[path = "aarch64_native/fp_reference.rs"]
mod fp_reference;
use fp_reference::raw_interp_run;

fn assert_raw_gpr0_to_gpr2_nzcv_matches(
    label: &str,
    insns: &[u32],
    setup: impl Fn(&mut Aarch64GuestRegs),
) {
    let hw = raw_native_run(insns, |g| setup(g));
    let interp = raw_interp_run(insns, |g| setup(g));
    for reg in 0..=2usize {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "{label}: raw EL0 control-flow oracle x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "{label}: raw EL0 control-flow oracle NZCV mismatch"
    );
}

fn host_has_aarch64_feature(feature: &str) -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|cpuinfo| {
            cpuinfo.lines().any(|line| {
                let Some((name, value)) = line.split_once(':') else {
                    return false;
                };
                matches!(name.trim(), "Features" | "flags")
                    && value.split_whitespace().any(|flag| flag == feature)
            })
        })
        .unwrap_or(false)
}

fn pin_sve_vl_128() -> Option<usize> {
    let ret = unsafe {
        libc::prctl(
            50, // PR_SVE_SET_VL
            16usize as libc::c_ulong,
            0usize as libc::c_ulong,
            0usize as libc::c_ulong,
            0usize as libc::c_ulong,
        )
    };
    if ret < 0 {
        None
    } else {
        Some((ret as usize) & 0xffff)
    }
}

#[test]
fn add_register() {
    // 8b020020  add x0, x1, x2
    let r = run(&[0x8b02_0020], |g| {
        g.x[1] = 40;
        g.x[2] = 2;
    });
    assert_eq!(r.x[0], 42);
}

#[test]
fn raw_el0_scalar_oracle_matches_interpreter() {
    let insns = [
        0xab02_0020, // adds x0, x1, x2
        0xba05_0083, // adcs x3, x4, x5
        0xda08_00e6, // sbc  x6, x7, x8
        0xeb0b_0149, // subs x9, x10, x11
    ];
    let cases: &[&[(u8, u64)]] = &[
        &[
            (1, 1),
            (2, 2),
            (4, u64::MAX),
            (5, 1),
            (7, 10),
            (8, 3),
            (10, 100),
            (11, 40),
        ],
        &[
            (1, u64::MAX),
            (2, 1),
            (4, 5),
            (5, 7),
            (7, 0),
            (8, 1),
            (10, 0),
            (11, 1),
        ],
    ];

    for case in cases {
        let hw = raw_native_run(&insns, |g| {
            for &(reg, value) in *case {
                g.x[reg as usize] = value;
            }
        });
        let interp = raw_interp_run(&insns, |g| {
            for &(reg, value) in *case {
                g.x[reg as usize] = value;
            }
        });
        for reg in 0..=11usize {
            assert_eq!(
                hw.x[reg], interp.x[reg],
                "raw EL0 oracle x{reg} mismatch for case {case:?}"
            );
        }
        assert_eq!(
            hw.nzcv & 0xf000_0000,
            interp.nzcv & 0xf000_0000,
            "raw EL0 oracle NZCV mismatch for case {case:?}"
        );
    }
}

#[test]
fn raw_el0_scalar_32bit_oracle_matches_interpreter() {
    let insns = [
        0x2b02_0020, // adds w0, w1, w2
        0x3a05_0083, // adcs w3, w4, w5
        0x5a08_00e6, // sbc  w6, w7, w8
        0x6b0b_0149, // subs w9, w10, w11
        0x0a0e_01ac, // and  w12, w13, w14
        0x2a11_020f, // orr  w15, w16, w17
        0x4a15_0293, // eor  w19, w20, w21
        0x0a38_02f6, // bic  w22, w23, w24
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xaaaa_aaaa_ffff_ffff;
        g.x[2] = 0xbbbb_bbbb_0000_0001;
        g.x[4] = 0xcccc_cccc_0000_0001;
        g.x[5] = 0xdddd_dddd_0000_0002;
        g.x[7] = 0xeeee_eeee_0000_0010;
        g.x[8] = 0xffff_ffff_0000_0003;
        g.x[10] = 0x1111_1111_8000_0000;
        g.x[11] = 0x2222_2222_0000_0001;
        g.x[13] = 0x3333_3333_ff00_ff00;
        g.x[14] = 0x4444_4444_0f0f_0f0f;
        g.x[16] = 0x5555_5555_00ff_00ff;
        g.x[17] = 0x6666_6666_f0f0_f0f0;
        g.x[20] = 0x7777_7777_5555_aaaa;
        g.x[21] = 0x8888_8888_ffff_0000;
        g.x[23] = 0x9999_9999_ffff_00ff;
        g.x[24] = 0xaaaa_aaaa_0f0f_f0f0;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 19, 22] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 32-bit scalar x{reg} mismatch"
        );
        assert_eq!(
            hw.x[reg] >> 32,
            0,
            "raw EL0 32-bit scalar x{reg} was not zero-extended"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 32-bit scalar NZCV mismatch"
    );
}

#[test]
fn raw_el0_scalar_immediate_oracle_matches_interpreter() {
    let insns = [
        0xd2a2_4680, // movz x0, #0x1234, lsl #16
        0xf295_79a0, // movk x0, #0xabcd
        0x92aa_b541, // movn x1, #0x55aa, lsl #16
        0x912a_f062, // add  x2, x3, #0xabc
        0xd144_8ca4, // sub  x4, x5, #0x123, lsl #12
        0xb208_9ce6, // orr  x6, x7, #0xff00ff00ff00ff00
        0x9200_cd28, // and  x8, x9, #0x0f0f0f0f0f0f0f0f
        0xd210_3d6a, // eor  x10, x11, #0xffff0000ffff0000
        0x529e_01ac, // movz w12, #0xf00d
        0x72a2_468c, // movk w12, #0x1234, lsl #16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[3] = 0x1111_2222_3333_4444;
        g.x[5] = 0xffff_0000_1234_5678;
        g.x[7] = 0x00ff_00ff_00ff_00ff;
        g.x[9] = 0xffff_ffff_ffff_ffff;
        g.x[11] = 0x1234_5678_9abc_def0;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 1, 2, 4, 6, 8, 10, 12] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 scalar immediate x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.x[12] >> 32,
        0,
        "raw EL0 scalar immediate w12 was not zero-extended"
    );
}

#[test]
fn raw_el0_multiply_divide_oracle_matches_interpreter() {
    let insns = [
        0x9b02_0c20, // madd  x0, x1, x2, x3
        0x9b06_9ca4, // msub  x4, x5, x6, x7
        0x9b2a_2d28, // smaddl x8, w9, w10, x11
        0x9b2e_bdac, // smsubl x12, w13, w14, x15
        0x9bb3_5230, // umaddl x16, w17, w19, x20
        0x9bb7_e2d5, // umsubl x21, w22, w23, x24
        0x9b5b_7f59, // smulh x25, x26, x27
        0x9bc2_7c3d, // umulh x29, x1, x2
        0x9ad4_0e63, // sdiv  x3, x19, x20
        0x9ad7_0ac5, // udiv  x5, x22, x23
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x1234_5678_9abc_def0;
        g.x[2] = 0x0102_0304_0506_0708;
        g.x[3] = 0x1111_2222_3333_4444;
        g.x[5] = 0xfedc_ba98_7654_3210;
        g.x[6] = 0x0f0f_f0f0_aaaa_5555;
        g.x[7] = 0x2222_3333_4444_5555;
        g.x[9] = 0xffff_8001;
        g.x[10] = 0x0000_7fff;
        g.x[11] = 0x0123_4567_89ab_cdef;
        g.x[13] = 0x8000_0001;
        g.x[14] = 0x0000_0003;
        g.x[15] = 0x5555_6666_7777_8888;
        g.x[17] = 0xffff_fffe;
        g.x[19] = 0xffff_ffff_ffff_ffc0;
        g.x[20] = 7;
        g.x[22] = 0xffff_ffff;
        g.x[23] = 0x0000_1001;
        g.x[24] = 0x7777_8888_9999_aaaa;
        g.x[26] = 0x8000_0000_0000_0001;
        g.x[27] = 0x7fff_ffff_ffff_fffe;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 4, 5, 8, 12, 16, 21, 25, 29] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 multiply/divide oracle x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_multiply_divide_32bit_oracle_matches_interpreter() {
    let insns = [
        0x1b02_0c20, // madd w0, w1, w2, w3
        0x1b06_9ca4, // msub w4, w5, w6, w7
        0x1b0a_7d28, // mul  w8, w9, w10
        0x1acd_0d8b, // sdiv w11, w12, w13
        0x1ad0_09ee, // udiv w14, w15, w16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xaaaa_aaaa_ffff_fffe;
        g.x[2] = 0xbbbb_bbbb_0000_0003;
        g.x[3] = 0xcccc_cccc_0000_0005;
        g.x[5] = 0xdddd_dddd_8000_0001;
        g.x[6] = 0xeeee_eeee_0000_0002;
        g.x[7] = 0xffff_ffff_0000_0010;
        g.x[9] = 0x1111_1111_0001_0001;
        g.x[10] = 0x2222_2222_0000_00ff;
        g.x[12] = 0x3333_3333_8000_0000;
        g.x[13] = 0x4444_4444_ffff_fff0;
        g.x[15] = 0x5555_5555_ffff_ffff;
        g.x[16] = 0x6666_6666_0000_1001;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 4, 8, 11, 14] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 32-bit multiply/divide x{reg} mismatch"
        );
        assert_eq!(
            hw.x[reg] >> 32,
            0,
            "raw EL0 32-bit multiply/divide x{reg} was not zero-extended"
        );
    }
}

#[test]
fn raw_el0_dp2src_32bit_edge_oracle_matches_interpreter() {
    let insns = [
        0x1ac2_2020, // lsl  w0, w1, w2
        0x1ac5_2483, // lsr  w3, w4, w5
        0x1ac8_28e6, // asr  w6, w7, w8
        0x1acb_2d49, // ror  w9, w10, w11
        0x1ace_0dac, // sdiv w12, w13, w14
        0x1ad1_0e0f, // sdiv w15, w16, w17
        0x1ad5_0a93, // udiv w19, w20, w21
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xffff_ffff_0000_0003;
        g.x[2] = 0xaaaa_aaaa_0000_0024; // masks to shift 4
        g.x[4] = 0xffff_ffff_8000_0000;
        g.x[5] = 0xbbbb_bbbb_0000_0021; // masks to shift 1
        g.x[7] = 0xffff_ffff_8000_0001;
        g.x[8] = 0xcccc_cccc_0000_003f; // masks to shift 31
        g.x[10] = 0xffff_ffff_0123_4567;
        g.x[11] = 0xdddd_dddd_0000_0028; // masks to rotate 8
        g.x[13] = 0xffff_ffff_8000_0000;
        g.x[14] = 0xffff_ffff_ffff_ffff;
        g.x[16] = 0xeeee_eeee_1234_5678;
        g.x[17] = 0xffff_ffff_0000_0000;
        g.x[20] = 0xffff_ffff_fedc_ba98;
        g.x[21] = 0xffff_ffff_0000_0000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 19] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 32-bit DP2 edge oracle x{reg} mismatch"
        );
        assert_eq!(
            hw.x[reg] >> 32,
            0,
            "raw EL0 32-bit DP2 edge x{reg} was not zero-extended"
        );
    }
}

#[test]
fn raw_el0_shift_extend_logic_oracle_matches_interpreter() {
    let insns = [
        0x9ac2_2020, // lsl  x0, x1, x2
        0x9ac5_2483, // lsr  x3, x4, x5
        0x9ac8_28e6, // asr  x6, x7, x8
        0x9acb_2d49, // ror  x9, x10, x11
        0x8b2e_c9ac, // add  x12, x13, w14, sxtw #2
        0xcb31_4e0f, // sub  x15, x16, w17, uxtw #3
        0x8b17_32d5, // add  x21, x22, x23, lsl #12
        0xcb9a_1338, // sub  x24, x25, x26, asr #4
        0xea02_003b, // ands x27, x1, x2
        0xcae4_347d, // eon  x29, x3, x4, ror #13
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x0123_4567_89ab_cdef;
        g.x[2] = 13;
        g.x[4] = 0xfedc_ba98_7654_3210;
        g.x[5] = 17;
        g.x[7] = 0x8000_0000_0000_00ff;
        g.x[8] = 9;
        g.x[10] = 0x1122_3344_5566_7788;
        g.x[11] = 29;
        g.x[13] = 0x1111_2222_3333_4444;
        g.x[14] = 0xffff_8000;
        g.x[16] = 0x9999_aaaa_bbbb_cccc;
        g.x[17] = 0x0000_7fff;
        g.x[22] = 0x0000_0000_0000_1000;
        g.x[23] = 0x0000_0000_0000_0020;
        g.x[25] = 0x1000_0000_0000_0000;
        g.x[26] = 0xf000_0000_0000_0000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 21, 24, 27, 29] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 shift/extend/logic oracle x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 shift/extend/logic NZCV mismatch"
    );
}

#[test]
fn raw_el0_bitfield_oracle_matches_interpreter() {
    let insns = [
        0xd348_3c20, // ubfx x0, x1, #8, #8
        0x9344_7c62, // sbfx x2, x3, #4, #28
        0xb350_7ca4, // bfxil x4, x5, #16, #16
        0x93c8_30e6, // extr x6, x7, x8, #12
        0xdac0_0149, // rbit x9, x10
        0xdac0_0d8b, // rev  x11, x12
        0xdac0_11cd, // clz  x13, x14
        0xdac0_160f, // cls  x15, x16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x0123_4567_89ab_cdef;
        g.x[3] = 0xffff_ffff_8000_0010;
        g.x[4] = 0xaaaa_5555_ffff_0000;
        g.x[5] = 0x1234_5678_9abc_def0;
        g.x[7] = 0x0fed_cba9_8765_4321;
        g.x[8] = 0x1122_3344_5566_7788;
        g.x[10] = 0x0123_4567_89ab_cdef;
        g.x[12] = 0x1020_3040_5060_7080;
        g.x[14] = 0x0000_0000_0000_0100;
        g.x[16] = 0xffff_ffff_ffff_f000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 9, 11, 13, 15] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 bitfield oracle x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_bitfield_32bit_oracle_matches_interpreter() {
    let insns = [
        0x5304_2c20, // ubfx  w0, w1, #4, #8
        0x1308_4c62, // sbfx  w2, w3, #8, #12
        0x3308_4ca4, // bfxil w4, w5, #8, #12
        0x1388_14e6, // extr  w6, w7, w8, #5
        0x5ac0_0149, // rbit  w9, w10
        0x5ac0_098b, // rev   w11, w12
        0x5ac0_05cd, // rev16 w13, w14
        0x5ac0_120f, // clz   w15, w16
        0x5ac0_1671, // cls   w17, w19
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xffff_ffff_89ab_cdef;
        g.x[3] = 0xffff_ffff_fff8_1010;
        g.x[4] = 0xffff_ffff_aaaa_5555;
        g.x[5] = 0xffff_ffff_1234_5678;
        g.x[7] = 0xffff_ffff_0fed_cba9;
        g.x[8] = 0xffff_ffff_8765_4321;
        g.x[10] = 0xffff_ffff_0123_4567;
        g.x[12] = 0xffff_ffff_1020_3040;
        g.x[14] = 0xffff_ffff_a1b2_c3d4;
        g.x[16] = 0xffff_ffff_0001_0000;
        g.x[19] = 0xffff_ffff_ffff_f000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 9, 11, 13, 15, 17] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 32-bit bitfield oracle x{reg} mismatch"
        );
        assert_eq!(
            hw.x[reg] >> 32,
            0,
            "raw EL0 32-bit bitfield x{reg} was not zero-extended"
        );
    }
}

#[test]
fn raw_el0_crc_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("crc32") {
        eprintln!("[skip] host does not advertise CRC32");
        return;
    }

    let insns = [
        0x1ac2_4020, // crc32b  w0, w1, w2
        0x1ac5_4483, // crc32h  w3, w4, w5
        0x1ac8_48e6, // crc32w  w6, w7, w8
        0x9acb_4d49, // crc32x  w9, w10, x11
        0x1ace_51ac, // crc32cb w12, w13, w14
        0x1ad1_560f, // crc32ch w15, w16, w17
        0x1ad4_5a78, // crc32cw w24, w19, w20
        0x9ad7_5ed5, // crc32cx w21, w22, x23
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x1234_5678;
        g.x[2] = 0xab;
        g.x[4] = 0x89ab_cdef;
        g.x[5] = 0x1234;
        g.x[7] = 0xfeed_face;
        g.x[8] = 0xcafe_beef;
        g.x[10] = 0x0102_0304;
        g.x[11] = 0x0123_4567_89ab_cdef;
        g.x[13] = 0x7654_3210;
        g.x[14] = 0xef;
        g.x[16] = 0x0bad_f00d;
        g.x[17] = 0xbeef;
        g.x[19] = 0xa5a5_5a5a;
        g.x[20] = 0x1357_9bdf;
        g.x[22] = 0xffff_0000;
        g.x[23] = 0xfedc_ba98_7654_3210;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 21, 24] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 CRC oracle x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_conditional_select_compare_oracle_matches_interpreter() {
    let insns = [
        0x9a82_0020, // csel  x0, x1, x2, eq
        0x9a85_1483, // csinc x3, x4, x5, ne
        0xda88_00e6, // csinv x6, x7, x8, eq
        0xda8b_1549, // csneg x9, x10, x11, ne
        0x9a9f_17f0, // cset  x16, eq
        0xda9f_03f1, // csetm x17, ne
        0x9a99_1738, // cinc  x24, x25, eq
        0xda95_02b4, // cinv  x20, x21, ne
        0xda97_16f6, // cneg  x22, x23, eq
        0xfa4d_018a, // ccmp  x12, x13, #10, eq
        0xba4f_11c5, // ccmn  x14, x15, #5, ne
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.nzcv = 0x4000_0000; // Z=1, so EQ is initially true.
        g.x[1] = 0x1111_2222_3333_4444;
        g.x[2] = 0xaaaa_bbbb_cccc_dddd;
        g.x[4] = 0x10;
        g.x[5] = 0x20;
        g.x[7] = 0x0123_4567_89ab_cdef;
        g.x[8] = 0xfedc_ba98_7654_3210;
        g.x[10] = 0x7;
        g.x[11] = 0x8;
        g.x[12] = 0x100;
        g.x[13] = 0x80;
        g.x[14] = 1;
        g.x[15] = u64::MAX;
        g.x[21] = 0x5555_aaaa_ffff_0000;
        g.x[23] = 9;
        g.x[25] = 0x1234;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 16, 17, 20, 22, 24] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 conditional select x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 conditional compare NZCV mismatch"
    );
}

#[test]
fn raw_el0_conditional_select_32bit_edge_oracle_matches_interpreter() {
    let insns = [
        0xd51b_4214, // msr   nzcv, x20
        0x1a82_0020, // csel  w0, w1, w2, eq
        0x1a85_1483, // csinc w3, w4, w5, ne
        0xd51b_4215, // msr   nzcv, x21
        0x5a88_00e6, // csinv w6, w7, w8, eq
        0x5a8b_5549, // csneg w9, w10, w11, pl
        0xd51b_4216, // msr   nzcv, x22
        0x1a8e_41ac, // csel  w12, w13, w14, mi
        0x1a91_560f, // csinc w15, w16, w17, pl
        0x5a97_1274, // csinv w20, w19, w23, ne
        0x5a9a_0738, // csneg w24, w25, w26, eq
        0xd53b_421b, // mrs   x27, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xffff_ffff_1234_5678;
        g.x[2] = 0xaaaa_aaaa_8765_4321;
        g.x[4] = 0x1111_1111_2222_2222;
        g.x[5] = 0x9999_9999_ffff_ffff;
        g.x[7] = 0x7777_7777_0102_0304;
        g.x[8] = 0x8888_8888_1357_9bdf;
        g.x[10] = 0xaaaa_aaaa_2468_ace0;
        g.x[11] = 0xbbbb_bbbb_0000_0005;
        g.x[13] = 0xdddd_dddd_dead_beef;
        g.x[14] = 0xeeee_eeee_cafe_f00d;
        g.x[16] = 0x1010_1010_8000_0000;
        g.x[17] = 0x1717_1717_7fff_ffff;
        g.x[19] = 0x1919_1919_fedc_ba98;
        g.x[23] = 0x2323_2323_0123_4567;
        g.x[25] = 0x2525_2525_0000_0006;
        g.x[26] = 0x2626_2626_8000_0001;
        g.x[20] = 0x4000_0000; // Z=1
        g.x[21] = 0x8000_0000; // N=1, Z=0
        g.x[22] = 0; // N=0, Z=0
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 20, 24] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 32-bit conditional select x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.x[27] & 0xf000_0000,
        interp.x[27] & 0xf000_0000,
        "raw EL0 32-bit conditional select mrs NZCV mismatch"
    );
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 32-bit conditional select final NZCV mismatch"
    );
}

#[test]
fn raw_el0_conditional_compare_fallback_oracle_matches_interpreter() {
    let insns = [
        0xd51b_4200, // msr  nzcv, x0
        0xfa42_102a, // ccmp x1, x2, #10, ne
        0xd53b_4203, // mrs  x3, nzcv
        0xd51b_4204, // msr  nzcv, x4
        0xba46_00a5, // ccmn x5, x6, #5, eq
        0xd53b_4207, // mrs  x7, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = 0x4000_0000; // Z=1, so NE is false.
        g.x[1] = 0x10;
        g.x[2] = 0x10;
        g.x[4] = 0; // Z=0, so EQ is false.
        g.x[5] = 0x20;
        g.x[6] = 0x20;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [3usize, 7] {
        assert_eq!(
            hw.x[reg] & 0xf000_0000,
            interp.x[reg] & 0xf000_0000,
            "raw EL0 conditional compare fallback x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 conditional compare fallback final NZCV mismatch"
    );
}

#[test]
fn raw_el0_conditional_compare_32bit_oracle_matches_interpreter() {
    let insns = [
        0xd51b_4214, // msr  nzcv, x20
        0x7a42_002a, // ccmp w1, w2, #10, eq
        0xd53b_4203, // mrs  x3, nzcv
        0xd51b_4215, // msr  nzcv, x21
        0x7a45_008a, // ccmp w4, w5, #10, eq
        0xd53b_4206, // mrs  x6, nzcv
        0xd51b_4216, // msr  nzcv, x22
        0x3a48_10e5, // ccmn w7, w8, #5, ne
        0xd53b_4209, // mrs  x9, nzcv
        0xd51b_4217, // msr  nzcv, x23
        0x3a4b_1145, // ccmn w10, w11, #5, ne
        0xd53b_420c, // mrs  x12, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0xffff_ffff_8000_0000;
        g.x[2] = 0x1111_1111_0000_0001;
        g.x[4] = 0x4444_4444_1234_5678;
        g.x[5] = 0x5555_5555_8765_4321;
        g.x[7] = 0x7777_7777_ffff_ffff;
        g.x[8] = 0x8888_8888_0000_0001;
        g.x[10] = 0xaaaa_aaaa_7fff_ffff;
        g.x[11] = 0xbbbb_bbbb_0000_0001;
        g.x[20] = 0x4000_0000; // Z=1, so EQ is true.
        g.x[21] = 0; // Z=0, so EQ is false and #10 becomes NZCV.
        g.x[22] = 0; // Z=0, so NE is true.
        g.x[23] = 0x4000_0000; // Z=1, so NE is false and #5 becomes NZCV.
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [3usize, 6, 9, 12] {
        assert_eq!(
            hw.x[reg] & 0xf000_0000,
            interp.x[reg] & 0xf000_0000,
            "raw EL0 32-bit conditional compare x{reg} NZCV mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 32-bit conditional compare final NZCV mismatch"
    );
}

#[test]
fn raw_el0_vector_oracle_matches_interpreter() {
    let insns = [
        0x4ee2_1c20, // orn v0.16b, v1.16b, v2.16b
        0x6e65_1c83, // bsl v3.16b, v4.16b, v5.16b
        0x6ea8_1ce6, // bit v6.16b, v7.16b, v8.16b
        0x6eeb_1d49, // bif v9.16b, v10.16b, v11.16b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x0123_4567_89ab_cdef;
        g.v[3] = 0xfedc_ba98_7654_3210;
        g.v[4] = 0x0f0f_f0f0_55aa_aa55;
        g.v[5] = 0x3333_cccc_9696_6969;
        g.v[6] = 0x00ff_00ff_00ff_00ff;
        g.v[7] = 0xff00_ff00_ff00_ff00;
        g.v[8] = 0x1111_2222_3333_4444;
        g.v[9] = 0x5555_6666_7777_8888;
        g.v[10] = 0x9999_aaaa_bbbb_cccc;
        g.v[11] = 0xdddd_eeee_ffff_0000;
        g.v[12] = 0x0123_4567_89ab_cdef;
        g.v[13] = 0xfedc_ba98_7654_3210;
        g.v[14] = 0x0f0f_f0f0_3333_cccc;
        g.v[15] = 0xffff_0000_cccc_3333;
        g.v[16] = 0x1234_5678_9abc_def0;
        g.v[17] = 0x0f0f_f0f0_55aa_aa55;
        g.v[18] = 0x00ff_00ff_00ff_00ff;
        g.v[19] = 0xff00_ff00_ff00_ff00;
        g.v[20] = 0x1357_9bdf_2468_ace0;
        g.v[21] = 0x0f0f_f0f0_3333_cccc;
        g.v[22] = 0xaaaa_5555_ffff_0000;
        g.v[23] = 0x3333_cccc_5555_aaaa;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0..=11usize {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 vector oracle v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_integer_oracle_matches_interpreter() {
    let insns = [
        0x4e62_8420, // add   v0.8h, v1.8h, v2.8h
        0x6ea5_8483, // sub   v3.4s, v4.4s, v5.4s
        0x0e68_94e6, // mla   v6.4h, v7.4h, v8.4h
        0x2e6b_c149, // umull v9.4s, v10.4h, v11.4h
        0x0e6e_01ac, // saddl v12.4s, v13.4h, v14.4h
        0x6e31_0e0f, // uqadd v15.16b, v16.16b, v17.16b
        0x4e74_2e72, // sqsub v18.8h, v19.8h, v20.8h
        0x4eb7_06d5, // shadd v21.4s, v22.4s, v23.4s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0001_0002_7fff_8000, 0x1234_5678_9abc_def0),
            (2, 0xffff_0001_0002_0003, 0x1111_2222_3333_4444),
            (4, 0x0000_0010_ffff_fff0, 0x7fff_ffff_8000_0000),
            (5, 0x0000_0001_0000_0020, 0x0000_0001_ffff_fffe),
            (6, 0x0001_0002_0003_0004, 0xaaaa_bbbb_cccc_dddd),
            (7, 0x0002_0003_0004_0005, 0x1111_2222_3333_4444),
            (8, 0x0006_0007_0008_0009, 0x5555_6666_7777_8888),
            (10, 0x0001_0002_0003_0004, 0x1000_2000_3000_4000),
            (11, 0x0005_0006_0007_0008, 0x5000_6000_7000_8000),
            (13, 0x7fff_8000_0001_ffff, 0x1111_2222_3333_4444),
            (14, 0x0001_ffff_8000_7fff, 0x5555_6666_7777_8888),
            (16, 0xfffe_fdfc_0102_0304, 0x8081_7f7e_1020_3040),
            (17, 0x0102_0304_fffe_fdfc, 0x8080_8181_f0e0_d0c0),
            (19, 0x8000_8001_7fff_0000, 0x0100_0200_0300_0400),
            (20, 0x0001_0002_ffff_8000, 0x8000_7000_6000_5000),
            (22, 0x0000_0010_ffff_fff0, 0x4000_0000_8000_0000),
            (23, 0xffff_fff0_0000_0010, 0x4000_0000_7fff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD integer v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_three_diff_oracle_matches_interpreter() {
    let insns = [
        0x0e62_0020, // saddl   v0.4s, v1.4h, v2.4h
        0x4e65_0083, // saddl2  v3.4s, v4.8h, v5.8h
        0x2e68_10e6, // uaddw   v6.4s, v7.4s, v8.4h
        0x4e6b_3149, // ssubw2  v9.4s, v10.4s, v11.8h
        0x0e6e_61ac, // subhn   v12.4h, v13.4s, v14.4s
        0x6e71_420f, // raddhn2 v15.8h, v16.4s, v17.4s
        0x0e74_7272, // sabdl   v18.4s, v19.4h, v20.4h
        0x0e7a_5338, // sabal   v24.4s, v25.4h, v26.4h
        0x6e7d_739b, // uabdl2  v27.4s, v28.8h, v29.8h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h8([0x0001, 0xffff, 0x7fff, 0x8000, 0, 0, 0, 0]),
            ),
            (2, pack_h8([0x0002, 0x0003, 0x8000, 0x7fff, 0, 0, 0, 0])),
            (4, pack_h8([1, 2, 3, 4, 0xfff0, 0x8000, 0x7fff, 0x0008])),
            (5, pack_h8([5, 6, 7, 8, 0x0004, 0x7fff, 0x8001, 0xfff8])),
            (7, pack_s4([10, 20, 30, 40])),
            (8, pack_h8([1, 2, 3, 4, 0, 0, 0, 0])),
            (10, pack_s4([100, 200, 300, 400])),
            (11, pack_h8([0, 0, 0, 0, 0xffff, 0x0002, 0x8000, 0x7fff])),
            (
                13,
                pack_s4([0x0001_0000, 0x8000_0000, 0xffff_0000, 0x7fff_ffff]),
            ),
            (
                14,
                pack_s4([0x0000_0001, 0x7fff_ffff, 0x0000_ffff, 0x8000_0000]),
            ),
            (
                15,
                pack_h8([
                    0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0x1111, 0x2222, 0x3333, 0x4444,
                ]),
            ),
            (
                16,
                pack_s4([0x0001_0000, 0x0002_0000, 0x7fff_0000, 0x8000_0000]),
            ),
            (
                17,
                pack_s4([0x0000_ffff, 0x0002_ffff, 0x8000_0000, 0x7fff_ffff]),
            ),
            (19, pack_h8([0x0001, 0xffff, 0x7fff, 0x8000, 0, 0, 0, 0])),
            (20, pack_h8([0xffff, 0x0001, 0x8000, 0x7fff, 0, 0, 0, 0])),
            (24, pack_s4([10, 20, 30, 40])),
            (25, pack_h8([0x0008, 0xfff0, 0x7fff, 0x8000, 0, 0, 0, 0])),
            (26, pack_h8([0xfff8, 0x0004, 0x8001, 0x7fff, 0, 0, 0, 0])),
            (28, pack_h8([1, 2, 3, 4, 0x1000, 0x2000, 0x3000, 0x4000])),
            (29, pack_h8([5, 6, 7, 8, 0x0100, 0x3000, 0x2000, 0x5000])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 24, 27] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD three-different v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_two_reg_integer_oracle_matches_interpreter() {
    let insns = [
        0x4e20_b820, // abs    v0.16b, v1.16b
        0x6e60_b862, // neg    v2.8h, v3.8h
        0x4e20_48a4, // cls    v4.16b, v5.16b
        0x6e60_48e6, // clz    v6.8h, v7.8h
        0x4e20_5928, // cnt    v8.16b, v9.16b
        0x4e20_196a, // rev16  v10.16b, v11.16b
        0x6e60_09ac, // rev32  v12.8h, v13.8h
        0x4ea0_09ee, // rev64  v14.4s, v15.4s
        0x4e60_7a30, // sqabs  v16.8h, v17.8h
        0x6ea0_7a72, // sqneg  v18.4s, v19.4s
        0x4e61_2ab4, // xtn2   v20.8h, v21.4s
        0x4e60_2af6, // saddlp v22.4s, v23.8h
        0x6e60_2b38, // uaddlp v24.4s, v25.8h
        0x4e20_3b7a, // suqadd v26.16b, v27.16b
        0x6e60_3bbc, // usqadd v28.8h, v29.8h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x807f_0102_fe03_0405, 0x1112_1314_1516_17f8),
            (3, 0x8000_7fff_0001_ffff, 0x1000_f000_0002_fffe),
            (5, 0x807f_0102_fe03_0405, 0x1112_1314_1516_17f8),
            (7, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
            (9, 0x0123_4567_89ab_cdef, 0xf0f0_0f0f_aaaa_5555),
            (11, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (13, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (15, 0x0000_0001_0000_0002, 0x0000_0003_0000_0004),
            (17, 0x8000_7fff_0001_ffff, 0x1000_f000_0002_fffe),
            (19, 0x8000_0000_7fff_ffff, 0x0000_0001_ffff_ffff),
            (20, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (21, 0x0001_0000_ffff_ffff, 0x1234_5678_8765_4321),
            (23, 0x0001_ffff_8000_7fff, 0x1000_f000_0002_fffe),
            (25, 0x0001_0002_0003_0004, 0x8000_7fff_ffff_fffe),
            (26, 0x7f80_0102_fe03_0405, 0x1112_1314_1516_17f8),
            (27, 0x0102_7fff_8000_fffe, 0x2020_e0e0_0001_ffff),
            (28, 0x8000_7fff_0001_ffff, 0x1000_f000_0002_fffe),
            (29, 0x0001_8000_ffff_7fff, 0x2000_e000_0001_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD two-register integer v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD two-register integer FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_scalar_two_reg_oracle_matches_interpreter() {
    let insns = [
        0x5ee0_b820, // abs    d0, d1
        0x7ee0_b862, // neg    d2, d3
        0x5e20_78a4, // sqabs  b4, b5
        0x7e60_78e6, // sqneg  h6, h7
        0x5ea0_3928, // suqadd s8, s9
        0x7ee0_396a, // usqadd d10, d11
        0x5e21_49ac, // sqxtn  b12, h13
        0x7e61_49ee, // uqxtn  h14, s15
        0x7e21_2a30, // sqxtun b16, h17
        0x7e61_6a72, // fcvtxn s18, d19
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = (-7i64) as u64; // d1
        g.v[6] = 9; // d3
        g.v[10] = 0x80; // b5 saturates for SQABS.
        g.v[14] = 0x8000; // h7 saturates for SQNEG.
        g.v[16] = 0x0000_0000_7000_0000; // s8 accumulator.
        g.v[18] = 0x0000_0000_2000_0000; // s9 signed addend.
        g.v[20] = 0xffff_ffff_ffff_ffff; // d10 accumulator.
        g.v[22] = 2; // d11 unsigned/signed addend.
        g.v[26] = 0x0100; // h13 narrows with signed saturation.
        g.v[30] = 0x0001_0000; // s15 narrows with unsigned saturation.
        g.v[34] = 0xffff; // h17 negative narrows to unsigned zero.
        g.v[38] = 1.5_f64.to_bits(); // d19
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD scalar two-register v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD scalar two-register FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_scalar_integer_oracle_matches_interpreter() {
    let insns = [
        0x5e22_0c20, // sqadd    b0, b1, b2
        0x5e65_2c83, // sqsub    h3, h4, h5
        0x5ee8_34e6, // cmgt     d6, d7, d8
        0x7eeb_3549, // cmhi     d9, d10, d11
        0x5eee_45ac, // sshl     d12, d13, d14
        0x7eb1_4e0f, // uqshl    s15, s16, s17
        0x5ef4_5672, // srshl    d18, d19, d20
        0x7e37_5ed5, // uqrshl   b21, b22, b23
        0x5e7a_b738, // sqdmulh  h24, h25, h26
        0x7ebd_b79b, // sqrdmulh s27, s28, s29
        0x5ee6_8ca4, // cmtst    d4, d5, d6
        0x5ee1_841e, // add      d30, d0, d1
        0x7ee3_845f, // sub      d31, d2, d3
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x7f; // b1
        g.v[4] = 0x02; // b2
        g.v[8] = 0x8000; // h4
        g.v[10] = 0x0001; // h5
        g.v[14] = 5; // d7
        g.v[16] = (-1i64) as u64; // d8
        g.v[20] = 0; // d10
        g.v[22] = u64::MAX; // d11
        g.v[26] = 1; // d13
        g.v[28] = 4; // d14
        g.v[32] = 0x8000_0000; // s16
        g.v[34] = 1; // s17
        g.v[38] = 3; // d19
        g.v[40] = (-1i64) as u64; // d20
        g.v[44] = 0xff; // b22
        g.v[46] = 1; // b23
        g.v[50] = 0x4000; // h25
        g.v[52] = 0x4000; // h26
        g.v[56] = 0x4000_0000; // s28
        g.v[58] = 0x4000_0000; // s29
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 4, 6, 9, 12, 15, 18, 21, 24, 27, 30, 31] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD scalar integer v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD scalar integer FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_indexed_integer_oracle_matches_interpreter() {
    let insns = [
        0x0f52_8020, // mul      v0.4h, v1.4h, v2.h[1]
        0x6f75_0083, // mla      v3.8h, v4.8h, v5.h[3]
        0x6fa8_40e6, // mls      v6.4s, v7.4s, v8.s[1]
        0x4f6b_c149, // sqdmulh  v9.8h, v10.8h, v11.h[2]
        0x4fae_d1ac, // sqrdmulh v12.4s, v13.4s, v14.s[1]
        0x0f51_320f, // sqdmlal  v15.4s, v16.4h, v1.h[1]
        0x4f62_3272, // sqdmlal2 v18.4s, v19.8h, v2.h[2]
        0x0f44_72d5, // sqdmlsl  v21.4s, v22.4h, v4.h[0]
        0x0f75_b338, // sqdmull  v24.4s, v25.4h, v5.h[3]
        0x4f57_b39b, // sqdmull2 v27.4s, v28.8h, v7.h[1]
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_h8([1, 3, 5, 7, 9, 11, 13, 15])),
            (2, pack_h8([2, 4, 0xfffe, 8, 10, 12, 14, 16])),
            (3, pack_h8([100, 200, 300, 400, 500, 600, 700, 800])),
            (4, pack_h8([2, 4, 6, 8, 10, 12, 14, 16])),
            (5, pack_h8([3, 5, 7, 9, 11, 13, 15, 17])),
            (6, pack_s4([1000, 2000, 3000, 4000])),
            (7, pack_s4([2, 4, 6, 8])),
            (8, pack_s4([3, 5, 7, 9])),
            (
                10,
                pack_h8([
                    0x4000, 0xc000, 0x2000, 0xe000, 0x1000, 0xf000, 0x3000, 0xd000,
                ]),
            ),
            (
                11,
                pack_h8([
                    0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x1000, 0x0800,
                ]),
            ),
            (
                13,
                pack_s4([0x4000_0000, 0xc000_0000, 0x2000_0000, 0xe000_0000]),
            ),
            (
                14,
                pack_s4([0x2000_0000, 0x4000_0000, 0x6000_0000, 0x1000_0000]),
            ),
            (15, pack_s4([10, 20, 30, 40])),
            (16, pack_h8([1, 2, 3, 4, 5, 6, 7, 8])),
            (18, pack_s4([50, 60, 70, 80])),
            (19, pack_h8([1, 2, 3, 4, 5, 6, 7, 8])),
            (21, pack_s4([90, 100, 110, 120])),
            (22, pack_h8([8, 7, 6, 5, 4, 3, 2, 1])),
            (25, pack_h8([2, 4, 6, 8, 10, 12, 14, 16])),
            (28, pack_h8([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24, 27] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD indexed integer v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD indexed integer FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_scalar_indexed_integer_oracle_matches_interpreter() {
    let insns = [
        0x5f72_c020, // sqdmulh  h0, h1, v2.h[3]
        0x5fa5_d083, // sqrdmulh s3, s4, v5.s[1]
        0x5f88_b0e6, // sqdmull  d6, s7, v8.s[0]
        0x5f6b_3149, // sqdmlal  s9, h10, v11.h[2]
        0x5f5e_71ac, // sqdmlsl  s12, h13, v14.h[1]
        0x5f41_b20f, // sqdmull  s15, h16, v1.h[0]
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h8([0x4000, 0x2000, 0x1000, 0x0800, 0, 0, 0, 0]),
            ),
            (2, pack_h8([0x1000, 0x2000, 0x3000, 0x4000, 0, 0, 0, 0])),
            (
                5,
                pack_s4([0x2000_0000, 0x4000_0000, 0x6000_0000, 0x1000_0000]),
            ),
            (
                8,
                pack_s4([0x4000_0000, 0x2000_0000, 0x1000_0000, 0x0800_0000]),
            ),
            (11, pack_h8([0x1000, 0x2000, 0x3000, 0x4000, 0, 0, 0, 0])),
            (14, pack_h8([0x1000, 0x2000, 0x3000, 0x4000, 0, 0, 0, 0])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.v[8] = 0x4000_0000; // s4
        g.v[14] = 0x2000_0000; // s7
        g.v[18] = 10; // s9 accumulator
        g.v[20] = 0x2000; // h10
        g.v[24] = 50; // s12 accumulator
        g.v[26] = 0x3000; // h13
        g.v[32] = 0x4000; // h16
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD scalar indexed integer v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD scalar indexed integer FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_scalar_shift_immediate_oracle_matches_interpreter() {
    let insns = [
        0x5f79_0420, // sshr    d0, d1, #7
        0x7f77_0462, // ushr    d2, d3, #9
        0x7f73_44a4, // sri     d4, d5, #13
        0x7f43_54e6, // sli     d6, d7, #3
        0x5f0f_7528, // sqshl   b8, b9, #7
        0x7f1f_756a, // uqshl   h10, h11, #15
        0x5f0c_95ac, // sqshrn  b12, h13, #4
        0x7f18_9dee, // uqrshrn h14, s15, #8
        0x7f0c_8e30, // sqrshrun b16, h17, #4
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = (-0x1000i64) as u64; // d1
        g.v[6] = 0xf000_0000_0000_0000; // d3
        g.v[8] = 0xaaaa_5555_ffff_0000; // d4 before SRI.
        g.v[10] = 0x1234_5678_9abc_def0; // d5
        g.v[12] = 0x1111_2222_3333_4444; // d6 before SLI.
        g.v[14] = 0x0123_4567_89ab_cdef; // d7
        g.v[18] = 0x02; // b9 saturates when shifted left.
        g.v[22] = 0x8000; // h11 saturates when shifted left.
        g.v[26] = 0x0800; // h13 narrows after shift.
        g.v[30] = 0xffff_ffff; // s15 saturates for UQRSHRN.
        g.v[34] = 0xffff; // h17 negative input for SQRSHRUN.
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD scalar shift immediate v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD scalar shift immediate FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_shift_accumulate_oracle_matches_interpreter() {
    let insns = [
        0x4f1d_1420, // ssra  v0.8h, v1.8h, #3
        0x6f3b_1462, // usra  v2.4s, v3.4s, #5
        0x4f73_34a4, // srsra v4.2d, v5.2d, #13
        0x6f0e_34e6, // ursra v6.16b, v7.16b, #2
        0x5f79_1528, // ssra  d8, d9, #7
        0x7f77_156a, // usra  d10, d11, #9
        0x5f75_35ac, // srsra d12, d13, #11
        0x7f7c_35ee, // ursra d14, d15, #4
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_h8([1, 2, 3, 4, 5, 6, 7, 8])),
            (
                1,
                pack_h8([
                    0x0008, 0xfff8, 0x7fff, 0x8000, 0x0010, 0xfff0, 0x0100, 0xff00,
                ]),
            ),
            (2, pack_s4([10, 20, 30, 40])),
            (
                3,
                pack_s4([0x0000_0020, 0xffff_ffe0, 0x8000_0000, 0x7fff_ffff]),
            ),
            (4, (100, 200)),
            (5, (0x0000_0000_0000_2000, (-0x2000i64) as u64)),
            (6, (0x0102_0304_0506_0708, 0xf0e0_d0c0_b0a0_9080)),
            (7, (0x0807_0605_0403_0201, 0x8070_6050_4030_2010)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.v[16] = 0x1000_0000_0000_0000; // d8 accumulator.
        g.v[18] = (-0x2000i64) as u64; // d9 source.
        g.v[20] = 0x0100_0000_0000_0000; // d10 accumulator.
        g.v[22] = 0xf000_0000_0000_0000; // d11 source.
        g.v[24] = 0; // d12 accumulator.
        g.v[26] = 0x0000_0000_0000_0800; // d13 source, rounding tie.
        g.v[28] = 0x10; // d14 accumulator.
        g.v[30] = 0xff; // d15 source.
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD shift accumulate v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_shift_narrow_oracle_matches_interpreter() {
    let insns = [
        0x4f13_5420, // shl   v0.8h, v1.8h, #3
        0x4f39_0462, // sshr  v2.4s, v3.4s, #7
        0x6f73_04a4, // ushr  v4.2d, v5.2d, #13
        0x6f0b_44e6, // sri   v6.16b, v7.16b, #5
        0x6f14_5528, // sli   v8.8h, v9.8h, #4
        0x4e6c_4d6a, // sqshl v10.8h, v11.8h, v12.8h
        0x6e2f_4dcd, // uqshl v13.16b, v14.16b, v15.16b
        0x0f12_a630, // sshll v16.4s, v17.4h, #2
        0x6f11_a672, // ushll2 v18.4s, v19.8h, #1
        0x0e61_2ab4, // xtn   v20.4h, v21.4s
        0x0e61_4af6, // sqxtn v22.4h, v23.4s
        0x2e21_4b38, // uqxtn v24.8b, v25.8h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0001_0002_1000_2000, 0x7fff_8000_00ff_ff00),
            (3, 0x0000_0080_ffff_ff80, 0x4000_0000_8000_0000),
            (5, 0x1000_0000_0000_0000, 0xffff_ffff_ffff_ffff),
            (6, 0xaaaa_5555_ffff_0000, 0x1357_2468_ace0_bdf1),
            (7, 0x0102_0304_0506_0708, 0x8899_aabb_ccdd_eeff),
            (8, 0xaaaa_5555_ffff_0000, 0x1357_2468_ace0_bdf1),
            (9, 0x0001_0002_0003_0004, 0x1000_2000_3000_4000),
            (11, 0x0001_7fff_8000_ffff, 0x1234_8001_7ffe_0002),
            (12, 0x0001_000f_ffff_0002, 0x0003_0004_0005_ffff),
            (14, 0x01fe_7f80_ff00_1020, 0x3040_5060_7080_90a0),
            (15, 0x0107_ff02_0003_0405, 0x0607_0809_0a0b_0c0d),
            (17, 0x0001_ffff_8000_7fff, 0x1234_edcb_0002_fffe),
            (19, 0x0001_0002_0003_0004, 0x1000_2000_3000_4000),
            (21, 0x0000_0001_ffff_ffff, 0x1234_5678_8765_4321),
            (23, 0x0000_7fff_0000_8000, 0x0001_0000_ffff_0000),
            (25, 0x0001_00ff_0100_ffff, 0x7fff_8000_1234_fedc),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 13, 16, 18, 20, 22, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD shift/narrow v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_shift_round_sat_oracle_matches_interpreter() {
    let insns = [
        0x4f1d_2420, // srshr   v0.8h, v1.8h, #3
        0x6f0c_2462, // urshr   v2.16b, v3.16b, #4
        0x4f1f_74a4, // sqshl   v4.8h, v5.8h, #15
        0x6f0f_74e6, // uqshl   v6.16b, v7.16b, #7
        0x6f1f_6528, // sqshlu  v8.8h, v9.8h, #15
        0x0f0c_9d6a, // sqrshrn v10.8b, v11.8h, #4
        0x2f0c_9dac, // uqrshrn v12.8b, v13.8h, #4
        0x2f0c_8dee, // sqrshrun v14.8b, v15.8h, #4
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0007_0008_ffff_fff8, 0x7fff_8000_0003_fffd),
            (3, 0x0708_0f10_7f80_ff00, 0x0102_0304_f0f1_feff),
            (5, 0x0001_0002_7fff_8000, 0x4000_c000_ffff_0000),
            (7, 0x0001_0002_007f_0080, 0x00ff_0040_0020_0010),
            (9, 0x0001_7fff_8000_ffff, 0x0002_4000_c000_0000),
            (11, 0x0007_0008_07f7_0800, 0xfff8_f800_0100_00ff),
            (13, 0x0007_0008_0fff_1000, 0x00ff_0100_07f8_0800),
            (15, 0x0007_0008_0fff_1000, 0xfff8_f800_0100_00ff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD rounded/saturating shift v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD rounded/saturating shift FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_reduction_oracle_matches_interpreter() {
    let insns = [
        0x4e31_b820, // addv  b0, v1.16b
        0x4e70_a862, // smaxv h2, v3.8h
        0x6eb1_a8a4, // uminv s4, v5.4s
        0x4ea8_bce6, // addp  v6.4s, v7.4s, v8.4s
        0x4e6b_a549, // smaxp v9.8h, v10.8h, v11.8h
        0x6e2e_adac, // uminp v12.16b, v13.16b, v14.16b
        0x6e31_d60f, // faddp v15.4s, v16.4s, v17.4s
        0x6e34_f672, // fmaxp v18.4s, v19.4s, v20.4s
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (3, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
            (5, 0x0000_0005_ffff_0000, 0x8000_0000_0000_0010),
            (7, 0x0000_0001_0000_0002, 0x0000_0003_0000_0004),
            (8, 0xffff_ffff_0000_0005, 0x8000_0000_7fff_ffff),
            (10, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
            (11, 0x0100_0200_0300_0400, 0x0500_0600_0700_0800),
            (13, 0x0102_0304_0506_0708, 0x8899_aabb_ccdd_eeff),
            (14, 0xffee_ddcc_bbaa_9988, 0x7766_5544_3322_1100),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        for (reg, (lo, hi)) in [
            (16usize, pack_s4(1.0, -2.0, 3.0, -4.0)),
            (17, pack_s4(0.5, 2.0, -1.5, -2.0)),
            (19, pack_s4(1.0, -9.0, 5.0, -7.0)),
            (20, pack_s4(2.0, -10.0, 4.0, -6.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD reduction v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_reduction_extra_oracle_matches_interpreter() {
    let insns = [
        0x0e30_3820, // saddlv  h0, v1.8b
        0x6e70_3862, // uaddlv  s2, v3.8h
        0x4e31_a8a4, // sminv   b4, v5.16b
        0x6e70_a8e6, // umaxv   h6, v7.8h
        0x6e30_f928, // fmaxv   s8, v9.4s
        0x6eb0_f96a, // fminv   s10, v11.4s
        0x6e30_c9ac, // fmaxnmv s12, v13.4s
        0x6eb0_c9ee, // fminnmv s14, v15.4s
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x7f80_0102_fe03_0405, 0x1112_1314_1516_1718),
            (3, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
            (5, 0x807f_0102_fe03_0405, 0x1112_1314_1516_17f8),
            (7, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        for (reg, (lo, hi)) in [
            (9usize, pack_s4(1.0, -9.0, 5.0, -7.0)),
            (11, pack_s4(2.0, -10.0, 4.0, -6.0)),
            (13, pack_s4(1.0, -9.0, 5.0, -7.0)),
            (15, pack_s4(2.0, -10.0, 4.0, -6.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD extra reduction v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD extra reduction FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_maxmin_snan_status_oracle_matches_interpreter() {
    let insns = [
        0x6e22_f420, // fmaxp   v0.4s, v1.4s, v2.4s
        0x6ee5_f483, // fminp   v3.2d, v4.2d, v5.2d
        0x6e28_c4e6, // fmaxnmp v6.4s, v7.4s, v8.4s
        0x6eeb_c549, // fminnmp v9.2d, v10.2d, v11.2d
        0x6e30_f9ac, // fmaxv   s12, v13.4s
        0x6eb0_f9ee, // fminv   s14, v15.4s
        0x6e30_ca30, // fmaxnmv s16, v17.4s
        0x6eb0_ca72, // fminnmv s18, v19.4s
    ];
    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let snan_s = 0x7f80_0001u32;
    let neg_snan_s = 0xff80_0002u32;
    let snan_d = 0x7ff0_0000_0000_0001u64;
    let neg_snan_d = 0xfff0_0000_0000_0002u64;
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_s_bits([snan_s, 1.0_f32.to_bits(), neg_snan_s, (-2.0_f32).to_bits()]),
            ),
            (
                2,
                pack_s_bits([2.0_f32.to_bits(), snan_s, (-3.0_f32).to_bits(), neg_snan_s]),
            ),
            (4, pack_d_bits([snan_d, (-4.0_f64).to_bits()])),
            (5, pack_d_bits([3.0_f64.to_bits(), neg_snan_d])),
            (
                7,
                pack_s_bits([snan_s, 1.0_f32.to_bits(), neg_snan_s, (-2.0_f32).to_bits()]),
            ),
            (
                8,
                pack_s_bits([2.0_f32.to_bits(), snan_s, (-3.0_f32).to_bits(), neg_snan_s]),
            ),
            (10, pack_d_bits([snan_d, (-4.0_f64).to_bits()])),
            (11, pack_d_bits([3.0_f64.to_bits(), neg_snan_d])),
            (
                13,
                pack_s_bits([
                    1.0_f32.to_bits(),
                    snan_s,
                    (-2.0_f32).to_bits(),
                    3.0_f32.to_bits(),
                ]),
            ),
            (
                15,
                pack_s_bits([
                    1.0_f32.to_bits(),
                    neg_snan_s,
                    (-2.0_f32).to_bits(),
                    3.0_f32.to_bits(),
                ]),
            ),
            (
                17,
                pack_s_bits([
                    1.0_f32.to_bits(),
                    snan_s,
                    (-2.0_f32).to_bits(),
                    3.0_f32.to_bits(),
                ]),
            ),
            (
                19,
                pack_s_bits([
                    1.0_f32.to_bits(),
                    neg_snan_s,
                    (-2.0_f32).to_bits(),
                    3.0_f32.to_bits(),
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP max/min sNaN v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP max/min sNaN FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_maxmin_ah_qnan_number_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e22_f420, // fmax   v0.4s, v1.4s, v2.4s
        0x4ea5_f483, // fmin   v3.4s, v4.4s, v5.4s
        0x4e28_c4e6, // fmaxnm v6.4s, v7.4s, v8.4s
        0x4eab_c549, // fminnm v9.4s, v10.4s, v11.4s
        0x4e6e_f5ac, // fmax   v12.2d, v13.2d, v14.2d
        0x4ef1_f60f, // fmin   v15.2d, v16.2d, v17.2d
    ];
    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let qnan_s = 0x7fc0_2000u32;
    let qnan_d = 0x7ff8_0000_0000_2000u64;
    let one_s = 1.0_f32.to_bits();
    let two_s = 2.0_f32.to_bits();
    let neg_one_s = (-1.0_f32).to_bits();
    let one_d = 1.0_f64.to_bits();
    let neg_one_d = (-1.0_f64).to_bits();
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, (lo, hi)) in [
            (1usize, pack_s_bits([qnan_s, one_s, qnan_s, neg_one_s])),
            (2, pack_s_bits([one_s, qnan_s, two_s, qnan_s])),
            (4, pack_s_bits([qnan_s, one_s, qnan_s, neg_one_s])),
            (5, pack_s_bits([one_s, qnan_s, two_s, qnan_s])),
            (7, pack_s_bits([qnan_s, one_s, qnan_s, neg_one_s])),
            (8, pack_s_bits([one_s, qnan_s, two_s, qnan_s])),
            (10, pack_s_bits([qnan_s, one_s, qnan_s, neg_one_s])),
            (11, pack_s_bits([one_s, qnan_s, two_s, qnan_s])),
            (13, pack_d_bits([qnan_d, one_d])),
            (14, pack_d_bits([one_d, qnan_d])),
            (16, pack_d_bits([qnan_d, neg_one_d])),
            (17, pack_d_bits([one_d, qnan_d])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH max/min qNaN-number v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP AH max/min qNaN-number FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_maxmin_ah_both_nan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e22_f420, // fmax  v0.4s, v1.4s, v2.4s
        0x4ea5_f483, // fmin  v3.4s, v4.4s, v5.4s
        0x6e28_f4e6, // fmaxp v6.4s, v7.4s, v8.4s
        0x6eab_f549, // fminp v9.4s, v10.4s, v11.4s
        0x4e6e_f5ac, // fmax  v12.2d, v13.2d, v14.2d
        0x4ef1_f60f, // fmin  v15.2d, v16.2d, v17.2d
        0x6e74_f672, // fmaxp v18.2d, v19.2d, v20.2d
        0x6ef7_f6d5, // fminp v21.2d, v22.2d, v23.2d
    ];
    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let qnan_s = 0x7fc0_2000u32;
    let snan_s = 0x7fa0_0001u32;
    let qnan_d = 0x7ff8_0000_0000_2000u64;
    let snan_d = 0x7ff0_0000_0000_0001u64;
    let s_src = pack_s_bits([qnan_s, snan_s, 1.0_f32.to_bits(), 0x0000_0001]);
    let d_src = pack_d_bits([qnan_d, snan_d]);
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, (lo, hi)) in [
            (1usize, s_src),
            (2, s_src),
            (4, s_src),
            (5, s_src),
            (7, s_src),
            (8, s_src),
            (10, s_src),
            (11, s_src),
            (13, d_src),
            (14, d_src),
            (16, d_src),
            (17, d_src),
            (19, d_src),
            (20, d_src),
            (22, d_src),
            (23, d_src),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH max/min both-NaN v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP AH max/min both-NaN FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_binary_ah_qnan_snan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e22_d420, // fadd v0.4s, v1.4s, v2.4s
        0x6e25_fc83, // fdiv v3.4s, v4.4s, v5.4s
        0x6ea8_d4e6, // fabd v6.4s, v7.4s, v8.4s
        0x4e6b_d549, // fadd v9.2d, v10.2d, v11.2d
        0x6e6e_fdac, // fdiv v12.2d, v13.2d, v14.2d
        0x6ef1_d60f, // fabd v15.2d, v16.2d, v17.2d
    ];
    let pack_s_bits = |value: u32| -> (u64, u64) {
        let lane = u64::from(value) | (u64::from(value) << 32);
        (lane, lane)
    };
    let pack_d_bits = |value: u64| -> (u64, u64) { (value, value) };
    let qnan_s = 0x7fc0_2000u32;
    let snan_s = 0x7fa0_0001u32;
    let qnan_d = 0x7ff8_0000_0000_2000u64;
    let snan_d = 0x7ff0_0000_0000_0001u64;
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, (lo, hi)) in [
            (1usize, pack_s_bits(qnan_s)),
            (2, pack_s_bits(snan_s)),
            (4, pack_s_bits(qnan_s)),
            (5, pack_s_bits(snan_s)),
            (7, pack_s_bits(qnan_s)),
            (8, pack_s_bits(snan_s)),
            (10, pack_d_bits(qnan_d)),
            (11, pack_d_bits(snan_d)),
            (13, pack_d_bits(qnan_d)),
            (14, pack_d_bits(snan_d)),
            (16, pack_d_bits(qnan_d)),
            (17, pack_d_bits(snan_d)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH binary qNaN/sNaN v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP AH binary qNaN/sNaN FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_fma_ah_qnan_snan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e22_cc20, // fmla v0.4s, v1.4s, v2.4s
        0x4e68_cce6, // fmla v6.2d, v7.2d, v8.2d
    ];
    let pack_s_bits = |value: u32| -> (u64, u64) {
        let lane = u64::from(value) | (u64::from(value) << 32);
        (lane, lane)
    };
    let pack_d_bits = |value: u64| -> (u64, u64) { (value, value) };
    let qnan_s = 0x7fc0_2000u32;
    let snan_s = 0x7fa0_0001u32;
    let qnan_d = 0x7ff8_0000_0000_2000u64;
    let snan_d = 0x7ff0_0000_0000_0001u64;
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, (lo, hi)) in [
            (0usize, (0, 0)),
            (1, pack_s_bits(qnan_s)),
            (2, pack_s_bits(snan_s)),
            (6, (0, 0)),
            (7, pack_d_bits(qnan_d)),
            (8, pack_d_bits(snan_d)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH FMLA qNaN/sNaN v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP AH FMLA qNaN/sNaN FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp32_ah_subnormal_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e22_d420, // fadd  v0.4s, v1.4s, v2.4s
        0x6e25_ec83, // facge v3.4s, v4.4s, v5.4s
        0x4e28_cce6, // fmla  v6.4s, v7.4s, v8.4s
        0x4eab_cd49, // fmls  v9.4s, v10.4s, v11.4s
    ];
    let pack_s_bits = |value: u32| -> (u64, u64) {
        let lane = u64::from(value) | (u64::from(value) << 32);
        (lane, lane)
    };
    let min_subnorm = 0x0000_2000u32;
    let qnan = 0x7fc0_2000u32;
    let one = 1.0_f32.to_bits();
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, (lo, hi)) in [
            (1usize, pack_s_bits(min_subnorm)),
            (2, (0, 0)),
            (4, pack_s_bits(qnan)),
            (5, pack_s_bits(min_subnorm)),
            (6, (0, 0)),
            (7, pack_s_bits(min_subnorm)),
            (8, pack_s_bits(one)),
            (9, (0, 0)),
            (10, pack_s_bits(min_subnorm)),
            (11, pack_s_bits(one)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP32 AH subnormal-status v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP32 AH subnormal-status FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_scalar_pairwise_exact_zero_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x7e30_d862, // faddp s2, v3.2s
        0x7e70_d8a4, // faddp d4, v5.2d
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            g.v[2 * 3] = u64::from((-1.5_f32).to_bits()) | (u64::from(1.5_f32.to_bits()) << 32);
            g.v[2 * 5] = (-1.5_f64).to_bits();
            g.v[2 * 5 + 1] = 1.5_f64.to_bits();
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [2usize, 4] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD scalar pairwise exact-zero FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD scalar pairwise exact-zero FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_scalar_pairwise_extrema_oracle_matches_interpreter() {
    let insns = [
        0x5ef1_b820, // addp    d0, v1.2d
        0x7e30_f862, // fmaxp   s2, v3.2s
        0x7ef0_f8a4, // fminp   d4, v5.2d
        0x7e30_c8e6, // fmaxnmp s6, v7.2s
        0x7ef0_c928, // fminnmp d8, v9.2d
    ];
    let pack_s2 =
        |a: f32, b: f32| -> u64 { u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32) };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x0000_0001_0000_0002; // v1.2d
        g.v[3] = 0xffff_ffff_ffff_ffff;
        g.v[6] = pack_s2(-2.0, 3.0); // v3.2s
        g.v[10] = (-9.0_f64).to_bits(); // v5.2d
        g.v[11] = 5.0_f64.to_bits();
        g.v[14] = pack_s2(1.0, -4.0); // v7.2s
        g.v[18] = 2.0_f64.to_bits(); // v9.2d
        g.v[19] = (-8.0_f64).to_bits();
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD scalar pairwise extrema v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD scalar pairwise extrema FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_pairwise_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x6e22_d420, // faddp v0.4s, v1.4s, v2.4s
        0x6e65_d483, // faddp v3.2d, v4.2d, v5.2d
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d2 = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (1usize, pack_s4(-1.5, 1.5, 0.33333334, 0.10000001)),
                (2, pack_s4(-2.0, 2.0, 1.0000001, 0.30000004)),
                (4, pack_d2(-1.5, 1.5)),
                (5, pack_d2(0.3333333333333333, 0.10000000000000002)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP pairwise FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP pairwise FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_compare_oracle_matches_interpreter() {
    let insns = [
        0x6e22_8c20, // cmeq  v0.16b, v1.16b, v2.16b
        0x4e65_3483, // cmgt  v3.8h, v4.8h, v5.8h
        0x6ea8_34e6, // cmhi  v6.4s, v7.4s, v8.4s
        0x4eeb_3d49, // cmge  v9.2d, v10.2d, v11.2d
        0x6e2e_3dac, // cmhs  v12.16b, v13.16b, v14.16b
        0x4e31_8e0f, // cmtst v15.16b, v16.16b, v17.16b
        0x4e34_e672, // fcmeq v18.4s, v19.4s, v20.4s
        0x6eb7_e6d5, // fcmgt v21.4s, v22.4s, v23.4s
        0x6e3a_e738, // fcmge v24.4s, v25.4s, v26.4s
        0x6ebd_ef9b, // facgt v27.4s, v28.4s, v29.4s
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (2, 0x0100_0304_0500_0708, 0x1012_1310_1516_1719),
            (4, 0x0001_7fff_8000_ffff, 0x1000_f000_0002_fffe),
            (5, 0x0000_7fff_7fff_ffff, 0x0fff_f001_0003_fffd),
            (7, 0x0000_0005_ffff_0000, 0x8000_0000_0000_0010),
            (8, 0x0000_0004_ffff_0001, 0x7fff_ffff_0000_0010),
            (10, 0x8000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (11, 0x8000_0000_0000_0001, 0x8000_0000_0000_0000),
            (13, 0x0102_0304_0506_0708, 0x8899_aabb_ccdd_eeff),
            (14, 0x0101_0404_0507_0608, 0x8898_aabc_ccdd_ee00),
            (16, 0xf0f0_0000_aaaa_5555, 0x1234_0000_ffff_0000),
            (17, 0x0f0f_ffff_5555_aaaa, 0x0000_ffff_00ff_ff00),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        for (reg, (lo, hi)) in [
            (19usize, pack_s4(1.0, -2.0, 3.0, -4.0)),
            (20, pack_s4(1.0, -1.0, 4.0, -4.0)),
            (22, pack_s4(2.0, -3.0, 4.0, -5.0)),
            (23, pack_s4(1.0, -4.0, 5.0, -5.0)),
            (25, pack_s4(2.0, -3.0, 4.0, -5.0)),
            (26, pack_s4(2.0, -4.0, 5.0, -5.0)),
            (28, pack_s4(-3.0, 2.0, -1.0, 8.0)),
            (29, pack_s4(2.0, -3.0, 4.0, -7.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24, 27] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD compare v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp_ordered_compare_qnan_status_oracle_matches_interpreter() {
    let insns = [
        0x6e22_e420, // fcmge v0.4s, v1.4s, v2.4s
        0x6ea5_e483, // fcmgt v3.4s, v4.4s, v5.4s
        0x6e68_e4e6, // fcmge v6.2d, v7.2d, v8.2d
        0x6eeb_e549, // fcmgt v9.2d, v10.2d, v11.2d
    ];
    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let qnan_s = 0x7fc0_0001u32;
    let neg_qnan_s = 0xffc0_0002u32;
    let qnan_d = 0x7ff8_0000_0000_0001u64;
    let neg_qnan_d = 0xfff8_0000_0000_0002u64;
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_s_bits([qnan_s, neg_qnan_s, qnan_s, neg_qnan_s]),
            ),
            (
                2,
                pack_s_bits([1.0_f32.to_bits(), 1.0_f32.to_bits(), qnan_s, neg_qnan_s]),
            ),
            (
                4,
                pack_s_bits([1.0_f32.to_bits(), qnan_s, neg_qnan_s, (-2.0_f32).to_bits()]),
            ),
            (
                5,
                pack_s_bits([qnan_s, 1.0_f32.to_bits(), neg_qnan_s, qnan_s]),
            ),
            (7, pack_d_bits([qnan_d, neg_qnan_d])),
            (8, pack_d_bits([1.0_f64.to_bits(), qnan_d])),
            (10, pack_d_bits([1.0_f64.to_bits(), neg_qnan_d])),
            (11, pack_d_bits([qnan_d, (-2.0_f64).to_bits()])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD ordered FP qNaN compare v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD ordered FP qNaN compare FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_compare_zero_oracle_matches_interpreter() {
    let insns = [
        0x4e20_9820, // cmeq  v0.16b, v1.16b, #0
        0x6e60_8862, // cmge  v2.8h, v3.8h, #0
        0x4ea0_88a4, // cmgt  v4.4s, v5.4s, #0
        0x6ee0_98e6, // cmle  v6.2d, v7.2d, #0
        0x4e20_a928, // cmlt  v8.16b, v9.16b, #0
        0x4ea0_d96a, // fcmeq v10.4s, v11.4s, #0.0
        0x6ee0_c9ac, // fcmge v12.2d, v13.2d, #0.0
        0x4ea0_c9ee, // fcmgt v14.4s, v15.4s, #0.0
        0x5ee0_9a30, // cmeq  d16, d17, #0
        0x5ee0_8a72, // cmgt  d18, d19, #0
        0x7ee0_cab4, // fcmge d20, d21, #0.0
        0x5ea0_caf6, // fcmgt s22, s23, #0.0
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0001_00ff_8000_7f00, 0x0000_ffff_0100_8001),
            (3, 0x0001_ffff_8000_7fff, 0x0000_0002_fffe_8001),
            (5, 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            (7, 0, (-7i64) as u64),
            (9, 0x0001_00ff_8000_7f00, 0x0000_ffff_0100_8001),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        for (reg, (lo, hi)) in [
            (11usize, pack_s4(0.0, -0.0, 1.0, -2.0)),
            (13, (0.0_f64.to_bits(), (-3.0_f64).to_bits())),
            (15, pack_s4(1.0, -1.0, 0.0, -0.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.v[34] = 0; // d17
        g.v[38] = 1; // d19
        g.v[42] = (-0.0_f64).to_bits(); // d21
        g.v[46] = 1.0_f32.to_bits().into(); // s23
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD compare-zero v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD compare-zero FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_permute_oracle_matches_interpreter() {
    let insns = [
        0x6e02_4020, // ext  v0.16b, v1.16b, v2.16b, #8
        0x4e05_3883, // zip1 v3.16b, v4.16b, v5.16b
        0x4e48_78e6, // zip2 v6.8h, v7.8h, v8.8h
        0x4e8b_2949, // trn1 v9.4s, v10.4s, v11.4s
        0x4ece_69ac, // trn2 v12.2d, v13.2d, v14.2d
        0x4e11_1a0f, // uzp1 v15.16b, v16.16b, v17.16b
        0x4e54_5a72, // uzp2 v18.8h, v19.8h, v20.8h
        0x4e17_02d5, // tbl  v21.16b, { v22.16b }, v23.16b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (2, 0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918),
            (4, 0x7766_5544_3322_1100, 0xffee_ddcc_bbaa_9988),
            (5, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (7, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (8, 0x1001_1002_1003_1004, 0x1005_1006_1007_1008),
            (10, 0x0000_0010_0000_0020, 0x0000_0030_0000_0040),
            (11, 0xffff_fff0_ffff_ffe0, 0xffff_fff0_ffff_ffc0),
            (13, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (14, 0x9999_aaaa_bbbb_cccc, 0xdddd_eeee_ffff_0000),
            (16, 0x0011_2233_4455_6677, 0x8899_aabb_ccdd_eeff),
            (17, 0xffee_ddcc_bbaa_9988, 0x7766_5544_3322_1100),
            (19, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (20, 0x1001_1002_1003_1004, 0x1005_1006_1007_1008),
            (22, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (23, 0x0706_0504_0302_0100, 0x1f10_0f0e_0d0c_0b0a),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD permute v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_table_edge_oracle_matches_interpreter() {
    let insns = [
        0x4e03_2020, // tbl v0.16b, { v1.16b, v2.16b }, v3.16b
        0x4e08_50a4, // tbx v4.16b, { v5.16b, v6.16b, v7.16b }, v8.16b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (2, 0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918),
            (3, 0x3f20_1f10_0f08_0700, 0xff80_3121_1e0e_0601),
            (4, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (5, 0x4746_4544_4342_4140, 0x4f4e_4d4c_4b4a_4948),
            (6, 0x5756_5554_5352_5150, 0x5f5e_5d5c_5b5a_5958),
            (7, 0x6766_6564_6362_6160, 0x6f6e_6d6c_6b6a_6968),
            (8, 0x3f2f_1f0f_0807_0605, 0xff80_3020_1018_0e01),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 4] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD table edge v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_copy_oracle_matches_interpreter() {
    let insns = [
        0x4e0f_0420, // dup  v0.16b, v1.b[7]
        0x4e08_0c62, // dup  v2.2d, x3
        0x4e14_1ca4, // ins  v4.s[2], w5
        0x6e16_14e6, // ins  v6.h[5], v7.h[1]
        0x4e0e_2d28, // smov x8, v9.h[3]
        0x0e19_3d6a, // umov w10, v11.b[12]
        0x5e18_05ac, // dup  d12, v13.d[1]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x8877_6655_4433_2211; // v1 low: b[7] has the sign bit set.
        g.v[3] = 0x1020_3040_5060_7080;
        g.x[3] = 0x0123_4567_89ab_cdef;
        g.v[8] = 0x1111_2222_3333_4444; // v4 before INS general.
        g.v[9] = 0x5555_6666_7777_8888;
        g.x[5] = 0xffff_ffff_aabb_ccdd;
        g.v[12] = 0x0001_0002_0003_0004; // v6 before INS element.
        g.v[13] = 0x0005_0006_0007_0008;
        g.v[14] = 0x1111_2222_3333_4444; // v7 source.
        g.v[15] = 0x5555_6666_7777_8888;
        g.v[18] = 0x8001_0002_0003_0004; // v9.h[3] sign-extends.
        g.v[22] = 0x0706_0504_0302_0100; // v11.b[12] zero-extends.
        g.v[23] = 0x8877_66fe_4433_2211;
        g.v[26] = 0xfedc_ba98_7654_3210; // v13.d[1] scalar duplicate source.
        g.v[27] = 0x0123_4567_89ab_cdef;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 12] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD copy v{reg} mismatch"
        );
    }
    for reg in [8usize, 10] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 AdvSIMD copy x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_modified_immediate_oracle_matches_interpreter() {
    let insns = [
        0x4f03_e7e0, // movi v0.16b, #0x7f
        0x6f00_a641, // mvni v1.8h, #0x12, lsl #8
        0x4f07_37e2, // orr  v2.4s, #0xff, lsl #8
        0x6f07_57e3, // bic  v3.4s, #0xff, lsl #16
        0x6f07_e7e4, // movi v4.2d, #0xffffffffffffffff
        0x4f03_f605, // fmov v5.4s, #1.0
        0x6f00_f406, // fmov v6.2d, #2.0
        0x4f00_c647, // movi v7.4s, #0x12, msl #8
        0x6f01_d688, // mvni v8.4s, #0x34, msl #16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[4] = 0x0000_ffff_0000_ffff; // v2 before ORR immediate.
        g.v[5] = 0x1234_5678_9abc_def0;
        g.v[6] = 0xffff_ffff_ffff_ffff; // v3 before BIC immediate.
        g.v[7] = 0x0123_4567_89ab_cdef;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=8 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD modified immediate v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_crypto_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("aes") || !host_has_aarch64_feature("pmull") {
        eprintln!("[skip] host does not advertise AdvSIMD AES/PMULL");
        return;
    }

    let insns = [
        0x4e28_4820, // aese   v0.16b, v1.16b
        0x4e28_5862, // aesd   v2.16b, v3.16b
        0x4e28_68a4, // aesmc  v4.16b, v5.16b
        0x4e28_78e6, // aesimc v6.16b, v7.16b
        0x0eea_e128, // pmull  v8.1q, v9.1d, v10.1d
        0x4eed_e18b, // pmull2 v11.1q, v12.2d, v13.2d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x0011_2233_4455_6677;
        g.v[1] = 0x8899_aabb_ccdd_eeff;
        g.v[2] = 0x0f1e_2d3c_4b5a_6978;
        g.v[3] = 0x8796_a5b4_c3d2_e1f0;
        g.v[4] = 0xffee_ddcc_bbaa_9988;
        g.v[5] = 0x7766_5544_3322_1100;
        g.v[6] = 0x0123_4567_89ab_cdef;
        g.v[7] = 0xfedc_ba98_7654_3210;
        g.v[10] = 0x63ca_b704_0953_d051;
        g.v[11] = 0xcd60_e0e7_ba70_e18c;
        g.v[14] = 0x8e51_ef21_fabb_4522;
        g.v[15] = 0xe43d_7a06_543b_2b6c;
        g.v[18] = 0x0102_0304_0506_0708;
        g.v[20] = 0x1112_1314_1516_1718;
        g.v[24] = 0x2122_2324_2526_2728;
        g.v[25] = 0x3132_3334_3536_3738;
        g.v[26] = 0x4142_4344_4546_4748;
        g.v[27] = 0x5152_5354_5556_5758;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 11] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD crypto v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_sha_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sha3") || !host_has_aarch64_feature("sha512") {
        eprintln!("[skip] host does not advertise AdvSIMD SHA3/SHA512");
        return;
    }

    let insns = [
        0xce02_0c20, // eor3      v0.16b, v1.16b, v2.16b, v3.16b
        0xce26_1ca4, // bcax      v4.16b, v5.16b, v6.16b, v7.16b
        0xce6a_8d28, // rax1      v8.2d, v9.2d, v10.2d
        0xce8d_818b, // xar       v11.2d, v12.2d, v13.2d, #32
        0xce70_81ee, // sha512h   q14, q15, v16.2d
        0xce73_8651, // sha512h2  q17, q18, v19.2d
        0xcec0_82b4, // sha512su0 v20.2d, v21.2d
        0xce78_8af6, // sha512su1 v22.2d, v23.2d, v24.2d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for reg in 0..=24usize {
            let lo = 2 * reg;
            g.v[lo] = 0x0102_0304_0506_0708u64.wrapping_mul(reg as u64 + 1);
            g.v[lo + 1] = 0x8877_6655_4433_2211u64
                .wrapping_add(0x1111_1111_1111_1111u64.wrapping_mul(reg as u64));
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 4, 8, 11, 14, 17, 20, 22] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD SHA v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_sha1_sha256_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sha1") || !host_has_aarch64_feature("sha2") {
        eprintln!("[skip] host does not advertise AdvSIMD SHA1/SHA256");
        return;
    }

    let insns = [
        0x5e28_0820, // sha1h    s0, s1
        0x5e28_1862, // sha1su1  v2.4s, v3.4s
        0x5e28_28a4, // sha256su0 v4.4s, v5.4s
        0x5e08_00e6, // sha1c    q6, s7, v8.4s
        0x5e0b_1149, // sha1p    q9, s10, v11.4s
        0x5e0e_21ac, // sha1m    q12, s13, v14.4s
        0x5e11_320f, // sha1su0  v15.4s, v16.4s, v17.4s
        0x5e14_4272, // sha256h  q18, q19, v20.4s
        0x5e17_52d5, // sha256h2 q21, q22, v23.4s
        0x5e1a_6338, // sha256su1 v24.4s, v25.4s, v26.4s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for reg in 0..=26usize {
            let lo = 2 * reg;
            g.v[lo] = 0x1234_5678_90ab_cdefu64
                .wrapping_add(0x0101_0101_0101_0101u64.wrapping_mul(reg as u64));
            g.v[lo + 1] = 0xfedc_ba09_8765_4321u64
                .wrapping_sub(0x1111_1111_1111_1111u64.wrapping_mul(reg as u64));
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD SHA1/SHA256 v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_dot_matrix_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("asimddp")
        || !host_has_aarch64_feature("i8mm")
        || !host_has_aarch64_feature("bf16")
    {
        eprintln!("[skip] host does not advertise AdvSIMD dot/I8MM/BF16");
        return;
    }

    let insns = [
        0x4e82_a420, // smmla  v0.4s, v1.16b, v2.16b
        0x6e85_a483, // ummla  v3.4s, v4.16b, v5.16b
        0x4e88_ace6, // usmmla v6.4s, v7.16b, v8.16b
        0x4e8b_9549, // sdot   v9.4s, v10.16b, v11.16b
        0x6e8e_95ac, // udot   v12.4s, v13.16b, v14.16b
        0x4e91_9e0f, // usdot  v15.4s, v16.16b, v17.16b
        0x6e54_fe72, // bfdot  v18.4s, v19.8h, v20.8h
        0x6e57_eed5, // bfmmla v21.4s, v22.8h, v23.8h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for reg in 0..=23usize {
            let lo = 2 * reg;
            g.v[lo] = 0x0011_2233_4455_6677u64
                .wrapping_add(0x1111_1111_1111_1111u64.wrapping_mul(reg as u64));
            g.v[lo + 1] = 0xffee_ddcc_bbaa_9988u64
                .wrapping_sub(0x0101_0101_0101_0101u64.wrapping_mul(reg as u64));
        }

        g.v[36] = 0x4000_0000_3f80_0000; // v18.s = [1.0, 2.0, ...]
        g.v[37] = 0x4080_0000_4040_0000;
        g.v[38] = 0x4000_3f80_4040_bf80; // v19.h finite bf16 values
        g.v[39] = 0xc000_4080_3f00_3fc0;
        g.v[40] = 0x3f80_4000_4080_4040; // v20.h finite bf16 values
        g.v[41] = 0x3fc0_bf80_3f00_c000;

        g.v[42] = 0x3f80_0000_4000_0000; // v21.s = [2.0, 1.0, ...]
        g.v[43] = 0xbf80_0000_4040_0000;
        g.v[44] = 0x3f80_4000_4040_4080; // v22.h finite bf16 values
        g.v[45] = 0xbf80_c000_3fc0_3f00;
        g.v[46] = 0x4000_3f80_bf80_3f00; // v23.h finite bf16 values
        g.v[47] = 0x4080_4040_c000_3fc0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD dot/matrix v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bf16_dot_ah_qnan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD BF16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    const QNAN_BF16: u128 = 0x7fc0_7fc0_7fc0_7fc0_7fc0_7fc0_7fc0_7fc0;
    let cases = [("bfdot", 0x6e42_fc20), ("bfmmla", 0x6e42_ec20)];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0;
            g.v[1] = 0;
            g.v[2] = QNAN_BF16 as u64;
            g.v[3] = (QNAN_BF16 >> 64) as u64;
            g.v[4] = QNAN_BF16 as u64;
            g.v[5] = (QNAN_BF16 >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD BF16 AH {label} qNaN v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD BF16 AH {label} qNaN FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_indexed_dot_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("asimddp")
        || !host_has_aarch64_feature("i8mm")
        || !host_has_aarch64_feature("bf16")
    {
        eprintln!("[skip] host does not advertise AdvSIMD indexed dot/BF16");
        return;
    }

    let insns = [
        0x4fa2_e020, // sdot    v0.4s, v1.16b, v2.4b[1]
        0x6f85_e883, // udot    v3.4s, v4.16b, v5.4b[2]
        0x4fa8_f8e6, // usdot   v6.4s, v7.16b, v8.4b[3]
        0x4f0b_f149, // sudot   v9.4s, v10.16b, v11.4b[0]
        0x4f6e_f1ac, // bfdot   v12.4s, v13.8h, v14.2h[1]
        0x0fe4_f20f, // bfmlalb v15.4s, v16.8h, v4.h[2]
        0x4ff5_f272, // bfmlalt v18.4s, v19.8h, v5.h[3]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for reg in 0..=19usize {
            let lo = 2 * reg;
            g.v[lo] = 0x7f80_0102_0304_0506u64
                .wrapping_add(0x0101_0202_0303_0404u64.wrapping_mul(reg as u64));
            g.v[lo + 1] = 0x8899_aabb_ccdd_eeffu64
                .wrapping_sub(0x0001_0002_0003_0004u64.wrapping_mul(reg as u64));
        }

        g.v[24] = 0x3f80_0000_4000_0000; // v12.s finite accumulators
        g.v[25] = 0x4040_0000_4080_0000;
        g.v[26] = 0x3f80_4000_4040_4080; // v13.h finite bf16 values
        g.v[27] = 0xbf80_c000_3fc0_3f00;
        g.v[28] = 0x4000_3f80_bf80_3f00; // v14.h finite bf16 values
        g.v[29] = 0x4080_4040_c000_3fc0;

        g.v[30] = 0x4000_0000_3f80_0000; // v15.s finite accumulators
        g.v[31] = 0xbf80_0000_4040_0000;
        g.v[32] = 0x3f80_4000_4040_4080; // v16.h finite bf16 values
        g.v[33] = 0xbf80_c000_3fc0_3f00;

        g.v[36] = 0x3f80_0000_4000_0000; // v18.s finite accumulators
        g.v[37] = 0x4040_0000_bf80_0000;
        g.v[38] = 0x4000_3f80_4040_bf80; // v19.h finite bf16 values
        g.v[39] = 0xc000_4080_3f00_3fc0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD indexed dot v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bfcvt_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AdvSIMD BF16");
        return;
    }

    let insns = [
        0x1e63_4020, // bfcvt   h0, s1
        0x0ea1_6862, // bfcvtn  v2.4h, v3.4s
        0x4ea1_6882, // bfcvtn2 v2.8h, v4.4s
    ];
    let pack_s4 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let tie_inputs = [
        0x3f80_8000u32, // exact half-way, bf16 LSB 0
        0x3f81_8000u32, // exact half-way, bf16 LSB 1
        0xbf80_8000u32,
        0xbf81_8000u32,
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            g.v[2] = u64::from(tie_inputs[rmode as usize]); // s1
            (g.v[6], g.v[7]) = pack_s4(tie_inputs); // v3.4s
            (g.v[8], g.v[9]) = pack_s4([0x3fc0_8000, 0xc020_8000, 0x0080_0000, 0x7f7f_ffff]); // v4.4s
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            hw.v[0] & 0xffff,
            interp.v[0] & 0xffff,
            "raw EL0 AdvSIMD BFCVT scalar rmode {rmode} mismatch"
        );
        assert_eq!(
            (hw.v[4], hw.v[5]),
            (interp.v[4], interp.v[5]),
            "raw EL0 AdvSIMD BFCVTN/BFCVTN2 rmode {rmode} mismatch"
        );
        assert_eq!(
            hw.fpsr, interp.fpsr,
            "raw EL0 AdvSIMD BFCVT FPSR rmode {rmode} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bfcvt_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD BF16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let lanes = [
        0x7fa0_0001u32,
        0x007f_ffffu32,
        0x3f80_0001u32,
        0x7f7f_ffffu32,
    ];
    for (label, bits) in [
        ("snan", lanes[0]),
        ("subnorm", lanes[1]),
        ("inexact", lanes[2]),
        ("overflow", lanes[3]),
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = u64::from(bits);
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[0x1e63_4020], setup); // bfcvt h0, s1
        let interp = raw_interp_run(&[0x1e63_4020], setup);
        assert_eq!(
            hw.v[0] & 0xffff,
            interp.v[0] & 0xffff,
            "raw EL0 AdvSIMD AH bfcvt {label} h0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH bfcvt {label} FPSR mismatch"
        );
    }

    let packed = u128::from(lanes[0])
        | (u128::from(lanes[1]) << 32)
        | (u128::from(lanes[2]) << 64)
        | (u128::from(lanes[3]) << 96);
    for (label, insn) in [
        ("bfcvtn", 0x0ea1_6820),  // bfcvtn  v0.4h, v1.4s
        ("bfcvtn2", 0x4ea1_6820), // bfcvtn2 v0.8h, v1.4s
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0xaaaa_aaaa_aaaa_aaaa;
            g.v[1] = 0xbbbb_bbbb_bbbb_bbbb;
            g.v[2] = packed as u64;
            g.v[3] = (packed >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bfmlal_ah_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD BF16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    const ZN: u128 = 0x0001_0001_0001_0001_0001_0001_0001_0001;
    const ZM: u128 = 0x3f80_3f80_3f80_3f80_3f80_3f80_3f80_3f80;
    const ACC: u128 = 0x0000_0001_0000_0001_0000_0001_0000_0001;
    let cases = [
        ("bfmlalb_product", 0x2ec2_fc20, 0u128, ZN),
        ("bfmlalb_acc", 0x2ec2_fc20, ACC, 0),
        ("bfmlalb_idx_product", 0x0fc2_f020, 0, ZN),
        ("bfmlalt_product", 0x6ec2_fc20, 0, ZN),
        ("bfmlalt_acc", 0x6ec2_fc20, ACC, 0),
        ("bfmlalt_idx_product", 0x4fc2_f020, 0, ZN),
    ];

    for (label, insn, rd, rn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = rd as u64;
            g.v[1] = (rd >> 64) as u64;
            g.v[2] = rn as u64;
            g.v[3] = (rn >> 64) as u64;
            g.v[4] = ZM as u64;
            g.v[5] = (ZM >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bfmlal_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD BF16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    const STATUS_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const NAN_PATTERN: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    const INF_ZERO_PATTERN: u128 = 0x3f80_0000_0000_0000_7f80_0000_0000_0001;
    let cases = [
        ("bfmlalb_status", 0x2ec2_fc20, STATUS_PATTERN),
        ("bfmlalt_status", 0x6ec2_fc20, STATUS_PATTERN),
        ("bfmlalb_idx_nan", 0x0ff2_f020, NAN_PATTERN),
        ("bfmlalt_idx_nan", 0x4ff2_f020, NAN_PATTERN),
        ("bfmlalb_idx_inf_zero", 0x0ff2_f020, INF_ZERO_PATTERN),
        ("bfmlalt_idx_inf_zero", 0x4ff2_f020, INF_ZERO_PATTERN),
    ];

    for (label, insn, pattern) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            for reg in [0usize, 1, 2] {
                g.v[2 * reg] = pattern as u64;
                g.v[2 * reg + 1] = (pattern >> 64) as u64;
            }
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_bf16_fmlal_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("bf16") {
        eprintln!("[skip] host does not advertise AdvSIMD BF16");
        return;
    }

    let insns = [
        0x0fe4_f20f, // bfmlalb v15.4s, v16.8h, v4.h[2]
        0x4ff5_f272, // bfmlalt v18.4s, v19.8h, v5.h[3]
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    4usize,
                    pack_h8([
                        0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80,
                    ]),
                ),
                (
                    5,
                    pack_h8([
                        0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80,
                    ]),
                ),
                (
                    15,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    16,
                    pack_h8([
                        0x3f80, 0x3f80, 0xbf80, 0x3f80, 0x3f80, 0x3f80, 0xbf80, 0x3f80,
                    ]),
                ),
                (
                    18,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    19,
                    pack_h8([
                        0x3f80, 0x3f80, 0xbf80, 0x3f80, 0x3f80, 0x3f80, 0xbf80, 0x3f80,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [15usize, 18] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD BF16 FMLAL FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD BF16 FMLAL FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_oracle_matches_interpreter() {
    let insns = [
        0x1e62_2820, // fadd d0, d1, d2
        0x1e25_0883, // fmul s3, s4, s5
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = (2.5_f64).to_bits();
        g.v[4] = (4.0_f64).to_bits();
        g.v[8] = (3.0_f32).to_bits() as u64;
        g.v[10] = (7.0_f32).to_bits() as u64;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    assert_eq!(hw.v[0], interp.v[0], "raw EL0 fadd d0");
    assert_eq!(hw.v[6] as u32, interp.v[6] as u32, "raw EL0 fmul s3");
}

#[test]
fn raw_el0_scalar_fp_misc_oracle_matches_interpreter() {
    let insns = [
        0x1e62_3820, // fsub   d0, d1, d2
        0x1e65_1883, // fdiv   d3, d4, d5
        0x1e61_c0e6, // fsqrt  d6, d7
        0x1e60_c128, // fabs   d8, d9
        0x1e61_416a, // fneg   d10, d11
        0x1e6e_49ac, // fmax   d12, d13, d14
        0x1e71_5a0f, // fmin   d15, d16, d17
        0x1e74_6a72, // fmaxnm d18, d19, d20
        0x1e77_7ad5, // fminnm d21, d22, d23
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = (9.5_f64).to_bits();
        g.v[4] = (2.25_f64).to_bits();
        g.v[8] = (81.0_f64).to_bits();
        g.v[10] = (9.0_f64).to_bits();
        g.v[14] = (144.0_f64).to_bits();
        g.v[18] = (-42.5_f64).to_bits();
        g.v[22] = (17.25_f64).to_bits();
        g.v[26] = (-5.0_f64).to_bits();
        g.v[28] = (7.0_f64).to_bits();
        g.v[32] = (-12.0_f64).to_bits();
        g.v[34] = (3.0_f64).to_bits();
        g.v[38] = (4.0_f64).to_bits();
        g.v[40] = (6.0_f64).to_bits();
        g.v[44] = (-8.0_f64).to_bits();
        g.v[46] = (-10.0_f64).to_bits();
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 8, 10, 12, 15, 18, 21] {
        let lo = 2 * reg;
        assert_eq!(hw.v[lo], interp.v[lo], "raw EL0 scalar FP misc d{reg}");
    }
}

#[test]
fn raw_el0_scalar_fp_estimate_oracle_matches_interpreter() {
    let insns = [
        0x5ea1_d820, // frecpe  s0, s1
        0x7ea1_d862, // frsqrte s2, s3
        0x5ee1_d8a4, // frecpe  d4, d5
        0x7ee1_d8e6, // frsqrte d6, d7
        0x5ea1_f928, // frecpx  s8, s9
        0x5ee1_f96a, // frecpx  d10, d11
        0x5e2e_fdac, // frecps  s12, s13, s14
        0x5ef1_fe0f, // frsqrts d15, d16, d17
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 2.0_f32.to_bits().into(); // s1
        g.v[6] = 4.0_f32.to_bits().into(); // s3
        g.v[10] = 2.0_f64.to_bits(); // d5
        g.v[14] = 4.0_f64.to_bits(); // d7
        g.v[18] = 2.0_f32.to_bits().into(); // s9
        g.v[22] = 2.0_f64.to_bits(); // d11
        g.v[26] = 0.5_f32.to_bits().into(); // s13
        g.v[28] = 2.0_f32.to_bits().into(); // s14
        g.v[32] = 0.5_f64.to_bits(); // d16
        g.v[34] = 2.0_f64.to_bits(); // d17
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 15] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP estimate d/s{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP estimate FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_frecpx_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x5ea1_f820, // frecpx s0, s1
        0x5ee1_f862, // frecpx d2, d3
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        g.v[2] = 0x0000_0001; // s1 min subnormal
        g.v[6] = 0x7ff8_0000_0000_2000; // d3 quiet NaN
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    assert_eq!(
        hw.v[0] as u32, interp.v[0] as u32,
        "raw EL0 scalar AH frecpx s0 mismatch"
    );
    assert_eq!(hw.v[4], interp.v[4], "raw EL0 scalar AH frecpx d2 mismatch");
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar AH frecpx FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp16_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1ee2_2820, // fadd  h0, h1, h2
        0x1ee5_3883, // fsub  h3, h4, h5
        0x1ee8_08e6, // fmul  h6, h7, h8
        0x1eeb_1949, // fdiv  h9, h10, h11
        0x1ee1_c1ac, // fsqrt h12, h13
        0x1ee0_c1ee, // fabs  h14, h15
        0x1ee1_4230, // fneg  h16, h17
        0x1ee2_4272, // fcvt  s18, h19
        0x1e23_c2b4, // fcvt  h20, s21
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, bits) in [
            (1usize, 0x3c00u16),
            (2, 0x4000),
            (4, 0x4200),
            (5, 0x3c00),
            (7, 0x4000),
            (8, 0xc000),
            (10, 0x4400),
            (11, 0x4000),
            (13, 0x4400),
            (15, 0xc200),
            (17, 0x3e00),
            (19, 0x3c00),
        ] {
            g.v[2 * reg] = u64::from(bits);
        }
        g.v[42] = u64::from(1.5_f32.to_bits());
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 14, 16, 20] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u16, interp.v[lo] as u16,
            "raw EL0 scalar FP16 h{reg} mismatch"
        );
    }
    assert_eq!(
        hw.v[36] as u32, interp.v[36] as u32,
        "raw EL0 scalar FP16 s18 mismatch"
    );
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP16 FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp16_misc_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1ee2_4820, // fmax   h0, h1, h2
        0x1ee5_5883, // fmin   h3, h4, h5
        0x1ee8_68e6, // fmaxnm h6, h7, h8
        0x1eeb_7949, // fminnm h9, h10, h11
        0x1eee_0dac, // fcsel  h12, h13, h14, eq
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.nzcv = 0x4000_0000; // Z=1, so EQ is true.
        for (reg, bits) in [
            (1usize, 0x3c00u16),
            (2, 0x4000),
            (4, 0xc200),
            (5, 0xbc00),
            (7, 0x7e01),
            (8, 0x4100),
            (10, 0x7e02),
            (11, 0xc100),
            (13, 0x3e00),
            (14, 0xbe00),
        ] {
            g.v[2 * reg] = u64::from(bits);
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u16, interp.v[lo] as u16,
            "raw EL0 scalar FP16 misc h{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP16 misc FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp16_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1ee2_2820, // fadd  h0, h1, h2
        0x1ee5_3883, // fsub  h3, h4, h5
        0x1ee8_08e6, // fmul  h6, h7, h8
        0x1eeb_1949, // fdiv  h9, h10, h11
        0x1ee1_c1ac, // fsqrt h12, h13
        0x1e23_c1ee, // fcvt  h14, s15
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, bits) in [
                (1usize, 0x3555u16),
                (2, 0x2e66),
                (4, 0x3c01),
                (5, 0x3555),
                (7, 0x3555),
                (8, 0x2e66),
                (10, 0x3c00),
                (11, 0x2e66),
                (13, 0x4001),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
            g.v[30] = u64::from(0.10000001_f32.to_bits());
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 12, 14] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u16, interp.v[lo] as u16,
                "raw EL0 scalar FP16 FPCR rmode {rmode} h{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP16 FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp16_convert_compare_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1ee1_2000, // fcmp   h0, h1
        0xd53b_420b, // mrs    x11, nzcv
        0x1ee0_2048, // fcmp   h2, #0.0
        0xd53b_420c, // mrs    x12, nzcv
        0x9ef8_0083, // fcvtzs x3, h4
        0x9ef9_00c5, // fcvtzu x5, h6
        0x9ee2_0107, // scvtf  h7, x8
        0x9ee3_0149, // ucvtf  h9, x10
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x3c00;
        g.v[2] = 0x4000;
        g.v[4] = 0x8000;
        g.v[8] = 0xc380;
        g.v[12] = 0x4380;
        g.x[8] = (-5i64) as u64;
        g.x[10] = 7;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [3usize, 5, 11, 12] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 scalar FP16 convert/compare x{reg} mismatch"
        );
    }
    for reg in [7usize, 9] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u16, interp.v[lo] as u16,
            "raw EL0 scalar FP16 convert/compare h{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 scalar FP16 convert/compare final NZCV mismatch"
    );
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP16 convert/compare FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp16_rounding_mode_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1ee7_c020, // frinti h0, h1
        0x1ee7_4062, // frintx h2, h3
        0x1ee4_40a4, // frintn h4, h5
        0x1ee4_c0e6, // frintp h6, h7
        0x1ee5_4128, // frintm h8, h9
        0x1ee5_c16a, // frintz h10, h11
        0x1ee6_41ac, // frinta h12, h13
    ];

    for (label, fpcr) in [
        ("nearest", 0u64),
        ("plus_inf", 1u64 << 22),
        ("minus_inf", 2u64 << 22),
        ("zero", 3u64 << 22),
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = fpcr;
            for (reg, bits) in [
                (1usize, 0x3e00u16),
                (3, 0xbe00),
                (5, 0x4100),
                (7, 0xbe66),
                (9, 0x3e66),
                (11, 0xc100),
                (13, 0x3e66),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2, 4, 6, 8, 10, 12] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u16, interp.v[lo] as u16,
                "raw EL0 scalar FP16 rounding {label} h{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP16 rounding {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp16_fused_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise scalar FP16");
        return;
    }

    let insns = [
        0x1fc2_0c20, // fmadd  h0, h1, h2, h3
        0x1fc6_9ca4, // fmsub  h4, h5, h6, h7
        0x1fea_2d28, // fnmadd h8, h9, h10, h11
        0x1fee_bdac, // fnmsub h12, h13, h14, h15
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, bits) in [
                (1usize, 0x3555u16),
                (2, 0x2e66),
                (3, 0x3c01),
                (5, 0xb555),
                (6, 0x3001),
                (7, 0xbc01),
                (9, 0x3c01),
                (10, 0xb555),
                (11, 0x3001),
                (13, 0xbc01),
                (14, 0x3555),
                (15, 0xb001),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 4, 8, 12] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u16, interp.v[lo] as u16,
                "raw EL0 scalar FP16 fused FPCR rmode {rmode} h{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP16 fused FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_arithmetic_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x1e62_2820, // fadd  d0, d1, d2
        0x1e65_3883, // fsub  d3, d4, d5
        0x1e68_18e6, // fdiv  d6, d7, d8
        0x1e61_c149, // fsqrt d9, d10
        0x1e2d_098b, // fmul  s11, s12, s13
        0x1e70_19ee, // fdiv  d14, d15, d16
        0x1e33_1a51, // fdiv  s17, s18, s19
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, bits) in [
                (1usize, 0.3333333333333333_f64.to_bits()),
                (2, 0.10000000000000002_f64.to_bits()),
                (4, 1.0000000000000002_f64.to_bits()),
                (5, 0.3333333333333333_f64.to_bits()),
                (7, 1.0_f64.to_bits()),
                (8, 10.0_f64.to_bits()),
                (10, 2.0_f64.to_bits()),
                (15, 1.0_f64.to_bits()),
                (16, (-10.0_f64).to_bits()),
            ] {
                g.v[2 * reg] = bits;
            }
            for (reg, bits) in [
                (12usize, 0.33333334_f32.to_bits()),
                (13, 0.10000001_f32.to_bits()),
                (18, 1.0_f32.to_bits()),
                (19, 10.0_f32.to_bits()),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 14] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo], interp.v[lo],
                "raw EL0 scalar FP arithmetic FPCR rmode {rmode} d{reg} mismatch"
            );
        }
        for reg in [11usize, 17] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u32, interp.v[lo] as u32,
                "raw EL0 scalar FP arithmetic FPCR rmode {rmode} s{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP arithmetic FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_arithmetic_exact_zero_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x1e62_2820, // fadd d0, d1, d2
        0x1e65_3883, // fsub d3, d4, d5
        0x1e28_28e6, // fadd s6, s7, s8
        0x1e2b_3949, // fsub s9, s10, s11
        0x1e6e_29ac, // fadd d12, d13, d14
        0x1e71_3a0f, // fsub d15, d16, d17
        0x1e34_2a72, // fadd s18, s19, s20
        0x1e37_3ad5, // fsub s21, s22, s23
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, bits) in [
                (1usize, (-1.5_f64).to_bits()),
                (2, 1.5_f64.to_bits()),
                (4, (-1.5_f64).to_bits()),
                (5, (-1.5_f64).to_bits()),
                (13, 0.0_f64.to_bits()),
                (14, (-0.0_f64).to_bits()),
                (16, (-0.0_f64).to_bits()),
                (17, (-0.0_f64).to_bits()),
            ] {
                g.v[2 * reg] = bits;
            }
            for (reg, bits) in [
                (7usize, (-1.5_f32).to_bits()),
                (8, 1.5_f32.to_bits()),
                (10, (-1.5_f32).to_bits()),
                (11, (-1.5_f32).to_bits()),
                (19, 0.0_f32.to_bits()),
                (20, (-0.0_f32).to_bits()),
                (22, (-0.0_f32).to_bits()),
                (23, (-0.0_f32).to_bits()),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 12, 15] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo], interp.v[lo],
                "raw EL0 scalar FP exact-zero FPCR rmode {rmode} d{reg} mismatch"
            );
        }
        for reg in [6usize, 9, 18, 21] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u32, interp.v[lo] as u32,
                "raw EL0 scalar FP exact-zero FPCR rmode {rmode} s{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP exact-zero FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fused_oracle_matches_interpreter() {
    let insns = [
        0x1f42_0c20, // fmadd  d0, d1, d2, d3
        0x1f46_9ca4, // fmsub  d4, d5, d6, d7
        0x1f6a_2d28, // fnmadd d8, d9, d10, d11
        0x1f6e_bdac, // fnmsub d12, d13, d14, d15
        0x1f12_4e30, // fmadd  s16, s17, s18, s19
        0x1f16_deb4, // fmsub  s20, s21, s22, s23
        0x1f3a_6f38, // fnmadd s24, s25, s26, s27
        0x1f3e_ffbc, // fnmsub s28, s29, s30, s31
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, bits) in [
            (1usize, (1.5_f64).to_bits()),
            (2, (2.0_f64).to_bits()),
            (3, (0.5_f64).to_bits()),
            (5, (-3.0_f64).to_bits()),
            (6, (4.0_f64).to_bits()),
            (7, (1.25_f64).to_bits()),
            (9, (2.5_f64).to_bits()),
            (10, (-2.0_f64).to_bits()),
            (11, (3.0_f64).to_bits()),
            (13, (-1.5_f64).to_bits()),
            (14, (-2.0_f64).to_bits()),
            (15, (0.75_f64).to_bits()),
        ] {
            g.v[2 * reg] = bits;
        }
        for (reg, bits) in [
            (17usize, (1.25_f32).to_bits()),
            (18, (2.0_f32).to_bits()),
            (19, (-0.5_f32).to_bits()),
            (21, (-2.5_f32).to_bits()),
            (22, (3.0_f32).to_bits()),
            (23, (1.0_f32).to_bits()),
            (25, (4.0_f32).to_bits()),
            (26, (-0.25_f32).to_bits()),
            (27, (2.0_f32).to_bits()),
            (29, (-1.0_f32).to_bits()),
            (30, (-3.0_f32).to_bits()),
            (31, (0.5_f32).to_bits()),
        ] {
            g.v[2 * reg] = u64::from(bits);
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 4, 8, 12] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP fused d{reg} mismatch"
        );
    }
    for reg in [16usize, 20, 24, 28] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 scalar FP fused s{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fused_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x1f42_0c20, // fmadd  d0, d1, d2, d3
        0x1f46_9ca4, // fmsub  d4, d5, d6, d7
        0x1f6a_2d28, // fnmadd d8, d9, d10, d11
        0x1f6e_bdac, // fnmsub d12, d13, d14, d15
        0x1f12_4e30, // fmadd  s16, s17, s18, s19
        0x1f16_deb4, // fmsub  s20, s21, s22, s23
        0x1f3a_6f38, // fnmadd s24, s25, s26, s27
        0x1f3e_ffbc, // fnmsub s28, s29, s30, s31
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, bits) in [
                (1usize, 0.3333333333333333_f64.to_bits()),
                (2, 0.10000000000000002_f64.to_bits()),
                (3, 1.0000000000000002_f64.to_bits()),
                (5, (-0.3333333333333333_f64).to_bits()),
                (6, 0.25000000000000006_f64.to_bits()),
                (7, (-1.0000000000000002_f64).to_bits()),
                (9, 1.0000000000000002_f64.to_bits()),
                (10, (-0.3333333333333333_f64).to_bits()),
                (11, 0.25000000000000006_f64.to_bits()),
                (13, (-1.0000000000000002_f64).to_bits()),
                (14, 0.3333333333333333_f64.to_bits()),
                (15, (-0.25000000000000006_f64).to_bits()),
            ] {
                g.v[2 * reg] = bits;
            }
            for (reg, bits) in [
                (17usize, 0.33333334_f32.to_bits()),
                (18, 0.10000001_f32.to_bits()),
                (19, 1.0000001_f32.to_bits()),
                (21, (-0.33333334_f32).to_bits()),
                (22, 0.25000003_f32.to_bits()),
                (23, (-1.0000001_f32).to_bits()),
                (25, 1.0000001_f32.to_bits()),
                (26, (-0.33333334_f32).to_bits()),
                (27, 0.25000003_f32.to_bits()),
                (29, (-1.0000001_f32).to_bits()),
                (30, 0.33333334_f32.to_bits()),
                (31, (-0.25000003_f32).to_bits()),
            ] {
                g.v[2 * reg] = u64::from(bits);
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 4, 8, 12] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo], interp.v[lo],
                "raw EL0 scalar FP fused FPCR rmode {rmode} d{reg} mismatch"
            );
        }
        for reg in [16usize, 20, 24, 28] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u32, interp.v[lo] as u32,
                "raw EL0 scalar FP fused FPCR rmode {rmode} s{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP fused FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fused_exact_zero_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x1f42_0c20, // fmadd d0, d1, d2, d3
        0x1f06_1ca4, // fmadd s4, s5, s6, s7
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            g.v[2] = (-1.5_f64).to_bits();
            g.v[4] = (-1.0_f64).to_bits();
            g.v[6] = (-1.5_f64).to_bits();
            g.v[10] = u64::from((-1.5_f32).to_bits());
            g.v[12] = u64::from((-1.0_f32).to_bits());
            g.v[14] = u64::from((-1.5_f32).to_bits());
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            hw.v[0], interp.v[0],
            "raw EL0 scalar FP fused exact zero FPCR rmode {rmode} d0 mismatch"
        );
        assert_eq!(
            hw.v[8] as u32, interp.v[8] as u32,
            "raw EL0 scalar FP fused exact zero FPCR rmode {rmode} s4 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP fused exact zero FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fixed_rounding_oracle_matches_interpreter() {
    let insns = [
        0x1e24_4020, // frintn s0, s1
        0x1e24_c062, // frintp s2, s3
        0x1e65_40a4, // frintm d4, d5
        0x1e65_c0e6, // frintz d6, d7
        0x1e26_4128, // frinta s8, s9
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 1.5_f32.to_bits().into();
        g.v[6] = (-1.5_f32).to_bits().into();
        g.v[10] = 2.25_f64.to_bits();
        g.v[14] = (-2.75_f64).to_bits();
        g.v[18] = (-2.5_f32).to_bits().into();
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 8] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 scalar FP fixed rounding s{reg} mismatch"
        );
    }
    for reg in [4usize, 6] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP fixed rounding d{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP fixed rounding FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp_rounding_mode_oracle_matches_interpreter() {
    let insns = [
        0x1e67_c020, // frinti d0, d1
        0x1e67_4062, // frintx d2, d3
        0x1e27_c0a4, // frinti s4, s5
        0x1e27_40e6, // frintx s6, s7
    ];

    for (label, fpcr) in [
        ("nearest", 0u64),
        ("plus_inf", 1u64 << 22),
        ("minus_inf", 2u64 << 22),
        ("zero", 3u64 << 22),
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = fpcr;
            g.v[2] = (1.5_f64).to_bits();
            g.v[6] = (-1.5_f64).to_bits();
            g.v[10] = (2.5_f32).to_bits() as u64;
            g.v[14] = (-2.5_f32).to_bits() as u64;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo], interp.v[lo],
                "raw EL0 scalar FP rounding {label} d{reg} mismatch"
            );
        }
        for reg in [4usize, 6] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo] as u32, interp.v[lo] as u32,
                "raw EL0 scalar FP rounding {label} s{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpcr as u32, interp.fpcr as u32,
            "raw EL0 scalar FP rounding {label} FPCR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_frintts_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("frint") {
        eprintln!("[skip] host does not advertise FRINT32/FRINT64");
        return;
    }

    let qnan_s = u64::from(0x7fc0_0001u32);
    let inf_s = u64::from(0x7f80_0000u32);
    let large_s = u64::from(0x5f00_0000u32);
    let qnan_d = 0x7ff8_0000_0000_0001u64;
    let inf_d = 0x7ff0_0000_0000_0000u64;
    let large_d = 0x43e0_0000_0000_0000u64;
    let cases = [
        (
            "frint32z_s_inexact",
            0x1e28_4020u32,
            true,
            u64::from(1.5_f32.to_bits()),
        ),
        ("frint32x_s_qnan", 0x1e28_c020, true, qnan_s),
        ("frint64z_s_large", 0x1e29_4020, true, large_s),
        ("frint64x_s_inf", 0x1e29_c020, true, inf_s),
        ("frint32z_d_inexact", 0x1e68_4020, false, 1.5_f64.to_bits()),
        ("frint32x_d_qnan", 0x1e68_c020, false, qnan_d),
        ("frint64z_d_large", 0x1e69_4020, false, large_d),
        ("frint64x_d_inf", 0x1e69_c020, false, inf_d),
    ];

    for (label, insn, is_single, bits) in cases {
        let insns = [insn];
        let setup = |g: &mut Aarch64GuestRegs| {
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        if is_single {
            assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar FP FRINTTS {label} s0 mismatch"
            );
        } else {
            assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar FP FRINTTS {label} d0 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP FRINTTS {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_frintts_fiz_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("frint") || !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise FRINT32/FRINT64 plus AFP/FIZ");
        return;
    }

    const FPCR_FIZ: u64 = 1;
    let cases = [
        ("frint32z_s_pos", 0x1e28_4020u32, true, 0x0000_0001u64),
        ("frint32x_s_neg", 0x1e28_c020, true, 0x8000_0001),
        ("frint64z_s_pos", 0x1e29_4020, true, 0x0000_0001),
        ("frint64x_s_neg", 0x1e29_c020, true, 0x8000_0001),
        ("frint32z_d_pos", 0x1e68_4020, false, 0x0000_0000_0000_0001),
        ("frint32x_d_neg", 0x1e68_c020, false, 0x8000_0000_0000_0001),
        ("frint64z_d_pos", 0x1e69_4020, false, 0x0000_0000_0000_0001),
        ("frint64x_d_neg", 0x1e69_c020, false, 0x8000_0000_0000_0001),
    ];

    for (label, insn, is_single, bits) in cases {
        let insns = [insn];
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_FIZ;
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        if is_single {
            assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar FP FRINTTS FIZ {label} s0 mismatch"
            );
        } else {
            assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar FP FRINTTS FIZ {label} d0 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP FRINTTS FIZ {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_frintts_ah_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("frint") || !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise FRINT32/FRINT64 plus AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("frint32z_s", 0x1e28_4020u32, true, 0x0000_2000u64),
        ("frint32x_s", 0x1e28_c020, true, 0x0000_2000),
        ("frint64z_s", 0x1e29_4020, true, 0x0000_2000),
        ("frint64x_s", 0x1e29_c020, true, 0x0000_2000),
        ("frint32z_d", 0x1e68_4020, false, 0x0000_0000_0000_2000),
        ("frint32x_d", 0x1e68_c020, false, 0x0000_0000_0000_2000),
        ("frint64z_d", 0x1e69_4020, false, 0x0000_0000_0000_2000),
        ("frint64x_d", 0x1e69_c020, false, 0x0000_0000_0000_2000),
    ];

    for (label, insn, is_single, bits) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        if is_single {
            assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar FP FRINTTS AH {label} s0 mismatch"
            );
        } else {
            assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar FP FRINTTS AH {label} d0 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP FRINTTS AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_convert_compare_oracle_matches_interpreter() {
    let insns = [
        0x9e67_0020, // fmov   d0, x1
        0x9e66_0002, // fmov   x2, d0
        0x9e62_0083, // scvtf  d3, x4
        0x9e63_00c5, // ucvtf  d5, x6
        0x9e78_0067, // fcvtzs x7, d3
        0x9e79_00a8, // fcvtzu x8, d5
        0x1e65_2060, // fcmp   d3, d5
        0x1e65_bc69, // fcsel  d9, d3, d5, lt
        0x1e60_2128, // fcmp   d9, #0.0
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = (1.5_f64).to_bits();
        g.x[4] = (-42_i64) as u64;
        g.x[6] = 100;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [2usize, 7, 8] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 scalar FP convert x{reg} mismatch"
        );
    }
    for reg in [0usize, 3, 5, 9] {
        let lo = 2 * reg;
        assert_eq!(hw.v[lo], interp.v[lo], "raw EL0 scalar FP v{reg} mismatch");
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 scalar FP compare NZCV mismatch"
    );
}

#[test]
fn raw_el0_scalar_fp_compare_ah_nan_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "fcmp_s_qnan",
            0x1e22_2020u32,
            u64::from(0x7fc0_2000u32),
            u64::from(0x0000_2000u32),
        ),
        (
            "fcmp_s_snan",
            0x1e22_2020,
            u64::from(0x7fa0_0001u32),
            u64::from(0x0000_2000u32),
        ),
        (
            "fcmpe_s_qnan",
            0x1e22_2030,
            u64::from(0x7fc0_2000u32),
            u64::from(0x0000_2000u32),
        ),
        (
            "fcmpe_s_snan",
            0x1e22_2030,
            u64::from(0x7fa0_0001u32),
            u64::from(0x0000_2000u32),
        ),
        (
            "fcmp_d_qnan",
            0x1e62_2020,
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
        (
            "fcmp_d_snan",
            0x1e62_2020,
            0x7ff0_0000_0000_0001,
            0x0000_0000_0000_0001,
        ),
        (
            "fcmpe_d_qnan",
            0x1e62_2030,
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
        (
            "fcmpe_d_snan",
            0x1e62_2030,
            0x7ff0_0000_0000_0001,
            0x0000_0000_0000_0001,
        ),
    ];

    for (label, insn, lhs, rhs) in cases {
        let insns = [insn];
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lhs;
            g.v[4] = rhs;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            hw.nzcv & 0xf000_0000,
            interp.nzcv & 0xf000_0000,
            "raw EL0 scalar FP AH compare {label} NZCV mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP AH compare {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_fp_unary_ah_qnan_sign_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x1e21_4020, // fneg s0, s1
        0x1e20_c062, // fabs s2, s3
        0x1e61_40a4, // fneg d4, d5
        0x1e60_c0e6, // fabs d6, d7
        0x6ea0_f928, // fneg v8.4s, v9.4s
        0x4ea0_f96a, // fabs v10.4s, v11.4s
        0x6ee0_f9ac, // fneg v12.2d, v13.2d
        0x4ee0_f9ee, // fabs v14.2d, v15.2d
    ];
    let pack_s_bits = |value: u32| -> (u64, u64) {
        let lane = u64::from(value) | (u64::from(value) << 32);
        (lane, lane)
    };
    let pack_d_bits = |value: u64| -> (u64, u64) { (value, value) };
    let qnan_s = 0x7fc0_2000u32;
    let neg_qnan_s = 0xffc0_2000u32;
    let qnan_d = 0x7ff8_0000_0000_2000u64;
    let neg_qnan_d = 0xfff8_0000_0000_2000u64;
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        g.v[2] = u64::from(qnan_s); // s1
        g.v[6] = u64::from(neg_qnan_s); // s3
        g.v[10] = qnan_d; // d5
        g.v[14] = neg_qnan_d; // d7
        for (reg, (lo, hi)) in [
            (9usize, pack_s_bits(qnan_s)),
            (11, pack_s_bits(neg_qnan_s)),
            (13, pack_d_bits(qnan_d)),
            (15, pack_d_bits(neg_qnan_d)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 scalar FP AH unary qNaN sign s{reg} mismatch"
        );
    }
    for reg in [4usize, 6] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP AH unary qNaN sign d{reg} mismatch"
        );
    }
    for reg in [8usize, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH unary qNaN sign v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 FP AH unary qNaN sign FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fnmul_ah_qnan_sign_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        Single,
        Double,
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("s_pos", 0x1e22_8820, 0x7fc0_2000u64, CompareKind::Single),
        ("s_neg", 0x1e22_8820, 0xffc0_2000, CompareKind::Single),
        (
            "d_pos",
            0x1e62_8820,
            0x7ff8_0000_0000_2000,
            CompareKind::Double,
        ),
        (
            "d_neg",
            0x1e62_8820,
            0xfff8_0000_0000_2000,
            CompareKind::Double,
        ),
    ];

    for (label, insn, nan, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = nan;
            g.v[4] = nan;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::Single => assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar AH fnmul {label} s0 mismatch"
            ),
            CompareKind::Double => assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar AH fnmul {label} d0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar AH fnmul {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_fp_sqrt_estimate_ah_invalid_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x1e21_c020, // fsqrt  s0, s1
        0x1e61_c062, // fsqrt  d2, d3
        0x6ea1_f8a4, // fsqrt  v4.4s, v5.4s
        0x6ee1_f8e6, // fsqrt  v6.2d, v7.2d
        0x7ea1_d928, // frsqrte s8, s9
        0x7ee1_d96a, // frsqrte d10, d11
        0x6ea1_d9ac, // frsqrte v12.4s, v13.4s
        0x6ee1_d9ee, // frsqrte v14.2d, v15.2d
    ];
    let pack_s = |value: f32| -> (u64, u64) {
        let bits = u64::from(value.to_bits());
        let lane = bits | (bits << 32);
        (lane, lane)
    };
    let pack_d = |value: f64| -> (u64, u64) { (value.to_bits(), value.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        g.v[2] = u64::from((-1.0_f32).to_bits()); // s1
        g.v[6] = (-1.0_f64).to_bits(); // d3
        g.v[18] = u64::from((-1.0_f32).to_bits()); // s9
        g.v[22] = (-1.0_f64).to_bits(); // d11
        for (reg, (lo, hi)) in [
            (5usize, pack_s(-1.0)),
            (7, pack_d(-1.0)),
            (13, pack_s(-1.0)),
            (15, pack_d(-1.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 8] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 scalar FP AH invalid sqrt/estimate s{reg} mismatch"
        );
    }
    for reg in [2usize, 10] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP AH invalid sqrt/estimate d{reg} mismatch"
        );
    }
    for reg in [4usize, 6, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP AH invalid sqrt/estimate v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 FP AH invalid sqrt/estimate FPSR mismatch"
    );
}

#[test]
fn raw_el0_scalar_fsqrt_ah_subnormal_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        Single,
        Double,
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("s", 0x1e21_c020, 0x0000_2000u64, CompareKind::Single),
        ("d", 0x1e61_c020, 0x0000_0000_0000_2000, CompareKind::Double),
    ];

    for (label, insn, bits, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::Single => assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar AH fsqrt {label} subnormal s0 mismatch"
            ),
            CompareKind::Double => assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar AH fsqrt {label} subnormal d0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar AH fsqrt {label} subnormal FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fsqrt_ah_negative_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise AFP and scalar FP16");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        Half,
        Single,
        Double,
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("h", 0x1ee1_c020, 0x8001u64, CompareKind::Half),
        ("s", 0x1e21_c020, 0x8000_0001, CompareKind::Single),
        ("d", 0x1e61_c020, 0x8000_0000_0000_0001, CompareKind::Double),
    ];

    for (label, insn, bits, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::Half => assert_eq!(
                hw.v[0] as u16, interp.v[0] as u16,
                "raw EL0 scalar AH fsqrt negative subnormal h0 mismatch"
            ),
            CompareKind::Single => assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 scalar AH fsqrt negative subnormal s0 mismatch"
            ),
            CompareKind::Double => assert_eq!(
                hw.v[0], interp.v[0],
                "raw EL0 scalar AH fsqrt negative subnormal d0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar AH fsqrt negative subnormal {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fsqrt_ah_negative_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "h",
            0x6ef9_f820,
            0x8001_8001_8001_8001,
            0x8001_8001_8001_8001,
        ),
        (
            "s",
            0x6ea1_f820,
            0x8000_0001_8000_0001,
            0x8000_0001_8000_0001,
        ),
        (
            "d",
            0x6ee1_f820,
            0x8000_0000_0000_0001,
            0x8000_0000_0000_0001,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH fsqrt negative subnormal {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH fsqrt negative subnormal {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fmov_oracle_matches_interpreter() {
    let insns = [
        0x1e2e_1000, // fmov s0, #1.0
        0x1e70_1001, // fmov d1, #-2.0
        0x1e27_03e2, // fmov s2, wzr
        0x9e67_03e3, // fmov d3, xzr
        0x1e26_0004, // fmov w4, s0
        0x9e66_0025, // fmov x5, d1
        0x1e27_00e6, // fmov s6, w7
        0x9e67_0128, // fmov d8, x9
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[7] = 1.5_f32.to_bits().into();
        g.x[9] = (-7.5_f64).to_bits();
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 1, 2, 3, 6, 8] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP FMOV v{reg} mismatch"
        );
    }
    for reg in [4usize, 5] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 scalar FP FMOV x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_fixed_convert_oracle_matches_interpreter() {
    let insns = [
        0x9e42_f020, // scvtf  d0, x1, #4
        0x9e43_e062, // ucvtf  d2, x3, #8
        0x9e58_f0a4, // fcvtzs x4, d5, #4
        0x9e59_e0e6, // fcvtzu x6, d7, #8
        0x1e02_f528, // scvtf  s8, w9, #3
        0x1e03_ed6a, // ucvtf  s10, w11, #5
        0x1e18_f5ac, // fcvtzs w12, s13, #3
        0x1e19_edee, // fcvtzu w14, s15, #5
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = (-32i64) as u64;
        g.x[3] = 0x12345;
        g.v[10] = (-7.75_f64).to_bits();
        g.v[14] = (1.5_f64).to_bits();
        g.x[9] = 0xffff_ff80;
        g.x[11] = 0xffff_fff0;
        g.v[26] = u64::from((-3.25_f32).to_bits());
        g.v[30] = u64::from((2.25_f32).to_bits());
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [4usize, 6, 12, 14] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 scalar FP fixed-point convert x{reg} mismatch"
        );
    }
    for reg in [0usize, 2] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 scalar FP fixed-point convert d{reg} mismatch"
        );
    }
    for reg in [8usize, 10] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 scalar FP fixed-point convert s{reg} mismatch"
        );
    }
    assert_eq!(
        hw.x[12] >> 32,
        0,
        "raw EL0 fixed fcvtzs w12 was not zero-extended"
    );
    assert_eq!(
        hw.x[14] >> 32,
        0,
        "raw EL0 fixed fcvtzu w14 was not zero-extended"
    );
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 scalar FP fixed-point convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_fp_to_int_ah_subnormal_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        Gpr,
        Vector,
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "scalar_fcvtzs_s_w",
            0x1e38_0020,
            0x0000_0001u64,
            0,
            CompareKind::Gpr,
        ),
        (
            "scalar_fcvtzs_d_x",
            0x9e78_0020,
            0x0000_0000_0000_0001,
            0,
            CompareKind::Gpr,
        ),
        (
            "scalar_fixed_fcvtzs_s_w",
            0x1e18_8020,
            0x0000_0001,
            0,
            CompareKind::Gpr,
        ),
        (
            "scalar_fixed_fcvtzs_d_x",
            0x9e58_0020,
            0x0000_0000_0000_0001,
            0,
            CompareKind::Gpr,
        ),
        (
            "simd_fcvtzs_s",
            0x4ea1_b820,
            0x0000_0001_0000_0001,
            0x0000_0001_0000_0001,
            CompareKind::Vector,
        ),
        (
            "simd_fcvtzs_d",
            0x4ee1_b820,
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0001,
            CompareKind::Vector,
        ),
        (
            "simd_fixed_fcvtzs_s",
            0x4f20_fc20,
            0x0000_0001_0000_0001,
            0x0000_0001_0000_0001,
            CompareKind::Vector,
        ),
        (
            "simd_fixed_fcvtzs_d",
            0x4f40_fc20,
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0001,
            CompareKind::Vector,
        ),
    ];

    for (label, insn, lo, hi, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::Gpr => assert_eq!(hw.x[0], interp.x[0], "raw EL0 AH {label} x0 mismatch"),
            CompareKind::Vector => assert_eq!(
                (hw.v[0], hw.v[1]),
                (interp.v[0], interp.v[1]),
                "raw EL0 AH {label} v0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_fjcvtzs_ah_subnormal_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("pos_min_subnormal", 0x0000_0000_0000_0001u64),
        ("neg_min_subnormal", 0x8000_0000_0000_0001),
    ];

    for (label, bits) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = bits;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[0x1e7e_0020], setup); // fjcvtzs w0, d1
        let interp = raw_interp_run(&[0x1e7e_0020], setup);
        assert_eq!(
            hw.x[0], interp.x[0],
            "raw EL0 AH fjcvtzs {label} w0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AH fjcvtzs {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_int_to_fp_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x9e62_0083, // scvtf d3, x4
        0x9e63_00c5, // ucvtf d5, x6
    ];

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            g.x[4] = (1u64 << 53) + 1;
            g.x[6] = u64::MAX;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [3usize, 5] {
            let lo = 2 * reg;
            assert_eq!(
                hw.v[lo], interp.v[lo],
                "raw EL0 scalar int-to-FP FPCR rmode {rmode} d{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar int-to-FP FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_to_int_status_oracle_matches_interpreter() {
    let insns = [
        0x9e78_0067, // fcvtzs x7, d3
        0x9e79_00a8, // fcvtzu x8, d5
    ];

    for (label, d3, d5) in [
        ("inexact", 3.75_f64.to_bits(), 4.5_f64.to_bits()),
        ("invalid", f64::INFINITY.to_bits(), (-1.0_f64).to_bits()),
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.v[6] = d3;
            g.v[10] = d5;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [7usize, 8] {
            assert_eq!(
                hw.x[reg], interp.x[reg],
                "raw EL0 scalar FP-to-int status {label} x{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP-to-int status {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_scalar_fp_jscvt_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("jscvt") {
        eprintln!("[skip] host does not advertise JSCVT");
        return;
    }

    let insns = [
        0x1e7e_0020, // fjcvtzs w0, d1
        0x1e7e_0062, // fjcvtzs w2, d3
        0x1e7e_00a4, // fjcvtzs w4, d5
    ];

    for (label, inputs) in [
        (
            "mixed_inexact",
            [
                (1usize, (42.75_f64).to_bits()),
                (3, (-0.0_f64).to_bits()),
                (5, (4_294_967_297.0_f64).to_bits()),
            ],
        ),
        (
            "exact",
            [
                (1usize, (-2_147_483_648.0_f64).to_bits()),
                (3, (0.0_f64).to_bits()),
                (5, (123.0_f64).to_bits()),
            ],
        ),
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = 0;
            g.fpsr = 0;
            for (reg, bits) in inputs {
                g.v[2 * reg] = bits;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2, 4] {
            assert_eq!(
                hw.x[reg], interp.x[reg],
                "raw EL0 scalar FP JSCVT {label} x{reg} mismatch"
            );
        }
        assert_eq!(
            hw.nzcv & 0xf000_0000,
            interp.nzcv & 0xf000_0000,
            "raw EL0 scalar FP JSCVT {label} NZCV mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 scalar FP JSCVT {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_frintts_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("frint") {
        eprintln!("[skip] host does not advertise AdvSIMD FRINT32/FRINT64");
        return;
    }

    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let qnan_s = 0x7fc0_0001u32;
    let inf_s = 0x7f80_0000u32;
    let large_s = 0x5f00_0000u32;
    let qnan_d = 0x7ff8_0000_0000_0001u64;
    let inf_d = 0x7ff0_0000_0000_0000u64;
    let large_d = 0x43e0_0000_0000_0000u64;
    let s_src = pack_s_bits([1.5_f32.to_bits(), qnan_s, large_s, inf_s]);
    let d_src = pack_d_bits([1.5_f64.to_bits(), qnan_d]);
    let d_large_src = pack_d_bits([large_d, inf_d]);
    let cases = [
        ("frint32z_v4s", 0x4e21_e820u32, s_src),
        ("frint32x_v4s", 0x6e21_e820, s_src),
        ("frint64z_v4s", 0x4e21_f820, s_src),
        ("frint64x_v4s", 0x6e21_f820, s_src),
        ("frint32z_v2d", 0x4e61_e820, d_src),
        ("frint32x_v2d", 0x6e61_e820, d_src),
        ("frint64z_v2d", 0x4e61_f820, d_large_src),
        ("frint64x_v2d", 0x6e61_f820, d_large_src),
    ];

    for (label, insn, src) in cases {
        let insns = [insn];
        let setup = |g: &mut Aarch64GuestRegs| {
            g.v[2] = src.0;
            g.v[3] = src.1;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD FRINTTS {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FRINTTS {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_frintts_fiz_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("frint") || !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AdvSIMD FRINT32/FRINT64 plus AFP/FIZ");
        return;
    }

    const FPCR_FIZ: u64 = 1;
    let pack_s_bits = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |lanes: [u64; 2]| -> (u64, u64) { (lanes[0], lanes[1]) };
    let s_src = pack_s_bits([0x0000_0001, 0x8000_0001, 0x0000_0001, 0x8000_0001]);
    let d_src = pack_d_bits([0x0000_0000_0000_0001, 0x8000_0000_0000_0001]);
    let cases = [
        ("frint32z_v4s", 0x4e21_e820u32, s_src),
        ("frint32x_v4s", 0x6e21_e820, s_src),
        ("frint64z_v4s", 0x4e21_f820, s_src),
        ("frint64x_v4s", 0x6e21_f820, s_src),
        ("frint32z_v2d", 0x4e61_e820, d_src),
        ("frint32x_v2d", 0x6e61_e820, d_src),
        ("frint64z_v2d", 0x4e61_f820, d_src),
        ("frint64x_v2d", 0x6e61_f820, d_src),
    ];

    for (label, insn, src) in cases {
        let insns = [insn];
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_FIZ;
            g.v[2] = src.0;
            g.v[3] = src.1;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD FRINTTS FIZ {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FRINTTS FIZ {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp_oracle_matches_interpreter() {
    let insns = [
        0x4e22_d420, // fadd   v0.4s, v1.4s, v2.4s
        0x4ea5_d483, // fsub   v3.4s, v4.4s, v5.4s
        0x6e28_dce6, // fmul   v6.4s, v7.4s, v8.4s
        0x4e2b_cd49, // fmla   v9.4s, v10.4s, v11.4s
        0x4eae_cdac, // fmls   v12.4s, v13.4s, v14.4s
        0x4e31_f60f, // fmax   v15.4s, v16.4s, v17.4s
        0x4eb4_f672, // fmin   v18.4s, v19.4s, v20.4s
        0x4e37_c6d5, // fmaxnm v21.4s, v22.4s, v23.4s
        0x4eba_c738, // fminnm v24.4s, v25.4s, v26.4s
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        let lanes = [
            (0, pack(1.0, -2.0, 3.0, -4.0)),
            (1, pack(1.5, -2.5, 3.5, -4.5)),
            (2, pack(0.5, 1.0, -1.5, 2.0)),
            (3, pack(8.0, -8.0, 4.0, -4.0)),
            (4, pack(9.0, -7.0, 5.0, -3.0)),
            (5, pack(1.0, 2.0, -3.0, -4.0)),
            (6, pack(0.0, 0.0, 0.0, 0.0)),
            (7, pack(2.0, -3.0, 4.0, -5.0)),
            (8, pack(0.5, 2.0, -1.0, -2.0)),
            (9, pack(1.0, 2.0, 3.0, 4.0)),
            (10, pack(2.0, -2.0, 4.0, -4.0)),
            (11, pack(0.5, 0.25, -0.5, -0.25)),
            (12, pack(8.0, -8.0, 6.0, -6.0)),
            (13, pack(2.0, -2.0, 3.0, -3.0)),
            (14, pack(0.5, 0.25, -0.5, -0.25)),
            (16, pack(1.0, -9.0, 5.0, -7.0)),
            (17, pack(2.0, -10.0, 4.0, -6.0)),
            (19, pack(1.0, -9.0, 5.0, -7.0)),
            (20, pack(2.0, -10.0, 4.0, -6.0)),
            (22, pack(1.0, -9.0, 5.0, -7.0)),
            (23, pack(2.0, -10.0, 4.0, -6.0)),
            (25, pack(1.0, -9.0, 5.0, -7.0)),
            (26, pack(2.0, -10.0, 4.0, -6.0)),
        ];
        for (reg, (lo, hi)) in lanes {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_indexed_fp_oracle_matches_interpreter() {
    let insns = [
        0x4fa2_1020, // fmla  v0.4s, v1.4s, v2.s[1]
        0x4f85_5083, // fmls  v3.4s, v4.4s, v5.s[0]
        0x4fc8_98e6, // fmul  v6.2d, v7.2d, v8.d[1]
        0x6f8b_9949, // fmulx v9.4s, v10.4s, v11.s[2]
        0x4fce_11ac, // fmla  v12.2d, v13.2d, v14.d[0]
        0x5fb1_920f, // fmul  s15, s16, v17.s[1]
        0x5fd4_1272, // fmla  d18, d19, v20.d[0]
        0x5f97_5ad5, // fmls  s21, s22, v23.s[2]
        0x7fda_9b38, // fmulx d24, d25, v26.d[1]
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s4(1.0, 2.0, 3.0, 4.0)),
            (1, pack_s4(2.0, -2.0, 4.0, -4.0)),
            (2, pack_s4(0.5, 0.25, -0.5, -0.25)),
            (3, pack_s4(8.0, -8.0, 6.0, -6.0)),
            (4, pack_s4(2.0, -2.0, 3.0, -3.0)),
            (5, pack_s4(0.5, 0.25, -0.5, -0.25)),
            (7, (2.0_f64.to_bits(), (-4.0_f64).to_bits())),
            (8, (0.5_f64.to_bits(), 0.25_f64.to_bits())),
            (9, pack_s4(0.0, 0.0, 0.0, 0.0)),
            (10, pack_s4(2.0, -2.0, 4.0, -4.0)),
            (11, pack_s4(0.5, 0.25, -0.5, -0.25)),
            (12, (1.0_f64.to_bits(), 2.0_f64.to_bits())),
            (13, (2.0_f64.to_bits(), (-2.0_f64).to_bits())),
            (14, (0.5_f64.to_bits(), (-0.25_f64).to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.v[30] = 0; // s15 destination before scalar FMUL.
        g.v[32] = 4.0_f32.to_bits().into(); // s16
        g.v[34] = u64::from(2.0_f32.to_bits()) | (u64::from(0.5_f32.to_bits()) << 32); // v17
        g.v[36] = 1.0_f64.to_bits(); // d18 accumulator
        g.v[38] = 2.0_f64.to_bits(); // d19
        g.v[40] = 0.5_f64.to_bits(); // v20.d[0]
        g.v[42] = 8.0_f32.to_bits().into(); // s21 accumulator
        g.v[44] = 2.0_f32.to_bits().into(); // s22
        g.v[46] = u64::from(0.5_f32.to_bits()) | (u64::from(0.25_f32.to_bits()) << 32);
        g.v[47] = 1.0_f32.to_bits().into(); // v23.s[2]
        g.v[48] = 0; // d24 destination before scalar FMULX.
        g.v[50] = 4.0_f64.to_bits(); // d25
        g.v[52] = 0.5_f64.to_bits();
        g.v[53] = 0.25_f64.to_bits(); // v26.d[1]
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD indexed FP v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD indexed FP FPSR mismatch"
    );
}

#[test]
fn raw_el0_fmulx_ah_input_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/AH");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        ScalarS,
        ScalarD,
        Vector,
    }

    const FPCR_AH: u64 = 1 << 1;
    const S_PATTERN: u128 = 0x3f80_0000_0000_0000_7f80_0000_0000_0001;
    const D_PATTERN: u128 = 0x0000_0000_0000_0001_7ff8_0000_0000_2000;
    let cases = [
        ("simd_fmulx_s", 0x4e22_dc20, S_PATTERN, CompareKind::Vector),
        ("simd_fmulx_d", 0x4e62_dc20, D_PATTERN, CompareKind::Vector),
        (
            "scalar_fmulx_s",
            0x5e22_dc20,
            S_PATTERN,
            CompareKind::ScalarS,
        ),
        (
            "scalar_fmulx_d",
            0x5e62_dc20,
            D_PATTERN,
            CompareKind::ScalarD,
        ),
        (
            "indexed_fmulx_s",
            0x6f82_9820,
            S_PATTERN,
            CompareKind::Vector,
        ),
        (
            "indexed_fmulx_d",
            0x6fc2_9820,
            D_PATTERN,
            CompareKind::Vector,
        ),
    ];

    for (label, insn, pattern, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = pattern as u64;
            g.v[3] = (pattern >> 64) as u64;
            g.v[4] = pattern as u64;
            g.v[5] = (pattern >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::ScalarS => assert_eq!(
                hw.v[0] as u32, interp.v[0] as u32,
                "raw EL0 AH {label} s0 mismatch"
            ),
            CompareKind::ScalarD => {
                assert_eq!(hw.v[0], interp.v[0], "raw EL0 AH {label} d0 mismatch")
            }
            CompareKind::Vector => assert_eq!(
                (hw.v[0], hw.v[1]),
                (interp.v[0], interp.v[1]),
                "raw EL0 AH {label} v0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_fp_ah_invalid_default_nan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16");
        return;
    }

    #[derive(Copy, Clone)]
    enum CompareKind {
        ScalarH,
        ScalarD,
        Vector,
    }

    const FPCR_AH: u64 = 1 << 1;
    const H_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const S_INF_ZERO_PATTERN: u128 = 0x3f80_0000_0000_0000_7f80_0000_0000_0001;
    const D_PATTERN: u128 = 0x0000_0000_0000_0001_7ff8_0000_0000_2000;
    const H_INF_PATTERN: u128 = 0x7c00_7c00_7c00_7c00_7c00_7c00_7c00_7c00;
    const D_INF_PATTERN: u128 = 0x7ff0_0000_0000_0000_7ff0_0000_0000_0000;
    let cases = [
        (
            "scalar_fdiv_h_inf_inf",
            0x1ee2_1820,
            H_INF_PATTERN,
            CompareKind::ScalarH,
        ),
        (
            "scalar_fdiv_d_inf_inf",
            0x1e62_1820,
            D_INF_PATTERN,
            CompareKind::ScalarD,
        ),
        (
            "simd_fsub_s_invalid",
            0x4ea2_d420,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fabd_s_invalid",
            0x6ea2_d420,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fdiv_h_nan",
            0x6e42_3c20,
            H_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fdiv_h_inf_inf",
            0x6e42_3c20,
            H_INF_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fdiv_s_invalid",
            0x6e22_fc20,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fdiv_d_nan",
            0x6e62_fc20,
            D_PATTERN,
            CompareKind::Vector,
        ),
        (
            "simd_fdiv_d_inf_inf",
            0x6e62_fc20,
            D_INF_PATTERN,
            CompareKind::Vector,
        ),
        (
            "indexed_fmul_s_invalid",
            0x4f82_9820,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
        (
            "indexed_fmla_s_invalid",
            0x4f82_1820,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
        (
            "indexed_fmls_s_invalid",
            0x4f82_5820,
            S_INF_ZERO_PATTERN,
            CompareKind::Vector,
        ),
    ];

    for (label, insn, pattern, compare_kind) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            for reg in [0usize, 1, 2] {
                g.v[2 * reg] = pattern as u64;
                g.v[2 * reg + 1] = (pattern >> 64) as u64;
            }
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        match compare_kind {
            CompareKind::ScalarH => assert_eq!(
                hw.v[0] as u16, interp.v[0] as u16,
                "raw EL0 AH {label} h0 mismatch"
            ),
            CompareKind::ScalarD => {
                assert_eq!(hw.v[0], interp.v[0], "raw EL0 AH {label} d0 mismatch")
            }
            CompareKind::Vector => assert_eq!(
                (hw.v[0], hw.v[1]),
                (interp.v[0], interp.v[1]),
                "raw EL0 AH {label} v0 mismatch"
            ),
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp_unary_convert_oracle_matches_interpreter() {
    let insns = [
        0x4ea0_f820, // fabs   v0.4s, v1.4s
        0x6ee0_f862, // fneg   v2.2d, v3.2d
        0x6ea1_f8a4, // fsqrt  v4.4s, v5.4s
        0x4e21_88e6, // frintn v6.4s, v7.4s
        0x4e61_9928, // frintm v8.2d, v9.2d
        0x4ea1_896a, // frintp v10.4s, v11.4s
        0x0e61_69ac, // fcvtn  v12.2s, v13.2d
        0x0e61_79ee, // fcvtl  v14.2d, v15.2s
        0x2e61_6a30, // fcvtxn v16.2s, v17.2d
        0x4ee1_9a72, // frintz v18.2d, v19.2d
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s4(-1.0, 2.0, -3.0, 4.0)),
            (3, ((-1.5_f64).to_bits(), 2.5_f64.to_bits())),
            (5, pack_s4(4.0, 9.0, 16.0, 25.0)),
            (7, pack_s4(1.5, -2.5, 3.0, -4.0)),
            (9, (1.5_f64.to_bits(), (-2.5_f64).to_bits())),
            (11, pack_s4(1.5, -2.5, 3.0, -4.0)),
            (13, (1.5_f64.to_bits(), (-2.5_f64).to_bits())),
            (15, pack_s4(1.5, -2.5, 3.0, -4.0)),
            (17, (1.5_f64.to_bits(), (-2.5_f64).to_bits())),
            (19, (1.5_f64.to_bits(), (-2.5_f64).to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP unary/convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP unary/convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_high_half_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4e61_6820, // fcvtn2  v0.4s, v1.2d
        0x4e61_7862, // fcvtl2  v2.2d, v3.4s
        0x6e61_68a4, // fcvtxn2 v4.4s, v5.2d
        0x4e21_68e6, // fcvtn2  v6.8h, v7.4s
        0x4e21_7928, // fcvtl2  v8.4s, v9.8h
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x1111_2222_3333_4444; // low half must be preserved by FCVTN2.
        g.v[1] = 0x5555_6666_7777_8888;
        g.v[2] = 1.5_f64.to_bits();
        g.v[3] = (-2.5_f64).to_bits();
        g.v[4] = 0xaaaa_bbbb_cccc_dddd; // low half must be preserved by FCVTL2.
        g.v[5] = 0xeeee_ffff_0000_1111;
        (g.v[6], g.v[7]) = pack_s4(1.0, -2.0, 3.0, -4.0);
        g.v[8] = 0x2222_3333_4444_5555; // low half must be preserved by FCVTXN2.
        g.v[9] = 0x6666_7777_8888_9999;
        g.v[10] = 1.25_f64.to_bits();
        g.v[11] = (-2.75_f64).to_bits();
        g.v[12] = 0x0123_4567_89ab_cdef; // low half must be preserved by FCVTN2.
        g.v[13] = 0xfedc_ba98_7654_3210;
        (g.v[14], g.v[15]) = pack_s4(1.0, -2.0, 0.33333334, -0.10000001);
        g.v[16] = 0x1357_2468_aaaa_5555; // low half must be preserved by FCVTL2.
        g.v[17] = 0xdead_beef_cafe_f00d;
        (g.v[18], g.v[19]) = pack_h8([
            0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x4200, 0xc200,
        ]);
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP high-half convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP high-half convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_to_int_convert_oracle_matches_interpreter() {
    let insns = [
        0x4e21_a820, // fcvtns v0.4s, v1.4s
        0x6e21_a862, // fcvtnu v2.4s, v3.4s
        0x4e61_b8a4, // fcvtms v4.2d, v5.2d
        0x6e61_b8e6, // fcvtmu v6.2d, v7.2d
        0x4ea1_a928, // fcvtps v8.4s, v9.4s
        0x6ea1_a96a, // fcvtpu v10.4s, v11.4s
        0x4e61_c9ac, // fcvtas v12.2d, v13.2d
        0x6e61_c9ee, // fcvtau v14.2d, v15.2d
        0x4ea1_ba30, // fcvtzs v16.4s, v17.4s
        0x6ee1_ba72, // fcvtzu v18.2d, v19.2d
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s4(1.5, -2.5, 3.25, -4.75)),
            (3, pack_s4(1.5, 2.5, 3.25, 4.75)),
            (5, (1.75_f64.to_bits(), (-2.25_f64).to_bits())),
            (7, (1.75_f64.to_bits(), 2.25_f64.to_bits())),
            (9, pack_s4(1.25, -2.75, 3.5, -4.125)),
            (11, pack_s4(1.25, 2.75, 3.5, 4.125)),
            (13, (1.5_f64.to_bits(), (-2.5_f64).to_bits())),
            (15, (1.5_f64.to_bits(), 2.5_f64.to_bits())),
            (17, pack_s4(1.75, -2.25, 3.875, -4.125)),
            (19, (1.75_f64.to_bits(), 2.25_f64.to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP-to-int convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP-to-int convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_to_int_status_oracle_matches_interpreter() {
    let insns = [
        0x4ea1_b820, // fcvtzs v0.4s, v1.4s
        0x6ea1_b862, // fcvtzu v2.4s, v3.4s
        0x4ee1_b8a4, // fcvtzs v4.2d, v5.2d
        0x6ee1_b8e6, // fcvtzu v6.2d, v7.2d
    ];
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_s4(
                    f32::INFINITY,
                    f32::NEG_INFINITY,
                    2_147_483_904.0,
                    -2_147_483_904.0,
                ),
            ),
            (3, pack_s4(-1.0, f32::INFINITY, 4_294_967_296.0, 1.0)),
            (5, (f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits())),
            (7, ((-1.0_f64).to_bits(), f64::INFINITY.to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP-to-int status v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP-to-int status FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_int_to_fp_convert_oracle_matches_interpreter() {
    let insns = [
        0x4e21_d820, // scvtf v0.4s, v1.4s
        0x6e21_d862, // ucvtf v2.4s, v3.4s
        0x4e61_d8a4, // scvtf v4.2d, v5.2d
        0x6e61_d8e6, // ucvtf v6.2d, v7.2d
    ];
    let pack_u32 = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_u32([1, (-2i32) as u32, 16_777_217, (-16_777_217i32) as u32]),
            ),
            (3, pack_u32([1, 2, 16_777_217, u32::MAX])),
            (5, (1, (-2i64) as u64)),
            (7, (1, 9_007_199_254_740_993)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD int-to-FP convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD int-to-FP convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fixed_convert_oracle_matches_interpreter() {
    let insns = [
        0x4f3c_e420, // scvtf  v0.4s, v1.4s, #4
        0x6f38_e462, // ucvtf  v2.4s, v3.4s, #8
        0x4f3c_fca4, // fcvtzs v4.4s, v5.4s, #4
        0x6f38_fce6, // fcvtzu v6.4s, v7.4s, #8
        0x4f7c_e528, // scvtf  v8.2d, v9.2d, #4
        0x6f78_e56a, // ucvtf  v10.2d, v11.2d, #8
        0x4f7c_fdac, // fcvtzs v12.2d, v13.2d, #4
        0x6f78_fdee, // fcvtzu v14.2d, v15.2d, #8
    ];
    let pack_u32 = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let pack_f32 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        pack_u32(a.to_bits(), b.to_bits(), c.to_bits(), d.to_bits())
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_u32((-32i32) as u32, 16, (-7i32) as u32, 9)),
            (3, pack_u32(0x1234, 0x8000, 0x0001_0000, 0x7fff_ffff)),
            (5, pack_f32(-7.75, 1.5, -0.25, 255.75)),
            (7, pack_f32(1.5, 0.5, 255.25, 1024.0)),
            (9, ((-32i64) as u64, 0x0000_0001_0000_0000)),
            (11, (0x1234_5678, 0x8000_0000_0000_0000)),
            (13, ((-7.75_f64).to_bits(), 1.5_f64.to_bits())),
            (15, (0.5_f64.to_bits(), 255.25_f64.to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD fixed-point convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD fixed-point convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_reciprocal_estimate_oracle_matches_interpreter() {
    let insns = [
        0x4ea1_d820, // frecpe  v0.4s, v1.4s
        0x6ea1_d862, // frsqrte v2.4s, v3.4s
        0x4ee1_d8a4, // frecpe  v4.2d, v5.2d
        0x6ee1_d8e6, // frsqrte v6.2d, v7.2d
        0x4e2a_fd28, // frecps  v8.4s, v9.4s, v10.4s
        0x4ead_fd8b, // frsqrts v11.4s, v12.4s, v13.4s
        0x4ea1_c9ee, // urecpe  v14.4s, v15.4s
        0x6ea1_ca30, // ursqrte v16.4s, v17.4s
        0x4e74_fe72, // frecps  v18.2d, v19.2d, v20.2d
        0x4ef7_fed5, // frsqrts v21.2d, v22.2d, v23.2d
    ];
    let pack_f32 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_u32 = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_f32(2.0, -4.0, 0.5, 8.0)),
            (3, pack_f32(4.0, 9.0, 0.25, 16.0)),
            (5, (2.0_f64.to_bits(), (-4.0_f64).to_bits())),
            (7, (4.0_f64.to_bits(), 0.25_f64.to_bits())),
            (9, pack_f32(0.5, 2.0, -1.0, -2.0)),
            (10, pack_f32(2.0, 0.25, -0.5, -4.0)),
            (12, pack_f32(0.5, 2.0, 4.0, 8.0)),
            (13, pack_f32(2.0, 0.25, 0.5, 0.125)),
            (15, pack_u32(1, 2, 0x1000, 0x8000_0000)),
            (17, pack_u32(1, 4, 0x1000, 0x8000_0000)),
            (19, (0.5_f64.to_bits(), (-2.0_f64).to_bits())),
            (20, (2.0_f64.to_bits(), (-4.0_f64).to_bits())),
            (22, (0.5_f64.to_bits(), 4.0_f64.to_bits())),
            (23, (2.0_f64.to_bits(), 0.25_f64.to_bits())),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 11, 14, 16, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD reciprocal estimate v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD reciprocal estimate FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_frecpe_frsqrte_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4ef9_d820, // frecpe  v0.8h, v1.8h
        0x6ef9_d862, // frsqrte v2.8h, v3.8h
        0x4ea1_d8a4, // frecpe  v4.4s, v5.4s
        0x6ea1_d8e6, // frsqrte v6.4s, v7.4s
        0x4ee1_d928, // frecpe  v8.2d, v9.2d
        0x6ee1_d96a, // frsqrte v10.2d, v11.2d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, pattern) in [
            (1usize, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (3, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (5, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (7, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (9, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
            (11, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
        ] {
            g.v[2 * reg] = pattern as u64;
            g.v[2 * reg + 1] = (pattern >> 64) as u64;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD AH frecpe/frsqrte v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD AH frecpe/frsqrte FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_recps_rsqrts_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let insns = [
        0x4e42_3c20, // frecps  v0.8h, v1.8h, v2.8h
        0x4ec5_3c83, // frsqrts v3.8h, v4.8h, v5.8h
        0x4e28_fce6, // frecps  v6.4s, v7.4s, v8.4s
        0x4eab_fd49, // frsqrts v9.4s, v10.4s, v11.4s
        0x4e6e_fdac, // frecps  v12.2d, v13.2d, v14.2d
        0x4ef1_fe0f, // frsqrts v15.2d, v16.2d, v17.2d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_AH;
        for (reg, pattern) in [
            (1usize, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (2, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (4, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (5, 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00u128),
            (7, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (8, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (10, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (11, 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
            (13, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
            (14, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
            (16, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
            (17, 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
        ] {
            g.v[2 * reg] = pattern as u64;
            g.v[2 * reg + 1] = (pattern >> 64) as u64;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD AH recps/rsqrts v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD AH recps/rsqrts FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp16_reciprocal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4ef9_d820, // frecpe  v0.8h, v1.8h
        0x6ef9_d862, // frsqrte v2.8h, v3.8h
        0x4e46_3ca4, // frecps  v4.8h, v5.8h, v6.8h
        0x4ec9_3d07, // frsqrts v7.8h, v8.8h, v9.8h
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, lane) in lanes.iter().copied().enumerate() {
            if i < 4 {
                lo |= u64::from(lane) << (i * 16);
            } else {
                hi |= u64::from(lane) << ((i - 4) * 16);
            }
        }
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h([
                    0x4000, 0xc400, 0x3800, 0x4800, 0x3c00, 0xbc00, 0x4200, 0xc200,
                ]),
            ),
            (
                3,
                pack_h([
                    0x4400, 0x4880, 0x3400, 0x4c00, 0x3c00, 0x4000, 0x4200, 0x4500,
                ]),
            ),
            (
                5,
                pack_h([
                    0x3800, 0x4000, 0xbc00, 0xc000, 0x3c00, 0x4200, 0xc200, 0x4400,
                ]),
            ),
            (
                6,
                pack_h([
                    0x4000, 0x3400, 0xb800, 0xc400, 0x3800, 0x3c00, 0x4200, 0xc000,
                ]),
            ),
            (
                8,
                pack_h([
                    0x3800, 0x4000, 0x4400, 0x4800, 0x3c00, 0x4200, 0x4500, 0x4c00,
                ]),
            ),
            (
                9,
                pack_h([
                    0x4000, 0x3400, 0x3800, 0x3000, 0x3c00, 0x4000, 0x4200, 0x4400,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 7] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP16 reciprocal v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP16 reciprocal FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp16_fixed_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4f1c_e420, // scvtf  v0.8h, v1.8h, #4
        0x6f1b_e462, // ucvtf  v2.8h, v3.8h, #5
        0x4f1c_fca4, // fcvtzs v4.8h, v5.8h, #4
        0x6f1b_fce6, // fcvtzu v6.8h, v7.8h, #5
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, lane) in lanes.iter().copied().enumerate() {
            if i < 4 {
                lo |= u64::from(lane) << (i * 16);
            } else {
                hi |= u64::from(lane) << ((i - 4) * 16);
            }
        }
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h([
                    0xffe0, 0x0010, 0xfff9, 0x0009, 0x0000, 0x0100, 0x8000, 0x7fff,
                ]),
            ),
            (
                3,
                pack_h([
                    0x0001, 0x0020, 0x0100, 0x1000, 0x7fff, 0x8000, 0x00ff, 0x0000,
                ]),
            ),
            (
                5,
                pack_h([
                    0xbc00, 0x3c00, 0xc000, 0x4000, 0x3800, 0xb800, 0x4400, 0xc400,
                ]),
            ),
            (
                7,
                pack_h([
                    0x0000, 0x3800, 0x3c00, 0x4000, 0x4200, 0x4400, 0x4800, 0x3555,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP16 fixed-point convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP16 fixed-point convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp_fpcr_rounding_oracle_matches_interpreter() {
    let insns = [
        0x4e22_d420, // fadd v0.4s, v1.4s, v2.4s
        0x4ea5_d483, // fsub v3.4s, v4.4s, v5.4s
        0x6e28_dce6, // fmul v6.4s, v7.4s, v8.4s
        0x4e2b_cd49, // fmla v9.4s, v10.4s, v11.4s
        0x4eae_cdac, // fmls v12.4s, v13.4s, v14.4s
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (1usize, pack(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (2, pack(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
                (4, pack(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (5, pack(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
                (7, pack(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (8, pack(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
                (9, pack(1.0000001, -2.0000002, 3.0000002, -4.0000005)),
                (10, pack(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (11, pack(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
                (12, pack(1.0000001, -2.0000002, 3.0000002, -4.0000005)),
                (13, pack(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (14, pack(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 12] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fpcr_fiz_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") {
        eprintln!("[skip] host does not advertise AFP/FIZ");
        return;
    }

    const FPCR_FIZ: u64 = 1;
    let insns = [
        0x4e22_d420, // fadd v0.4s, v1.4s, v2.4s
        0x6e25_dc83, // fmul v3.4s, v4.4s, v5.4s
        0x4e28_cce6, // fmla v6.4s, v7.4s, v8.4s
        0x4eab_cd49, // fmls v9.4s, v10.4s, v11.4s
    ];
    let pack = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let min_subnorm = 0x0000_0001u32;
    let neg_min_subnorm = 0x8000_0001u32;
    let pos_zero = 0.0_f32.to_bits();
    let neg_zero = (-0.0_f32).to_bits();
    let one = 1.0_f32.to_bits();
    let setup = |g: &mut Aarch64GuestRegs| {
        g.fpcr = FPCR_FIZ;
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack([min_subnorm, neg_min_subnorm, min_subnorm, neg_min_subnorm]),
            ),
            (2, pack([pos_zero, neg_zero, one, one])),
            (
                4,
                pack([min_subnorm, neg_min_subnorm, min_subnorm, neg_min_subnorm]),
            ),
            (5, pack([one, one, one, one])),
            (6, pack([one, one, one, one])),
            (
                7,
                pack([min_subnorm, neg_min_subnorm, min_subnorm, neg_min_subnorm]),
            ),
            (8, pack([one, one, one, one])),
            (9, pack([one, one, one, one])),
            (
                10,
                pack([min_subnorm, neg_min_subnorm, min_subnorm, neg_min_subnorm]),
            ),
            (11, pack([one, one, one, one])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FPCR.FIZ subnormal v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FPCR.FIZ subnormal FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp16_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4e42_1420, // fadd  v0.8h, v1.8h, v2.8h
        0x4ec5_1483, // fsub  v3.8h, v4.8h, v5.8h
        0x6e48_1ce6, // fmul  v6.8h, v7.8h, v8.8h
        0x6e4b_3d49, // fdiv  v9.8h, v10.8h, v11.8h
        0x6ef9_f9ac, // fsqrt v12.8h, v13.8h
        0x4ef8_f9ee, // fabs  v14.8h, v15.8h
        0x6ef8_fa30, // fneg  v16.8h, v17.8h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    1usize,
                    pack_h8([
                        0x3555, 0xb555, 0x3c01, 0xbc01, 0x4001, 0xc001, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    2,
                    pack_h8([
                        0x2e66, 0xae66, 0x3001, 0xb001, 0x3555, 0xb555, 0x3c00, 0xbc00,
                    ]),
                ),
                (
                    4,
                    pack_h8([
                        0x3c01, 0xbc01, 0x4001, 0xc001, 0x3555, 0xb555, 0x2e66, 0xae66,
                    ]),
                ),
                (
                    5,
                    pack_h8([
                        0x3555, 0xb555, 0x2e66, 0xae66, 0x3001, 0xb001, 0x3c00, 0xbc00,
                    ]),
                ),
                (
                    7,
                    pack_h8([
                        0x3555, 0xb555, 0x3c01, 0xbc01, 0x4001, 0xc001, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    8,
                    pack_h8([
                        0x2e66, 0xae66, 0x3001, 0xb001, 0x3555, 0xb555, 0x3c00, 0xbc00,
                    ]),
                ),
                (
                    10,
                    pack_h8([
                        0x3c00, 0xbc00, 0x4001, 0xc001, 0x3555, 0xb555, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    11,
                    pack_h8([
                        0x2e66, 0xae66, 0x3001, 0xb001, 0x3555, 0xb555, 0x3c00, 0xbc00,
                    ]),
                ),
                (
                    13,
                    pack_h8([
                        0x3c01, 0x4001, 0x4201, 0x4401, 0x3555, 0x2e66, 0x3e00, 0x4100,
                    ]),
                ),
                (
                    15,
                    pack_h8([
                        0xb555, 0xae66, 0xbc01, 0xb001, 0xc001, 0xbe00, 0x8000, 0x3555,
                    ]),
                ),
                (
                    17,
                    pack_h8([
                        0x3555, 0xb555, 0x3c01, 0xbc01, 0x4001, 0xc001, 0x3e00, 0xbe00,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 12, 14, 16] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP16 FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP16 FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_ah_add_max_finite_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let cases = [
        (
            "fadd",
            0x4e42_1420,
            pack_h8([0x7bff; 8]),
            pack_h8([0x0400; 8]),
        ),
        (
            "faddp",
            0x6e42_1420,
            pack_h8([
                0x7bff, 0x0400, 0x7bff, 0x0400, 0x7bff, 0x0400, 0x7bff, 0x0400,
            ]),
            pack_h8([
                0x7bff, 0x0400, 0x7bff, 0x0400, 0x7bff, 0x0400, 0x7bff, 0x0400,
            ]),
        ),
    ];

    for (label, insn, (rn_lo, rn_hi), (rm_lo, rm_hi)) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = rn_lo;
            g.v[3] = rn_hi;
            g.v[4] = rm_lo;
            g.v[5] = rm_hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD FP16 AH {label} max finite v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP16 AH {label} max finite FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_misc_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4e42_0c20, // fmla   v0.8h, v1.8h, v2.8h
        0x4ec5_0c83, // fmls   v3.8h, v4.8h, v5.8h
        0x4e48_34e6, // fmax   v6.8h, v7.8h, v8.8h
        0x4ecb_3549, // fmin   v9.8h, v10.8h, v11.8h
        0x4e4e_05ac, // fmaxnm v12.8h, v13.8h, v14.8h
        0x4ed1_060f, // fminnm v15.8h, v16.8h, v17.8h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    0usize,
                    pack_h8([
                        0x3c01, 0xbc01, 0x4001, 0xc001, 0x3555, 0xb555, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    1,
                    pack_h8([
                        0x3555, 0xb555, 0x3c01, 0xbc01, 0x4001, 0xc001, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    2,
                    pack_h8([
                        0x2e66, 0xae66, 0x3001, 0xb001, 0x3555, 0xb555, 0x3c00, 0xbc00,
                    ]),
                ),
                (
                    3,
                    pack_h8([
                        0x4001, 0xc001, 0x3c01, 0xbc01, 0x3555, 0xb555, 0x3e00, 0xbe00,
                    ]),
                ),
                (
                    4,
                    pack_h8([
                        0xb555, 0x3555, 0xbc01, 0x3c01, 0xc001, 0x4001, 0xbe00, 0x3e00,
                    ]),
                ),
                (
                    5,
                    pack_h8([
                        0x3001, 0xb001, 0x2e66, 0xae66, 0x3c00, 0xbc00, 0x3555, 0xb555,
                    ]),
                ),
                (
                    7,
                    pack_h8([
                        0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x7e01, 0x4100,
                    ]),
                ),
                (
                    8,
                    pack_h8([
                        0x4000, 0xc000, 0x3c00, 0xbc00, 0x2e66, 0xae66, 0x4100, 0x7e02,
                    ]),
                ),
                (
                    10,
                    pack_h8([
                        0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x7e03, 0xc100,
                    ]),
                ),
                (
                    11,
                    pack_h8([
                        0x4000, 0xc000, 0x3c00, 0xbc00, 0x2e66, 0xae66, 0xc100, 0x7e04,
                    ]),
                ),
                (
                    13,
                    pack_h8([
                        0x7e01, 0x3c00, 0xbc00, 0x7e02, 0x3555, 0xb555, 0x4000, 0xc000,
                    ]),
                ),
                (
                    14,
                    pack_h8([
                        0x4000, 0x7e03, 0xc000, 0xbc00, 0x7e04, 0x3555, 0xc100, 0x3c00,
                    ]),
                ),
                (
                    16,
                    pack_h8([
                        0x7e05, 0x3c00, 0xbc00, 0x7e06, 0x3555, 0xb555, 0x4000, 0xc000,
                    ]),
                ),
                (
                    17,
                    pack_h8([
                        0x4000, 0x7e07, 0xc000, 0xbc00, 0x7e08, 0x3555, 0xc100, 0x3c00,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 12, 15] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP16 misc FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP16 misc FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_pairwise_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x6e42_1420, // faddp  v0.8h, v1.8h, v2.8h
        0x6e45_3483, // fmaxp  v3.8h, v4.8h, v5.8h
        0x6ec8_34e6, // fminp  v6.8h, v7.8h, v8.8h
        0x6e4b_0549, // fmaxnmp v9.8h, v10.8h, v11.8h
        0x6ece_05ac, // fminnmp v12.8h, v13.8h, v14.8h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    1usize,
                    pack_h8([
                        0x3555, 0x2e66, 0xb555, 0xae66, 0x3c01, 0xbc01, 0x4001, 0xc001,
                    ]),
                ),
                (
                    2,
                    pack_h8([
                        0x3001, 0xb001, 0x3e00, 0xbe00, 0x3555, 0xb555, 0x2e66, 0xae66,
                    ]),
                ),
                (
                    4,
                    pack_h8([
                        0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x7e01, 0x4100,
                    ]),
                ),
                (
                    5,
                    pack_h8([
                        0x4000, 0xc000, 0x3c00, 0xbc00, 0x2e66, 0xae66, 0x4100, 0x7e02,
                    ]),
                ),
                (
                    7,
                    pack_h8([
                        0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x7e03, 0xc100,
                    ]),
                ),
                (
                    8,
                    pack_h8([
                        0x4000, 0xc000, 0x3c00, 0xbc00, 0x2e66, 0xae66, 0xc100, 0x7e04,
                    ]),
                ),
                (
                    10,
                    pack_h8([
                        0x7e01, 0x3c00, 0xbc00, 0x7e02, 0x3555, 0xb555, 0x4000, 0xc000,
                    ]),
                ),
                (
                    11,
                    pack_h8([
                        0x4000, 0x7e03, 0xc000, 0xbc00, 0x7e04, 0x3555, 0xc100, 0x3c00,
                    ]),
                ),
                (
                    13,
                    pack_h8([
                        0x7e05, 0x3c00, 0xbc00, 0x7e06, 0x3555, 0xb555, 0x4000, 0xc000,
                    ]),
                ),
                (
                    14,
                    pack_h8([
                        0x4000, 0x7e07, 0xc000, 0xbc00, 0x7e08, 0x3555, 0xc100, 0x3c00,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9, 12] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP16 pairwise FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP16 pairwise FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_compare_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x4e42_2420, // fcmeq v0.8h, v1.8h, v2.8h
        0x6ec5_2483, // fcmgt v3.8h, v4.8h, v5.8h
        0x6e48_24e6, // fcmge v6.8h, v7.8h, v8.8h
        0x6ecb_2d49, // facgt v9.8h, v10.8h, v11.8h
        0x6e4e_2dac, // facge v12.8h, v13.8h, v14.8h
        0x0e21_7a0f, // fcvtl v15.4s, v16.4h
        0x0e21_6a51, // fcvtn v17.4h, v18.4s
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h8([
                    0x3c00, 0x4000, 0xbc00, 0xc000, 0x0000, 0x8000, 0x3555, 0xb555,
                ]),
            ),
            (
                2,
                pack_h8([
                    0x3c00, 0xbc00, 0xbc00, 0x4000, 0x8000, 0x0000, 0xb555, 0x3555,
                ]),
            ),
            (
                4,
                pack_h8([
                    0x4000, 0xc000, 0x3c00, 0xbc00, 0x3555, 0xb555, 0x3e00, 0xbe00,
                ]),
            ),
            (
                5,
                pack_h8([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x2e66, 0xae66, 0x3e00, 0xbe00,
                ]),
            ),
            (
                7,
                pack_h8([
                    0x4000, 0xc000, 0x3c00, 0xbc00, 0x3555, 0xb555, 0x3e00, 0xbe00,
                ]),
            ),
            (
                8,
                pack_h8([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x2e66, 0xae66, 0x3e00, 0xbe00,
                ]),
            ),
            (
                10,
                pack_h8([
                    0x3c00, 0xc000, 0x3555, 0xb555, 0x4000, 0xbc00, 0x0000, 0x8000,
                ]),
            ),
            (
                11,
                pack_h8([
                    0x4000, 0xbc00, 0x2e66, 0xae66, 0x3c00, 0xc000, 0x8000, 0x0000,
                ]),
            ),
            (
                13,
                pack_h8([
                    0x4000, 0xc000, 0x3555, 0xb555, 0x3c00, 0xbc00, 0x0000, 0x8000,
                ]),
            ),
            (
                14,
                pack_h8([
                    0x3c00, 0xbc00, 0x2e66, 0xae66, 0x4000, 0xc000, 0x8000, 0x0000,
                ]),
            ),
            (
                16,
                pack_h8([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x3555, 0xb555, 0x3e00, 0xbe00,
                ]),
            ),
            (18, pack_s4(1.0, -2.0, 0.33333334, -0.10000001)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 17] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP16 compare/convert v{reg} mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP16 compare/convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fp16_fabd_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp") || !host_has_aarch64_feature("asimdhp") {
        eprintln!("[skip] host does not advertise AdvSIMD FP16");
        return;
    }

    let insns = [
        0x6ec2_1420, // fabd v0.8h, v1.8h, v2.8h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h8([
                    0x3c00, 0xc000, 0x4200, 0xc400, 0x3800, 0xb800, 0x4000, 0xbc00,
                ]),
            ),
            (
                2,
                pack_h8([
                    0x4000, 0xbc00, 0xc000, 0x4200, 0x3400, 0xb400, 0x3800, 0xc000,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        g.fpsr = 0;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    assert_eq!(
        (hw.v[0], hw.v[1]),
        (interp.v[0], interp.v[1]),
        "raw EL0 AdvSIMD FP16 FABD v0 mismatch"
    );
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 AdvSIMD FP16 FABD FPSR mismatch"
    );
}

#[test]
fn raw_el0_advsimd_fcma_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fcma") {
        eprintln!("[skip] host does not advertise AdvSIMD FCMA");
        return;
    }

    let insns = [
        0x6e82_e420, // fcadd v0.4s, v1.4s, v2.4s, #90
        0x6e85_f483, // fcadd v3.4s, v4.4s, v5.4s, #270
        0x6e88_c4e6, // fcmla v6.4s, v7.4s, v8.4s, #0
        0x6e8b_cd49, // fcmla v9.4s, v10.4s, v11.4s, #90
        0x6e8e_d5ac, // fcmla v12.4s, v13.4s, v14.4s, #180
        0x6e91_de0f, // fcmla v15.4s, v16.4s, v17.4s, #270
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack(1.0, 2.0, -3.0, 4.0)),
            (2, pack(0.5, -1.0, 1.5, -2.0)),
            (4, pack(-2.0, 3.0, 4.0, -5.0)),
            (5, pack(1.0, 0.5, -0.5, -1.0)),
            (6, pack(1.0, 1.0, 2.0, 2.0)),
            (7, pack(1.0, 2.0, 3.0, 4.0)),
            (8, pack(0.5, 1.5, -0.5, -1.5)),
            (9, pack(2.0, -2.0, 3.0, -3.0)),
            (10, pack(-1.0, 2.0, -3.0, 4.0)),
            (11, pack(1.5, -0.5, 0.25, -0.75)),
            (12, pack(4.0, 1.0, -4.0, -1.0)),
            (13, pack(2.0, -1.0, 1.0, -2.0)),
            (14, pack(-0.5, 1.5, -1.5, 0.5)),
            (15, pack(-2.0, 2.0, -1.0, 1.0)),
            (16, pack(3.0, 1.0, -3.0, -1.0)),
            (17, pack(0.25, -0.5, 0.75, -1.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FCMA v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fcma_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fcma") {
        eprintln!("[skip] host does not advertise AdvSIMD FCMA");
        return;
    }

    let insns = [
        0x6e82_e420, // fcadd v0.4s, v1.4s, v2.4s, #90
        0x6e85_f483, // fcadd v3.4s, v4.4s, v5.4s, #270
        0x6e88_c4e6, // fcmla v6.4s, v7.4s, v8.4s, #0
        0x6e8b_cd49, // fcmla v9.4s, v10.4s, v11.4s, #90
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (1usize, pack(1.0000001, -2.0000002, 3.0000002, -4.0000005)),
                (2, pack(0.33333334, -0.25000003, 0.20000002, -0.10000001)),
                (4, pack(-1.0000001, 2.0000002, -3.0000002, 4.0000005)),
                (5, pack(0.50000006, -0.75000006, 0.33333334, -0.25000003)),
                (6, pack(0.25000003, -0.50000006, 1.2500001, -1.5000001)),
                (7, pack(1.0000001, 2.0000002, -3.0000002, -4.0000005)),
                (8, pack(0.33333334, -0.25000003, 0.20000002, -0.10000001)),
                (9, pack(-0.25000003, 0.75000006, -1.2500001, 1.5000001)),
                (10, pack(2.0000002, -1.0000001, 3.0000002, -4.0000005)),
                (11, pack(0.25000003, 0.50000006, -0.33333334, -0.10000001)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FCMA FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FCMA FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_fhm_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
        || !host_has_aarch64_feature("asimdfhm")
    {
        eprintln!("[skip] host does not advertise AdvSIMD FP16/FHM");
        return;
    }

    let insns = [
        0x4e42_1420, // fadd   v0.8h, v1.8h, v2.8h
        0x4ec5_1483, // fsub   v3.8h, v4.8h, v5.8h
        0x6e48_1ce6, // fmul   v6.8h, v7.8h, v8.8h
        0x4e4b_0d49, // fmla   v9.8h, v10.8h, v11.8h
        0x4ece_0dac, // fmls   v12.8h, v13.8h, v14.8h
        0x4e31_ee0f, // fmlal  v15.4s, v16.4h, v17.4h
        0x6e34_ce72, // fmlal2 v18.4s, v19.4h, v20.4h
        0x4eb7_eed5, // fmlsl  v21.4s, v22.4h, v23.4h
        0x6eba_cf38, // fmlsl2 v24.4s, v25.4h, v26.4h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        let h_regs = [
            (
                1,
                pack_h8([
                    0x3c00, 0xc000, 0x4200, 0xc400, 0x3800, 0xb800, 0x4000, 0xbc00,
                ]),
            ),
            (
                2,
                pack_h8([
                    0x3800, 0x3c00, 0xbc00, 0x4000, 0x3c00, 0x4000, 0xc000, 0xb800,
                ]),
            ),
            (
                4,
                pack_h8([
                    0x4400, 0xc200, 0x4000, 0xbc00, 0x3c00, 0xc000, 0x4200, 0xb800,
                ]),
            ),
            (
                5,
                pack_h8([
                    0x3c00, 0x4000, 0xc000, 0xb800, 0x3800, 0xbc00, 0x3c00, 0x4000,
                ]),
            ),
            (
                7,
                pack_h8([
                    0x4000, 0xc200, 0x4400, 0xc400, 0x3c00, 0xbc00, 0x3800, 0xb800,
                ]),
            ),
            (
                8,
                pack_h8([
                    0x3800, 0x4000, 0xbc00, 0xc000, 0x3c00, 0x4200, 0x4000, 0x3800,
                ]),
            ),
            (
                9,
                pack_h8([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                10,
                pack_h8([
                    0x4000, 0xc000, 0x4200, 0xc200, 0x3c00, 0xbc00, 0x3800, 0xb800,
                ]),
            ),
            (
                11,
                pack_h8([
                    0x3800, 0x3c00, 0xbc00, 0x4000, 0x4000, 0x3800, 0xb800, 0xbc00,
                ]),
            ),
            (
                12,
                pack_h8([
                    0x4400, 0xc400, 0x4200, 0xc200, 0x4000, 0xc000, 0x3c00, 0xbc00,
                ]),
            ),
            (
                13,
                pack_h8([
                    0x4000, 0xc000, 0x4200, 0xc200, 0x3c00, 0xbc00, 0x3800, 0xb800,
                ]),
            ),
            (
                14,
                pack_h8([
                    0x3800, 0x3c00, 0xbc00, 0x4000, 0x4000, 0x3800, 0xb800, 0xbc00,
                ]),
            ),
            (
                16,
                pack_h8([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0x3800, 0x3c00, 0x4000, 0x4200,
                ]),
            ),
            (
                17,
                pack_h8([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0xb800, 0xbc00, 0xc000, 0xc200,
                ]),
            ),
            (
                19,
                pack_h8([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                20,
                pack_h8([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0x3c00, 0x3800, 0xb800, 0xbc00,
                ]),
            ),
            (
                22,
                pack_h8([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0x3800, 0x3c00, 0x4000, 0x4200,
                ]),
            ),
            (
                23,
                pack_h8([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0xb800, 0xbc00, 0xc000, 0xc200,
                ]),
            ),
            (
                25,
                pack_h8([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                26,
                pack_h8([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0x3c00, 0x3800, 0xb800, 0xbc00,
                ]),
            ),
        ];
        for (reg, (lo, hi)) in h_regs {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }

        for (reg, (lo, hi)) in [
            (15, pack_s4(1.0, -2.0, 3.0, -4.0)),
            (18, pack_s4(2.0, -3.0, 4.0, -5.0)),
            (21, pack_s4(6.0, -7.0, 8.0, -9.0)),
            (24, pack_s4(10.0, -11.0, 12.0, -13.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 AdvSIMD FP16/FHM v{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fmlal_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
        || !host_has_aarch64_feature("asimdfhm")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16/FHM");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    const H_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const S_PATTERN: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    let cases = [
        ("fmlal", 0x4e22_ec20),
        ("fmlsl", 0x4ea2_ec20),
        ("fmlal2", 0x6e22_cc20),
        ("fmlsl2", 0x6ea2_cc20),
    ];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = S_PATTERN as u64;
            g.v[1] = (S_PATTERN >> 64) as u64;
            g.v[2] = H_PATTERN as u64;
            g.v[3] = (H_PATTERN >> 64) as u64;
            g.v[4] = H_PATTERN as u64;
            g.v[5] = (H_PATTERN >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fmlal_indexed_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
        || !host_has_aarch64_feature("asimdfhm")
    {
        eprintln!("[skip] host does not advertise AFP and AdvSIMD FP16/FHM");
        return;
    }

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        ("s_qnan_snan", 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
        ("d_qnan_snan", 0x0000_0000_0000_0001_7ff8_0000_0000_2000),
        ("s_inf_zero", 0x3f80_0000_0000_0000_7f80_0000_0000_0001),
    ];

    for (label, pattern) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            for reg in [0usize, 1, 2] {
                g.v[2 * reg] = pattern as u64;
                g.v[2 * reg + 1] = (pattern >> 64) as u64;
            }
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[0x4fb2_0020], setup); // fmlal v0.4s, v1.4h, v2.h[3]
        let interp = raw_interp_run(&[0x4fb2_0020], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 AdvSIMD AH fmlal indexed {label} v0 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD AH fmlal indexed {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_advsimd_fp16_fhm_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("fphp")
        || !host_has_aarch64_feature("asimdhp")
        || !host_has_aarch64_feature("asimdfhm")
    {
        eprintln!("[skip] host does not advertise AdvSIMD FP16/FHM");
        return;
    }

    let insns = [
        0x4e31_ee0f, // fmlal  v15.4s, v16.4h, v17.4h
        0x6e34_ce72, // fmlal2 v18.4s, v19.4h, v20.4h
        0x4eb7_eed5, // fmlsl  v21.4s, v22.4h, v23.4h
        0x6eba_cf38, // fmlsl2 v24.4s, v25.4h, v26.4h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s4 = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    15usize,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    16,
                    pack_h8([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    17,
                    pack_h8([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    18,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    19,
                    pack_h8([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    20,
                    pack_h8([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    21,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    22,
                    pack_h8([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    23,
                    pack_h8([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    24,
                    pack_s4(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    25,
                    pack_h8([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    26,
                    pack_h8([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [15usize, 18, 21, 24] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 AdvSIMD FP16/FHM FPCR rmode {rmode} v{reg} mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 AdvSIMD FP16/FHM FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_system_state_oracle_matches_interpreter() {
    let insns = [
        0xd51b_4401, // msr fpcr, x1
        0xd53b_4400, // mrs x0, fpcr
        0xd51b_4422, // msr fpsr, x2
        0xd53b_4423, // mrs x3, fpsr
        0xd51b_4204, // msr nzcv, x4
        0xd53b_4205, // mrs x5, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x00c0_0000;
        g.x[2] = 0x0800_0000;
        g.x[4] = 0xa000_0000;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    assert_eq!(hw.x[0] as u32, interp.x[0] as u32, "raw EL0 mrs fpcr");
    assert_eq!(hw.x[3] as u32, interp.x[3] as u32, "raw EL0 mrs fpsr");
    assert_eq!(
        hw.x[5] & 0xf000_0000,
        interp.x[5] & 0xf000_0000,
        "raw EL0 mrs nzcv"
    );
    assert_eq!(hw.fpcr as u32, interp.fpcr as u32, "raw EL0 fpcr state");
    assert_eq!(hw.fpsr as u32, interp.fpsr as u32, "raw EL0 fpsr state");
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 nzcv state"
    );
}

#[test]
fn raw_el0_flag_manipulation_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("flagm") {
        eprintln!("[skip] host does not advertise flag manipulation");
        return;
    }

    let insns = [
        0xd51b_4200, // msr   nzcv, x0
        0xd500_401f, // cfinv
        0xd53b_4203, // mrs   x3, nzcv
        0xba1e_042f, // rmif  x1, #60, #15
        0xd53b_4204, // mrs   x4, nzcv
        0x3a00_084d, // setf8 w2
        0xd53b_4205, // mrs   x5, nzcv
        0x3a00_48cd, // setf16 w6
        0xd53b_4207, // mrs   x7, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = 0x2000_0000;
        g.x[1] = 0xa000_0000_0000_0000;
        g.x[2] = 0x80;
        g.x[6] = 0x8000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [3usize, 4, 5, 7] {
        assert_eq!(
            hw.x[reg] & 0xf000_0000,
            interp.x[reg] & 0xf000_0000,
            "raw EL0 flag manipulation x{reg} NZCV mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 flag manipulation final NZCV mismatch"
    );
}

#[test]
fn raw_el0_alternative_flag_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("flagm2") {
        eprintln!("[skip] host does not advertise alternative NZCV conversion");
        return;
    }

    let insns = [
        0xd51b_4200, // msr    nzcv, x0
        0xd500_405f, // axflag
        0xd53b_4201, // mrs    x1, nzcv
        0xd500_403f, // xaflag
        0xd53b_4202, // mrs    x2, nzcv
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = 0xb000_0000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [1usize, 2] {
        assert_eq!(
            hw.x[reg] & 0xf000_0000,
            interp.x[reg] & 0xf000_0000,
            "raw EL0 alternative flag x{reg} NZCV mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 alternative flag final NZCV mismatch"
    );
}

#[test]
fn raw_el0_system_hint_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("bti")
        || !host_has_aarch64_feature("dgh")
        || !host_has_aarch64_feature("sb")
    {
        eprintln!("[skip] host does not advertise BTI/DGH/SB hints");
        return;
    }

    let insns = [
        0xd280_0020, // mov  x0, #1
        0xd503_241f, // bti
        0xd503_245f, // bti  c
        0xd503_249f, // bti  j
        0xd503_24df, // bti  jc
        0xd503_203f, // yield
        0xd503_209f, // sev
        0xd503_20bf, // sevl
        0xd503_20df, // dgh
        0xd503_229f, // csdb
        0xd503_30ff, // sb
        0xd503_3fdf, // isb
        0xd503_3fbf, // dmb  sy
        0xd503_3f9f, // dsb  sy
        0xd503_3f5f, // clrex
        0x9100_0800, // add  x0, x0, #2
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x1122_3344_5566_7788;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 1] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 system hint x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_pointer_auth_roundtrip_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("paca") {
        eprintln!("[skip] host does not advertise pointer authentication");
        return;
    }

    let insns = [
        0xdac1_0020, // pacia x0, x1
        0xdac1_1020, // autia x0, x1
        0xdac1_0462, // pacib x2, x3
        0xdac1_1462, // autib x2, x3
        0xdac1_08a4, // pacda x4, x5
        0xdac1_18a4, // autda x4, x5
        0xdac1_0ce6, // pacdb x6, x7
        0xdac1_1ce6, // autdb x6, x7
        0xdac1_23e8, // paciza x8
        0xdac1_33e8, // autiza x8
        0xdac1_27e9, // pacizb x9
        0xdac1_37e9, // autizb x9
        0xdac1_2bea, // pacdza x10
        0xdac1_3bea, // autdza x10
        0xdac1_2feb, // pacdzb x11
        0xdac1_3feb, // autdzb x11
        0xdac1_01cc, // pacia  x12, x14
        0xdac1_43ec, // xpaci  x12
        0xdac1_09ed, // pacda  x13, x15
        0xdac1_47ed, // xpacd  x13
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = 0x0000_1234_5678_9000;
        g.x[1] = 0xaaaa_5555_1234_0001;
        g.x[2] = 0x0000_2234_5678_a000;
        g.x[3] = 0xbbbb_6666_1234_0002;
        g.x[4] = 0x0000_3234_5678_b000;
        g.x[5] = 0xcccc_7777_1234_0003;
        g.x[6] = 0x0000_4234_5678_c000;
        g.x[7] = 0xdddd_8888_1234_0004;
        g.x[8] = 0x0000_5234_5678_d000;
        g.x[9] = 0x0000_6234_5678_e000;
        g.x[10] = 0x0000_7234_5678_f000;
        g.x[11] = 0x0000_8234_5678_1000;
        g.x[12] = 0x0000_9234_5678_2000;
        g.x[13] = 0x0000_a234_5678_3000;
        g.x[14] = 0xeeee_9999_1234_0005;
        g.x[15] = 0xffff_aaaa_1234_0006;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 9, 10, 11, 12, 13] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 pointer-auth roundtrip x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_memory_oracle_matches_interpreter() {
    let insns = [
        0xf940_0020, // ldr   x0, [x1]
        0xb980_0062, // ldrsw x2, [x3]
        0xf900_0080, // str   x0, [x4]
        0x3940_00c5, // ldrb  w5, [x6]
        0x3900_00e5, // strb  w5, [x7]
    ];

    let native_u64 = 0x0123_4567_89ab_cdefu64;
    let native_i32 = (-1234567i32).to_le_bytes();
    let native_byte = 0xa5u8;
    let mut native_out64 = 0u64;
    let mut native_out8 = 0u8;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &native_u64 as *const u64 as u64;
        g.x[3] = native_i32.as_ptr() as u64;
        g.x[4] = &mut native_out64 as *mut u64 as u64;
        g.x[6] = &native_byte as *const u8 as u64;
        g.x[7] = &mut native_out8 as *mut u8 as u64;
    });

    const IN64: u64 = 0x4000;
    const IN32: u64 = 0x5000;
    const OUT64: u64 = 0x6000;
    const IN8: u64 = 0x7000;
    const OUT8: u64 = 0x8000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(IN64, &native_u64.to_le_bytes())
        .unwrap();
    interp.write_memory(IN32, &native_i32).unwrap();
    interp.write_memory(IN8, &[native_byte]).unwrap();
    interp.set_x(1, IN64);
    interp.set_x(3, IN32);
    interp.set_x(4, OUT64);
    interp.set_x(6, IN8);
    interp.set_x(7, OUT8);
    drive_to_done(&mut interp);

    assert_eq!(hw.x[0], interp.get_x(0), "raw EL0 ldr x0");
    assert_eq!(hw.x[2], interp.get_x(2), "raw EL0 ldrsw x2");
    assert_eq!(u64::from(hw.x[5] as u8), interp.get_x(5), "raw EL0 ldrb w5");
    assert_eq!(
        native_out64,
        interp.mem_read_u64(OUT64).unwrap(),
        "raw EL0 str x0"
    );
    assert_eq!(
        native_out8,
        interp.mem_read_u8(OUT8).unwrap(),
        "raw EL0 strb w5"
    );
}

#[test]
fn raw_el0_signed_memory_oracle_matches_interpreter() {
    let insns = [
        0x39c0_0020, // ldrsb  w0, [x1]
        0x3980_0062, // ldrsb  x2, [x3]
        0x79c0_00a4, // ldrsh  w4, [x5]
        0x7980_00e6, // ldrsh  x6, [x7]
        0xb980_0128, // ldrsw  x8, [x9]
        0x389f_f16a, // ldursb x10, [x11, #-1]
        0x789f_e1ac, // ldursh x12, [x13, #-2]
        0xb89f_c1ee, // ldursw x14, [x15, #-4]
    ];

    let native_byte_w = 0x80u8;
    let native_byte_x = 0x81u8;
    let native_half_w = 0x8001u16;
    let native_half_x = 0x8002u16;
    let native_word_x = 0x8000_0003u32;
    let native_unscaled_byte = [0x82u8, 0x7f];
    let native_unscaled_half = [0x8004u16, 0x0001];
    let native_unscaled_word = [0x8000_0005u32, 0x0000_0001];
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &native_byte_w as *const u8 as u64;
        g.x[3] = &native_byte_x as *const u8 as u64;
        g.x[5] = &native_half_w as *const u16 as u64;
        g.x[7] = &native_half_x as *const u16 as u64;
        g.x[9] = &native_word_x as *const u32 as u64;
        g.x[11] = unsafe { native_unscaled_byte.as_ptr().add(1) } as u64;
        g.x[13] = unsafe { native_unscaled_half.as_ptr().add(1) } as u64;
        g.x[15] = unsafe { native_unscaled_word.as_ptr().add(1) } as u64;
    });

    const BYTE_W: u64 = 0x1e_000;
    const BYTE_X: u64 = 0x1f_000;
    const HALF_W: u64 = 0x20_000;
    const HALF_X: u64 = 0x21_000;
    const WORD_X: u64 = 0x22_000;
    const UNSCALED_BYTE: u64 = 0x23_000;
    const UNSCALED_HALF: u64 = 0x24_000;
    const UNSCALED_WORD: u64 = 0x25_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(BYTE_W, &[native_byte_w]).unwrap();
    interp.write_memory(BYTE_X, &[native_byte_x]).unwrap();
    interp
        .write_memory(HALF_W, &native_half_w.to_le_bytes())
        .unwrap();
    interp
        .write_memory(HALF_X, &native_half_x.to_le_bytes())
        .unwrap();
    interp
        .write_memory(WORD_X, &native_word_x.to_le_bytes())
        .unwrap();
    interp
        .write_memory(UNSCALED_BYTE, &native_unscaled_byte)
        .unwrap();
    for (addr, value) in [
        (UNSCALED_HALF, native_unscaled_half[0]),
        (UNSCALED_HALF + 2, native_unscaled_half[1]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    for (addr, value) in [
        (UNSCALED_WORD, native_unscaled_word[0]),
        (UNSCALED_WORD + 4, native_unscaled_word[1]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(1, BYTE_W);
    interp.set_x(3, BYTE_X);
    interp.set_x(5, HALF_W);
    interp.set_x(7, HALF_X);
    interp.set_x(9, WORD_X);
    interp.set_x(11, UNSCALED_BYTE + 1);
    interp.set_x(13, UNSCALED_HALF + 2);
    interp.set_x(15, UNSCALED_WORD + 4);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 4, 6, 8, 10, 12, 14] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 signed memory x{reg} mismatch"
        );
    }
    for reg in [0usize, 4] {
        assert_eq!(
            hw.x[reg] >> 32,
            0,
            "raw EL0 signed memory W-destination x{reg} was not zero-extended"
        );
    }
}

#[test]
fn raw_el0_memory_addressing_oracle_matches_interpreter() {
    let insns = [
        0xf862_6820, // ldr  x0, [x1, x2]
        0xb865_d883, // ldr  w3, [x4, w5, sxtw #2]
        0x7868_58e6, // ldrh w6, [x7, w8, uxtw #1]
        0x782b_6949, // strh w9, [x10, x11]
        0xf940_0dac, // ldr  x12, [x13, #24]
        0xb900_0dee, // str  w14, [x15, #12]
    ];

    let native_reg64_in = [0x0102_0304_0506_0708u64, 0x1112_1314_1516_1718];
    let native_reg32_in = [0x8899_aabb_u32, 0x1122_3344];
    let native_half_in = [0x0102u16, 0x0304, 0x0506];
    let mut native_half_out = [0u16; 2];
    let native_imm64_in = [
        0xaaaa_bbbb_cccc_ddddu64,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_aaaa_bbbb_cccc,
    ];
    let mut native_word_out = [0u32; 4];
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = native_reg64_in.as_ptr() as u64;
        g.x[2] = 8;
        g.x[4] = unsafe { native_reg32_in.as_ptr().add(1) } as u64;
        g.x[5] = u32::MAX as u64;
        g.x[7] = native_half_in.as_ptr() as u64;
        g.x[8] = 2;
        g.x[9] = 0xffff_ffff_0000_beef;
        g.x[10] = native_half_out.as_mut_ptr() as u64;
        g.x[11] = 2;
        g.x[13] = native_imm64_in.as_ptr() as u64;
        g.x[14] = 0xaaaa_bbbb_ccdd_eeff;
        g.x[15] = native_word_out.as_mut_ptr() as u64;
    });

    const REG64: u64 = 0x12_000;
    const REG32: u64 = 0x13_000;
    const HALF_IN: u64 = 0x14_000;
    const HALF_OUT: u64 = 0x15_000;
    const IMM64: u64 = 0x16_000;
    const WORD_OUT: u64 = 0x17_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (REG64, native_reg64_in[0]),
        (REG64 + 8, native_reg64_in[1]),
        (IMM64, native_imm64_in[0]),
        (IMM64 + 8, native_imm64_in[1]),
        (IMM64 + 16, native_imm64_in[2]),
        (IMM64 + 24, native_imm64_in[3]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    for (addr, value) in [(REG32, native_reg32_in[0]), (REG32 + 4, native_reg32_in[1])] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    for (addr, value) in [
        (HALF_IN, native_half_in[0]),
        (HALF_IN + 2, native_half_in[1]),
        (HALF_IN + 4, native_half_in[2]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(1, REG64);
    interp.set_x(2, 8);
    interp.set_x(4, REG32 + 4);
    interp.set_x(5, u32::MAX as u64);
    interp.set_x(7, HALF_IN);
    interp.set_x(8, 2);
    interp.set_x(9, 0xffff_ffff_0000_beef);
    interp.set_x(10, HALF_OUT);
    interp.set_x(11, 2);
    interp.set_x(13, IMM64);
    interp.set_x(14, 0xaaaa_bbbb_ccdd_eeff);
    interp.set_x(15, WORD_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 6, 12] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 memory addressing x{reg} mismatch"
        );
    }
    assert_eq!(
        native_half_out[1],
        interp.mem_read_u16(HALF_OUT + 2).unwrap(),
        "raw EL0 memory addressing strh register offset"
    );
    assert_eq!(
        native_word_out[3],
        interp.mem_read_u32(WORD_OUT + 12).unwrap(),
        "raw EL0 memory addressing str immediate"
    );
}

#[test]
fn raw_el0_unprivileged_memory_oracle_matches_interpreter() {
    let insns = [
        0xf840_0820, // ldtr  x0, [x1]
        0x3840_0862, // ldtrb w2, [x3]
        0x7840_08a4, // ldtrh w4, [x5]
        0xf800_08e6, // sttr  x6, [x7]
        0x3800_0928, // sttrb w8, [x9]
        0x7800_096a, // sttrh w10, [x11]
    ];

    let native_in64 = 0x0123_4567_89ab_cdefu64;
    let native_in8 = 0xa5u8;
    let native_in16 = 0xbeefu16;
    let mut native_out64 = 0u64;
    let mut native_out8 = 0u8;
    let mut native_out16 = 0u16;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &native_in64 as *const u64 as u64;
        g.x[3] = &native_in8 as *const u8 as u64;
        g.x[5] = &native_in16 as *const u16 as u64;
        g.x[6] = 0x1111_2222_3333_4444;
        g.x[7] = &mut native_out64 as *mut u64 as u64;
        g.x[8] = 0xffff_ffff_0000_00cc;
        g.x[9] = &mut native_out8 as *mut u8 as u64;
        g.x[10] = 0xffff_ffff_0000_ddaa;
        g.x[11] = &mut native_out16 as *mut u16 as u64;
    });

    const IN64: u64 = 0x18_000;
    const IN8: u64 = 0x19_000;
    const IN16: u64 = 0x1a_000;
    const OUT64: u64 = 0x1b_000;
    const OUT8: u64 = 0x1c_000;
    const OUT16: u64 = 0x1d_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(IN64, &native_in64.to_le_bytes())
        .unwrap();
    interp.write_memory(IN8, &[native_in8]).unwrap();
    interp
        .write_memory(IN16, &native_in16.to_le_bytes())
        .unwrap();
    interp.set_x(1, IN64);
    interp.set_x(3, IN8);
    interp.set_x(5, IN16);
    interp.set_x(6, 0x1111_2222_3333_4444);
    interp.set_x(7, OUT64);
    interp.set_x(8, 0xffff_ffff_0000_00cc);
    interp.set_x(9, OUT8);
    interp.set_x(10, 0xffff_ffff_0000_ddaa);
    interp.set_x(11, OUT16);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 4] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 unprivileged memory x{reg} mismatch"
        );
    }
    assert_eq!(
        native_out64,
        interp.mem_read_u64(OUT64).unwrap(),
        "raw EL0 unprivileged memory sttr"
    );
    assert_eq!(
        native_out8,
        interp.mem_read_u8(OUT8).unwrap(),
        "raw EL0 unprivileged memory sttrb"
    );
    assert_eq!(
        native_out16,
        interp.mem_read_u16(OUT16).unwrap(),
        "raw EL0 unprivileged memory sttrh"
    );
}

#[test]
fn raw_el0_ordered_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("lrcpc") {
        eprintln!("[skip] host does not advertise RCpc loads");
        return;
    }

    let insns = [
        0xc8df_fc20, // ldar   x0, [x1]
        0x08df_fc62, // ldarb  w2, [x3]
        0xc89f_fca4, // stlr   x4, [x5]
        0x089f_fce6, // stlrb  w6, [x7]
        0xf8bf_c128, // ldapr  x8, [x9]
        0x38bf_c16a, // ldaprb w10, [x11]
    ];

    let native_ldar = 0x0123_4567_89ab_cdefu64;
    let native_ldarb = 0xa5u8;
    let mut native_stlr = 0u64;
    let mut native_stlrb = 0u8;
    let native_ldapr = 0xfedc_ba98_7654_3210u64;
    let native_ldaprb = 0x5au8;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &native_ldar as *const u64 as u64;
        g.x[3] = &native_ldarb as *const u8 as u64;
        g.x[4] = 0x1111_2222_3333_4444;
        g.x[5] = &mut native_stlr as *mut u64 as u64;
        g.x[6] = 0xee;
        g.x[7] = &mut native_stlrb as *mut u8 as u64;
        g.x[9] = &native_ldapr as *const u64 as u64;
        g.x[11] = &native_ldaprb as *const u8 as u64;
    });

    const LDAR: u64 = 0x8100;
    const LDARB: u64 = 0x8200;
    const STLR: u64 = 0x8300;
    const STLRB: u64 = 0x8400;
    const LDAPR: u64 = 0x8500;
    const LDAPRB: u64 = 0x8600;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(LDAR, &native_ldar.to_le_bytes())
        .unwrap();
    interp.write_memory(LDARB, &[native_ldarb]).unwrap();
    interp
        .write_memory(LDAPR, &native_ldapr.to_le_bytes())
        .unwrap();
    interp.write_memory(LDAPRB, &[native_ldaprb]).unwrap();
    interp.set_x(1, LDAR);
    interp.set_x(3, LDARB);
    interp.set_x(4, 0x1111_2222_3333_4444);
    interp.set_x(5, STLR);
    interp.set_x(6, 0xee);
    interp.set_x(7, STLRB);
    interp.set_x(9, LDAPR);
    interp.set_x(11, LDAPRB);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 8, 10] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 ordered memory x{reg} mismatch"
        );
    }
    assert_eq!(
        native_stlr,
        interp.mem_read_u64(STLR).unwrap(),
        "raw EL0 ordered memory stlr"
    );
    assert_eq!(
        native_stlrb,
        interp.mem_read_u8(STLRB).unwrap(),
        "raw EL0 ordered memory stlrb"
    );
}

#[test]
fn raw_el0_pair_writeback_memory_oracle_matches_interpreter() {
    let insns = [
        0xa940_0440, // ldp  x0, x1, [x2]
        0xa900_10a3, // stp  x3, x4, [x5]
        0xf840_84e6, // ldr  x6, [x7], #8
        0xf800_8d28, // str  x8, [x9, #8]!
        0xf85f_816a, // ldur x10, [x11, #-8]
        0xf81f_81ac, // stur x12, [x13, #-8]
    ];

    let native_pair_in = [0x0102_0304_0506_0708u64, 0x8877_6655_4433_2211];
    let mut native_pair_out = [0u64; 2];
    let native_post_in = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888];
    let mut native_pre_out = [0u64; 2];
    let native_unscaled_in = [0xaaaa_bbbb_cccc_ddddu64, 0xeeee_ffff_0000_1111];
    let mut native_unscaled_out = [0u64; 2];
    let hw = raw_native_run(&insns, |g| {
        g.x[2] = native_pair_in.as_ptr() as u64;
        g.x[3] = 0x1234_5678_9abc_def0;
        g.x[4] = 0x0fed_cba9_8765_4321;
        g.x[5] = native_pair_out.as_mut_ptr() as u64;
        g.x[7] = native_post_in.as_ptr() as u64;
        g.x[8] = 0xfeed_face_cafe_beef;
        g.x[9] = native_pre_out.as_mut_ptr() as u64;
        g.x[11] = unsafe { native_unscaled_in.as_ptr().add(1) } as u64;
        g.x[12] = 0xdead_beef_1234_5678;
        g.x[13] = unsafe { native_unscaled_out.as_mut_ptr().add(1) } as u64;
    });

    const PAIR_IN: u64 = 0xd000;
    const PAIR_OUT: u64 = 0xd100;
    const POST_IN: u64 = 0xd200;
    const PRE_OUT: u64 = 0xd300;
    const UNSCALED_IN: u64 = 0xd400;
    const UNSCALED_OUT: u64 = 0xd500;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (PAIR_IN, native_pair_in[0]),
        (PAIR_IN + 8, native_pair_in[1]),
        (POST_IN, native_post_in[0]),
        (POST_IN + 8, native_post_in[1]),
        (UNSCALED_IN, native_unscaled_in[0]),
        (UNSCALED_IN + 8, native_unscaled_in[1]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(2, PAIR_IN);
    interp.set_x(3, 0x1234_5678_9abc_def0);
    interp.set_x(4, 0x0fed_cba9_8765_4321);
    interp.set_x(5, PAIR_OUT);
    interp.set_x(7, POST_IN);
    interp.set_x(8, 0xfeed_face_cafe_beef);
    interp.set_x(9, PRE_OUT);
    interp.set_x(11, UNSCALED_IN + 8);
    interp.set_x(12, 0xdead_beef_1234_5678);
    interp.set_x(13, UNSCALED_OUT + 8);
    drive_to_done(&mut interp);

    for reg in [0u8, 1, 6, 10] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 pair/writeback memory x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.x[7],
        native_post_in.as_ptr() as u64 + 8,
        "raw EL0 ldr post-index native writeback"
    );
    assert_eq!(
        interp.get_x(7),
        POST_IN + 8,
        "raw EL0 ldr post-index interp writeback"
    );
    assert_eq!(
        hw.x[9],
        native_pre_out.as_ptr() as u64 + 8,
        "raw EL0 str pre-index native writeback"
    );
    assert_eq!(
        interp.get_x(9),
        PRE_OUT + 8,
        "raw EL0 str pre-index interp writeback"
    );
    assert_eq!(
        native_pair_out[0],
        interp.mem_read_u64(PAIR_OUT).unwrap(),
        "raw EL0 stp first lane"
    );
    assert_eq!(
        native_pair_out[1],
        interp.mem_read_u64(PAIR_OUT + 8).unwrap(),
        "raw EL0 stp second lane"
    );
    assert_eq!(
        native_pre_out[1],
        interp.mem_read_u64(PRE_OUT + 8).unwrap(),
        "raw EL0 pre-index str memory"
    );
    assert_eq!(
        native_unscaled_out[0],
        interp.mem_read_u64(UNSCALED_OUT).unwrap(),
        "raw EL0 stur negative offset memory"
    );
}

#[test]
fn raw_el0_pair_width_memory_oracle_matches_interpreter() {
    let insns = [
        0x6940_0440, // ldpsw x0, x1, [x2]
        0x2940_10a3, // ldp   w3, w4, [x5]
        0x2900_1d06, // stp   w6, w7, [x8]
    ];

    let native_signed = [0x8000_0001u32, 0x7fff_ffff];
    let native_word = [0x8000_0002u32, 0xffff_fff0];
    let mut native_out = [0u32; 2];
    let hw = raw_native_run(&insns, |g| {
        g.x[2] = native_signed.as_ptr() as u64;
        g.x[5] = native_word.as_ptr() as u64;
        g.x[6] = 0xaaaa_aaaa_dead_beef;
        g.x[7] = 0xbbbb_bbbb_cafe_f00d;
        g.x[8] = native_out.as_mut_ptr() as u64;
    });

    const SIGNED: u64 = 0x35_000;
    const WORD: u64 = 0x36_000;
    const OUT: u64 = 0x37_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (SIGNED, native_signed[0]),
        (SIGNED + 4, native_signed[1]),
        (WORD, native_word[0]),
        (WORD + 4, native_word[1]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(2, SIGNED);
    interp.set_x(5, WORD);
    interp.set_x(6, 0xaaaa_aaaa_dead_beef);
    interp.set_x(7, 0xbbbb_bbbb_cafe_f00d);
    interp.set_x(8, OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 1, 3, 4] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 pair width x{reg} mismatch"
        );
    }
    assert_eq!(hw.x[3] >> 32, 0, "raw EL0 ldp w3 was not zero-extended");
    assert_eq!(hw.x[4] >> 32, 0, "raw EL0 ldp w4 was not zero-extended");
    assert_eq!(
        native_out[0],
        interp.mem_read_u32(OUT).unwrap(),
        "raw EL0 stp w first lane"
    );
    assert_eq!(
        native_out[1],
        interp.mem_read_u32(OUT + 4).unwrap(),
        "raw EL0 stp w second lane"
    );
}

#[test]
fn raw_el0_vector_memory_oracle_matches_interpreter() {
    let insns = [
        0x3dc0_0020, // ldr q0, [x1]
        0x3d80_0040, // str q0, [x2]
        0x4c40_7083, // ld1 { v3.16b }, [x4]
        0x4c00_70a3, // st1 { v3.16b }, [x5]
        0xad40_1d06, // ldp q6, q7, [x8]
        0xad00_1d26, // stp q6, q7, [x9]
    ];

    let native_q_in = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let mut native_q_out = [0u64; 2];
    let native_ld1_in = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888];
    let mut native_st1_out = [0u64; 2];
    let native_pair_in = [
        0x0001_0002_0003_0004u64,
        0x0005_0006_0007_0008,
        0x1001_1002_1003_1004,
        0x1005_1006_1007_1008,
    ];
    let mut native_pair_out = [0u64; 4];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_q_in.as_ptr() as u64;
        g.x[2] = native_q_out.as_mut_ptr() as u64;
        g.x[4] = native_ld1_in.as_ptr() as u64;
        g.x[5] = native_st1_out.as_mut_ptr() as u64;
        g.x[8] = native_pair_in.as_ptr() as u64;
        g.x[9] = native_pair_out.as_mut_ptr() as u64;
    });

    const Q_IN: u64 = 0xe000;
    const Q_OUT: u64 = 0xe100;
    const LD1_IN: u64 = 0xe200;
    const ST1_OUT: u64 = 0xe300;
    const PAIR_IN: u64 = 0xe400;
    const PAIR_OUT: u64 = 0xe500;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (Q_IN, native_q_in[0]),
        (Q_IN + 8, native_q_in[1]),
        (LD1_IN, native_ld1_in[0]),
        (LD1_IN + 8, native_ld1_in[1]),
        (PAIR_IN, native_pair_in[0]),
        (PAIR_IN + 8, native_pair_in[1]),
        (PAIR_IN + 16, native_pair_in[2]),
        (PAIR_IN + 24, native_pair_in[3]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(1, Q_IN);
    interp.set_x(2, Q_OUT);
    interp.set_x(4, LD1_IN);
    interp.set_x(5, ST1_OUT);
    interp.set_x(8, PAIR_IN);
    interp.set_x(9, PAIR_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 6, 7] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 vector memory v{reg} mismatch"
        );
    }
    for (label, native, addr) in [
        ("str q0 low", native_q_out[0], Q_OUT),
        ("str q0 high", native_q_out[1], Q_OUT + 8),
        ("st1 low", native_st1_out[0], ST1_OUT),
        ("st1 high", native_st1_out[1], ST1_OUT + 8),
        ("stp q6 low", native_pair_out[0], PAIR_OUT),
        ("stp q6 high", native_pair_out[1], PAIR_OUT + 8),
        ("stp q7 low", native_pair_out[2], PAIR_OUT + 16),
        ("stp q7 high", native_pair_out[3], PAIR_OUT + 24),
    ] {
        assert_eq!(
            native,
            interp.mem_read_u64(addr).unwrap(),
            "raw EL0 vector memory {label}"
        );
    }
}

#[test]
fn raw_el0_advsimd_structure_memory_oracle_matches_interpreter() {
    let insns = [
        0x0c40_8040, // ld2 { v0.8b, v1.8b }, [x2]
        0x0c00_8060, // st2 { v0.8b, v1.8b }, [x3]
        0x0c40_44e4, // ld3 { v4.4h, v5.4h, v6.4h }, [x7]
        0x0c00_4504, // st3 { v4.4h, v5.4h, v6.4h }, [x8]
        0x4c40_09a9, // ld4 { v9.4s, v10.4s, v11.4s, v12.4s }, [x13]
        0x4c00_09c9, // st4 { v9.4s, v10.4s, v11.4s, v12.4s }, [x14]
    ];

    let native_ld2_in: [u8; 16] = std::array::from_fn(|i| 0x10 + i as u8);
    let mut native_st2_out = [0u8; 16];
    let native_ld3_in: [u8; 24] = std::array::from_fn(|i| 0x30 + i as u8);
    let mut native_st3_out = [0u8; 24];
    let native_ld4_in: [u8; 64] = std::array::from_fn(|i| 0x80 + i as u8);
    let mut native_st4_out = [0u8; 64];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[2] = native_ld2_in.as_ptr() as u64;
        g.x[3] = native_st2_out.as_mut_ptr() as u64;
        g.x[7] = native_ld3_in.as_ptr() as u64;
        g.x[8] = native_st3_out.as_mut_ptr() as u64;
        g.x[13] = native_ld4_in.as_ptr() as u64;
        g.x[14] = native_st4_out.as_mut_ptr() as u64;
    });

    const LD2_IN: u64 = 0x29_000;
    const ST2_OUT: u64 = 0x2a_000;
    const LD3_IN: u64 = 0x2b_000;
    const ST3_OUT: u64 = 0x2c_000;
    const LD4_IN: u64 = 0x2d_000;
    const ST4_OUT: u64 = 0x2e_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(LD2_IN, &native_ld2_in).unwrap();
    interp.write_memory(LD3_IN, &native_ld3_in).unwrap();
    interp.write_memory(LD4_IN, &native_ld4_in).unwrap();
    interp.set_x(2, LD2_IN);
    interp.set_x(3, ST2_OUT);
    interp.set_x(7, LD3_IN);
    interp.set_x(8, ST3_OUT);
    interp.set_x(13, LD4_IN);
    interp.set_x(14, ST4_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 1, 4, 5, 6, 9, 10, 11, 12] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 AdvSIMD structure memory v{reg} mismatch"
        );
    }
    for (label, native, addr) in [
        ("st2", native_st2_out.as_slice(), ST2_OUT),
        ("st3", native_st3_out.as_slice(), ST3_OUT),
        ("st4", native_st4_out.as_slice(), ST4_OUT),
    ] {
        for (offset, byte) in native.iter().copied().enumerate() {
            assert_eq!(
                byte,
                interp.mem_read_u8(addr + offset as u64).unwrap(),
                "raw EL0 AdvSIMD structure memory {label} byte {offset}"
            );
        }
    }
}

#[test]
fn raw_el0_sve_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue p0.d
        0xa5e0_a020, // ld1d  { z0.d }, p0/z, [x1]
        0xe5e0_e040, // st1d  { z0.d }, p0, [x2]
        0xa460_a083, // ld1b  { z3.d }, p0/z, [x4]
        0xe460_e0a3, // st1b  { z3.d }, p0, [x5]
    ];

    let native_d_in = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let mut native_d_out = [0u64; 2];
    let native_b_in = [0xa5u8, 0x5a];
    let mut native_b_out = [0u8; 2];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_d_in.as_ptr() as u64;
        g.x[2] = native_d_out.as_mut_ptr() as u64;
        g.x[4] = native_b_in.as_ptr() as u64;
        g.x[5] = native_b_out.as_mut_ptr() as u64;
    });

    const D_IN: u64 = 0xf000;
    const D_OUT: u64 = 0xf100;
    const B_IN: u64 = 0xf200;
    const B_OUT: u64 = 0xf300;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(D_IN, &native_d_in[0].to_le_bytes())
        .unwrap();
    interp
        .write_memory(D_IN + 8, &native_d_in[1].to_le_bytes())
        .unwrap();
    interp.write_memory(B_IN, &native_b_in).unwrap();
    interp.set_x(1, D_IN);
    interp.set_x(2, D_OUT);
    interp.set_x(4, B_IN);
    interp.set_x(5, B_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 3] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE memory z{reg} low-128 mismatch"
        );
    }
    for (label, native, addr) in [
        ("st1d low", native_d_out[0], D_OUT),
        ("st1d high", native_d_out[1], D_OUT + 8),
    ] {
        assert_eq!(
            native,
            interp.mem_read_u64(addr).unwrap(),
            "raw EL0 SVE memory {label}"
        );
    }
    for (label, native, addr) in [
        ("st1b lane 0", native_b_out[0], B_OUT),
        ("st1b lane 1", native_b_out[1], B_OUT + 1),
    ] {
        assert_eq!(
            native,
            interp.mem_read_u8(addr).unwrap(),
            "raw EL0 SVE memory {label}"
        );
    }
}

#[test]
fn raw_el0_sve_scalar_imm_memory_offset_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e3e0, // ptrue p0.h
        0xa421_a020, // ld1b  { z0.h }, p0/z, [x1, #1, mul vl]
        0xe421_e062, // st1b  { z2.h }, p0, [x3, #1, mul vl]
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };

    let mut native_load_in = [0u8; 32];
    for (i, byte) in native_load_in.iter_mut().enumerate() {
        *byte = 0x80 + i as u8;
    }
    native_load_in[8] = 0xaa;
    native_load_in[16] = 0xbb;
    let mut native_store_out = [0xccu8; 32];
    let store_values = pack_h([
        0x0011, 0x0022, 0x0033, 0x0044, 0x0055, 0x0066, 0x0077, 0x0088,
    ]);
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_load_in.as_ptr() as u64;
        g.x[3] = native_store_out.as_mut_ptr() as u64;
        g.v[4] = store_values.0;
        g.v[5] = store_values.1;
    });

    const LOAD_IN: u64 = 0xf400;
    const STORE_OUT: u64 = 0xf500;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(LOAD_IN, &native_load_in).unwrap();
    interp.write_memory(STORE_OUT, &[0xccu8; 32]).unwrap();
    interp.set_x(1, LOAD_IN);
    interp.set_x(3, STORE_OUT);
    interp
        .set_simd_reg(2, store_values.0, store_values.1)
        .unwrap();
    drive_to_done(&mut interp);

    let hw_z0 = u128::from(hw.v[0]) | (u128::from(hw.v[1]) << 64);
    assert_eq!(
        hw_z0,
        interp.get_simd(0),
        "raw EL0 SVE scalar+imm memory offset z0 low-128 mismatch"
    );
    for (offset, native) in native_store_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u8(STORE_OUT + offset as u64).unwrap(),
            "raw EL0 SVE scalar+imm memory offset store byte {offset}"
        );
    }
}

#[test]
fn raw_el0_sve_whole_reg_imm_memory_offset_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x8580_4420, // ldr z0, [x1, #1, mul vl]
        0xe580_4440, // str z0, [x2, #1, mul vl]
    ];

    let native_in: [u8; 32] = std::array::from_fn(|i| 0x40 + i as u8);
    let mut native_out = [0xccu8; 32];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_in.as_ptr() as u64;
        g.x[2] = native_out.as_mut_ptr() as u64;
    });

    const Z_IN: u64 = 0xf600;
    const Z_OUT: u64 = 0xf700;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(Z_IN, &native_in).unwrap();
    interp.write_memory(Z_OUT, &[0xccu8; 32]).unwrap();
    interp.set_x(1, Z_IN);
    interp.set_x(2, Z_OUT);
    drive_to_done(&mut interp);

    let hw_z0 = u128::from(hw.v[0]) | (u128::from(hw.v[1]) << 64);
    assert_eq!(
        hw_z0,
        interp.get_simd(0),
        "raw EL0 SVE whole-register immediate memory z0 low-128 mismatch"
    );
    for (offset, native) in native_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u8(Z_OUT + offset as u64).unwrap(),
            "raw EL0 SVE whole-register immediate memory store byte {offset}"
        );
    }
}

#[test]
fn raw_el0_sve_memory_extra_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e020, // ptrue p0.d, vl1
        0xa480_a020, // ld1sw { z0.d }, p0/z, [x1]
        0xe560_e040, // st1w  { z0.d }, p0, [x2]
        0x2598_e041, // ptrue p1.s, vl2
        0xa520_a483, // ld1sh { z3.s }, p1/z, [x4]
        0xe4c0_e4a3, // st1h  { z3.s }, p1, [x5]
        0x8540_c4e6, // ld1rw { z6.s }, p1/z, [x7]
        0x8580_4128, // ldr   z8, [x9]
        0xe580_4148, // str   z8, [x10]
        0x8580_0162, // ldr   p2, [x11]
        0xe580_0182, // str   p2, [x12]
    ];

    let native_w_in = [0xffff_ff80u32, 0x0000_007fu32];
    let mut native_w_out = [0xcccc_ccccu32; 2];
    let native_h_in = [0xff80u16, 0x007fu16, 0x1234u16, 0x5678u16];
    let mut native_h_out = [0xccccu16; 4];
    let native_repl_in = [0x1122_3344u32];
    let native_z_in: [u8; 16] = std::array::from_fn(|i| 0xa0 + i as u8);
    let mut native_z_out = [0xccu8; 16];
    let native_p_in = [0xa5u8, 0x03];
    let mut native_p_out = [0xccu8; 2];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_w_in.as_ptr() as u64;
        g.x[2] = native_w_out.as_mut_ptr() as u64;
        g.x[4] = native_h_in.as_ptr() as u64;
        g.x[5] = native_h_out.as_mut_ptr() as u64;
        g.x[7] = native_repl_in.as_ptr() as u64;
        g.x[9] = native_z_in.as_ptr() as u64;
        g.x[10] = native_z_out.as_mut_ptr() as u64;
        g.x[11] = native_p_in.as_ptr() as u64;
        g.x[12] = native_p_out.as_mut_ptr() as u64;
    });

    const W_IN: u64 = 0x30_000;
    const W_OUT: u64 = 0x31_000;
    const H_IN: u64 = 0x32_000;
    const H_OUT: u64 = 0x33_000;
    const REPL_IN: u64 = 0x34_000;
    const Z_IN: u64 = 0x35_000;
    const Z_OUT: u64 = 0x36_000;
    const P_IN: u64 = 0x37_000;
    const P_OUT: u64 = 0x38_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_w_in.iter().copied().enumerate() {
        interp
            .write_memory(W_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_w_out.iter().copied().enumerate() {
        interp
            .write_memory(W_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_h_in.iter().copied().enumerate() {
        interp
            .write_memory(H_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_h_out.iter().copied().enumerate() {
        interp
            .write_memory(H_OUT + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp
        .write_memory(REPL_IN, &native_repl_in[0].to_le_bytes())
        .unwrap();
    interp.write_memory(Z_IN, &native_z_in).unwrap();
    interp.write_memory(Z_OUT, &[0xccu8; 16]).unwrap();
    interp.write_memory(P_IN, &native_p_in).unwrap();
    interp.write_memory(P_OUT, &[0xccu8; 2]).unwrap();
    interp.set_x(1, W_IN);
    interp.set_x(2, W_OUT);
    interp.set_x(4, H_IN);
    interp.set_x(5, H_OUT);
    interp.set_x(7, REPL_IN);
    interp.set_x(9, Z_IN);
    interp.set_x(10, Z_OUT);
    interp.set_x(11, P_IN);
    interp.set_x(12, P_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 6, 8] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE extra memory z{reg} low-128 mismatch"
        );
    }
    for (label, native, addr) in [
        ("st1w lane 0", native_w_out[0], W_OUT),
        ("st1w inactive lane", native_w_out[1], W_OUT + 4),
    ] {
        assert_eq!(
            native,
            interp.mem_read_u32(addr).unwrap(),
            "raw EL0 SVE extra memory {label}"
        );
    }
    for (label, native, addr) in [
        ("st1h lane 0", native_h_out[0], H_OUT),
        ("st1h lane 1", native_h_out[1], H_OUT + 2),
        ("st1h inactive lane 2", native_h_out[2], H_OUT + 4),
        ("st1h inactive lane 3", native_h_out[3], H_OUT + 6),
    ] {
        assert_eq!(
            native,
            interp.mem_read_u16(addr).unwrap(),
            "raw EL0 SVE extra memory {label}"
        );
    }
    for (offset, byte) in native_z_out.iter().copied().enumerate() {
        assert_eq!(
            byte,
            interp.mem_read_u8(Z_OUT + offset as u64).unwrap(),
            "raw EL0 SVE extra memory str z8 byte {offset}"
        );
    }
    for (offset, byte) in native_p_out.iter().copied().enumerate() {
        assert_eq!(
            byte,
            interp.mem_read_u8(P_OUT + offset as u64).unwrap(),
            "raw EL0 SVE extra memory str p2 byte {offset}"
        );
    }
}

#[test]
fn raw_el0_sve_ld1r_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0x8440_8020, // ld1rb { z0.b }, p0/z, [x1]
        0x84c0_c062, // ld1rh { z2.s }, p0/z, [x3]
        0x8540_e0a4, // ld1rw { z4.d }, p0/z, [x5]
        0x85c0_e0e6, // ld1rd { z6.d }, p0/z, [x7]
    ];

    let native_b_in = [0xa5u8];
    let native_h_in = [0x8123u16];
    let native_w_in = [0x89ab_cdefu32];
    let native_d_in = [0x0123_4567_89ab_cdefu64];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_b_in.as_ptr() as u64;
        g.x[3] = native_h_in.as_ptr() as u64;
        g.x[5] = native_w_in.as_ptr() as u64;
        g.x[7] = native_d_in.as_ptr() as u64;
    });

    const B_IN: u64 = 0x39_000;
    const H_IN: u64 = 0x3a_000;
    const W_IN: u64 = 0x3b_000;
    const D_IN: u64 = 0x3c_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(B_IN, &native_b_in).unwrap();
    interp
        .write_memory(H_IN, &native_h_in[0].to_le_bytes())
        .unwrap();
    interp
        .write_memory(W_IN, &native_w_in[0].to_le_bytes())
        .unwrap();
    interp
        .write_memory(D_IN, &native_d_in[0].to_le_bytes())
        .unwrap();
    interp.set_x(1, B_IN);
    interp.set_x(3, H_IN);
    interp.set_x(5, W_IN);
    interp.set_x(7, D_IN);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 4, 6] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE LD1R z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ld1rq_reg_offset_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue  p0.s
        0xa502_0020, // ld1rqw { z0.s }, p0/z, [x1, x2]
    ];

    let native_in = [
        0xaaaa_0000u32,
        0x1111_2222,
        0x3333_4444,
        0x5555_6666,
        0xbbbb_0000,
    ];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_in.as_ptr() as u64;
        g.x[2] = 1;
    });

    const LD1RQ_IN: u64 = 0x4c_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_in.iter().copied().enumerate() {
        interp
            .write_memory(LD1RQ_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, LD1RQ_IN);
    interp.set_x(2, 1);
    drive_to_done(&mut interp);

    let hw_z0 = u128::from(hw.v[0]) | (u128::from(hw.v[1]) << 64);
    assert_eq!(
        hw_z0,
        interp.get_simd(0),
        "raw EL0 SVE LD1RQ reg-offset z0 low-128 mismatch"
    );
}

#[test]
fn raw_el0_sve_indexed_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue p0.d
        0xa5e2_4020, // ld1d  { z0.d }, p0/z, [x1, x2, lsl #3]
        0xe5e4_4060, // st1d  { z0.d }, p0, [x3, x4, lsl #3]
        0xc567_c0c5, // ld1w  { z5.d }, p0/z, [x6, z7.d, lsl #2]
        0xe52a_a128, // st1w  { z8.d }, p0, [x9, z10.d, lsl #2]
        0x2598_e061, // ptrue p1.s, vl3
        0x84ad_458b, // ld1h  { z11.s }, p1/z, [x12, z13.s, uxtw #1]
        0xe4f0_85ee, // st1h  { z14.s }, p1, [x15, z16.s, uxtw #1]
    ];
    let pack_d = |a: u64, b: u64| -> (u64, u64) { (a, b) };
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };

    let native_ld1d_in = [
        0x0101_0101_0101_0101u64,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_aaaa_bbbb_cccc,
    ];
    let mut native_st1d_out = [0xcccc_cccc_cccc_ccccu64; 5];
    let native_gather_w_in = [0x1122_3344u32, 0xcccc_cccc, 0x8877_6655, 0xdddd_dddd];
    let mut native_scatter_w_out = [0xcccc_ccccu32; 5];
    let native_gather_h_in = [0x1111u16, 0xcccc, 0x2222, 0xdddd, 0x3333, 0xeeee];
    let mut native_scatter_h_out = [0xccccu16; 7];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_ld1d_in.as_ptr() as u64;
        g.x[2] = 1;
        g.x[3] = native_st1d_out.as_mut_ptr() as u64;
        g.x[4] = 2;
        g.x[6] = native_gather_w_in.as_ptr() as u64;
        g.x[9] = native_scatter_w_out.as_mut_ptr() as u64;
        g.x[12] = native_gather_h_in.as_ptr() as u64;
        g.x[15] = native_scatter_h_out.as_mut_ptr() as u64;
        let (lo, hi) = pack_d(0, 2);
        g.v[14] = lo; // z7.d offsets
        g.v[15] = hi;
        let (lo, hi) = pack_d(0xaabb_ccdd, 0x5566_7788);
        g.v[16] = lo; // z8.d scatter values
        g.v[17] = hi;
        let (lo, hi) = pack_d(1, 3);
        g.v[20] = lo; // z10.d offsets
        g.v[21] = hi;
        let (lo, hi) = pack_s(0, 2, 4, 6);
        g.v[26] = lo; // z13.s offsets
        g.v[27] = hi;
        let (lo, hi) = pack_s(0xabcd, 0x5678, 0x2468, 0x1357);
        g.v[28] = lo; // z14.s scatter values
        g.v[29] = hi;
        let (lo, hi) = pack_s(1, 3, 5, 7);
        g.v[32] = lo; // z16.s offsets
        g.v[33] = hi;
    });

    const LD1D_IN: u64 = 0x39_000;
    const ST1D_OUT: u64 = 0x3a_000;
    const GATHER_W_IN: u64 = 0x3b_000;
    const SCATTER_W_OUT: u64 = 0x3c_000;
    const GATHER_H_IN: u64 = 0x3d_000;
    const SCATTER_H_OUT: u64 = 0x3e_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_ld1d_in.iter().copied().enumerate() {
        interp
            .write_memory(LD1D_IN + (i * 8) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_st1d_out.iter().copied().enumerate() {
        interp
            .write_memory(ST1D_OUT + (i * 8) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_gather_w_in.iter().copied().enumerate() {
        interp
            .write_memory(GATHER_W_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_scatter_w_out.iter().copied().enumerate() {
        interp
            .write_memory(SCATTER_W_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_gather_h_in.iter().copied().enumerate() {
        interp
            .write_memory(GATHER_H_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_scatter_h_out.iter().copied().enumerate() {
        interp
            .write_memory(SCATTER_H_OUT + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, LD1D_IN);
    interp.set_x(2, 1);
    interp.set_x(3, ST1D_OUT);
    interp.set_x(4, 2);
    interp.set_x(6, GATHER_W_IN);
    interp.set_x(9, SCATTER_W_OUT);
    interp.set_x(12, GATHER_H_IN);
    interp.set_x(15, SCATTER_H_OUT);
    for (reg, (lo, hi)) in [
        (7u8, pack_d(0, 2)),
        (8, pack_d(0xaabb_ccdd, 0x5566_7788)),
        (10, pack_d(1, 3)),
        (13, pack_s(0, 2, 4, 6)),
        (14, pack_s(0xabcd, 0x5678, 0x2468, 0x1357)),
        (16, pack_s(1, 3, 5, 7)),
    ] {
        interp.set_simd_reg(reg, lo, hi).unwrap();
    }
    drive_to_done(&mut interp);

    for reg in [0u8, 5, 11] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE indexed memory z{reg} low-128 mismatch"
        );
    }
    for (i, native) in native_st1d_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u64(ST1D_OUT + (i * 8) as u64).unwrap(),
            "raw EL0 SVE indexed memory st1d slot {i}"
        );
    }
    for (i, native) in native_scatter_w_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(SCATTER_W_OUT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE indexed memory scatter-w slot {i}"
        );
    }
    for (i, native) in native_scatter_h_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u16(SCATTER_H_OUT + (i * 2) as u64).unwrap(),
            "raw EL0 SVE indexed memory scatter-h slot {i}"
        );
    }
}

#[test]
fn raw_el0_sve_vector_base_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue p0.d
        0xc520_c020, // ld1w { z0.d }, p0/z, [z1.d]
        0xe540_a062, // st1w { z2.d }, p0, [z3.d]
        0xc521_c0a4, // ld1w { z4.d }, p0/z, [z5.d, #4]
        0xe541_a0e6, // st1w { z6.d }, p0, [z7.d, #4]
    ];
    let pack_d = |a: u64, b: u64| -> (u64, u64) { (a, b) };

    let native_load_direct = [0x1111_2222u32, 0x3333_4444];
    let native_load_imm = [0xaaaa_0000u32, 0x5555_6666, 0xbbbb_0000, 0x7777_8888];
    let mut native_store_direct = [0xcccc_ccccu32; 4];
    let mut native_store_imm = [0xdddd_ddddu32; 4];
    let hw = raw_native_run_fp(&insns, |g| {
        let (lo, hi) = pack_d(
            native_load_direct[0..1].as_ptr() as u64,
            native_load_direct[1..2].as_ptr() as u64,
        );
        g.v[2] = lo; // z1.d bases
        g.v[3] = hi;
        let (lo, hi) = pack_d(0x1234_5678, 0x9abc_def0);
        g.v[4] = lo; // z2.d direct store values
        g.v[5] = hi;
        let (lo, hi) = pack_d(
            native_store_direct[1..2].as_mut_ptr() as u64,
            native_store_direct[3..4].as_mut_ptr() as u64,
        );
        g.v[6] = lo; // z3.d direct store bases
        g.v[7] = hi;
        let (lo, hi) = pack_d(
            native_load_imm[0..1].as_ptr() as u64,
            native_load_imm[2..3].as_ptr() as u64,
        );
        g.v[10] = lo; // z5.d bases, instruction adds #4
        g.v[11] = hi;
        let (lo, hi) = pack_d(0x2468_ace0, 0x1357_bdf0);
        g.v[12] = lo; // z6.d immediate store values
        g.v[13] = hi;
        let (lo, hi) = pack_d(
            native_store_imm[0..1].as_mut_ptr() as u64,
            native_store_imm[2..3].as_mut_ptr() as u64,
        );
        g.v[14] = lo; // z7.d bases, instruction adds #4
        g.v[15] = hi;
    });

    const LOAD_DIRECT: u64 = 0x4c_000;
    const LOAD_IMM: u64 = 0x4d_000;
    const STORE_DIRECT: u64 = 0x4e_000;
    const STORE_IMM: u64 = 0x4f_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_load_direct.iter().copied().enumerate() {
        interp
            .write_memory(LOAD_DIRECT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_load_imm.iter().copied().enumerate() {
        interp
            .write_memory(LOAD_IMM + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_store_direct.iter().copied().enumerate() {
        interp
            .write_memory(STORE_DIRECT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_store_imm.iter().copied().enumerate() {
        interp
            .write_memory(STORE_IMM + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (reg, (lo, hi)) in [
        (1u8, pack_d(LOAD_DIRECT, LOAD_DIRECT + 4)),
        (2, pack_d(0x1234_5678, 0x9abc_def0)),
        (3, pack_d(STORE_DIRECT + 4, STORE_DIRECT + 12)),
        (5, pack_d(LOAD_IMM, LOAD_IMM + 8)),
        (6, pack_d(0x2468_ace0, 0x1357_bdf0)),
        (7, pack_d(STORE_IMM, STORE_IMM + 8)),
    ] {
        interp.set_simd_reg(reg, lo, hi).unwrap();
    }
    drive_to_done(&mut interp);

    for reg in [0u8, 4] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE vector-base memory z{reg} low-128 mismatch"
        );
    }
    for (i, native) in native_store_direct.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(STORE_DIRECT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE vector-base memory direct store slot {i}"
        );
    }
    for (i, native) in native_store_imm.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(STORE_IMM + (i * 4) as u64).unwrap(),
            "raw EL0 SVE vector-base memory immediate store slot {i}"
        );
    }
}

#[test]
fn raw_el0_sve_first_fault_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue  p0.d
        0xa562_6020, // ldff1w { z0.d }, p0/z, [x1, x2, lsl #2]
        0xa570_a083, // ldnf1w { z3.d }, p0/z, [x4]
        0x2598_e061, // ptrue  p1.s, vl3
        0xa4c7_64c5, // ldff1h { z5.s }, p1/z, [x6, x7, lsl #1]
        0xa4d0_a528, // ldnf1h { z8.s }, p1/z, [x9]
    ];

    let native_ff_w = [0xaaaa_0000u32, 0x1111_2222, 0x3333_4444, 0xbbbb_0000];
    let native_nf_w = [0xffff_ff80u32, 0x0000_007f, 0xcccc_cccc, 0xdddd_dddd];
    let native_ff_h = [0xaaaa_u16, 0xff80, 0x007f, 0x1234, 0xbbbb];
    let native_nf_h = [0xff00_u16, 0x0100, 0x0200, 0xcccc];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_ff_w.as_ptr() as u64;
        g.x[2] = 1;
        g.x[4] = native_nf_w.as_ptr() as u64;
        g.x[6] = native_ff_h.as_ptr() as u64;
        g.x[7] = 1;
        g.x[9] = native_nf_h.as_ptr() as u64;
    });

    const FF_W: u64 = 0x50_000;
    const NF_W: u64 = 0x51_000;
    const FF_H: u64 = 0x52_000;
    const NF_H: u64 = 0x53_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_ff_w.iter().copied().enumerate() {
        interp
            .write_memory(FF_W + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_nf_w.iter().copied().enumerate() {
        interp
            .write_memory(NF_W + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_ff_h.iter().copied().enumerate() {
        interp
            .write_memory(FF_H + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_nf_h.iter().copied().enumerate() {
        interp
            .write_memory(NF_H + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, FF_W);
    interp.set_x(2, 1);
    interp.set_x(4, NF_W);
    interp.set_x(6, FF_H);
    interp.set_x(7, 1);
    interp.set_x(9, NF_H);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 5, 8] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE first-fault memory z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ldnf1_imm_memory_offset_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e3e0, // ptrue  p0.h
        0xa4b1_a020, // ldnf1h { z0.h }, p0/z, [x1, #1, mul vl]
        0xa4bf_a062, // ldnf1h { z2.h }, p0/z, [x3, #-1, mul vl]
    ];

    let native_pos: [u16; 16] = std::array::from_fn(|i| 0x1000 + i as u16);
    let native_neg: [u16; 16] = std::array::from_fn(|i| 0x2000 + i as u16);
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_pos.as_ptr() as u64;
        g.x[3] = native_neg[8..].as_ptr() as u64;
    });

    const POS_IN: u64 = 0x54_000;
    const NEG_IN: u64 = 0x55_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_pos.iter().copied().enumerate() {
        interp
            .write_memory(POS_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_neg.iter().copied().enumerate() {
        interp
            .write_memory(NEG_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, POS_IN);
    interp.set_x(3, NEG_IN + 16);
    drive_to_done(&mut interp);

    for reg in [0u8, 2] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE LDNF1 immediate memory z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ldff1_vector_offset_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue  p0.d
        0xc563_e044, // ldff1w { z4.d }, p0/z, [x2, z3.d, lsl #2]
    ];
    let pack_d = |a: u64, b: u64| -> (u64, u64) { (a, b) };

    let native_in = [0x1111_2222u32, 0xcccc_cccc, 0x3333_4444, 0xdddd_dddd];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[2] = native_in.as_ptr() as u64;
        let (lo, hi) = pack_d(0, 2);
        g.v[6] = lo; // z3.d offsets
        g.v[7] = hi;
    });

    const LDFF1_IN: u64 = 0x58_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_in.iter().copied().enumerate() {
        interp
            .write_memory(LDFF1_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(2, LDFF1_IN);
    let (lo, hi) = pack_d(0, 2);
    interp.set_simd_reg(3, lo, hi).unwrap();
    drive_to_done(&mut interp);

    let hw_z4 = u128::from(hw.v[8]) | (u128::from(hw.v[9]) << 64);
    assert_eq!(
        hw_z4,
        interp.get_simd(4),
        "raw EL0 SVE LDFF1 vector-offset memory z4 low-128 mismatch"
    );
}

#[test]
fn raw_el0_sve_ldff1_vector_base_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue  p0.d
        0xc520_e064, // ldff1w { z4.d }, p0/z, [z3.d]
    ];
    let pack_d = |a: u64, b: u64| -> (u64, u64) { (a, b) };

    let native_a = [0x1111_2222u32];
    let native_b = [0x3333_4444u32];
    let hw = raw_native_run_fp(&insns, |g| {
        let (lo, hi) = pack_d(native_a.as_ptr() as u64, native_b.as_ptr() as u64);
        g.v[6] = lo; // z3.d bases
        g.v[7] = hi;
    });

    const LDFF1_A: u64 = 0x59_000;
    const LDFF1_B: u64 = 0x59_100;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(LDFF1_A, &native_a[0].to_le_bytes())
        .unwrap();
    interp
        .write_memory(LDFF1_B, &native_b[0].to_le_bytes())
        .unwrap();
    let (lo, hi) = pack_d(LDFF1_A, LDFF1_B);
    interp.set_simd_reg(3, lo, hi).unwrap();
    drive_to_done(&mut interp);

    let hw_z4 = u128::from(hw.v[8]) | (u128::from(hw.v[9]) << 64);
    assert_eq!(
        hw_z4,
        interp.get_simd(4),
        "raw EL0 SVE LDFF1 vector-base memory z4 low-128 mismatch"
    );
}

#[test]
fn raw_el0_sve_prefetch_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x8422_2020, // PRFH vector offset, x1 base, z2 offsets
        0x85c0_0020, // PRFB scalar base immediate, x1 base
        0x8583_c040, // PRFD scalar base register, x2 + x3
    ];

    let native_a = [0u8; 64];
    let native_b = [0u8; 64];
    let z4_lo = 0x0123_4567_89ab_cdef;
    let z4_hi = 0xfedc_ba98_7654_3210;
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_a.as_ptr() as u64;
        g.x[2] = native_b.as_ptr() as u64;
        g.x[3] = 0;
        g.v[4] = 0; // z2.s offsets
        g.v[5] = 0;
        g.v[8] = z4_lo; // z4 sentinel
        g.v[9] = z4_hi;
    });
    assert_eq!(hw.x[1], native_a.as_ptr() as u64, "raw EL0 SVE prefetch x1");
    assert_eq!(hw.x[2], native_b.as_ptr() as u64, "raw EL0 SVE prefetch x2");
    assert_eq!(hw.x[3], 0, "raw EL0 SVE prefetch x3");
    assert_eq!(hw.v[4], 0, "raw EL0 SVE prefetch z2 low");
    assert_eq!(hw.v[5], 0, "raw EL0 SVE prefetch z2 high");
    assert_eq!(hw.v[8], z4_lo, "raw EL0 SVE prefetch z4 low");
    assert_eq!(hw.v[9], z4_hi, "raw EL0 SVE prefetch z4 high");

    const PREF_A: u64 = 0x5a_000;
    const PREF_B: u64 = 0x5b_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(PREF_A, &[0u8; 64]).unwrap();
    interp.write_memory(PREF_B, &[0u8; 64]).unwrap();
    interp.set_x(1, PREF_A);
    interp.set_x(2, PREF_B);
    interp.set_x(3, 0);
    interp.set_simd_reg(2, 0, 0).unwrap();
    interp.set_simd_reg(4, z4_lo, z4_hi).unwrap();
    drive_to_done(&mut interp);
    assert_eq!(interp.get_x(1), PREF_A, "interpreted SVE prefetch x1");
    assert_eq!(interp.get_x(2), PREF_B, "interpreted SVE prefetch x2");
    assert_eq!(interp.get_x(3), 0, "interpreted SVE prefetch x3");
    assert_eq!(interp.get_simd(2), 0, "interpreted SVE prefetch z2");
    assert_eq!(
        interp.get_simd(4),
        u128::from(z4_lo) | (u128::from(z4_hi) << 64),
        "interpreted SVE prefetch z4"
    );
}

#[test]
fn raw_el0_sve_ldst_reg_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0xa402_4020, // ld1b  { z0.b }, p0/z, [x1, x2]
        0xe405_4083, // st1b  { z3.b }, p0, [x4, x5]
    ];
    let pack_b = |xs: [u8; 16]| -> (u64, u64) {
        (
            u64::from_le_bytes(xs[0..8].try_into().unwrap()),
            u64::from_le_bytes(xs[8..16].try_into().unwrap()),
        )
    };

    let native_load_in: [u8; 32] = std::array::from_fn(|i| 0x30 + i as u8);
    let mut native_store_out = [0xccu8; 32];
    let native_store_values: [u8; 16] = std::array::from_fn(|i| 0x80 + i as u8);
    let (store_lo, store_hi) = pack_b(native_store_values);
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_load_in.as_ptr() as u64;
        g.x[2] = 7;
        g.x[4] = native_store_out.as_mut_ptr() as u64;
        g.x[5] = 5;
        g.v[6] = store_lo;
        g.v[7] = store_hi;
    });

    const LOAD_IN: u64 = 0x56_000;
    const STORE_OUT: u64 = 0x57_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(LOAD_IN, &native_load_in).unwrap();
    interp.write_memory(STORE_OUT, &native_store_out).unwrap();
    interp.set_x(1, LOAD_IN);
    interp.set_x(2, 7);
    interp.set_x(4, STORE_OUT);
    interp.set_x(5, 5);
    interp.set_simd_reg(3, store_lo, store_hi).unwrap();
    drive_to_done(&mut interp);

    let hw_z0 = u128::from(hw.v[0]) | (u128::from(hw.v[1]) << 64);
    assert_eq!(
        hw_z0,
        interp.get_simd(0),
        "raw EL0 SVE LD1/ST1 register-offset memory z0 low-128 mismatch"
    );
    for (offset, native) in native_store_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u8(STORE_OUT + offset as u64).unwrap(),
            "raw EL0 SVE LD1/ST1 register-offset memory store byte {offset}"
        );
    }
}

#[test]
fn raw_el0_sve_structure_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0xa520_e020, // ld2w  { z0.s, z1.s }, p0/z, [x1]
        0xe530_e040, // st2w  { z0.s, z1.s }, p0, [x2]
        0x2558_e061, // ptrue p1.h, vl3
        0xa4c0_e4c3, // ld3h  { z3.h, z4.h, z5.h }, p1/z, [x6]
        0xe4d0_e4e3, // st3h  { z3.h, z4.h, z5.h }, p1, [x7]
        0x2518_e082, // ptrue p2.b, vl4
        0xa460_e988, // ld4b  { z8.b, z9.b, z10.b, z11.b }, p2/z, [x12]
        0xe470_e9a8, // st4b  { z8.b, z9.b, z10.b, z11.b }, p2, [x13]
    ];

    let native_ld2w_in: [u32; 8] = std::array::from_fn(|i| 0x1000_0000 + i as u32);
    let mut native_st2w_out = [0xcccc_ccccu32; 8];
    let native_ld3h_in: [u16; 24] = std::array::from_fn(|i| 0x2000 + i as u16);
    let mut native_st3h_out = [0xccccu16; 24];
    let native_ld4b_in: [u8; 64] = std::array::from_fn(|i| 0x40 + i as u8);
    let mut native_st4b_out = [0xccu8; 64];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_ld2w_in.as_ptr() as u64;
        g.x[2] = native_st2w_out.as_mut_ptr() as u64;
        g.x[6] = native_ld3h_in.as_ptr() as u64;
        g.x[7] = native_st3h_out.as_mut_ptr() as u64;
        g.x[12] = native_ld4b_in.as_ptr() as u64;
        g.x[13] = native_st4b_out.as_mut_ptr() as u64;
    });

    const LD2W_IN: u64 = 0x40_000;
    const ST2W_OUT: u64 = 0x41_000;
    const LD3H_IN: u64 = 0x42_000;
    const ST3H_OUT: u64 = 0x43_000;
    const LD4B_IN: u64 = 0x44_000;
    const ST4B_OUT: u64 = 0x45_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_ld2w_in.iter().copied().enumerate() {
        interp
            .write_memory(LD2W_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_st2w_out.iter().copied().enumerate() {
        interp
            .write_memory(ST2W_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_ld3h_in.iter().copied().enumerate() {
        interp
            .write_memory(LD3H_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_st3h_out.iter().copied().enumerate() {
        interp
            .write_memory(ST3H_OUT + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.write_memory(LD4B_IN, &native_ld4b_in).unwrap();
    interp.write_memory(ST4B_OUT, &native_st4b_out).unwrap();
    interp.set_x(1, LD2W_IN);
    interp.set_x(2, ST2W_OUT);
    interp.set_x(6, LD3H_IN);
    interp.set_x(7, ST3H_OUT);
    interp.set_x(12, LD4B_IN);
    interp.set_x(13, ST4B_OUT);
    drive_to_done(&mut interp);

    for reg in [0u8, 1, 3, 4, 5, 8, 9, 10, 11] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE structure memory z{reg} low-128 mismatch"
        );
    }
    for (i, native) in native_st2w_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(ST2W_OUT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE structure memory st2w slot {i}"
        );
    }
    for (i, native) in native_st3h_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u16(ST3H_OUT + (i * 2) as u64).unwrap(),
            "raw EL0 SVE structure memory st3h slot {i}"
        );
    }
    for (i, native) in native_st4b_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u8(ST4B_OUT + i as u64).unwrap(),
            "raw EL0 SVE structure memory st4b slot {i}"
        );
    }
}

#[test]
fn raw_el0_sve_structure_reg_offset_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0xa522_c020, // ld2w { z0.s, z1.s }, p0/z, [x1, x2]
        0xe524_6060, // st2w { z0.s, z1.s }, p0, [x3, x4]
    ];

    let native_in = [
        0xaaaa_0000u32,
        0x1111_2222,
        0x3333_4444,
        0x5555_6666,
        0x7777_8888,
        0xbbbb_0000,
    ];
    let mut native_out = [0xcccc_ccccu32; 6];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_in.as_ptr() as u64;
        g.x[2] = 1;
        g.x[3] = native_out.as_mut_ptr() as u64;
        g.x[4] = 1;
    });

    const STRUCT_IN: u64 = 0x4e_000;
    const STRUCT_OUT: u64 = 0x4f_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_in.iter().copied().enumerate() {
        interp
            .write_memory(STRUCT_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_out.iter().copied().enumerate() {
        interp
            .write_memory(STRUCT_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, STRUCT_IN);
    interp.set_x(2, 1);
    interp.set_x(3, STRUCT_OUT);
    interp.set_x(4, 1);
    drive_to_done(&mut interp);

    for reg in [0u8, 1] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE structure reg-offset memory z{reg} low-128 mismatch"
        );
    }
    for (i, native) in native_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(STRUCT_OUT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE structure reg-offset memory st2w slot {i}"
        );
    }
}

#[test]
fn raw_el0_sve_nontemporal_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue  p0.s, vl2
        0xa500_e020, // ldnt1w { z0.s }, p0/z, [x1]
        0xe510_e040, // stnt1w { z0.s }, p0, [x2]
        0xa500_2083, // ld1rqw { z3.s }, p0/z, [x4]
        0x2558_e061, // ptrue  p1.h, vl3
        0xa480_e4c5, // ldnt1h { z5.h }, p1/z, [x6]
        0xe490_e4e5, // stnt1h { z5.h }, p1, [x7]
        0xa480_2528, // ld1rqh { z8.h }, p1/z, [x9]
    ];

    let native_nt_w_in = [0x1010_0000u32, 0x2020_0001, 0x3030_0002, 0x4040_0003];
    let mut native_nt_w_out = [0xcccc_ccccu32; 4];
    let native_rq_w_in = [0x1111_0000u32, 0x2222_0001, 0x3333_0002, 0x4444_0003];
    let native_nt_h_in: [u16; 8] = std::array::from_fn(|i| 0x5000 + i as u16);
    let mut native_nt_h_out = [0xccccu16; 8];
    let native_rq_h_in: [u16; 8] = std::array::from_fn(|i| 0x6000 + i as u16);
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_nt_w_in.as_ptr() as u64;
        g.x[2] = native_nt_w_out.as_mut_ptr() as u64;
        g.x[4] = native_rq_w_in.as_ptr() as u64;
        g.x[6] = native_nt_h_in.as_ptr() as u64;
        g.x[7] = native_nt_h_out.as_mut_ptr() as u64;
        g.x[9] = native_rq_h_in.as_ptr() as u64;
    });

    const NT_W_IN: u64 = 0x46_000;
    const NT_W_OUT: u64 = 0x47_000;
    const RQ_W_IN: u64 = 0x48_000;
    const NT_H_IN: u64 = 0x49_000;
    const NT_H_OUT: u64 = 0x4a_000;
    const RQ_H_IN: u64 = 0x4b_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_nt_w_in.iter().copied().enumerate() {
        interp
            .write_memory(NT_W_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_nt_w_out.iter().copied().enumerate() {
        interp
            .write_memory(NT_W_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_rq_w_in.iter().copied().enumerate() {
        interp
            .write_memory(RQ_W_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_nt_h_in.iter().copied().enumerate() {
        interp
            .write_memory(NT_H_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_nt_h_out.iter().copied().enumerate() {
        interp
            .write_memory(NT_H_OUT + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_rq_h_in.iter().copied().enumerate() {
        interp
            .write_memory(RQ_H_IN + (i * 2) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, NT_W_IN);
    interp.set_x(2, NT_W_OUT);
    interp.set_x(4, RQ_W_IN);
    interp.set_x(6, NT_H_IN);
    interp.set_x(7, NT_H_OUT);
    interp.set_x(9, RQ_H_IN);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 5, 8] {
        let hw_value =
            u128::from(hw.v[(2 * reg) as usize]) | (u128::from(hw.v[(2 * reg + 1) as usize]) << 64);
        assert_eq!(
            hw_value,
            interp.get_simd(reg),
            "raw EL0 SVE non-temporal memory z{reg} low-128 mismatch"
        );
    }
    for (i, native) in native_nt_w_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(NT_W_OUT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE non-temporal memory stnt1w slot {i}"
        );
    }
    for (i, native) in native_nt_h_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u16(NT_H_OUT + (i * 2) as u64).unwrap(),
            "raw EL0 SVE non-temporal memory stnt1h slot {i}"
        );
    }
}

#[test]
fn raw_el0_sve_nontemporal_reg_offset_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue  p0.s, vl2
        0xa502_c020, // ldnt1w { z0.s }, p0/z, [x1, x2]
        0xe504_6060, // stnt1w { z0.s }, p0, [x3, x4]
    ];

    let native_in = [0xaaaa_0000u32, 0x1111_2222, 0x3333_4444, 0xbbbb_0000];
    let mut native_out = [0xcccc_ccccu32; 5];
    let hw = raw_native_run_fp(&insns, |g| {
        g.x[1] = native_in.as_ptr() as u64;
        g.x[2] = 1;
        g.x[3] = native_out.as_mut_ptr() as u64;
        g.x[4] = 2;
    });

    const NT_IN: u64 = 0x4c_000;
    const NT_OUT: u64 = 0x4d_000;
    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (i, v) in native_in.iter().copied().enumerate() {
        interp
            .write_memory(NT_IN + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    for (i, v) in native_out.iter().copied().enumerate() {
        interp
            .write_memory(NT_OUT + (i * 4) as u64, &v.to_le_bytes())
            .unwrap();
    }
    interp.set_x(1, NT_IN);
    interp.set_x(2, 1);
    interp.set_x(3, NT_OUT);
    interp.set_x(4, 2);
    drive_to_done(&mut interp);

    let hw_z0 = u128::from(hw.v[0]) | (u128::from(hw.v[1]) << 64);
    assert_eq!(
        hw_z0,
        interp.get_simd(0),
        "raw EL0 SVE non-temporal reg-offset memory z0 low-128 mismatch"
    );
    for (i, native) in native_out.iter().copied().enumerate() {
        assert_eq!(
            native,
            interp.mem_read_u32(NT_OUT + (i * 4) as u64).unwrap(),
            "raw EL0 SVE non-temporal reg-offset memory stnt1w slot {i}"
        );
    }
}

#[test]
fn raw_el0_exclusive_acquire_release_memory_oracle_matches_interpreter() {
    let insns = [
        0xc85f_fc20, // ldaxr  x0, [x1]
        0xc802_fc23, // stlxr  w2, x3, [x1]
        0x085f_fca4, // ldaxrb w4, [x5]
        0x0806_fca7, // stlxrb w6, w7, [x5]
        0x485f_fd28, // ldaxrh w8, [x9]
        0x480a_fd2b, // stlxrh w10, w11, [x9]
    ];

    let mut native_x = 0x0102_0304_0506_0708u64;
    let mut native_b = 0xa5u8;
    let mut native_h = 0xbeefu16;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &mut native_x as *mut u64 as u64;
        g.x[3] = 0x8877_6655_4433_2211;
        g.x[5] = &mut native_b as *mut u8 as u64;
        g.x[7] = 0x5a;
        g.x[9] = &mut native_h as *mut u16 as u64;
        g.x[11] = 0x1234;
    });

    const EXCL_X: u64 = 0x26_000;
    const EXCL_B: u64 = 0x27_000;
    const EXCL_H: u64 = 0x28_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(EXCL_X, &0x0102_0304_0506_0708u64.to_le_bytes())
        .unwrap();
    interp.write_memory(EXCL_B, &[0xa5]).unwrap();
    interp
        .write_memory(EXCL_H, &0xbeefu16.to_le_bytes())
        .unwrap();
    interp.set_x(1, EXCL_X);
    interp.set_x(3, 0x8877_6655_4433_2211);
    interp.set_x(5, EXCL_B);
    interp.set_x(7, 0x5a);
    interp.set_x(9, EXCL_H);
    interp.set_x(11, 0x1234);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 4, 6, 8, 10] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 exclusive acquire/release x{reg} mismatch"
        );
    }
    assert_eq!(
        native_x,
        interp.mem_read_u64(EXCL_X).unwrap(),
        "raw EL0 exclusive acquire/release stlxr"
    );
    assert_eq!(
        native_b,
        interp.mem_read_u8(EXCL_B).unwrap(),
        "raw EL0 exclusive acquire/release stlxrb"
    );
    assert_eq!(
        native_h,
        interp.mem_read_u16(EXCL_H).unwrap(),
        "raw EL0 exclusive acquire/release stlxrh"
    );
}

#[test]
fn raw_el0_atomic_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("atomics") {
        eprintln!("[skip] host does not advertise LSE atomics");
        return;
    }

    let insns = [
        0xc85f_7c20, // ldxr  x0, [x1]
        0xc802_7c23, // stxr  w2, x3, [x1]
        0xf825_00e6, // ldadd x5, x6, [x7]
        0xc8a8_7d49, // cas   x8, x9, [x10]
        0xf82b_81ac, // swp   x11, x12, [x13]
    ];

    let mut native_excl = 0x0102_0304_0506_0708u64;
    let mut native_ldadd = 0x1000_2000_3000_4000u64;
    let mut native_cas = 0x1111_2222_3333_4444u64;
    let mut native_swp = 0xaaaa_bbbb_cccc_ddddu64;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = &mut native_excl as *mut u64 as u64;
        g.x[3] = 0x8877_6655_4433_2211;
        g.x[5] = 0x10;
        g.x[7] = &mut native_ldadd as *mut u64 as u64;
        g.x[8] = native_cas;
        g.x[9] = 0x9999_8888_7777_6666;
        g.x[10] = &mut native_cas as *mut u64 as u64;
        g.x[11] = 0x0123_4567_89ab_cdef;
        g.x[13] = &mut native_swp as *mut u64 as u64;
    });

    const EXCL: u64 = 0x9000;
    const LDADD: u64 = 0xa000;
    const CAS: u64 = 0xb000;
    const SWP: u64 = 0xc000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp
        .write_memory(EXCL, &0x0102_0304_0506_0708u64.to_le_bytes())
        .unwrap();
    interp
        .write_memory(LDADD, &0x1000_2000_3000_4000u64.to_le_bytes())
        .unwrap();
    interp
        .write_memory(CAS, &0x1111_2222_3333_4444u64.to_le_bytes())
        .unwrap();
    interp
        .write_memory(SWP, &0xaaaa_bbbb_cccc_ddddu64.to_le_bytes())
        .unwrap();
    interp.set_x(1, EXCL);
    interp.set_x(3, 0x8877_6655_4433_2211);
    interp.set_x(5, 0x10);
    interp.set_x(7, LDADD);
    interp.set_x(8, 0x1111_2222_3333_4444);
    interp.set_x(9, 0x9999_8888_7777_6666);
    interp.set_x(10, CAS);
    interp.set_x(11, 0x0123_4567_89ab_cdef);
    interp.set_x(13, SWP);
    drive_to_done(&mut interp);

    for reg in [0u8, 2, 6, 8, 12] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 atomic oracle x{reg} mismatch"
        );
    }
    assert_eq!(
        native_excl,
        interp.mem_read_u64(EXCL).unwrap(),
        "raw EL0 stxr memory"
    );
    assert_eq!(
        native_ldadd,
        interp.mem_read_u64(LDADD).unwrap(),
        "raw EL0 ldadd memory"
    );
    assert_eq!(
        native_cas,
        interp.mem_read_u64(CAS).unwrap(),
        "raw EL0 cas memory"
    );
    assert_eq!(
        native_swp,
        interp.mem_read_u64(SWP).unwrap(),
        "raw EL0 swp memory"
    );
}

#[test]
fn raw_el0_atomic_pair_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("atomics") {
        eprintln!("[skip] host does not advertise LSE atomics");
        return;
    }

    #[repr(align(16))]
    struct AlignedPair([u64; 2]);

    let insns = [
        0x4820_7c82, // casp x0, x1, x2, x3, [x4]
        0x4826_7d48, // casp x6, x7, x8, x9, [x10]
    ];

    let initial_success = [0x0102_0304_0506_0708u64, 0x1112_1314_1516_1718];
    let update_success = [0x2122_2324_2526_2728u64, 0x3132_3334_3536_3738];
    let initial_fail = [0x4142_4344_4546_4748u64, 0x5152_5354_5556_5758];
    let update_fail = [0x6162_6364_6566_6768u64, 0x7172_7374_7576_7778];
    let mut native_success = AlignedPair(initial_success);
    let mut native_fail = AlignedPair(initial_fail);

    let hw = raw_native_run(&insns, |g| {
        g.x[0] = initial_success[0];
        g.x[1] = initial_success[1];
        g.x[2] = update_success[0];
        g.x[3] = update_success[1];
        g.x[4] = native_success.0.as_mut_ptr() as u64;
        g.x[6] = 0xffff_ffff_ffff_ffff;
        g.x[7] = 0;
        g.x[8] = update_fail[0];
        g.x[9] = update_fail[1];
        g.x[10] = native_fail.0.as_mut_ptr() as u64;
    });

    const CASP_SUCCESS: u64 = 0xd000;
    const CASP_FAIL: u64 = 0xe000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (CASP_SUCCESS, initial_success[0]),
        (CASP_SUCCESS + 8, initial_success[1]),
        (CASP_FAIL, initial_fail[0]),
        (CASP_FAIL + 8, initial_fail[1]),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(0, initial_success[0]);
    interp.set_x(1, initial_success[1]);
    interp.set_x(2, update_success[0]);
    interp.set_x(3, update_success[1]);
    interp.set_x(4, CASP_SUCCESS);
    interp.set_x(6, 0xffff_ffff_ffff_ffff);
    interp.set_x(7, 0);
    interp.set_x(8, update_fail[0]);
    interp.set_x(9, update_fail[1]);
    interp.set_x(10, CASP_FAIL);
    drive_to_done(&mut interp);

    for reg in [0u8, 1, 6, 7] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 atomic pair x{reg} mismatch"
        );
    }
    assert_eq!(
        native_success.0,
        [
            interp.mem_read_u64(CASP_SUCCESS).unwrap(),
            interp.mem_read_u64(CASP_SUCCESS + 8).unwrap(),
        ],
        "raw EL0 casp success memory"
    );
    assert_eq!(
        native_fail.0,
        [
            interp.mem_read_u64(CASP_FAIL).unwrap(),
            interp.mem_read_u64(CASP_FAIL + 8).unwrap(),
        ],
        "raw EL0 casp failed memory"
    );
}

#[test]
fn raw_el0_atomic_variant_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("atomics") {
        eprintln!("[skip] host does not advertise LSE atomics");
        return;
    }

    let insns = [
        0x3820_1041, // ldclrb w0, w1, [x2]
        0x7823_20a4, // ldeorh w3, w4, [x5]
        0xf826_3107, // ldset  x6, x7, [x8]
        0x08a9_7d6a, // casb   w9, w10, [x11]
        0x48ac_7dcd, // cash   w12, w13, [x14]
    ];

    let mut native_ldclrb = 0b1111_0011u8;
    let mut native_ldeorh = 0x55aau16;
    let mut native_ldset = 0x0000_ffff_0000_3333u64;
    let mut native_casb = 0x7au8;
    let mut native_cash = 0x1357u16;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = 0b0000_1111;
        g.x[2] = &mut native_ldclrb as *mut u8 as u64;
        g.x[4] = 0x0f0f;
        g.x[5] = &mut native_ldeorh as *mut u16 as u64;
        g.x[7] = 0xffff_0000_ffff_0000;
        g.x[8] = &mut native_ldset as *mut u64 as u64;
        g.x[9] = 0x7a;
        g.x[10] = 0xa5;
        g.x[11] = &mut native_casb as *mut u8 as u64;
        g.x[12] = 0xbeef;
        g.x[13] = 0x2468;
        g.x[14] = &mut native_cash as *mut u16 as u64;
    });

    const LDCLRB: u64 = 0xd000;
    const LDEORH: u64 = 0xe000;
    const LDSET: u64 = 0xf000;
    const CASB: u64 = 0x10_000;
    const CASH: u64 = 0x11_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    interp.write_memory(LDCLRB, &[0b1111_0011]).unwrap();
    interp
        .write_memory(LDEORH, &0x55aau16.to_le_bytes())
        .unwrap();
    interp
        .write_memory(LDSET, &0x0000_ffff_0000_3333u64.to_le_bytes())
        .unwrap();
    interp.write_memory(CASB, &[0x7a]).unwrap();
    interp.write_memory(CASH, &0x1357u16.to_le_bytes()).unwrap();
    interp.set_x(1, 0b0000_1111);
    interp.set_x(2, LDCLRB);
    interp.set_x(4, 0x0f0f);
    interp.set_x(5, LDEORH);
    interp.set_x(7, 0xffff_0000_ffff_0000);
    interp.set_x(8, LDSET);
    interp.set_x(9, 0x7a);
    interp.set_x(10, 0xa5);
    interp.set_x(11, CASB);
    interp.set_x(12, 0xbeef);
    interp.set_x(13, 0x2468);
    interp.set_x(14, CASH);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 6, 9, 12] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 atomic variant oracle x{reg} mismatch"
        );
    }
    assert_eq!(
        native_ldclrb,
        interp.mem_read_u8(LDCLRB).unwrap(),
        "raw EL0 ldclrb memory"
    );
    assert_eq!(
        native_ldeorh,
        interp.mem_read_u16(LDEORH).unwrap(),
        "raw EL0 ldeorh memory"
    );
    assert_eq!(
        native_ldset,
        interp.mem_read_u64(LDSET).unwrap(),
        "raw EL0 ldset memory"
    );
    assert_eq!(
        native_casb,
        interp.mem_read_u8(CASB).unwrap(),
        "raw EL0 casb memory"
    );
    assert_eq!(
        native_cash,
        interp.mem_read_u16(CASH).unwrap(),
        "raw EL0 cash memory"
    );
}

#[test]
fn raw_el0_atomic_minmax_memory_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("atomics") {
        eprintln!("[skip] host does not advertise LSE atomics");
        return;
    }

    let insns = [
        0xf820_4041, // ldsmax x0, x1, [x2]
        0xf823_50a4, // ldsmin x3, x4, [x5]
        0xf826_6107, // ldumax x6, x7, [x8]
        0xf829_716a, // ldumin x9, x10, [x11]
    ];

    let mut native_smax = (-16i64) as u64;
    let mut native_smin = 16u64;
    let mut native_umax = 0x7fff_ffff_ffff_ffffu64;
    let mut native_umin = 0x8000_0000_0000_0000u64;
    let hw = raw_native_run(&insns, |g| {
        g.x[1] = 7;
        g.x[2] = &mut native_smax as *mut u64 as u64;
        g.x[4] = (-8i64) as u64;
        g.x[5] = &mut native_smin as *mut u64 as u64;
        g.x[7] = u64::MAX;
        g.x[8] = &mut native_umax as *mut u64 as u64;
        g.x[10] = 1;
        g.x[11] = &mut native_umin as *mut u64 as u64;
    });

    const SMAX: u64 = 0x31_000;
    const SMIN: u64 = 0x32_000;
    const UMAX: u64 = 0x33_000;
    const UMIN: u64 = 0x34_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    interp
        .write_memory(PROG_BASE, &code_bytes_with_ret(&insns))
        .unwrap();
    for (addr, value) in [
        (SMAX, (-16i64) as u64),
        (SMIN, 16u64),
        (UMAX, 0x7fff_ffff_ffff_ffff),
        (UMIN, 0x8000_0000_0000_0000),
    ] {
        interp.write_memory(addr, &value.to_le_bytes()).unwrap();
    }
    interp.set_x(1, 7);
    interp.set_x(2, SMAX);
    interp.set_x(4, (-8i64) as u64);
    interp.set_x(5, SMIN);
    interp.set_x(7, u64::MAX);
    interp.set_x(8, UMAX);
    interp.set_x(10, 1);
    interp.set_x(11, UMIN);
    drive_to_done(&mut interp);

    for reg in [0u8, 3, 6, 9] {
        assert_eq!(
            hw.x[reg as usize],
            interp.get_x(reg),
            "raw EL0 atomic min/max x{reg} mismatch"
        );
    }
    assert_eq!(
        native_smax,
        interp.mem_read_u64(SMAX).unwrap(),
        "raw EL0 ldsmax memory"
    );
    assert_eq!(
        native_smin,
        interp.mem_read_u64(SMIN).unwrap(),
        "raw EL0 ldsmin memory"
    );
    assert_eq!(
        native_umax,
        interp.mem_read_u64(UMAX).unwrap(),
        "raw EL0 ldumax memory"
    );
    assert_eq!(
        native_umin,
        interp.mem_read_u64(UMIN).unwrap(),
        "raw EL0 ldumin memory"
    );
}

#[test]
fn raw_el0_sve_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0420_e3e0, // cntb x0
        0x04e3_0041, // add  z1.d, z2.d, z3.d
        0x04a6_30a4, // eor  z4.d, z5.d, z6.d
        0x0469_3107, // orr  z7.d, z8.d, z9.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[4] = 0x0000_0000_0000_0001;
        g.v[5] = 0x7fff_ffff_ffff_fff0;
        g.v[6] = 0x0000_0000_0000_0002;
        g.v[7] = 0x0000_0000_0000_0010;
        g.v[10] = 0x5555_aaaa_ffff_0000;
        g.v[11] = 0x0123_4567_89ab_cdef;
        g.v[12] = 0xffff_0000_5555_aaaa;
        g.v[13] = 0xfedc_ba98_7654_3210;
        g.v[16] = 0x0000_ffff_0000_ffff;
        g.v[17] = 0x1357_2468_ace0_bdf1;
        g.v[18] = 0xffff_0000_ffff_0000;
        g.v[19] = 0xf0f0_0f0f_aaaa_5555;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    assert_eq!(hw.x[0], interp.x[0], "raw EL0 SVE cntb");
    for reg in [1usize, 4, 7] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_unpredicated_alu_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0462_0420, // sub   z0.h, z1.h, z2.h
        0x04a5_1083, // sqadd z3.s, z4.s, z5.s
        0x0428_14e6, // uqadd z6.b, z7.b, z8.b
        0x04eb_1949, // sqsub z9.d, z10.d, z11.d
        0x046e_1dac, // uqsub z12.h, z13.h, z14.h
        0x0431_320f, // and   z15.d, z16.d, z17.d
        0x04f4_3272, // bic   z18.d, z19.d, z20.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0001_8000_7fff_ffff, 0x1234_edcc_4000_c000),
            (2, 0xffff_0001_0002_8000, 0x2222_1111_c000_4000),
            (4, 0x7fff_ffff_4000_0000, 0x8000_0000_c000_0000),
            (5, 0x0000_0001_4000_0000, 0xffff_ffff_c000_0000),
            (7, 0xf0_80_7f_01_ff_10_20_30, 0x00_fe_02_fd_80_7f_40_c0),
            (8, 0x20_90_82_ff_01_f0_e0_d0, 0xff_04_fe_08_80_02_c0_80),
            (10, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (11, 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_0001),
            (13, 0x0001_8000_7fff_ffff, 0x1234_edcc_4000_c000),
            (14, 0xffff_0001_0002_8000, 0x2222_1111_c000_4000),
            (16, 0xffff_0000_ffff_0000, 0x1234_5678_9abc_def0),
            (17, 0x0f0f_0f0f_f0f0_f0f0, 0xffff_0000_5555_aaaa),
            (19, 0xffff_0000_ffff_0000, 0x1234_5678_9abc_def0),
            (20, 0x0f0f_0f0f_f0f0_f0f0, 0xffff_0000_5555_aaaa),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE unpredicated ALU z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_immediate_integer_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2560_c0a0, // add   z0.h, z0.h, #5
        0x25a1_c0e1, // sub   z1.s, z1.s, #7
        0x25e3_c162, // subr  z2.d, z2.d, #11
        0x25a4_c023, // sqadd z3.s, z3.s, #1
        0x2565_c044, // uqadd z4.h, z4.h, #2
        0x25e6_c025, // sqsub z5.d, z5.d, #1
        0x2527_c066, // uqsub z6.b, z6.b, #3
        0x25a8_dfc7, // smax  z7.s, z7.s, #-2
        0x2569_d008, // umax  z8.h, z8.h, #128
        0x25aa_c0e9, // smin  z9.s, z9.s, #7
        0x252b_cfea, // umin  z10.b, z10.b, #127
        0x2570_dfab, // mul   z11.h, z11.h, #-3
        0x2560_e02c, // add   z12.h, z12.h, #256
        0x25a1_e04d, // sub   z13.s, z13.s, #512
        0x2564_e02e, // sqadd z14.h, z14.h, #256
        0x25a7_e02f, // uqsub z15.s, z15.s, #256
        0x2578_ffd0, // mov   z16.h, #-512
    ];
    let pack_b = |xs: [u8; 16]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 8 {
                lo |= u64::from(x) << (8 * i);
            } else {
                hi |= u64::from(x) << (8 * (i - 8));
            }
        }
        (lo, hi)
    };
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_h([0, 1, 0xfffe, 0x7fff, 0x8000, 0x1234, 0xffff, 42]),
            ),
            (1, pack_s(0, 7, 0x8000_0000, 0xffff_ffff)),
            (2, (0, 11)),
            (
                3,
                pack_s(0x7fff_ffff, 0x4000_0000, 0x8000_0000, 0xffff_ffff),
            ),
            (
                4,
                pack_h([0xfffe, 0xffff, 0x7fff, 0, 1, 0x8000, 0x1234, 0xfffd]),
            ),
            (5, (0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff)),
            (
                6,
                pack_b([
                    0, 1, 2, 3, 4, 0x7f, 0x80, 0xff, 0xfe, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                ]),
            ),
            (7, pack_s(0xffff_fffd, 0xffff_fffe, 0xffff_ffff, 0)),
            (8, pack_h([0, 1, 127, 128, 129, 0x7fff, 0x8000, 0xffff])),
            (9, pack_s(0xffff_ffff, 0, 7, 8)),
            (
                10,
                pack_b([0, 1, 126, 127, 128, 129, 0xfe, 0xff, 2, 3, 4, 5, 6, 7, 8, 9]),
            ),
            (
                11,
                pack_h([0xffff, 0xfffe, 1, 2, 0x7fff, 0x8000, 0x1234, 0xedcc]),
            ),
            (
                12,
                pack_h([0, 1, 0xff00, 0x7f00, 0x8000, 0x1234, 0xffff, 42]),
            ),
            (13, pack_s(0, 512, 0x8000_0000, 0xffff_ffff)),
            (
                14,
                pack_h([0x7fff, 0x7f00, 0x8000, 0xff00, 1, 0, 0xffff, 0x1234]),
            ),
            (15, pack_s(0, 1, 255, 256)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=16 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE immediate-integer z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_dupm_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x05c0_44e0, // dupm z0.h, #0xff00
        0x05c0_0781, // dupm z1.b, #0x55
        0x05c2_0002, // dupm z2.d, #0x1
        0x05c2_07c3, // mov  z3.d, #0x7fffffffffffffff
        0x05c0_0e05, // dupm z5.b, #0x80
        0x05c0_0006, // dupm z6.s, #0x1
        0x05c2_83e7, // mov  z7.d, #0xffff00000000ffff
    ];

    let hw = raw_native_run_fp(&insns, |_| {});
    let interp = raw_interp_run(&insns, |_| {});
    for reg in [0usize, 1, 2, 3, 5, 6, 7] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE DUPM z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_logical_immediate_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0580_04e0, // and z0.h, z0.h, #0xff
        0x0500_01e2, // orr z2.s, z2.s, #0xffff
        0x0540_81e4, // eor z4.s, z4.s, #0xffff0000
        0x0580_04e6, // and z6.h, z6.h, #0xff
        0x0500_04e8, // orr z8.h, z8.h, #0xff
        0x0540_078a, // eor z10.b, z10.b, #0x55
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210)),
            (2, (0xffff_0000_aaaa_5555, 0x1234_5678_9abc_def0)),
            (4, (0x0000_ffff_1357_2468, 0xeeee_dddd_cccc_bbbb)),
            (6, (0x7777_8888_9999_aaaa, 0xbbbb_cccc_dddd_eeee)),
            (8, (0x0102_0304_0506_0708, 0x1112_1314_1516_1718)),
            (10, (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE logical-immediate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_dup_indexed_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x053f_2020, // mov z0.b, z1.b[15]
        0x053e_2062, // mov z2.h, z3.h[7]
        0x053c_20a4, // mov z4.s, z5.s[3]
        0x0538_20e6, // mov z6.d, z7.d[1]
        0x0530_2128, // mov z8.q, q9
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)),
            (
                3,
                pack_h([
                    0x0000, 0x0001, 0x7fff, 0x8000, 0xfffe, 0xffff, 0x1234, 0xabcd,
                ]),
            ),
            (
                5,
                pack_s([0x0000_0001, 0x7fff_ffff, 0x8000_0000, 0x8765_4321]),
            ),
            (7, (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210)),
            (9, (0x8899_aabb_ccdd_eeff, 0x0011_2233_4455_6677)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE indexed DUP z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_insr_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0524_3820, // insr z0.b, w1
        0x0564_3862, // insr z2.h, w3
        0x05a4_38a4, // insr z4.s, w5
        0x05e4_38e6, // insr z6.d, x7
        0x0534_3928, // insr z8.b, b9
        0x0574_396a, // insr z10.h, h11
        0x05b4_39ac, // insr z12.s, s13
        0x05f4_39ee, // insr z14.d, d15
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x1122_3344_5566_7788;
        g.x[3] = 0x8877_6655_4433_2211;
        g.x[5] = 0xaabb_ccdd_eeff_0011;
        g.x[7] = 0x0123_4567_89ab_cdef;
        for (reg, (lo, hi)) in [
            (0usize, (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)),
            (2, (0x0003_0002_0001_0000, 0x0007_0006_0005_0004)),
            (4, (0x0000_0001_0000_0000, 0x0000_0003_0000_0002)),
            (6, (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210)),
            (8, (0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918)),
            (9, (0xaaaa_bbbb_cccc_dd99, 0)),
            (10, (0x1003_1002_1001_1000, 0x1007_1006_1005_1004)),
            (11, (0xbbbb_cccc_dddd_8877, 0)),
            (12, (0x2000_0001_2000_0000, 0x2000_0003_2000_0002)),
            (13, (0xaaaa_bbbb_ccdd_eeff, 0)),
            (14, (0x3333_4444_5555_6666, 0x7777_8888_9999_aaaa)),
            (15, (0x0123_4567_89ab_cdef, 0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE INSR z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fcpy_fdup_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e080, // ptrue p0.h, vl4
        0x2598_e041, // ptrue p1.s, vl2
        0x25d8_e022, // ptrue p2.d, vl1
        0x0550_ce00, // fmov  z0.h, p0/m, #1.0
        0x0591_dc02, // fmov  z2.s, p1/m, #-0.5
        0x05d2_d004, // fmov  z4.d, p2/m, #-2.0
        0x2579_ce06, // fmov  z6.h, #1.0
        0x25b9_dc08, // fmov  z8.s, #-0.5
        0x25f9_d00a, // fmov  z10.d, #-2.0
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, (0x1003_1002_1001_1000, 0x1007_1006_1005_1004)),
            (2, (0x2000_0001_2000_0000, 0x2000_0003_2000_0002)),
            (4, (0x3333_4444_5555_6666, 0x7777_8888_9999_aaaa)),
            (6, (0x6003_6002_6001_6000, 0x6007_6006_6005_6004)),
            (8, (0x8000_0001_8000_0000, 0x8000_0003_8000_0002)),
            (10, (0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FCPY/FDUP z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_sp_source_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x9100_03f0, // mov   x16, sp
        0x9100_003f, // mov   sp, x1
        0x2518_e100, // ptrue p0.b, vl8
        0x2558_e081, // ptrue p1.h, vl4
        0x2598_e042, // ptrue p2.s, vl2
        0x0528_a3e0, // mov   z0.b, p0/m, wsp
        0x0568_a7e2, // mov   z2.h, p1/m, wsp
        0x05a8_abe4, // mov   z4.s, p2/m, wsp
        0x0520_3be6, // mov   z6.b, wsp
        0x0560_3be8, // mov   z8.h, wsp
        0x05a0_3bea, // mov   z10.s, wsp
        0x05e0_3bec, // mov   z12.d, sp
        0x9100_021f, // mov   sp, x16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.sp = 0x0102_0304_0506_0700;
        g.x[1] = 0x1122_3344_5566_7780;
        for (reg, (lo, hi)) in [
            (0usize, (0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f)),
            (2, (0x2223_2425_2627_2829, 0x2a2b_2c2d_2e2f_3031)),
            (4, (0x4445_4647_4849_4a4b, 0x4c4d_4e4f_5051_5253)),
            (6, (0x6667_6869_6a6b_6c6d, 0x6e6f_7071_7273_7475)),
            (8, (0x8889_8a8b_8c8d_8e8f, 0x9091_9293_9495_9697)),
            (10, (0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444)),
            (12, (0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE SP-source z{reg} low-128 mismatch"
        );
    }
    assert_eq!(hw.sp, interp.sp, "raw EL0 SVE SP-source SP mismatch");
}

#[test]
fn raw_el0_sve_stack_alloc_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0421_5040, // addvl x0, x1, #2
        0x0463_57e2, // addpl x2, x3, #-1
        0x9100_03f0, // mov   x16, sp
        0x9100_009f, // mov   sp, x4
        0x043f_5025, // addvl x5, sp, #1
        0x047f_5046, // addpl x6, sp, #2
        0x043f_57ff, // addvl sp, sp, #-1
        0x9100_03e7, // mov   x7, sp
        0x9100_021f, // mov   sp, x16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.sp = 0x0102_0304_0506_0700;
        g.x[1] = 0x1000_0000_0000_0000;
        g.x[3] = 0x2000_0000_0000_0000;
        g.x[4] = 0x3000_0000_0000_1000;
    };

    let hw = raw_native_run(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 5, 6, 7] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE stack-alloc x{reg} mismatch"
        );
    }
    assert_eq!(hw.sp, interp.sp, "raw EL0 SVE stack-alloc SP mismatch");
}

#[test]
fn raw_el0_sve_count_index_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x04bf_5020, // rdvl  x0, #1
        0x0421_e3e1, // cntb  x1, all, mul #2
        0x0460_e102, // cnth  x2, vl8
        0x04a2_e083, // cntw  x3, vl4, mul #3
        0x04e0_e3e4, // cntd  x4
        0x04b0_e085, // incw  x5, vl4
        0x04f1_e3e6, // incd  x6, all, mul #2
        0x0432_e7e7, // decb  x7, all, mul #3
        0x0470_c488, // dech  z8.h, vl4
        0x04b1_c3e9, // incw  z9.s, all, mul #2
        0x04f0_c44a, // decd  z10.d, vl2
        0x04a2_43ab, // index z11.s, #-3, #2
        0x04ff_45ac, // index z12.d, x13, #-1
        0x04af_488e, // index z14.s, #4, w15
        0x04f3_4e30, // index z16.d, x17, x19
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[5] = 100;
        g.x[6] = 200;
        g.x[7] = 300;
        g.x[13] = 10;
        g.x[15] = 3;
        g.x[17] = 20;
        g.x[19] = 5;
        for (reg, (lo, hi)) in [
            (8usize, pack_h([10, 20, 30, 40, 50, 60, 70, 80])),
            (9, pack_s(1, 2, 3, 4)),
            (10, (1000, 2000)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=7 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE count/index x{reg} mismatch"
        );
    }
    for reg in [8usize, 9, 10, 11, 12, 14, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE count/index z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicate_count_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e060, // ptrue p0.s, vl3
        0x2558_e081, // ptrue p1.h, vl4
        0x25a0_8000, // cntp  x0, p0, p0.s
        0x2560_8421, // cntp  x1, p1, p1.h
        0x25ac_8802, // incp  x2, p0.s
        0x256d_8823, // decp  x3, p1.h
        0x25ac_8004, // incp  z4.s, p0.s
        0x256d_8025, // decp  z5.h, p1.h
        0x25a8_8c06, // sqincp x6, p0.s
        0x256b_8827, // uqdecp w7, p1.h
        0x25aa_8008, // sqdecp z8.s, p0.s
        0x2569_8029, // uqincp z9.h, p1.h
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[2] = 100;
        g.x[3] = 200;
        g.x[6] = i64::MAX as u64 - 1;
        g.x[7] = 2;
        for (reg, (lo, hi)) in [
            (4usize, pack_s(10, 20, 30, 40)),
            (5, pack_h([100, 200, 300, 400, 500, 600, 700, 800])),
            (8, pack_s(0x8000_0000, 1, 2, 3)),
            (9, pack_h([0xfffe, 0xffff, 1, 2, 3, 4, 5, 6])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=7 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE predicate-count x{reg} mismatch"
        );
    }
    for reg in [4usize, 5, 8, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE predicate-count z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_saturating_incp_decp_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e120, // ptrue  p0.b, vl16
        0x25d8_e041, // ptrue  p1.d, vl2
        0x2528_8c00, // sqincp x0, p0.b
        0x252a_8c01, // sqdecp x1, p0.b
        0x2529_8c02, // uqincp x2, p0.b
        0x252b_8c03, // uqdecp x3, p0.b
        0x25e8_8024, // sqincp z4.d, p1.d
        0x25ea_8025, // sqdecp z5.d, p1.d
        0x25e9_8026, // uqincp z6.d, p1.d
        0x25eb_8027, // uqdecp z7.d, p1.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = (i64::MAX - 8) as u64;
        g.x[1] = (i64::MIN + 8) as u64;
        g.x[2] = u64::MAX - 8;
        g.x[3] = 8;
        for (reg, lo, hi) in [
            (4usize, (i64::MAX - 1) as u64, i64::MIN as u64),
            (5, (i64::MIN + 1) as u64, i64::MAX as u64),
            (6, u64::MAX - 1, 0),
            (7, 1, u64::MAX),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=3 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE saturating INCP/DECP x{reg} mismatch"
        );
    }
    for reg in [4usize, 5, 6, 7] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE saturating INCP/DECP z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicate_logic_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0x2518_e101, // ptrue p1.b, vl8
        0x2518_e082, // ptrue p2.b, vl4
        0x2518_e043, // ptrue p3.b, vl2
        0x2502_4024, // and   p4.b, p0/z, p1.b, p2.b
        0x2583_4025, // orr   p5.b, p0/z, p1.b, p3.b
        0x2503_4246, // eor   p6.b, p0/z, p2.b, p3.b
        0x2503_4037, // bic   p7.b, p0/z, p1.b, p3.b
        0x2582_4038, // orn   p8.b, p0/z, p1.b, p2.b
        0x2583_4249, // nor   p9.b, p0/z, p2.b, p3.b
        0x2582_423a, // nand  p10.b, p0/z, p1.b, p2.b
        0x2542_402b, // ands  p11.b, p0/z, p1.b, p2.b
        0x2503_465c, // sel   p12.b, p1, p2.b, p3.b
        0x2520_8080, // cntp  x0, p0, p4.b
        0x2520_80a1, // cntp  x1, p0, p5.b
        0x2520_80c2, // cntp  x2, p0, p6.b
        0x2520_80e3, // cntp  x3, p0, p7.b
        0x2520_8104, // cntp  x4, p0, p8.b
        0x2520_8125, // cntp  x5, p0, p9.b
        0x2520_8146, // cntp  x6, p0, p10.b
        0x2520_8167, // cntp  x7, p0, p11.b
        0x2520_8188, // cntp  x8, p0, p12.b
    ];

    let hw = raw_native_run_fp(&insns, |_| {});
    let interp = raw_interp_run(&insns, |_| {});
    for reg in 0usize..=8 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE predicate-logic x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE predicate-logic NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_predicate_permute_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue   p0.b, vl8
        0x2558_e081, // ptrue   p1.h, vl4
        0x2500_4202, // not     p2.b, p0/z, p0.b
        0x0574_4023, // rev     p3.h, p1.h
        0x0530_4004, // punpklo p4.h, p0.b
        0x0531_4005, // punpkhi p5.h, p0.b
        0x2520_8040, // cntp    x0, p0, p2.b
        0x2560_8461, // cntp    x1, p1, p3.h
        0x2560_8482, // cntp    x2, p1, p4.h
        0x2560_84a3, // cntp    x3, p1, p5.h
    ];

    let hw = raw_native_run_fp(&insns, |_| {});
    let interp = raw_interp_run(&insns, |_| {});
    for reg in 0usize..=3 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE predicate-permute x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ffr_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e0a0, // ptrue  p0.b, vl5
        0x2518_e3e4, // ptrue  p4.b
        0x2528_9000, // wrffr  p0.b
        0x2519_f001, // rdffr  p1.b
        0x2520_9020, // cntp   x0, p4, p1.b
        0x252c_9000, // setffr
        0x2519_f002, // rdffr  p2.b
        0x2520_9041, // cntp   x1, p4, p2.b
        0x2518_e103, // ptrue  p3.b, vl8
        0x2518_f065, // rdffr  p5.b, p3/z
        0x2520_90a2, // cntp   x2, p4, p5.b
        0x2528_9000, // wrffr  p0.b
        0x2558_f066, // rdffrs p6.b, p3/z
        0x2520_90c3, // cntp   x3, p4, p6.b
    ];

    let hw = raw_native_run_fp(&insns, |_| {});
    let interp = raw_interp_run(&insns, |_| {});
    for reg in 0usize..=3 {
        assert_eq!(hw.x[reg], interp.x[reg], "raw EL0 SVE FFR x{reg} mismatch");
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE FFR NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_predicate_flag_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e080, // ptrue  p0.b, vl4
        0x2518_e041, // ptrue  p1.b, vl2
        0x2550_c020, // ptest  p0, p1.b
        0x9a9f_57e0, // cset   x0, mi
        0x9a9f_17e1, // cset   x1, eq
        0x9a9f_37e2, // cset   x2, hs
        0x9a9f_77e3, // cset   x3, vs
        0x2519_e062, // ptrues p2.b, vl3
        0x9a9f_57e4, // cset   x4, mi
        0x9a9f_17e5, // cset   x5, eq
        0x9a9f_37e6, // cset   x6, hs
        0x9a9f_77e7, // cset   x7, vs
        0xeb0a_013f, // cmp    x9, x10
        0x25ea_2120, // ctermeq x9, x10
        0x9a9f_57e8, // cset   x8, mi
        0x9a9f_17eb, // cset   x11, eq
        0x9a9f_37ec, // cset   x12, hs
        0x9a9f_77ed, // cset   x13, vs
        0x25ea_2130, // ctermne x9, x10
        0x9a9f_57ee, // cset   x14, mi
        0x9a9f_17ef, // cset   x15, eq
        0x9a9f_37f0, // cset   x16, hs
        0x9a9f_77f1, // cset   x17, vs
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[9] = 5;
        g.x[10] = 6;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE predicate-flag x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE predicate-flag final NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_predicate_break_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue  p0.b
        0x2518_e0a1, // ptrue  p1.b, vl5
        0x2518_e062, // ptrue  p2.b, vl3
        0x2510_4023, // brka   p3.b, p0/z, p1.b
        0x2590_4024, // brkb   p4.b, p0/z, p1.b
        0x2550_4025, // brkas  p5.b, p0/z, p1.b
        0x25d0_4026, // brkbs  p6.b, p0/z, p1.b
        0x2582_4047, // orr    p7.b, p0/z, p2.b, p2.b
        0x2518_4027, // brkn   p7.b, p0/z, p1.b, p7.b
        0x2520_8060, // cntp   x0, p0, p3.b
        0x2520_8081, // cntp   x1, p0, p4.b
        0x2520_80a2, // cntp   x2, p0, p5.b
        0x2520_80c3, // cntp   x3, p0, p6.b
        0x2520_80e4, // cntp   x4, p0, p7.b
        0x2582_4047, // orr    p7.b, p0/z, p2.b, p2.b
        0x2558_4027, // brkns  p7.b, p0/z, p1.b, p7.b
        0x2520_80e5, // cntp   x5, p0, p7.b
        0x2502_c028, // brkpa  p8.b, p0/z, p1.b, p2.b
        0x2502_c039, // brkpb  p9.b, p0/z, p1.b, p2.b
        0x2520_8106, // cntp   x6, p0, p8.b
        0x2520_8127, // cntp   x7, p0, p9.b
        0x2518_e405, // pfalse p5.b
        0x2558_c025, // pfirst p5.b, p1, p5.b
        0x2519_c425, // pnext  p5.b, p1, p5.b
        0x2520_80a8, // cntp   x8, p0, p5.b
        0x2538_c00c, // mov    z12.b, #0
        0x2538_c02d, // mov    z13.b, #1
        0x0400_15ac, // add    z12.b, p5/m, z12.b, z13.b
    ];

    let hw = raw_native_run_fp(&insns, |_| {});
    let interp = raw_interp_run(&insns, |_| {});
    for reg in 0usize..=8 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE predicate-break x{reg} mismatch"
        );
    }
    assert_eq!(
        (hw.v[24], hw.v[25]),
        (interp.v[24], interp.v[25]),
        "raw EL0 SVE predicate-break z12 low-128 mismatch"
    );
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE predicate-break final NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve2_while_hazard_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2522_3030, // whilerw p0.b, x1, x2
        0x9a9f_57ea, // cset    x10, mi
        0x9a9f_17eb, // cset    x11, eq
        0x9a9f_37ec, // cset    x12, hs
        0x9a9f_77ed, // cset    x13, vs
        0x2520_8000, // cntp    x0, p0, p0.b
        0x2564_3061, // whilewr p1.h, x3, x4
        0x9a9f_57ee, // cset    x14, mi
        0x9a9f_17ef, // cset    x15, eq
        0x9a9f_37f0, // cset    x16, hs
        0x9a9f_77f1, // cset    x17, vs
        0x2560_8425, // cntp    x5, p1, p1.h
        0x25a7_30c2, // whilewr p2.s, x6, x7
        0x9a9f_57f3, // cset    x19, mi
        0x9a9f_17f4, // cset    x20, eq
        0x9a9f_37f5, // cset    x21, hs
        0x9a9f_77f6, // cset    x22, vs
        0x25a0_8848, // cntp    x8, p2, p2.s
        0x25f8_32f3, // whilerw p3.d, x23, x24
        0x9a9f_57f7, // cset    x23, mi
        0x9a9f_17f8, // cset    x24, eq
        0x9a9f_37f9, // cset    x25, hs
        0x9a9f_77fa, // cset    x26, vs
        0x25e0_8c69, // cntp    x9, p3, p3.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 100;
        g.x[2] = 104;
        g.x[3] = 200;
        g.x[4] = 206;
        g.x[6] = 100;
        g.x[7] = 50;
        g.x[23] = 300;
        g.x[24] = 300;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [
        0usize, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26,
    ] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE2 WHILE hazard x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE2 WHILE hazard final NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve2_while_gt_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25a2_1030, // whilegt p0.s, x1, x2
        0x25a4_1061, // whilege p1.s, x3, x4
        0x25e6_18b2, // whilehi p2.d, x5, x6
        0x25e8_18e3, // whilehs p3.d, x7, x8
        0x2598_e3e4, // ptrue   p4.s
        0x25d8_e3e5, // ptrue   p5.d
        0x25a0_9009, // cntp    x9, p4, p0.s
        0x25a0_902a, // cntp    x10, p4, p1.s
        0x25e0_944b, // cntp    x11, p5, p2.d
        0x25e0_946c, // cntp    x12, p5, p3.d
        0x9a9f_57ed, // cset    x13, mi
        0x9a9f_17ee, // cset    x14, eq
        0x9a9f_37ef, // cset    x15, hs
        0x9a9f_77f0, // cset    x16, vs
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 10;
        g.x[2] = 6;
        g.x[3] = (-4_i64) as u64;
        g.x[4] = (-4_i64) as u64;
        g.x[5] = 0xffff_ffff_ffff_fffe;
        g.x[6] = 0xffff_ffff_ffff_fffb;
        g.x[7] = 8;
        g.x[8] = 8;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 9usize..=16 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE2 WHILEGT-family x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE2 WHILEGT-family final NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_adr_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0422_a820, // adr z0.d, [z1.d, z2.d, sxtw #2]
        0x0465_a483, // adr z3.d, [z4.d, z5.d, uxtw #1]
        0x04e8_ace6, // adr z6.d, [z7.d, z8.d, lsl #3]
        0x04ab_a949, // adr z9.s, [z10.s, z11.s, lsl #2]
    ];
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0000_0000_0000_1000, 0x0000_0001_0000_0000),
            (2, 0x0000_0000_ffff_ffff, 0x0000_0000_8000_0000),
            (4, 0x0000_0000_0000_2000, 0xffff_ffff_0000_0000),
            (5, 0xffff_ffff_ffff_fffe, 0x0000_0000_8000_0000),
            (7, 0x0000_0000_0000_3000, 0xffff_ffff_ffff_fff0),
            (8, 0x0000_0000_0000_0004, 0x0000_0000_0000_0003),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
        for (reg, (lo, hi)) in [
            (
                10usize,
                pack_s(0x1000, 0xffff_ff00, 0x8000_0000, 0x7fff_fff0),
            ),
            (11, pack_s(1, 0x10, 0x4000_0000, 0xffff_fffe)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE ADR z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_shift_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0x2598_e041, // ptrue p1.s, vl2
        0x2558_e082, // ptrue p2.h, vl4
        0x0440_87a0, // asr   z0.s, p1/m, z0.s, #3
        0x04c1_8381, // lsr   z1.d, p0/m, z1.d, #4
        0x0403_8a42, // lsl   z2.h, p2/m, z2.h, #2
        0x0444_87a3, // asrd  z3.s, p1/m, z3.s, #3
        0x047d_90e4, // asr   z4.s, z7.s, #3
        0x04fc_9505, // lsr   z5.d, z8.d, #4
        0x0432_9d26, // lsl   z6.h, z9.h, #2
        0x0490_85aa, // asr   z10.s, p1/m, z10.s, z13.s
        0x04d1_81cb, // lsr   z11.d, p0/m, z11.d, z14.d
        0x0453_89ec, // lsl   z12.h, p2/m, z12.h, z15.h
        0x0494_8670, // asrr  z16.s, p1/m, z16.s, z19.s
        0x0495_8691, // lsrr  z17.s, p1/m, z17.s, z20.s
        0x0497_86b2, // lslr  z18.s, p1/m, z18.s, z21.s
        0x0498_8736, // asr   z22.s, p1/m, z22.s, z25.d
        0x0459_8b57, // lsr   z23.h, p2/m, z23.h, z26.d
        0x041b_8378, // lsl   z24.b, p0/m, z24.b, z27.d
        0x04b9_839c, // asr   z28.s, z28.s, z25.d
        0x047a_87bd, // lsr   z29.h, z29.h, z26.d
        0x043b_8fde, // lsl   z30.b, z30.b, z27.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x7fff_ffff_8000_0000, 0xffff_fff0_0000_0010),
            (1, 0x8000_0000_0000_0000, 0x0000_0000_0000_0100),
            (2, 0x7fff_8000_4000_0001, 0xffff_0001_00ff_ff00),
            (3, 0x7fff_ffff_8000_0000, 0xffff_fff0_0000_0010),
            (7, 0xffff_fff8_8000_0000, 0x0000_0040_7fff_ffff),
            (8, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (9, 0x0001_8000_4000_7fff, 0xffff_00ff_0100_ff00),
            (10, 0x7fff_ffff_8000_0000, 0x2222_2222_1111_1111),
            (11, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (12, 0x0001_8000_4000_7fff, 0xffff_00ff_0100_ff00),
            (13, 0x0000_001f_0000_0001, 0x0000_0021_0000_0004),
            (14, 0x0000_0000_0000_0004, 0x0000_0000_0000_0041),
            (15, 0x0004_0010_0003_0001, 0x0001_0008_000f_0002),
            (16, 0x0000_001f_0000_0001, 0x2222_2222_1111_1111),
            (17, 0x0000_0020_0000_0004, 0x4444_4444_3333_3333),
            (18, 0x0000_0020_0000_0001, 0x6666_6666_5555_5555),
            (19, 0x7fff_ffff_8000_0000, 0xffff_fff0_0000_0010),
            (20, 0xffff_ffff_8000_0000, 0x0000_0010_7fff_ffff),
            (21, 0x0000_0002_4000_0000, 0x0000_0001_8000_0000),
            (22, 0x7fff_ffff_8000_0000, 0x2222_2222_1111_1111),
            (23, 0x0001_8000_4000_7fff, 0xffff_00ff_0100_ff00),
            (24, 0x817f_4020_1008_0401, 0xff80_7e3f_1f0f_0703),
            (25, 0x0000_0000_0000_0003, 0x0000_0000_0000_0021),
            (26, 0x0000_0000_0000_0004, 0x0000_0000_0000_0011),
            (27, 0x0000_0000_0000_0001, 0x0000_0000_0000_0009),
            (28, 0x7fff_ffff_8000_0000, 0xffff_fff0_0000_0010),
            (29, 0x0001_8000_4000_7fff, 0xffff_00ff_0100_ff00),
            (30, 0x817f_4020_1008_0401, 0xff80_7e3f_1f0f_0703),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [
        0usize, 1, 2, 3, 4, 5, 6, 10, 11, 12, 16, 17, 18, 22, 23, 24, 28, 29, 30,
    ] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE shift z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_rev_rbit_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0x2558_e081, // ptrue p1.h, vl4
        0x2598_e042, // ptrue p2.s, vl2
        0x25d8_e023, // ptrue p3.d, vl1
        0x0527_8020, // rbit  z0.b, p0/m, z1.b
        0x0564_8462, // revb  z2.h, p1/m, z3.h
        0x05a5_88a4, // revh  z4.s, p2/m, z5.s
        0x05e6_8ce6, // revw  z6.d, p3/m, z7.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, (0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f)),
            (1, (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)),
            (2, (0x2223_2425_2627_2829, 0x2a2b_2c2d_2e2f_3031)),
            (3, (0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00)),
            (4, (0x4445_4647_4849_4a4b, 0x4c4d_4e4f_5051_5253)),
            (5, (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210)),
            (6, (0x6667_6869_6a6b_6c6d, 0x6e6f_7071_7273_7475)),
            (7, (0x0011_2233_4455_6677, 0x8899_aabb_ccdd_eeff)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE REV/RBIT z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicated_unary_integer_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x25d8_e021, // ptrue p1.d, vl1
        0x0490_a020, // sxtb  z0.s, p0/m, z1.s
        0x0491_a062, // uxtb  z2.s, p0/m, z3.s
        0x0492_a0a4, // sxth  z4.s, p0/m, z5.s
        0x04d3_a4e6, // uxth  z6.d, p1/m, z7.d
        0x04d4_a528, // sxtw  z8.d, p1/m, z9.d
        0x04d5_a56a, // uxtw  z10.d, p1/m, z11.d
        0x0498_a1ac, // cls   z12.s, p0/m, z13.s
        0x0499_a1ee, // clz   z14.s, p0/m, z15.s
        0x049a_a230, // cnt   z16.s, p0/m, z17.s
        0x04db_a672, // cnot  z18.d, p1/m, z19.d
        0x041e_a2b4, // not   z20.b, p0/m, z21.b
    ];
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_s([0xaaaa_0000, 0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003]),
            ),
            (
                1,
                pack_s([0x0000_0080, 0x0000_007f, 0x0000_00ff, 0x0000_0001]),
            ),
            (
                2,
                pack_s([0xbbbb_0000, 0xbbbb_0001, 0xbbbb_0002, 0xbbbb_0003]),
            ),
            (
                3,
                pack_s([0x0000_0080, 0x0000_00ff, 0x0000_007f, 0x0000_0001]),
            ),
            (
                4,
                pack_s([0xcccc_0000, 0xcccc_0001, 0xcccc_0002, 0xcccc_0003]),
            ),
            (
                5,
                pack_s([0x0000_8000, 0x0000_7fff, 0x0000_ffff, 0x0000_0001]),
            ),
            (6, (0x6666_0000_6666_0001, 0x6666_0002_6666_0003)),
            (7, (0x0000_0000_0000_ffff, 0x0000_0000_0000_8000)),
            (8, (0x8888_0000_8888_0001, 0x8888_0002_8888_0003)),
            (9, (0x0000_0000_8000_0000, 0x0000_0000_7fff_ffff)),
            (10, (0xaaaa_0000_aaaa_0001, 0xaaaa_0002_aaaa_0003)),
            (11, (0x0000_0000_8000_0000, 0x0000_0000_ffff_ffff)),
            (
                12,
                pack_s([0x1212_0000, 0x1212_0001, 0x1212_0002, 0x1212_0003]),
            ),
            (
                13,
                pack_s([0x0000_0000, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]),
            ),
            (
                14,
                pack_s([0x1414_0000, 0x1414_0001, 0x1414_0002, 0x1414_0003]),
            ),
            (
                15,
                pack_s([0x0000_0000, 0x0000_0001, 0x8000_0000, 0xffff_ffff]),
            ),
            (
                16,
                pack_s([0x1616_0000, 0x1616_0001, 0x1616_0002, 0x1616_0003]),
            ),
            (
                17,
                pack_s([0x0000_0000, 0xffff_ffff, 0x1234_5678, 0x8000_0001]),
            ),
            (18, (0x1818_0000_1818_0001, 0x1818_0002_1818_0003)),
            (19, (0x0000_0000_0000_0000, 0xffff_ffff_ffff_ffff)),
            (20, (0x2021_2223_2425_2627, 0x2829_2a2b_2c2d_2e2f)),
            (21, (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE predicated unary integer z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicated_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e020, // ptrue p0.d, vl1
        0x25f8_c020, // mov   z0.d, #1
        0x04c0_0020, // add   z0.d, p0/m, z0.d, z1.d
        0x04c1_0062, // sub   z2.d, p0/m, z2.d, z3.d
        0x04da_00a4, // and   z4.d, p0/m, z4.d, z5.d
        0x04d8_00e6, // orr   z6.d, p0/m, z6.d, z7.d
        0x04d9_0128, // eor   z8.d, p0/m, z8.d, z9.d
        0x04d0_816a, // asr   z10.d, p0/m, z10.d, z11.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x0000_0000_0000_0004;
        g.v[3] = 0x0000_0000_0000_0008;
        g.v[4] = 0x0100_0000_0000_0000;
        g.v[5] = 0x8000_0000_0000_0000;
        g.v[6] = 0x0000_0000_0000_0001;
        g.v[7] = 0x0000_0000_0000_0002;
        g.v[8] = 0xff00_ff00_ff00_ff00;
        g.v[9] = 0x0f0f_0f0f_0f0f_0f0f;
        g.v[10] = 0x00ff_00ff_00ff_00ff;
        g.v[11] = 0xf0f0_f0f0_f0f0_f0f0;
        g.v[12] = 0x0000_ffff_0000_ffff;
        g.v[13] = 0x1111_2222_3333_4444;
        g.v[14] = 0xffff_0000_ffff_0000;
        g.v[15] = 0xaaaa_5555_aaaa_5555;
        g.v[16] = 0x1234_5678_9abc_def0;
        g.v[17] = 0x0fed_cba9_8765_4321;
        g.v[18] = 0xffff_0000_5555_aaaa;
        g.v[19] = 0x3333_cccc_7777_8888;
        g.v[20] = 0x8000_0000_0000_0000;
        g.v[21] = 0xffff_ffff_ffff_ff00;
        g.v[22] = 1;
        g.v[23] = 8;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE predicated z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicated_alu_extra_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e060, // ptrue p0.s, vl3
        0x0488_0020, // smax  z0.s, p0/m, z0.s, z1.s
        0x0489_0062, // umax  z2.s, p0/m, z2.s, z3.s
        0x048a_00a4, // smin  z4.s, p0/m, z4.s, z5.s
        0x048b_00e6, // umin  z6.s, p0/m, z6.s, z7.s
        0x048c_0128, // sabd  z8.s, p0/m, z8.s, z9.s
        0x048d_016a, // uabd  z10.s, p0/m, z10.s, z11.s
        0x0490_01ac, // mul   z12.s, p0/m, z12.s, z13.s
        0x0492_01ee, // smulh z14.s, p0/m, z14.s, z15.s
        0x0493_0230, // umulh z16.s, p0/m, z16.s, z17.s
        0x0494_0272, // sdiv  z18.s, p0/m, z18.s, z19.s
        0x0495_02b4, // udiv  z20.s, p0/m, z20.s, z21.s
        0x0496_02f6, // sdivr z22.s, p0/m, z22.s, z23.s
        0x0497_0338, // udivr z24.s, p0/m, z24.s, z25.s
    ];
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let sx = |x: i32| -> u32 { x as u32 };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(sx(-5), sx(100), sx(-1), 0x1111_1111)),
            (1, pack_s(sx(3), sx(-200), sx(0), 0x2222_2222)),
            (2, pack_s(1, 0xffff_fffe, 0x7fff_ffff, 0x3333_3333)),
            (3, pack_s(2, 3, 0x8000_0000, 0x4444_4444)),
            (4, pack_s(sx(-5), sx(100), sx(-1), 0x5555_5555)),
            (5, pack_s(sx(3), sx(-200), sx(0), 0x6666_6666)),
            (6, pack_s(1, 0xffff_fffe, 0x7fff_ffff, 0x7777_7777)),
            (7, pack_s(2, 3, 0x8000_0000, 0x8888_8888)),
            (8, pack_s(sx(-100), sx(50), sx(-2_000_000_000), 0x9999_9999)),
            (9, pack_s(sx(25), sx(-50), sx(1_000_000_000), 0xaaaa_aaaa)),
            (10, pack_s(1, 0xffff_ffff, 100, 0xbbbb_bbbb)),
            (11, pack_s(2, 0, 200, 0xcccc_cccc)),
            (12, pack_s(0x4000_0000, 3, 0xffff_ffff, 0xdddd_dddd)),
            (13, pack_s(4, 0x8000_0000, 5, 0xeeee_eeee)),
            (
                14,
                pack_s(sx(-2), sx(0x4000_0000), sx(-123_456_789), 0x1357_9bdf),
            ),
            (15, pack_s(sx(3), sx(4), sx(987_654_321), 0x2468_ace0)),
            (
                16,
                pack_s(0xffff_ffff, 0x8000_0000, 0x1234_5678, 0x1122_3344),
            ),
            (17, pack_s(2, 4, 0x9abc_def0, 0x5566_7788)),
            (18, pack_s(sx(-9), sx(42), sx(-2_147_483_648), 0x1111_2222)),
            (19, pack_s(sx(2), sx(0), sx(-1), 0x3333_4444)),
            (20, pack_s(100, 42, 0xffff_ffff, 0x5555_6666)),
            (21, pack_s(3, 0, 2, 0x7777_8888)),
            (22, pack_s(sx(2), sx(0), sx(-1), 0x9999_aaaa)),
            (23, pack_s(sx(-9), sx(42), sx(-2_147_483_648), 0xbbbb_cccc)),
            (24, pack_s(3, 0, 2, 0xdddd_eeee)),
            (25, pack_s(100, 42, 0xffff_ffff, 0xffff_0000)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE predicated ALU-extra z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_sel_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue p0.b, vl8
        0x0522_c020, // sel   z0.b, p0, z1.b, z2.b
        0x2558_e081, // ptrue p1.h, vl4
        0x0565_c483, // sel   z3.h, p1, z4.h, z5.h
        0x2598_e042, // ptrue p2.s, vl2
        0x05a8_c8e6, // sel   z6.s, p2, z7.s, z8.s
        0x25d8_e023, // ptrue p3.d, vl1
        0x05eb_cd49, // sel   z9.d, p3, z10.d, z11.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, (0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f)),
            (2, (0x8081_8283_8485_8687, 0x8889_8a8b_8c8d_8e8f)),
            (4, (0x1001_1002_1003_1004, 0x1005_1006_1007_1008)),
            (5, (0x9001_9002_9003_9004, 0x9005_9006_9007_9008)),
            (7, (0x0000_0001_0000_0002, 0x0000_0003_0000_0004)),
            (8, (0x8000_0001_8000_0002, 0x8000_0003_8000_0004)),
            (10, (0x0102_0304_0506_0708, 0x1112_1314_1516_1718)),
            (11, (0x8182_8384_8586_8788, 0x9192_9394_9596_9798)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE SEL z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_data_movement_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e060, // ptrue   p0.s, vl3
        0x05a1_8020, // compact z0.s, p0, z1.s
        0x05ac_8062, // splice  z2.s, p0, z2.s, z3.s
        0x05a8_a0a4, // mov     z4.s, p0/m, w5
        0x05a0_80e6, // mov     z6.s, p0/m, s7
        0x0590_0548, // mov     z8.s, p0/z, #42
        0x05a0_a149, // lasta   w9, p0, z10.s
        0x05a1_a18b, // lastb   w11, p0, z12.s
        0x05a2_81cd, // lasta   s13, p0, z14.s
        0x05a3_820f, // lastb   s15, p0, z16.s
    ];
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[5] = 0x1234_5678;
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_s(0xaaaa_0000, 0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003),
            ),
            (
                1,
                pack_s(0x1111_0000, 0x1111_0001, 0x1111_0002, 0x1111_0003),
            ),
            (
                2,
                pack_s(0x2222_0000, 0x2222_0001, 0x2222_0002, 0x2222_0003),
            ),
            (
                3,
                pack_s(0x3333_0000, 0x3333_0001, 0x3333_0002, 0x3333_0003),
            ),
            (
                4,
                pack_s(0x4444_0000, 0x4444_0001, 0x4444_0002, 0x4444_0003),
            ),
            (
                6,
                pack_s(0x6666_0000, 0x6666_0001, 0x6666_0002, 0x6666_0003),
            ),
            (7, pack_s(0x7777_1234, 0, 0, 0)),
            (
                8,
                pack_s(0x8888_0000, 0x8888_0001, 0x8888_0002, 0x8888_0003),
            ),
            (
                10,
                pack_s(0x1010_0000, 0x1010_0001, 0x1010_0002, 0x1010_0003),
            ),
            (
                12,
                pack_s(0x1212_0000, 0x1212_0001, 0x1212_0002, 0x1212_0003),
            ),
            (13, pack_s(0xdddd_0000, 0, 0, 0)),
            (
                14,
                pack_s(0x1414_0000, 0x1414_0001, 0x1414_0002, 0x1414_0003),
            ),
            (15, pack_s(0xffff_0000, 0, 0, 0)),
            (
                16,
                pack_s(0x1616_0000, 0x1616_0001, 0x1616_0002, 0x1616_0003),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 13, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE data movement z{reg} low-128 mismatch"
        );
    }
    for reg in [9usize, 11] {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE data movement x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_movprfx_prefix_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue   p0.b, vl8
        0x0411_2020, // movprfx z0.b, p0/m, z1.b
        0x0400_0040, // add     z0.b, p0/m, z0.b, z2.b
        0x2558_e081, // ptrue   p1.h, vl4
        0x0450_2483, // movprfx z3.h, p1/z, z4.h
        0x0441_04a3, // sub     z3.h, p1/m, z3.h, z5.h
        0x25d8_e022, // ptrue   p2.d, vl1
        0x04d1_28e6, // movprfx z6.d, p2/m, z7.d
        0x04d0_0906, // mul     z6.d, p2/m, z6.d, z8.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, (0x8081_8283_8485_8687, 0x8889_8a8b_8c8d_8e8f)),
            (1, (0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f)),
            (2, (0x1010_1010_1010_1010, 0x2020_2020_2020_2020)),
            (3, (0x3001_3002_3003_3004, 0x3005_3006_3007_3008)),
            (4, (0x4010_4020_4030_4040, 0x4050_4060_4070_4080)),
            (5, (0x0001_0002_0003_0004, 0x0005_0006_0007_0008)),
            (6, (0x6000_0000_0000_0003, 0x6000_0000_0000_0005)),
            (7, (0x0000_0000_0000_0011, 0x0000_0000_0000_0013)),
            (8, (0x0000_0000_0000_0007, 0x0000_0000_0000_000b)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE MOVPRFX prefix z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_cpy_dup_variants_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue p0.b, vl8
        0x2558_e081, // ptrue p1.h, vl4
        0x25d8_e022, // ptrue p2.d, vl1
        0x0528_a020, // mov   z0.b, p0/m, w1
        0x0568_a462, // mov   z2.h, p1/m, w3
        0x05e8_a8a4, // mov   z4.d, p2/m, x5
        0x0520_80e6, // mov   z6.b, p0/m, b7
        0x0560_8528, // mov   z8.h, p1/m, h9
        0x05e0_896a, // mov   z10.d, p2/m, d11
        0x0510_054c, // mov   z12.b, p0/z, #42
        0x0551_5f2e, // mov   z14.h, p1/m, #-7
        0x25f8_c550, // mov   z16.d, #42
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0x1122_3344_5566_7788;
        g.x[3] = 0x8877_6655_4433_2211;
        g.x[5] = 0x0123_4567_89ab_cdef;
        for (reg, (lo, hi)) in [
            (0usize, (0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f)),
            (2, (0x2223_2425_2627_2829, 0x2a2b_2c2d_2e2f_3031)),
            (4, (0x4445_4647_4849_4a4b, 0x4c4d_4e4f_5051_5253)),
            (6, (0x6667_6869_6a6b_6c6d, 0x6e6f_7071_7273_7475)),
            (7, (0xaaaa_bbbb_cccc_dd99, 0)),
            (8, (0x8889_8a8b_8c8d_8e8f, 0x9091_9293_9495_9697)),
            (9, (0xbbbb_cccc_dddd_8877, 0)),
            (10, (0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444)),
            (11, (0x0123_4567_89ab_cdef, 0)),
            (12, (0x1213_1415_1617_1819, 0x1a1b_1c1d_1e1f_2021)),
            (14, (0x1415_1617_1819_1a1b, 0x1c1d_1e1f_2021_2223)),
            (16, (0x1617_1819_1a1b_1c1d, 0x1e1f_2021_2223_2425)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE CPY/DUP variants z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_unpk_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0570_3820, // sunpklo z0.h, z1.b
        0x0571_3862, // sunpkhi z2.h, z3.b
        0x05b2_38a4, // uunpklo z4.s, z5.h
        0x05b3_38e6, // uunpkhi z6.s, z7.h
        0x05f0_3928, // sunpklo z8.d, z9.s
        0x05f3_396a, // uunpkhi z10.d, z11.s
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, (0x807f_00ff_8001_7ffe, 0x8000_7fff_ffff_0001)),
            (3, (0x55aa_aa55_0f0f_f0f0, 0x33cc_cc33_ff00_00ff)),
            (
                5,
                pack_h([
                    0x0000, 0xffff, 0x8000, 0x7fff, 0x0001, 0x00ff, 0xff00, 0x1234,
                ]),
            ),
            (
                7,
                pack_h([
                    0xabcd, 0x0102, 0xfedc, 0x8001, 0x7ffe, 0xffff, 0x0000, 0x1357,
                ]),
            ),
            (
                9,
                pack_s([0x8000_0000, 0x7fff_ffff, 0xffff_ffff, 0x0000_0001]),
            ),
            (
                11,
                pack_s([0x1234_5678, 0xffff_0000, 0x0000_ffff, 0x8765_4321]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE UNPK z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_clast_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e400, // pfalse p0.b
        0x2598_e041, // ptrue  p1.s, vl2
        0x05b0_a020, // clasta w0, p0, w0, z1.s
        0x05b1_a062, // clastb w2, p0, w2, z3.s
        0x05b0_a4a4, // clasta w4, p1, w4, z5.s
        0x05b1_a4e6, // clastb w6, p1, w6, z7.s
        0x05aa_8128, // clasta s8, p0, s8, z9.s
        0x05ab_856a, // clastb s10, p1, s10, z11.s
    ];
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[0] = 0xaaaa_bbbb_cccc_dddd;
        g.x[2] = 0x1111_2222_3333_4444;
        g.x[4] = 0x5555_6666_7777_8888;
        g.x[6] = 0x9999_aaaa_bbbb_cccc;
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_s(0x1010_0000, 0x1010_0001, 0x1010_0002, 0x1010_0003),
            ),
            (
                3,
                pack_s(0x3030_0000, 0x3030_0001, 0x3030_0002, 0x3030_0003),
            ),
            (
                5,
                pack_s(0x5050_0000, 0x5050_0001, 0x5050_0002, 0x5050_0003),
            ),
            (
                7,
                pack_s(0x7070_0000, 0x7070_0001, 0x7070_0002, 0x7070_0003),
            ),
            (8, (0x8888_0000, 0x8888_1111_8888_2222)),
            (
                9,
                pack_s(0x9090_0000, 0x9090_0001, 0x9090_0002, 0x9090_0003),
            ),
            (10, (0xaaaa_0000, 0xaaaa_1111_aaaa_2222)),
            (
                11,
                pack_s(0xb0b0_0000, 0xb0b0_0001, 0xb0b0_0002, 0xb0b0_0003),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        assert_eq!(hw.x[reg], interp.x[reg], "raw EL0 SVE CLAST x{reg}");
    }
    for reg in [8usize, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE CLAST z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_predicate_generation_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25e2_1c20, // whilelo p0.d, x1, x2
        0x25e4_1c71, // whilels p1.d, x3, x4
        0x25d8_e3e2, // ptrue   p2.d
        0x24c7_a8c3, // cmpeq   p3.d, p2/z, z6.d, z7.d
        0x24c9_8914, // cmpgt   p4.d, p2/z, z8.d, z9.d
        0x24cb_8945, // cmpge   p5.d, p2/z, z10.d, z11.d
        0x24cd_a996, // cmpne   p6.d, p2/z, z12.d, z13.d
        0x04c0_0020, // add     z0.d, p0/m, z0.d, z1.d
        0x04c0_0462, // add     z2.d, p1/m, z2.d, z3.d
        0x04c0_0ca4, // add     z4.d, p3/m, z4.d, z5.d
        0x04c0_11ee, // add     z14.d, p4/m, z14.d, z15.d
        0x04c0_1630, // add     z16.d, p5/m, z16.d, z17.d
        0x04c0_1a72, // add     z18.d, p6/m, z18.d, z19.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.x[1] = 0;
        g.x[2] = 1;
        g.x[3] = 0;
        g.x[4] = 0;

        for (reg, lo, hi) in [
            (0usize, 10, 100),
            (1, 1, 1000),
            (2, 20, 200),
            (3, 2, 2000),
            (4, 30, 300),
            (5, 3, 3000),
            (6, 5, 6),
            (7, 5, 7),
            (8, 10, u64::MAX),
            (9, 5, 1),
            (10, 9, 0),
            (11, 9, 1),
            (12, 12, 13),
            (13, 12, 14),
            (14, 40, 400),
            (15, 4, 4000),
            (16, 50, 500),
            (17, 5, 5000),
            (18, 60, 600),
            (19, 6, 6000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE predicate-generation z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_compare_register_widths_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e0, // ptrue p0.b
        0x2403_0051, // cmphi p1.b, p0/z, z2.b, z3.b
        0x2520_8020, // cntp  x0, p0, p1.b
        0x2445_8092, // cmpgt p2.h, p0/z, z4.h, z5.h
        0x2560_8041, // cntp  x1, p0, p2.h
        0x2487_80c3, // cmpge p3.s, p0/z, z6.s, z7.s
        0x25a0_8062, // cntp  x2, p0, p3.s
        0x24c9_a114, // cmpne p4.d, p0/z, z8.d, z9.d
        0x25e0_8083, // cntp  x3, p0, p4.d
    ];
    let pack_b = |xs: [u8; 16]| -> (u64, u64) {
        let value = u128::from_le_bytes(xs);
        (value as u64, (value >> 64) as u64)
    };
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: u32, b: u32, c: u32, d: u32| -> (u64, u64) {
        let lo = u64::from(a) | (u64::from(b) << 32);
        let hi = u64::from(c) | (u64::from(d) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                2usize,
                pack_b([5, 4, 3, 2, 1, 0, 255, 128, 127, 1, 2, 3, 4, 5, 6, 7]),
            ),
            (
                3,
                pack_b([4, 4, 4, 1, 2, 0, 254, 129, 126, 2, 1, 3, 5, 4, 6, 8]),
            ),
            (4, pack_h([5, 4, 0x8000, 0x7fff, 1, 0xffff, 0, 100])),
            (5, pack_h([4, 4, 0x7fff, 0x8000, 2, 1, 0xffff, 99])),
            (6, pack_s(5, 0x8000_0000, 0x7fff_ffff, 0xffff_ffff)),
            (7, pack_s(4, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff)),
            (8, (0, 0x0123_4567_89ab_cdef)),
            (9, (0, 0xfedc_ba98_7654_3210)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=3 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE compare-register-width x{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_compare_immediate_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e3e0, // ptrue p0.h
        0x2598_e3e1, // ptrue p1.s
        0x25d8_e3e2, // ptrue p2.d
        0x258f_0493, // cmpgt p3.s, p1/z, z4.s, #15
        0x25c0_88a4, // cmpeq p4.d, p2/z, z5.d, #0
        0x247f_c0d5, // cmphi p5.h, p0/z, z6.h, #127
        0x2470_20e6, // cmplo p6.h, p0/z, z7.h, #64
        0x25a0_8460, // cntp  x0, p1, p3.s
        0x25e0_8881, // cntp  x1, p2, p4.d
        0x2560_80a2, // cntp  x2, p0, p5.h
        0x2560_80c3, // cntp  x3, p0, p6.h
        0x9a9f_57e4, // cset  x4, mi
        0x9a9f_17e5, // cset  x5, eq
        0x9a9f_37e6, // cset  x6, hs
        0x9a9f_77e7, // cset  x7, vs
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (4usize, pack_s([0, 15, 16, 0xffff_ffff])),
            (5, (0, 1)),
            (6, pack_h([0, 1, 126, 127, 128, 129, 0xfffe, 0xffff])),
            (7, pack_h([0, 1, 63, 64, 65, 127, 128, 0xffff])),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=7 {
        assert_eq!(
            hw.x[reg], interp.x[reg],
            "raw EL0 SVE compare-immediate x{reg} mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE compare-immediate final NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_fp_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x6580_8020, // fadd  z0.s, p0/m, z0.s, z1.s
        0x6581_8062, // fsub  z2.s, p0/m, z2.s, z3.s
        0x6582_80a4, // fmul  z4.s, p0/m, z4.s, z5.s
        0x658d_80e6, // fdiv  z6.s, p0/m, z6.s, z7.s
        0x6586_8128, // fmax  z8.s, p0/m, z8.s, z9.s
        0x6585_816a, // fminnm z10.s, p0/m, z10.s, z11.s
        0x049c_a18c, // fabs  z12.s, p0/m, z12.s
        0x049d_a1ce, // fneg  z14.s, p0/m, z14.s
        0x658d_a210, // fsqrt z16.s, p0/m, z16.s
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack(1.0, -2.0, 3.0, -4.0)),
            (1, pack(0.5, 1.0, -1.5, 2.0)),
            (2, pack(8.0, -8.0, 4.0, -4.0)),
            (3, pack(1.0, 2.0, -3.0, -4.0)),
            (4, pack(2.0, -3.0, 4.0, -5.0)),
            (5, pack(0.5, 2.0, -1.0, -2.0)),
            (6, pack(9.0, -8.0, 6.0, -4.0)),
            (7, pack(3.0, 2.0, -2.0, -2.0)),
            (8, pack(1.0, -9.0, 5.0, -7.0)),
            (9, pack(2.0, -10.0, 4.0, -6.0)),
            (10, pack(1.0, -9.0, 5.0, -7.0)),
            (11, pack(2.0, -10.0, 4.0, -6.0)),
            (12, pack(-1.0, 2.0, -3.0, 4.0)),
            (14, pack(1.0, -2.0, 3.0, -4.0)),
            (16, pack(4.0, 9.0, 16.0, 25.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_predicated_extra_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue  p0.s, vl2
        0x6583_8020, // fsubr  z0.s, p0/m, z0.s, z1.s
        0x6588_8062, // fabd   z2.s, p0/m, z2.s, z3.s
        0x658a_80a4, // fmulx  z4.s, p0/m, z4.s, z5.s
        0x658c_80e6, // fdivr  z6.s, p0/m, z6.s, z7.s
        0x6589_8128, // fscale z8.s, p0/m, z8.s, z9.s
        0x6598_800a, // fadd   z10.s, p0/m, z10.s, #0.5
        0x659b_802b, // fsubr  z11.s, p0/m, z11.s, #1.0
        0x659e_800c, // fmax   z12.s, p0/m, z12.s, #0.0
        0x659d_802d, // fminnm z13.s, p0/m, z13.s, #1.0
        0x25d8_e021, // ptrue  p1.d, vl1
        0x65c9_85ee, // fscale z14.d, p1/m, z14.d, z15.d
        0x65cc_8630, // fdivr  z16.d, p1/m, z16.d, z17.d
        0x65ca_8672, // fmulx  z18.d, p1/m, z18.d, z19.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let pack_d_bits = |a: u64, b: u64| -> (u64, u64) { (a, b) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(8.0, -4.0, 30.0, -40.0)),
            (1, pack_s(2.0, -10.0, 300.0, -400.0)),
            (2, pack_s(5.0, -6.0, 31.0, -41.0)),
            (3, pack_s(2.0, -10.0, 301.0, -401.0)),
            (4, pack_s(1.5, -2.0, 32.0, -42.0)),
            (5, pack_s(4.0, -0.5, 302.0, -402.0)),
            (6, pack_s(8.0, -4.0, 33.0, -43.0)),
            (7, pack_s(2.0, -20.0, 303.0, -403.0)),
            (8, pack_s(1.5, -4.0, 34.0, -44.0)),
            (9, pack_s_bits([1, u32::MAX, 2, u32::MAX - 1])),
            (10, pack_s(1.0, -2.0, 35.0, -45.0)),
            (11, pack_s(0.25, -3.0, 36.0, -46.0)),
            (12, pack_s(-1.0, 2.0, 37.0, -47.0)),
            (13, pack_s(0.25, 2.0, 38.0, -48.0)),
            (14, pack_d(1.5, -4.0)),
            (15, pack_d_bits(2, u64::MAX)),
            (16, pack_d(8.0, -40.0)),
            (17, pack_d(2.0, -20.0)),
            (18, pack_d(1.5, -42.0)),
            (19, pack_d(4.0, -0.5)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 11, 12, 13, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP predicated-extra z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fscale_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue  p0.s
        0x6589_8020, // fscale z0.s, p0/m, z0.s, z1.s
        0x25d8_e3e1, // ptrue  p1.d
        0x65c9_85ee, // fscale z14.d, p1/m, z14.d, z15.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let pack_d_bits = |a: u64, b: u64| -> (u64, u64) { (a, b) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_s(1.0, -1.0, 1.0, -1.0)),
                (1, pack_s_bits([200, -200i32 as u32, 149, -149i32 as u32])),
                (14, pack_d(1.0, -1.0)),
                (15, pack_d_bits(1100, -1100i64 as u64)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 14] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE FSCALE FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FSCALE FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fscale_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "s_subnormal",
            [0x2598_e3e0, 0x6589_8020],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
            0,
            0,
        ),
        (
            "d_subnormal",
            [0x25d8_e3e0, 0x65c9_8020],
            0x0000_0000_0000_0001,
            0x3ff0_0000_0000_0000,
            0,
            0,
        ),
        (
            "s_mixed_nan_subnormal",
            [0x2598_e3e0, 0x6589_8020],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
    ];

    for (label, insns, zdn_lo, zdn_hi, zm_lo, zm_hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = zdn_lo;
            g.v[1] = zdn_hi;
            g.v[2] = zm_lo;
            g.v[3] = zm_hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH fscale {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH fscale {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_frint_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue  p0.s
        0x6586_a020, // frintx z0.s, p0/m, z1.s
        0x6587_a062, // frinti z2.s, p0/m, z3.s
        0x25d8_e3e1, // ptrue  p1.d
        0x65c6_a4a4, // frintx z4.d, p1/m, z5.d
        0x65c7_a4e6, // frinti z6.d, p1/m, z7.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
                (1, pack_s(-1.5, -0.5, 0.5, 1.5)),
                (2, pack_s(101.0, 201.0, 301.0, 401.0)),
                (3, pack_s(-1.5, -0.5, 0.5, 1.5)),
                (4, pack_d(1000.0, 2000.0)),
                (5, pack_d(-1.5, 1.5)),
                (6, pack_d(1001.0, 2001.0)),
                (7, pack_d(-1.5, 1.5)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2, 4, 6] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE FRINT FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FRINT FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fsqrt_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x658d_a020, // fsqrt z0.s, p0/m, z1.s
        0x25d8_e3e1, // ptrue p1.d
        0x65cd_a462, // fsqrt z2.d, p1/m, z3.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
                (1, pack_s(2.0, 3.0, 5.0, 7.0)),
                (2, pack_d(1000.0, 2000.0)),
                (3, pack_d(2.0, 3.0)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE FSQRT FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FSQRT FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fsqrt_ah_negative_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "h",
            0x654d_a020,
            0x8001_8001_8001_8001,
            0x8001_8001_8001_8001,
        ),
        (
            "s",
            0x658d_a020,
            0x8000_0001_8000_0001,
            0x8000_0001_8000_0001,
        ),
        (
            "d",
            0x65cd_a020,
            0x8000_0000_0000_0001,
            0x8000_0000_0000_0001,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.fpsr = 0;
        };
        let insns = [0x2518_e3e0, insn]; // ptrue p0.b; fsqrt z0, p0/m, z1

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH fsqrt negative subnormal {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH fsqrt negative subnormal {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fcvt_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue p0.d
        0x65ca_a020, // fcvt  z0.s, p0/m, z1.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
                (1, pack_d(16_777_217.0, -16_777_217.0)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE FCVT FPCR rmode {rmode} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FCVT FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fp16_fcvt_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue  p0.s
        0x6588_a062, // fcvt   z2.h, p0/m, z3.s
        0x25d8_e3e1, // ptrue  p1.d
        0x65c8_a56a, // fcvt   z10.h, p1/m, z11.d
        0x64ca_a5ee, // fcvtnt z14.s, p1/m, z15.d
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    2usize,
                    pack_h([
                        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
                    ]),
                ),
                (
                    3,
                    pack_s_bits([0x3f80_0fff, 0x3f80_1000, 0x3f80_1001, 0xbf80_1000]),
                ),
                (
                    10,
                    pack_h([
                        0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555,
                    ]),
                ),
                (11, pack_d(1.00048828125, -1.00048828125)),
                (14, (0xaaaa_aaaa_1111_1111, 0xbbbb_bbbb_2222_2222)),
                (15, pack_d(16_777_217.0, -16_777_217.0)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [2usize, 10, 14] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE2 FP16 FCVT FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE2 FP16 FCVT FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fp_unary_extra_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x658c_a020, // frecpx z0.s, p0/m, z1.s
        0x6580_a062, // frintn z2.s, p0/m, z3.s
        0x6581_a0a4, // frintp z4.s, p0/m, z5.s
        0x6582_a0e6, // frintm z6.s, p0/m, z7.s
        0x6583_a128, // frintz z8.s, p0/m, z9.s
        0x6584_a16a, // frinta z10.s, p0/m, z11.s
        0x6586_a1ac, // frintx z12.s, p0/m, z13.s
        0x6587_a1ee, // frinti z14.s, p0/m, z15.s
        0x651c_a230, // flogb  z16.s, p0/m, z17.s
        0x25d8_e021, // ptrue p1.d, vl1
        0x65cc_a672, // frecpx z18.d, p1/m, z19.d
        0x65c3_a6b4, // frintz z20.d, p1/m, z21.d
        0x651e_a6f6, // flogb  z22.d, p1/m, z23.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
            (1, pack_s(2.0, -4.0, 30.0, -40.0)),
            (2, pack_s(101.0, 201.0, 301.0, 401.0)),
            (3, pack_s(1.25, -1.75, 31.0, -41.0)),
            (4, pack_s(102.0, 202.0, 302.0, 402.0)),
            (5, pack_s(1.25, -1.75, 32.0, -42.0)),
            (6, pack_s(103.0, 203.0, 303.0, 403.0)),
            (7, pack_s(1.25, -1.75, 33.0, -43.0)),
            (8, pack_s(104.0, 204.0, 304.0, 404.0)),
            (9, pack_s(1.25, -1.75, 34.0, -44.0)),
            (10, pack_s(105.0, 205.0, 305.0, 405.0)),
            (11, pack_s(1.25, -1.75, 35.0, -45.0)),
            (12, pack_s(106.0, 206.0, 306.0, 406.0)),
            (13, pack_s(1.25, -1.75, 36.0, -46.0)),
            (14, pack_s(107.0, 207.0, 307.0, 407.0)),
            (15, pack_s(1.25, -1.75, 37.0, -47.0)),
            (16, pack_s(108.0, 208.0, 308.0, 408.0)),
            (17, pack_s(1.0, 8.0, 38.0, -48.0)),
            (18, pack_d(1000.0, 2000.0)),
            (19, pack_d(2.0, -4.0)),
            (20, pack_d(1001.0, 2001.0)),
            (21, pack_d(1.25, -1.75)),
            (22, pack_d(1002.0, 2002.0)),
            (23, pack_d(1.0, 16.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 FP unary-extra z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fp_precision_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x6589_a020, // fcvt   z0.s, p0/m, z1.h
        0x6588_a062, // fcvt   z2.h, p0/m, z3.s
        0x25d8_e021, // ptrue p1.d, vl1
        0x65cb_a4a4, // fcvt   z4.d, p1/m, z5.s
        0x65ca_a4e6, // fcvt   z6.s, p1/m, z7.d
        0x650a_a528, // fcvtx  z8.s, p1/m, z9.d
        0x65c8_a56a, // fcvt   z10.h, p1/m, z11.d
        0x64ca_a5ee, // fcvtnt z14.s, p1/m, z15.d
        0x64cb_a630, // fcvtlt z16.d, p1/m, z17.s
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
            (
                1,
                pack_h([
                    0x3c00, 0x7bff, 0xc000, 0x7bff, 0x4200, 0x4400, 0x4600, 0x4800,
                ]),
            ),
            (
                2,
                pack_h([
                    0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff,
                ]),
            ),
            (3, pack_s(1.5, -2.5, 300.0, 400.0)),
            (4, pack_d(1000.0, 2000.0)),
            (5, pack_s(1.25, -2.25, 300.0, 400.0)),
            (6, pack_s(101.0, 201.0, 301.0, 401.0)),
            (7, pack_d(1.5, -2.5)),
            (8, pack_s(102.0, 202.0, 302.0, 402.0)),
            (9, pack_d(1.25, -2.25)),
            (
                10,
                pack_h([
                    0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff, 0x7bff,
                ]),
            ),
            (11, pack_d(1.0, -2.0)),
            (14, (0xaaaa_aaaa_1111_1111, 0xbbbb_bbbb_2222_2222)),
            (15, pack_d(1.5, -2.5)),
            (16, pack_d(1003.0, 2003.0)),
            (17, pack_s(100.0, 1.5, 200.0, 300.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 14, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 FP precision-convert z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fmlal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x64a2_8020, // fmlalb z0.s, z1.h, z2.h
        0x64a5_8483, // fmlalt z3.s, z4.h, z5.h
        0x64a8_a0e6, // fmlslb z6.s, z7.h, z8.h
        0x64ab_a549, // fmlslt z9.s, z10.h, z11.h
        0x64ac_41ac, // fmlalb z12.s, z13.h, z4.h[2]
        0x64ad_6e0f, // fmlslt z15.s, z16.h, z5.h[3]
        0x64a7_4e72, // fmlalt z18.s, z19.h, z7.h[1]
        0x64a1_62d5, // fmlslb z21.s, z22.h, z1.h[0]
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, -2.0, 4.0, -8.0)),
            (
                1,
                pack_h([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                2,
                pack_h([
                    0x4000, 0x3c00, 0x4400, 0x4200, 0xc000, 0xbc00, 0xc400, 0xc200,
                ]),
            ),
            (3, pack_s(2.0, -4.0, 8.0, -16.0)),
            (
                4,
                pack_h([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0xb800, 0xbc00, 0xc000, 0xc200,
                ]),
            ),
            (
                5,
                pack_h([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (6, pack_s(3.0, -6.0, 12.0, -24.0)),
            (
                7,
                pack_h([
                    0x4400, 0x4200, 0x4000, 0x3c00, 0xc400, 0xc200, 0xc000, 0xbc00,
                ]),
            ),
            (
                8,
                pack_h([
                    0x3800, 0x3c00, 0x4000, 0x4200, 0xb800, 0xbc00, 0xc000, 0xc200,
                ]),
            ),
            (9, pack_s(4.0, -8.0, 16.0, -32.0)),
            (
                10,
                pack_h([
                    0x3c00, 0x3800, 0x4000, 0x4200, 0xbc00, 0xb800, 0xc000, 0xc200,
                ]),
            ),
            (
                11,
                pack_h([
                    0x4400, 0x4200, 0x4000, 0x3c00, 0xc400, 0xc200, 0xc000, 0xbc00,
                ]),
            ),
            (12, pack_s(5.0, -10.0, 20.0, -40.0)),
            (
                13,
                pack_h([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x4200, 0xc200, 0x4400, 0xc400,
                ]),
            ),
            (15, pack_s(6.0, -12.0, 24.0, -48.0)),
            (
                16,
                pack_h([
                    0x3800, 0xb800, 0x3c00, 0xbc00, 0x4000, 0xc000, 0x4200, 0xc200,
                ]),
            ),
            (18, pack_s(7.0, -14.0, 28.0, -56.0)),
            (
                19,
                pack_h([
                    0x3c00, 0x4000, 0xbc00, 0xc000, 0x4200, 0x4400, 0xc200, 0xc400,
                ]),
            ),
            (21, pack_s(8.0, -16.0, 32.0, -64.0)),
            (
                22,
                pack_h([
                    0x4400, 0xc400, 0x4200, 0xc200, 0x4000, 0xc000, 0x3c00, 0xbc00,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 FMLAL z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fmlal_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise AFP and SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const H_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const S_PATTERN: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    let cases = [
        ("fmlalb", 0x64a2_8020),
        ("fmlalt", 0x64a2_8420),
        ("fmlslb", 0x64a2_a020),
        ("fmlslt", 0x64a2_a420),
    ];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = S_PATTERN as u64;
            g.v[1] = (S_PATTERN >> 64) as u64;
            g.v[2] = H_PATTERN as u64;
            g.v[3] = (H_PATTERN >> 64) as u64;
            g.v[4] = H_PATTERN as u64;
            g.v[5] = (H_PATTERN >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE2 AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE2 AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fmlal_ah_input_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise AFP and SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let patterns = [
        ("s_qnan_snan", 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000u128),
        ("d_qnan_snan", 0x0000_0000_0000_0001_7ff8_0000_0000_2000u128),
        ("s_inf_zero", 0x3f80_0000_0000_0000_7f80_0000_0000_0001u128),
    ];
    let cases = [
        ("fmlalb", 0x64a2_8020),
        ("fmlalt", 0x64a2_8420),
        ("fmlslb", 0x64a2_a020),
        ("fmlslt", 0x64a2_a420),
    ];

    for (pattern_label, pattern) in patterns {
        for (label, insn) in cases {
            let setup = |g: &mut Aarch64GuestRegs| {
                g.fpcr = FPCR_AH;
                g.v[0] = pattern as u64;
                g.v[1] = (pattern >> 64) as u64;
                g.v[2] = pattern as u64;
                g.v[3] = (pattern >> 64) as u64;
                g.v[4] = pattern as u64;
                g.v[5] = (pattern >> 64) as u64;
                g.fpsr = 0;
            };

            let hw = raw_native_run_fp(&[insn], setup);
            let interp = raw_interp_run(&[insn], setup);
            assert_eq!(
                (hw.v[0], hw.v[1]),
                (interp.v[0], interp.v[1]),
                "raw EL0 SVE2 AH {label} {pattern_label} z0 low-128 mismatch"
            );
            assert_eq!(
                hw.fpsr as u32, interp.fpsr as u32,
                "raw EL0 SVE2 AH {label} {pattern_label} FPSR mismatch"
            );
        }
    }
}

#[test]
fn raw_el0_sve2_fmlal_indexed_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise AFP and SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const H_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const S_PATTERN: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    let cases = [
        ("fmlalb_idx", 0x64aa_4820),
        ("fmlalt_idx", 0x64aa_4c20),
        ("fmlslb_idx", 0x64aa_6820),
        ("fmlslt_idx", 0x64aa_6c20),
    ];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = S_PATTERN as u64;
            g.v[1] = (S_PATTERN >> 64) as u64;
            g.v[2] = H_PATTERN as u64;
            g.v[3] = (H_PATTERN >> 64) as u64;
            g.v[4] = H_PATTERN as u64;
            g.v[5] = (H_PATTERN >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE2 AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE2 AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fmlal_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x64a2_8020, // fmlalb z0.s, z1.h, z2.h
        0x64a5_8483, // fmlalt z3.s, z4.h, z5.h
        0x64a8_a0e6, // fmlslb z6.s, z7.h, z8.h
        0x64ab_a549, // fmlslt z9.s, z10.h, z11.h
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    0usize,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    1,
                    pack_h([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    2,
                    pack_h([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    3,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    4,
                    pack_h([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    5,
                    pack_h([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    6,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    7,
                    pack_h([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    8,
                    pack_h([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
                (
                    9,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    10,
                    pack_h([
                        0x3c00, 0x3c00, 0xbc00, 0x3c00, 0x3c00, 0x3c00, 0xbc00, 0x3c00,
                    ]),
                ),
                (
                    11,
                    pack_h([
                        0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00, 0x3c00,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE2 FMLAL FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE2 FMLAL FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_int_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x659c_a020, // fcvtzs z0.s, p0/m, z1.s
        0x659d_a062, // fcvtzu z2.s, p0/m, z3.s
        0x6594_a0a4, // scvtf  z4.s, p0/m, z5.s
        0x6595_a0e6, // ucvtf  z6.s, p0/m, z7.s
        0x25d8_e021, // ptrue p1.d, vl1
        0x65de_a528, // fcvtzs z8.d, p1/m, z9.d
        0x65df_a56a, // fcvtzu z10.d, p1/m, z11.d
        0x65d6_a5ac, // scvtf  z12.d, p1/m, z13.d
        0x65d7_a5ee, // ucvtf  z14.d, p1/m, z15.d
        0x65dc_a630, // fcvtzs z16.d, p1/m, z17.s
        0x65d4_a672, // scvtf  z18.s, p1/m, z19.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(100.0, 200.0, 300.0, 400.0)),
            (1, pack_s(1.5, -2.75, 30.0, -40.0)),
            (2, pack_s(101.0, 201.0, 301.0, 401.0)),
            (3, pack_s(1.5, 2.75, 31.0, 41.0)),
            (4, pack_s(102.0, 202.0, 302.0, 402.0)),
            (5, pack_s_bits([(-3_i32) as u32, 5, 300, 400])),
            (6, pack_s(103.0, 203.0, 303.0, 403.0)),
            (7, pack_s_bits([3, 5, 300, 400])),
            (8, (1000, 2000)),
            (9, pack_d(3.75, -4.5)),
            (10, (1001, 2001)),
            (11, pack_d(3.75, 4.5)),
            (12, pack_d(1002.0, 2002.0)),
            (13, ((-7_i64) as u64, 8)),
            (14, pack_d(1003.0, 2003.0)),
            (15, (9, 10)),
            (16, (1004, 2004)),
            (17, pack_s(6.75, -7.25, 30.0, 40.0)),
            (18, pack_s(104.0, 204.0, 304.0, 404.0)),
            (19, ((-11_i64) as u64, 12)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP-int convert z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fcvtz_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "fcvtzs_s_i32",
            [0x2598_e3e0, 0x659c_a020],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "fcvtzu_s_i32",
            [0x2598_e3e0, 0x659d_a020],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "fcvtzs_d_i64",
            [0x25d8_e3e0, 0x65de_a020],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
        (
            "fcvtzu_d_i64",
            [0x25d8_e3e0, 0x65df_a020],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
    ];

    for (label, insns, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0xaaaa_aaaa_5555_5555;
            g.v[1] = 0xcccc_cccc_3333_3333;
            g.v[2] = lo;
            g.v[3] = hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_int_to_fp_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x6594_a0a4, // scvtf  z4.s, p0/m, z5.s
        0x6595_a0e6, // ucvtf  z6.s, p0/m, z7.s
        0x25d8_e3e1, // ptrue p1.d
        0x65d6_a5ac, // scvtf  z12.d, p1/m, z13.d
        0x65d7_a5ee, // ucvtf  z14.d, p1/m, z15.d
    ];
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (4usize, pack_s(100.0, 200.0, 300.0, 400.0)),
                (
                    5,
                    pack_s_bits([
                        16_777_217,
                        (-16_777_217i32) as u32,
                        i32::MAX as u32,
                        i32::MIN as u32,
                    ]),
                ),
                (6, pack_s(101.0, 201.0, 301.0, 401.0)),
                (
                    7,
                    pack_s_bits([16_777_217, 16_777_219, u32::MAX - 1, u32::MAX]),
                ),
                (12, pack_d(1000.0, 2000.0)),
                (13, ((1u64 << 53) + 1, (-((1i64 << 53) + 1)) as u64)),
                (14, pack_d(1001.0, 2001.0)),
                (15, ((1u64 << 53) + 1, u64::MAX)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [4usize, 6, 12, 14] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE int-to-FP FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE int-to-FP FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_to_int_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x659c_a020, // fcvtzs z0.s, p0/m, z1.s
        0x659d_a062, // fcvtzu z2.s, p0/m, z3.s
        0x25d8_e3e1, // ptrue p1.d
        0x65de_a528, // fcvtzs z8.d, p1/m, z9.d
        0x65df_a56a, // fcvtzu z10.d, p1/m, z11.d
        0x65dc_a630, // fcvtzs z16.d, p1/m, z17.s
    ];
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d_bits = |a: u64, b: u64| -> (u64, u64) { (a, b) };

    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_s_bits([0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]),
            ),
            (
                1,
                pack_s_bits([
                    1.5f32.to_bits(),
                    (-2.75f32).to_bits(),
                    f32::INFINITY.to_bits(),
                    0x7fc0_0001,
                ]),
            ),
            (
                2,
                pack_s_bits([0x5555_5555, 0x6666_6666, 0x7777_7777, 0x8888_8888]),
            ),
            (
                3,
                pack_s_bits([
                    1.5f32.to_bits(),
                    (-2.75f32).to_bits(),
                    4_294_967_296.0f32.to_bits(),
                    0x7fc0_0001,
                ]),
            ),
            (8, pack_d_bits(0x1111_1111_1111_1111, 0x2222_2222_2222_2222)),
            (9, pack_d_bits(3.75f64.to_bits(), f64::INFINITY.to_bits())),
            (
                10,
                pack_d_bits(0x3333_3333_3333_3333, 0x4444_4444_4444_4444),
            ),
            (11, pack_d_bits(3.75f64.to_bits(), (-4.5f64).to_bits())),
            (
                16,
                pack_d_bits(0x5555_5555_5555_5555, 0x6666_6666_6666_6666),
            ),
            (
                17,
                pack_s_bits([
                    6.75f32.to_bits(),
                    (-7.25f32).to_bits(),
                    f32::INFINITY.to_bits(),
                    0x7fc0_0001,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 8, 10, 16] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP-to-int status z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE FP-to-int status FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_fp16_int_convert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e080, // ptrue  p0.h, vl4
        0x2598_e041, // ptrue  p1.s, vl2
        0x25d8_e022, // ptrue  p2.d, vl1
        0x655a_a020, // fcvtzs z0.h, p0/m, z1.h
        0x655d_a462, // fcvtzu z2.s, p1/m, z3.h
        0x655e_a8a4, // fcvtzs z4.d, p2/m, z5.h
        0x6552_a0e6, // scvtf  z6.h, p0/m, z7.h
        0x6555_a528, // ucvtf  z8.h, p1/m, z9.s
        0x6556_a96a, // scvtf  z10.h, p2/m, z11.d
    ];
    let pack_h = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_h([
                    0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
                ]),
            ),
            (
                1,
                pack_h([
                    0x0000, 0x3c00, 0xc000, 0x4200, 0x4400, 0xc400, 0x4800, 0xc800,
                ]),
            ),
            (
                2,
                pack_s([0x2000_0000, 0x2000_0001, 0x2000_0002, 0x2000_0003]),
            ),
            (
                3,
                pack_h([
                    0x0000, 0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700,
                ]),
            ),
            (4, (0x4000_0000_0000_0000, 0x4000_0000_0000_0001)),
            (
                5,
                pack_h([
                    0xc000, 0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700,
                ]),
            ),
            (
                6,
                pack_h([
                    0x6000, 0x6001, 0x6002, 0x6003, 0x6004, 0x6005, 0x6006, 0x6007,
                ]),
            ),
            (
                7,
                pack_h([
                    0xfffd, 0x0005, 0x002a, 0xffd6, 0x0001, 0x0002, 0x0003, 0x0004,
                ]),
            ),
            (
                8,
                pack_h([
                    0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006, 0x8007,
                ]),
            ),
            (9, pack_s([0, 1, 42, 127])),
            (
                10,
                pack_h([
                    0xa000, 0xa001, 0xa002, 0xa003, 0xa004, 0xa005, 0xa006, 0xa007,
                ]),
            ),
            (11, ((-7_i64) as u64, 8)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP16-int convert z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE FP16-int convert FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_fp_int_cross_width_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue  p0.s, vl2
        0x25d8_e021, // ptrue  p1.d, vl1
        0x65d8_a020, // fcvtzs z0.s, p0/m, z1.d
        0x65d9_a062, // fcvtzu z2.s, p0/m, z3.d
        0x65d0_a4a4, // scvtf  z4.d, p1/m, z5.s
        0x65d1_a4e6, // ucvtf  z6.d, p1/m, z7.s
        0x65dd_a528, // fcvtzu z8.d, p1/m, z9.s
        0x65d5_a16a, // ucvtf  z10.s, p0/m, z11.d
    ];
    let pack_s = |lanes: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(lanes[0]) | (u64::from(lanes[1]) << 32);
        let hi = u64::from(lanes[2]) | (u64::from(lanes[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_s([0x1000_0000, 0x1000_0001, 0x1000_0002, 0x1000_0003]),
            ),
            (1, pack_d(-7.0, 8.0)),
            (
                2,
                pack_s([0x2000_0000, 0x2000_0001, 0x2000_0002, 0x2000_0003]),
            ),
            (3, pack_d(7.0, 8.0)),
            (4, (0x4000_0000_0000_0000, 0x4000_0000_0000_0001)),
            (5, pack_s([(-7_i32) as u32, 8, 9, 10])),
            (6, (0x6000_0000_0000_0000, 0x6000_0000_0000_0001)),
            (7, pack_s([7, 8, 9, 10])),
            (8, (0x8000_0000_0000_0000, 0x8000_0000_0000_0001)),
            (
                9,
                pack_s([
                    7.0_f32.to_bits(),
                    8.0_f32.to_bits(),
                    9.0_f32.to_bits(),
                    10.0_f32.to_bits(),
                ]),
            ),
            (
                10,
                pack_s([0xa000_0000, 0xa000_0001, 0xa000_0002, 0xa000_0003]),
            ),
            (11, (7, 8)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP-int cross-width z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE FP-int cross-width FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_fp_fma_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x25d8_e021, // ptrue p1.d, vl1
        0x65e1_0418, // fmla  z24.d, p1/m, z0.d, z1.d
        0x65e3_2459, // fmls  z25.d, p1/m, z2.d, z3.d
        0x65e5_449a, // fnmla z26.d, p1/m, z4.d, z5.d
        0x65e7_64db, // fnmls z27.d, p1/m, z6.d, z7.d
        0x65e1_841c, // fmad  z28.d, p1/m, z0.d, z1.d
        0x65e3_a45d, // fmsb  z29.d, p1/m, z2.d, z3.d
        0x65e5_c49e, // fnmad z30.d, p1/m, z4.d, z5.d
        0x65e7_e4df, // fnmsb z31.d, p1/m, z6.d, z7.d
        0x65a9_0110, // fmla  z16.s, p0/m, z8.s, z9.s
        0x65ab_2151, // fmls  z17.s, p0/m, z10.s, z11.s
        0x65ad_4192, // fnmla z18.s, p0/m, z12.s, z13.s
        0x65af_61d3, // fnmls z19.s, p0/m, z14.s, z15.s
        0x65a9_8114, // fmad  z20.s, p0/m, z8.s, z9.s
        0x65ab_a155, // fmsb  z21.s, p0/m, z10.s, z11.s
        0x65ad_c196, // fnmad z22.s, p0/m, z12.s, z13.s
        0x65af_e1d7, // fnmsb z23.s, p0/m, z14.s, z15.s
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_d(0.5, 50.0)),
            (1, pack_d(2.0, -60.0)),
            (2, pack_d(3.0, 70.0)),
            (3, pack_d(0.25, -80.0)),
            (4, pack_d(-1.5, 90.0)),
            (5, pack_d(4.0, -100.0)),
            (6, pack_d(2.5, 110.0)),
            (7, pack_d(-0.5, -120.0)),
            (8, pack_s(0.5, -1.0, 10.0, -20.0)),
            (9, pack_s(2.0, 3.0, -30.0, 40.0)),
            (10, pack_s(3.0, -4.0, 11.0, -21.0)),
            (11, pack_s(0.25, -0.5, -31.0, 41.0)),
            (12, pack_s(-1.5, 2.5, 12.0, -22.0)),
            (13, pack_s(4.0, -2.0, -32.0, 42.0)),
            (14, pack_s(2.5, -3.5, 13.0, -23.0)),
            (15, pack_s(-0.5, 1.5, -33.0, 43.0)),
            (16, pack_s(1.0, 2.0, 100.0, -100.0)),
            (17, pack_s(-3.0, 4.0, 101.0, -101.0)),
            (18, pack_s(5.0, -6.0, 102.0, -102.0)),
            (19, pack_s(-7.0, 8.0, 103.0, -103.0)),
            (20, pack_s(1.25, -2.25, 104.0, -104.0)),
            (21, pack_s(-3.25, 4.25, 105.0, -105.0)),
            (22, pack_s(5.25, -6.25, 106.0, -106.0)),
            (23, pack_s(-7.25, 8.25, 107.0, -107.0)),
            (24, pack_d(1.0, 1000.0)),
            (25, pack_d(-2.0, 1001.0)),
            (26, pack_d(3.0, 1002.0)),
            (27, pack_d(-4.0, 1003.0)),
            (28, pack_d(1.25, 1004.0)),
            (29, pack_d(-2.25, 1005.0)),
            (30, pack_d(3.25, 1006.0)),
            (31, pack_d(-4.25, 1007.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 16usize..=31 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP FMA z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_fma_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const PATTERN: u128 = 0x3f80_0000_0000_0000_7f80_0000_0000_0001;
    let cases = [
        ("fmla", 0x65a2_0020),
        ("fmls", 0x65a2_2020),
        ("fnmla", 0x65a2_4020),
        ("fnmls", 0x65a2_6020),
        ("fmad", 0x65a2_8020),
        ("fmsb", 0x65a2_a020),
        ("fnmad", 0x65a2_c020),
        ("fnmsb", 0x65a2_e020),
    ];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            for reg in [0usize, 1, 2] {
                g.v[2 * reg] = PATTERN as u64;
                g.v[2 * reg + 1] = (PATTERN >> 64) as u64;
            }
            g.fpsr = 0;
        };
        let insns = [0x2598_e3e0, insn]; // ptrue p0.s; FMA variant z0.s, p0/m, z1.s, z2.s

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH {label} status z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} status FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_fma_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x25d8_e3e1, // ptrue p1.d
        0x65a9_0110, // fmla  z16.s, p0/m, z8.s, z9.s
        0x65ab_2151, // fmls  z17.s, p0/m, z10.s, z11.s
        0x65a9_8114, // fmad  z20.s, p0/m, z8.s, z9.s
        0x65ab_a155, // fmsb  z21.s, p0/m, z10.s, z11.s
        0x65e1_0418, // fmla  z24.d, p1/m, z0.d, z1.d
        0x65e3_a45d, // fmsb  z29.d, p1/m, z2.d, z3.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_d(0.3333333333333333, -0.3333333333333333)),
                (1, pack_d(0.10000000000000002, -0.20000000000000004)),
                (2, pack_d(1.0000000000000002, -1.0000000000000002)),
                (3, pack_d(0.3333333333333333, -0.25000000000000006)),
                (8, pack_s(0.33333334, -0.33333334, 1.0000001, -1.0000001)),
                (9, pack_s(0.10000001, -0.20000002, 0.30000004, -0.40000004)),
                (10, pack_s(1.0000001, -1.0000001, 0.50000006, -0.50000006)),
                (11, pack_s(0.33333334, -0.25000003, 0.20000002, -0.10000001)),
                (16, pack_s(1.0000001, -2.0000002, 3.0000002, -4.0000005)),
                (17, pack_s(-1.0000001, 2.0000002, -3.0000002, 4.0000005)),
                (20, pack_s(0.50000006, -0.75000006, 1.2500001, -1.5000001)),
                (21, pack_s(-0.50000006, 0.75000006, -1.2500001, 1.5000001)),
                (24, pack_d(1.0000000000000002, -2.0000000000000004)),
                (29, pack_d(-1.0000000000000002, 2.0000000000000004)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [16usize, 17, 20, 21, 24, 29] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE FP FMA FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FP FMA FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_complex_fp_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fcma") {
        eprintln!("[skip] host does not advertise SVE FCMA");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x25d8_e021, // ptrue p1.d, vl1
        0x6480_8020, // fcadd z0.s, p0/m, z0.s, z1.s, #90
        0x6481_8062, // fcadd z2.s, p0/m, z2.s, z3.s, #270
        0x64c0_84a4, // fcadd z4.d, p1/m, z4.d, z5.d, #90
        0x64c1_84e6, // fcadd z6.d, p1/m, z6.d, z7.d, #270
        0x648a_0128, // fcmla z8.s, p0/m, z9.s, z10.s, #0
        0x648d_218b, // fcmla z11.s, p0/m, z12.s, z13.s, #90
        0x64d0_45ee, // fcmla z14.d, p1/m, z15.d, z16.d, #180
        0x64d3_6651, // fcmla z17.d, p1/m, z18.d, z19.d, #270
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, 2.0, 10.0, 20.0)),
            (1, pack_s(0.5, -1.0, 30.0, 40.0)),
            (2, pack_s(-2.0, 3.0, 11.0, 21.0)),
            (3, pack_s(1.5, -0.5, 31.0, 41.0)),
            (4, pack_d(1.0, 10.0)),
            (5, pack_d(0.5, -1.0)),
            (6, pack_d(-2.0, 11.0)),
            (7, pack_d(1.5, -0.5)),
            (8, pack_s(0.25, -0.5, 12.0, 22.0)),
            (9, pack_s(1.0, 2.0, 32.0, 42.0)),
            (10, pack_s(0.5, -1.0, 33.0, 43.0)),
            (11, pack_s(-0.25, 0.75, 13.0, 23.0)),
            (12, pack_s(2.0, -1.0, 34.0, 44.0)),
            (13, pack_s(0.25, 0.5, 35.0, 45.0)),
            (14, pack_d(0.5, 14.0)),
            (15, pack_d(1.5, -2.0)),
            (16, pack_d(0.25, 0.75)),
            (17, pack_d(-0.5, 15.0)),
            (18, pack_d(2.0, -1.5)),
            (19, pack_d(0.5, 0.25)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 11, 14, 17] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE complex-FP z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE complex-FP FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_complex_fp_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fcma") {
        eprintln!("[skip] host does not advertise SVE FCMA");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x25d8_e3e1, // ptrue p1.d
        0x6480_8020, // fcadd z0.s, p0/m, z0.s, z1.s, #90
        0x6481_8062, // fcadd z2.s, p0/m, z2.s, z3.s, #270
        0x64c0_84a4, // fcadd z4.d, p1/m, z4.d, z5.d, #90
        0x648a_0128, // fcmla z8.s, p0/m, z9.s, z10.s, #0
        0x648d_218b, // fcmla z11.s, p0/m, z12.s, z13.s, #90
        0x64d0_45ee, // fcmla z14.d, p1/m, z15.d, z16.d, #180
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (0usize, pack_s(1.0000001, -2.0000002, 10.0, 20.0)),
                (1, pack_s(0.33333334, -0.25000003, 30.0, 40.0)),
                (2, pack_s(-1.0000001, 2.0000002, 11.0, 21.0)),
                (3, pack_s(0.50000006, -0.75000006, 31.0, 41.0)),
                (4, pack_d(1.0000000000000002, -2.0000000000000004)),
                (5, pack_d(0.3333333333333333, -0.25000000000000006)),
                (8, pack_s(0.25000003, -0.50000006, 12.0, 22.0)),
                (9, pack_s(1.0000001, 2.0000002, 32.0, 42.0)),
                (10, pack_s(0.33333334, -0.25000003, 33.0, 43.0)),
                (11, pack_s(-0.25000003, 0.75000006, 13.0, 23.0)),
                (12, pack_s(2.0000002, -1.0000001, 34.0, 44.0)),
                (13, pack_s(0.25000003, 0.50000006, 35.0, 45.0)),
                (14, pack_d(0.5000000000000001, -0.7500000000000001)),
                (15, pack_d(1.5000000000000002, -2.0000000000000004)),
                (16, pack_d(0.25000000000000006, 0.7500000000000001)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 2, 4, 8, 11, 14] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE complex-FP FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE complex-FP FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_estimate_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x658e_3020, // frecpe  z0.s, z1.s
        0x658f_3062, // frsqrte z2.s, z3.s
        0x65ce_30a4, // frecpe  z4.d, z5.d
        0x65cf_30e6, // frsqrte z6.d, z7.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s(0.5, 1.0, 2.0, 4.0)),
            (3, pack_s(0.25, 1.0, 4.0, 16.0)),
            (5, pack_d(0.5, 8.0)),
            (7, pack_d(0.25, 9.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP estimate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_estimate_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x658e_3020, // frecpe  z0.s, z1.s
        0x658f_3062, // frsqrte z2.s, z3.s
        0x65ce_30a4, // frecpe  z4.d, z5.d
        0x65cf_30e6, // frsqrte z6.d, z7.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s(0.0, -0.0, 1.0, f32::INFINITY)),
            (3, pack_s(-1.0, -4.0, 0.0, f32::INFINITY)),
            (5, pack_d(0.0, -0.0)),
            (7, pack_d(-1.0, -4.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP estimate status z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE FP estimate status FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_fexpa_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0460_b820, // fexpa z0.h, z1.h
        0x04a0_b883, // fexpa z3.s, z4.s
        0x04e0_b8e6, // fexpa z6.d, z7.d
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        let h_src = pack_h([
            0x0000, 0x0001, 0x001f, 0x0020, 0x3fff, 0x4000, 0x4001, 0xffff,
        ]);
        let s_src = pack_s_bits([0x0000_0000, 0x0000_0001, 0x0000_003f, 0xffff_ffff]);
        for (reg, (lo, hi)) in [
            (0usize, (0xdead_beef_dead_beef, 0xfeed_face_feed_face)),
            (1, h_src),
            (3, (0xdead_beef_dead_beef, 0xfeed_face_feed_face)),
            (4, s_src),
            (6, (0xdead_beef_dead_beef, 0xfeed_face_feed_face)),
            (7, (0x0000_0000_0000_007f, 0xffff_ffff_ffff_ffff)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FEXPA z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_reciprocal_step_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x6582_1820, // frecps  z0.s, z1.s, z2.s
        0x6585_1c83, // frsqrts z3.s, z4.s, z5.s
        0x65c8_18e6, // frecps  z6.d, z7.d, z8.d
        0x65cb_1d49, // frsqrts z9.d, z10.d, z11.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s(0.5, 1.0, -2.0, 4.0)),
            (2, pack_s(1.5, -0.25, 0.5, -0.125)),
            (4, pack_s(0.25, 1.0, 4.0, 9.0)),
            (5, pack_s(4.0, 1.0, 0.25, 0.125)),
            (7, pack_d(0.5, -2.0)),
            (8, pack_d(1.5, 0.25)),
            (10, pack_d(0.25, 9.0)),
            (11, pack_d(4.0, 0.125)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP reciprocal-step z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_recps_rsqrts_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x6582_1820, // frecps  z0.s, z1.s, z2.s
        0x6585_1c83, // frsqrts z3.s, z4.s, z5.s
        0x65c8_18e6, // frecps  z6.d, z7.d, z8.d
        0x65cb_1d49, // frsqrts z9.d, z10.d, z11.d
    ];
    let pack_s_bits = |bits: u32| -> (u64, u64) {
        let x = u64::from(bits);
        (x | (x << 32), x | (x << 32))
    };
    let pack_d_bits = |bits: u64| -> (u64, u64) { (bits, bits) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            let s = 0x3f80_0001;
            let d = 0x3ff0_0000_0000_0001;
            for (reg, (lo, hi)) in [
                (1usize, pack_s_bits(s)),
                (2, pack_s_bits(s)),
                (4, pack_s_bits(s)),
                (5, pack_s_bits(s)),
                (7, pack_d_bits(d)),
                (8, pack_d_bits(d)),
                (10, pack_d_bits(d)),
                (11, pack_d_bits(d)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 9] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE RECPS/RSQRTS FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE RECPS/RSQRTS FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_trig_helper_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x6582_0c20, // ftsmul z0.s, z1.s, z2.s
        0x65c5_0c83, // ftsmul z3.d, z4.d, z5.d
        0x6591_80e6, // ftmad  z6.s, z6.s, z7.s, #1
        0x6594_8128, // ftmad  z8.s, z8.s, z9.s, #4
        0x65d2_816a, // ftmad  z10.d, z10.d, z11.d, #2
        0x65d6_81ac, // ftmad  z12.d, z12.d, z13.d, #6
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, pack_s(0.5, -1.25, 2.0, -3.5)),
            (2, pack_s_bits([0, 1, 0, 1])),
            (4, pack_d(0.75, -2.5)),
            (5, (0, 1)),
            (6, pack_s(1.0, -2.0, 0.5, -0.75)),
            (7, pack_s(0.5, -0.25, -1.5, 2.0)),
            (8, pack_s(0.25, -0.5, 1.25, -1.75)),
            (9, pack_s(-0.75, 1.5, 0.5, -2.0)),
            (10, pack_d(1.0, -2.0)),
            (11, pack_d(0.5, -0.25)),
            (12, pack_d(0.25, -0.75)),
            (13, pack_d(-0.5, 1.25)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 8, 10, 12] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP trig-helper z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ftsmul_ah_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "s",
            0x6582_0c20,
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "d",
            0x65c2_0c20,
            0x0000_0000_0000_0001,
            0x3ff0_0000_0000_0000,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.v[4] = 0;
            g.v[5] = 0;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH ftsmul {label} subnormal z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH ftsmul {label} subnormal FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ftsmul_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "h",
            0x6542_0c20,
            0x3c00_0001_7d01_7e00,
            0x3c00_0001_7d01_7e00,
        ),
        (
            "s",
            0x6582_0c20,
            0x7fa0_0001_7fc0_2000,
            0x3f80_0000_0000_0001,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.v[4] = lo;
            g.v[5] = hi;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH ftsmul {label} NaN/status z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH ftsmul {label} NaN/status FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ftssel_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0462_b020, // ftssel z0.h, z1.h, z2.h
        0x04a5_b083, // ftssel z3.s, z4.s, z5.s
        0x04e8_b0e6, // ftssel z6.d, z7.d, z8.d
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                1usize,
                pack_h([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x3800, 0xb800, 0x4200, 0xc200,
                ]),
            ),
            (2, pack_h([0, 1, 2, 3, 0, 1, 2, 3])),
            (4, pack_s(1.0, -1.0, 2.0, -2.0)),
            (5, pack_s_bits([0, 1, 2, 3])),
            (7, pack_d(1.0, -1.0)),
            (8, (0, 3)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FTSSEL z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fp_pairwise_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e060, // ptrue  p0.s, vl3
        0x6490_8020, // faddp  z0.s, p0/m, z0.s, z1.s
        0x6494_8062, // fmaxnmp z2.s, p0/m, z2.s, z3.s
        0x6495_80a4, // fminnmp z4.s, p0/m, z4.s, z5.s
        0x6496_80e6, // fmaxp  z6.s, p0/m, z6.s, z7.s
        0x6497_8128, // fminp  z8.s, p0/m, z8.s, z9.s
        0x25d8_e021, // ptrue  p1.d, vl1
        0x64d0_856a, // faddp  z10.d, p1/m, z10.d, z11.d
        0x64d6_85ac, // fmaxp  z12.d, p1/m, z12.d, z13.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, 2.0, 3.0, 40.0)),
            (1, pack_s(10.0, 20.0, 30.0, 400.0)),
            (2, pack_s(1.0, -2.0, 3.0, 40.0)),
            (3, pack_s(10.0, -20.0, 30.0, 400.0)),
            (4, pack_s(1.0, -2.0, 3.0, 40.0)),
            (5, pack_s(10.0, -20.0, 30.0, 400.0)),
            (6, pack_s(1.0, -2.0, 3.0, 40.0)),
            (7, pack_s(10.0, -20.0, 30.0, 400.0)),
            (8, pack_s(1.0, -2.0, 3.0, 40.0)),
            (9, pack_s(10.0, -20.0, 30.0, 400.0)),
            (10, pack_d(1.0, 2.0)),
            (11, pack_d(10.0, 20.0)),
            (12, pack_d(1.0, -2.0)),
            (13, pack_d(10.0, -20.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 FP pairwise z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_fp16_pairwise_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("fphp")
    {
        eprintln!("[skip] host does not advertise SVE2 + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e3e0, // ptrue p0.h
        0x6450_8020, // faddp z0.h, p0/m, z0.h, z1.h
    ];
    let pack_h8 = |lanes: [u16; 8]| -> (u64, u64) {
        let lo = u64::from(lanes[0])
            | (u64::from(lanes[1]) << 16)
            | (u64::from(lanes[2]) << 32)
            | (u64::from(lanes[3]) << 48);
        let hi = u64::from(lanes[4])
            | (u64::from(lanes[5]) << 16)
            | (u64::from(lanes[6]) << 32)
            | (u64::from(lanes[7]) << 48);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    0usize,
                    pack_h8([
                        0xbe00, 0x3e00, 0x0000, 0x8000, 0x3555, 0x3001, 0xb555, 0xb001,
                    ]),
                ),
                (
                    1,
                    pack_h8([
                        0xc000, 0x4000, 0x8000, 0x8000, 0x3c01, 0x2e66, 0xbc01, 0xae66,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE2 FP16 pairwise FPCR rmode {rmode} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE2 FP16 pairwise FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_compare_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let qnan = f32::from_bits(0x7fc0_0000);
    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x6581_6001, // fcmeq p1.s, p0/z, z0.s, z1.s
        0x6583_6052, // fcmne p2.s, p0/z, z2.s, z3.s
        0x6585_4093, // fcmgt p3.s, p0/z, z4.s, z5.s
        0x6587_40c4, // fcmge p4.s, p0/z, z6.s, z7.s
        0x6589_c105, // fcmuo p5.s, p0/z, z8.s, z9.s
        0x658b_e156, // facgt p6.s, p0/z, z10.s, z11.s
        0x658d_c197, // facge p7.s, p0/z, z12.s, z13.s
        0x0480_07f0, // add   z16.s, p1/m, z16.s, z31.s
        0x0480_0bf1, // add   z17.s, p2/m, z17.s, z31.s
        0x0480_0ff2, // add   z18.s, p3/m, z18.s, z31.s
        0x0480_13f3, // add   z19.s, p4/m, z19.s, z31.s
        0x0480_17f4, // add   z20.s, p5/m, z20.s, z31.s
        0x0480_1bf5, // add   z21.s, p6/m, z21.s, z31.s
        0x0480_1ff6, // add   z22.s, p7/m, z22.s, z31.s
        0x25d8_e3e0, // ptrue p0.d
        0x65db_6341, // fcmeq p1.d, p0/z, z26.d, z27.d
        0x65dd_4392, // fcmgt p2.d, p0/z, z28.d, z29.d
        0x65cf_c1d3, // facge p3.d, p0/z, z14.d, z15.d
        0x04c0_07d7, // add   z23.d, p1/m, z23.d, z30.d
        0x04c0_0bd8, // add   z24.d, p2/m, z24.d, z30.d
        0x04c0_0fd9, // add   z25.d, p3/m, z25.d, z30.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, -2.0, 3.0, -4.0)),
            (1, pack_s(1.0, 2.0, 3.0, -5.0)),
            (2, pack_s(1.0, -2.0, 3.0, -4.0)),
            (3, pack_s(0.0, -2.0, 4.0, -4.0)),
            (4, pack_s(5.0, -1.0, 2.0, -4.0)),
            (5, pack_s(4.0, -2.0, 2.0, -3.0)),
            (6, pack_s(5.0, -1.0, 2.0, -4.0)),
            (7, pack_s(5.0, -2.0, 3.0, -3.0)),
            (8, pack_s(qnan, 1.0, qnan, -2.0)),
            (9, pack_s(1.0, qnan, qnan, -2.0)),
            (10, pack_s(-5.0, 2.0, -3.0, 4.0)),
            (11, pack_s(4.0, -3.0, -3.0, 2.0)),
            (12, pack_s(-5.0, 2.0, -3.0, 4.0)),
            (13, pack_s(5.0, -3.0, -2.0, 4.0)),
            (14, pack_d(-5.0, 2.0)),
            (15, pack_d(5.0, -3.0)),
            (16, pack_s(10.0, 20.0, 30.0, 40.0)),
            (17, pack_s(11.0, 21.0, 31.0, 41.0)),
            (18, pack_s(12.0, 22.0, 32.0, 42.0)),
            (19, pack_s(13.0, 23.0, 33.0, 43.0)),
            (20, pack_s(14.0, 24.0, 34.0, 44.0)),
            (21, pack_s(15.0, 25.0, 35.0, 45.0)),
            (22, pack_s(16.0, 26.0, 36.0, 46.0)),
            (23, pack_d(100.0, 200.0)),
            (24, pack_d(101.0, 201.0)),
            (25, pack_d(102.0, 202.0)),
            (26, pack_d(1.0, -2.0)),
            (27, pack_d(1.0, 3.0)),
            (28, pack_d(5.0, -1.0)),
            (29, pack_d(4.0, -2.0)),
            (30, pack_d(1000.0, 2000.0)),
            (31, pack_s(100.0, 200.0, 300.0, 400.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 16usize..=25 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP compare z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE FP compare NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve_fp_compare_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "fcmge_s",
            [0x2598_e3e1, 0x6582_4420, 0x0480_03f0],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "fcmeq_s",
            [0x2598_e3e1, 0x6582_6420, 0x0480_03f0],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "fcmgt0_s",
            [0x2598_e3e1, 0x6590_2430, 0x0480_03f0],
            0x7f80_0000_0000_0001,
            0x3f80_0000_0000_0000,
        ),
        (
            "fcmge_d",
            [0x25d8_e3e1, 0x65c2_4420, 0x04c0_03f0],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
        (
            "fcmeq_d",
            [0x25d8_e3e1, 0x65c2_6420, 0x04c0_03f0],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
        (
            "fcmgt0_d",
            [0x25d8_e3e1, 0x65d0_2430, 0x04c0_03f0],
            0x7ff8_0000_0000_2000,
            0x0000_0000_0000_0001,
        ),
    ];

    for (label, insns, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[2] = lo;
            g.v[3] = hi;
            g.v[4] = lo;
            g.v[5] = hi;
            g.v[32] = 0x0010_0000_0001_0000;
            g.v[33] = 0x0030_0000_0020_0000;
            g.v[62] = 0x0001_0000_0001_0000;
            g.v[63] = 0x0001_0000_0001_0000;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[32], hw.v[33]),
            (interp.v[32], interp.v[33]),
            "raw EL0 SVE AH {label} materialized predicate mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_compare_zero_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let qnan = f32::from_bits(0x7fc0_0000);
    let insns = [
        0x2598_e3e0, // ptrue p0.s
        0x6590_2001, // fcmge p1.s, p0/z, z0.s, #0.0
        0x6590_2032, // fcmgt p2.s, p0/z, z1.s, #0.0
        0x6591_2043, // fcmlt p3.s, p0/z, z2.s, #0.0
        0x6591_2074, // fcmle p4.s, p0/z, z3.s, #0.0
        0x6592_2085, // fcmeq p5.s, p0/z, z4.s, #0.0
        0x6593_20a6, // fcmne p6.s, p0/z, z5.s, #0.0
        0x0480_07f0, // add   z16.s, p1/m, z16.s, z31.s
        0x0480_0bf1, // add   z17.s, p2/m, z17.s, z31.s
        0x0480_0ff2, // add   z18.s, p3/m, z18.s, z31.s
        0x0480_13f3, // add   z19.s, p4/m, z19.s, z31.s
        0x0480_17f4, // add   z20.s, p5/m, z20.s, z31.s
        0x0480_1bf5, // add   z21.s, p6/m, z21.s, z31.s
        0x25d8_e3e0, // ptrue p0.d
        0x65d0_2341, // fcmge p1.d, p0/z, z26.d, #0.0
        0x65d1_2362, // fcmlt p2.d, p0/z, z27.d, #0.0
        0x65d3_2383, // fcmne p3.d, p0/z, z28.d, #0.0
        0x04c0_07d6, // add   z22.d, p1/m, z22.d, z30.d
        0x04c0_0bd7, // add   z23.d, p2/m, z23.d, z30.d
        0x04c0_0fd8, // add   z24.d, p3/m, z24.d, z30.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, 0.0, -0.0, -2.0)),
            (1, pack_s(1.0, 0.0, -0.0, -2.0)),
            (2, pack_s(1.0, 0.0, -0.0, -2.0)),
            (3, pack_s(1.0, 0.0, -0.0, -2.0)),
            (4, pack_s(1.0, 0.0, -0.0, -2.0)),
            (5, pack_s(1.0, 0.0, qnan, -2.0)),
            (16, pack_s(10.0, 20.0, 30.0, 40.0)),
            (17, pack_s(11.0, 21.0, 31.0, 41.0)),
            (18, pack_s(12.0, 22.0, 32.0, 42.0)),
            (19, pack_s(13.0, 23.0, 33.0, 43.0)),
            (20, pack_s(14.0, 24.0, 34.0, 44.0)),
            (21, pack_s(15.0, 25.0, 35.0, 45.0)),
            (22, pack_d(100.0, 200.0)),
            (23, pack_d(101.0, 201.0)),
            (24, pack_d(102.0, 202.0)),
            (26, pack_d(1.0, -0.0)),
            (27, pack_d(1.0, -2.0)),
            (28, pack_d(0.0, -3.0)),
            (30, pack_d(1000.0, 2000.0)),
            (31, pack_s(100.0, 200.0, 300.0, 400.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 16usize..=24 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP compare-zero z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fabd_ah_qnan_sign_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "h",
            0x6548_8020,
            0xfe01_fe01_fe01_fe01,
            0xfe01_fe01_fe01_fe01,
        ),
        (
            "s",
            0x6588_8020,
            0xffc0_2000_ffc0_2000,
            0xffc0_2000_ffc0_2000,
        ),
        (
            "d",
            0x65c8_8020,
            0xfff8_0000_0000_2000,
            0xfff8_0000_0000_2000,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = lo;
            g.v[1] = hi;
            g.v[2] = lo;
            g.v[3] = hi;
            g.fpsr = 0;
        };
        let insns = [0x2518_e3e0, insn]; // ptrue p0.b; fabd z0, p0/m, z0, z1

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH fabd {label} qNaN sign mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH fabd {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fmin_zero_ah_sign_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let cases = [
        (
            "h",
            0x655f_8000,
            0x8000_8000_8000_8000,
            0x8000_8000_8000_8000,
        ),
        (
            "s",
            0x659f_8000,
            0x8000_0000_8000_0000,
            0x8000_0000_8000_0000,
        ),
        (
            "d",
            0x65df_8000,
            0x8000_0000_0000_0000,
            0x8000_0000_0000_0000,
        ),
    ];

    for (label, insn, lo, hi) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = lo;
            g.v[1] = hi;
            g.fpsr = 0;
        };
        let insns = [0x2518_e3e0, insn]; // ptrue p0.b; fmin z0, p0/m, z0, #0.0

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH fmin zero {label} sign mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH fmin zero {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_indexed_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") || !host_has_aarch64_feature("fphp") {
        eprintln!("[skip] host does not advertise SVE + FP16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x643e_2272, // fmul z18.h, z19.h, z6.h[3]
        0x6466_02d5, // fmla z21.h, z22.h, z6.h[4]
        0x646e_0738, // fmls z24.h, z25.h, z6.h[5]
        0x64aa_2020, // fmul z0.s, z1.s, z2.s[1]
        0x64b5_0083, // fmla z3.s, z4.s, z5.s[2]
        0x64bd_04e6, // fmls z6.s, z7.s, z5.s[3]
        0x64fb_2149, // fmul z9.d, z10.d, z11.d[1]
        0x64ee_01ac, // fmla z12.d, z13.d, z14.d[0]
        0x64fe_060f, // fmls z15.d, z16.d, z14.d[1]
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (0usize, pack_s(1.0, -2.0, 3.0, -4.0)),
            (1, pack_s(2.0, -3.0, 4.0, -5.0)),
            (2, pack_s(0.5, 2.0, -1.0, -2.0)),
            (3, pack_s(1.0, 2.0, 3.0, 4.0)),
            (4, pack_s(0.5, -1.0, 1.5, -2.0)),
            (5, pack_s(2.0, 3.0, -4.0, -5.0)),
            (
                6,
                pack_h([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (7, pack_s(8.0, -8.0, 4.0, -4.0)),
            (9, pack_d(1.0, -2.0)),
            (10, pack_d(2.0, -3.0)),
            (11, pack_d(0.5, -2.0)),
            (12, pack_d(1.0, 2.0)),
            (13, pack_d(0.5, -1.0)),
            (14, pack_d(2.0, -3.0)),
            (15, pack_d(4.0, -5.0)),
            (16, pack_d(1.5, -2.0)),
            (
                18,
                pack_h([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x4200, 0xc200, 0x4400, 0xc400,
                ]),
            ),
            (
                19,
                pack_h([
                    0x4000, 0x4200, 0x4400, 0x4500, 0xc000, 0xc200, 0xc400, 0xc500,
                ]),
            ),
            (
                21,
                pack_h([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                22,
                pack_h([
                    0x3c00, 0xbc00, 0x4000, 0xc000, 0x4200, 0xc200, 0x4400, 0xc400,
                ]),
            ),
            (
                24,
                pack_h([
                    0x3c00, 0x4000, 0x4200, 0x4400, 0xbc00, 0xc000, 0xc200, 0xc400,
                ]),
            ),
            (
                25,
                pack_h([
                    0x4000, 0x4200, 0x4400, 0x4500, 0xc000, 0xc200, 0xc400, 0xc500,
                ]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE FP indexed z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_indexed_fma_ah_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const ONES: u128 = 0x3f80_0000_3f80_0000_3f80_0000_3f80_0000;
    const SUBNORMALS: u128 = 0x0000_2000_0000_2000_0000_2000_0000_2000;
    let cases = [("fmla", 0x64a2_0020), ("fmls", 0x64a2_0420)];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0;
            g.v[1] = 0;
            g.v[2] = ONES as u64;
            g.v[3] = (ONES >> 64) as u64;
            g.v[4] = SUBNORMALS as u64;
            g.v[5] = (SUBNORMALS >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH indexed {label} subnormal z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH indexed {label} subnormal FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_indexed_fma_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise AFP and SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const V0: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    let cases = [("fmla", 0x64a0_0000), ("fmls", 0x64a0_0400)];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = V0 as u64;
            g.v[1] = (V0 >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH indexed {label} NaN z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH indexed {label} NaN FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_reduction_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e3e0, // ptrue  p0.d
        0x04c1_2020, // uaddv  d0, p0, z1.d
        0x04c8_2062, // smaxv  d2, p0, z3.d
        0x04cb_20a4, // uminv  d4, p0, z5.d
        0x2598_e3e1, // ptrue  p1.s
        0x6598_24e6, // fadda  s6, p1, s6, z7.s
        0x6586_2528, // fmaxv  s8, p1, z9.s
        0x6585_256a, // fminnmv s10, p1, z11.s
    ];
    let pack = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 5;
        g.v[3] = 7;
        g.v[6] = (-2_i64) as u64;
        g.v[7] = 10;
        g.v[10] = 100;
        g.v[11] = 3;
        g.v[12] = (1.0_f32).to_bits() as u64;
        for (reg, (lo, hi)) in [
            (7usize, pack(0.5, 1.5, -2.0, 4.0)),
            (9, pack(1.0, -9.0, 5.0, -7.0)),
            (11, pack(2.0, -10.0, 4.0, -6.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 SVE integer reduction d{reg} mismatch"
        );
    }
    for reg in [6usize, 8, 10] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 SVE FP reduction s{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_reduction_extra_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x25d8_e020, // ptrue  p0.d, vl1
        0x04c9_2020, // umaxv  d0, p0, z1.d
        0x04c8_2062, // smaxv  d2, p0, z3.d
        0x04ca_20a4, // sminv  d4, p0, z5.d
        0x04cb_20e6, // uminv  d6, p0, z7.d
        0x2598_e061, // ptrue  p1.s, vl3
        0x0480_2528, // saddv  d8, p1, z9.s
        0x0481_256a, // uaddv  d10, p1, z11.s
        0x6580_25ac, // faddv  s12, p1, z13.s
        0x6584_25ee, // fmaxnmv s14, p1, z15.s
        0x6587_2630, // fminv  s16, p1, z17.s
        0x25d8_e3e2, // ptrue  p2.d
        0x65c0_2a72, // faddv  d18, p2, z19.d
        0x65c7_2ab4, // fminv  d20, p2, z21.d
        0x65c4_2af6, // fmaxnmv d22, p2, z23.d
    ];
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        pack_s_bits([a.to_bits(), b.to_bits(), c.to_bits(), d.to_bits()])
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (1usize, (5, 100)),
            (3, ((-5_i64) as u64, 10)),
            (5, ((-5_i64) as u64, (-100_i64) as u64)),
            (7, (100, 3)),
            (9, pack_s_bits([(-3_i32) as u32, 5, (-7_i32) as u32, 100])),
            (11, pack_s_bits([1, 2, 3, 100])),
            (13, pack_s(1.0, 2.0, 3.0, 100.0)),
            (15, pack_s(1.0, -9.0, 5.0, 100.0)),
            (17, pack_s(2.0, -10.0, 4.0, -100.0)),
            (19, pack_d(1.5, 2.5)),
            (21, pack_d(3.0, -2.0)),
            (23, pack_d(1.0, 4.0)),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 SVE extra reduction d{reg} mismatch"
        );
    }
    for reg in [12usize, 14, 16] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo] as u32, interp.v[lo] as u32,
            "raw EL0 SVE extra FP reduction s{reg} mismatch"
        );
    }
    for reg in [18usize, 20, 22] {
        let lo = 2 * reg;
        assert_eq!(
            hw.v[lo], interp.v[lo],
            "raw EL0 SVE extra FP reduction d{reg} mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_trig_helper_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x6582_0c20, // ftsmul z0.s, z1.s, z2.s
        0x65c5_0c83, // ftsmul z3.d, z4.d, z5.d
        0x6591_80e6, // ftmad  z6.s, z6.s, z7.s, #1
        0x6594_8128, // ftmad  z8.s, z8.s, z9.s, #4
        0x65d2_816a, // ftmad  z10.d, z10.d, z11.d, #2
        0x65d6_81ac, // ftmad  z12.d, z12.d, z13.d, #6
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    1usize,
                    pack_s(1.0000001, -1.0000001, 0.33333334, -0.33333334),
                ),
                (2, pack_s_bits([0, 1, 0, 1])),
                (4, pack_d(1.0000000000000002, -1.0000000000000002)),
                (5, (0, 1)),
                (6, pack_s(1.0000001, -2.0000002, 0.50000006, -0.75000006)),
                (7, pack_s(0.33333334, -0.25000003, -1.5000001, 2.0000002)),
                (8, pack_s(0.25000003, -0.50000006, 1.2500001, -1.7500001)),
                (9, pack_s(-0.75000006, 1.5000001, 0.33333334, -2.0000002)),
                (10, pack_d(1.0000000000000002, -2.0000000000000004)),
                (11, pack_d(0.3333333333333333, -0.25000000000000006)),
                (12, pack_d(0.25000000000000006, -0.7500000000000001)),
                (13, pack_d(-0.5000000000000001, 1.2500000000000002)),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 3, 6, 8, 10, 12] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE FP trig-helper FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE FP trig-helper FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_fp_reduction_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue p0.s, vl2
        0x6580_2020, // faddv s0, p0, z1.s
        0x6598_2062, // fadda s2, p0, s2, z3.s
        0x25d8_e041, // ptrue p1.d, vl2
        0x65c0_24a4, // faddv d4, p1, z5.d
        0x65d8_24e6, // fadda d6, p1, d6, z7.d
    ];
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };
    let pack_d = |a: f64, b: f64| -> (u64, u64) { (a.to_bits(), b.to_bits()) };

    for rmode in 0..4u64 {
        for (label, acc, addend) in [
            ("pos", 16_777_216.0f32, 1.0f32),
            ("neg", -16_777_216.0f32, -1.0f32),
            ("cancel", -1.5f32, 1.5f32),
        ] {
            let setup = |g: &mut Aarch64GuestRegs| {
                g.fpcr = rmode << 22;
                for (reg, (lo, hi)) in [
                    (1usize, pack_s(acc, addend, 1000.0, 2000.0)),
                    (2, pack_s(acc, 0.0, 0.0, 0.0)),
                    (3, pack_s(addend, 0.0, 1001.0, 2001.0)),
                    (5, pack_d(acc as f64, addend as f64)),
                    (6, pack_d(acc as f64, 0.0)),
                    (7, pack_d(addend as f64, 0.0)),
                ] {
                    g.v[2 * reg] = lo;
                    g.v[2 * reg + 1] = hi;
                }
            };

            let hw = raw_native_run_fp(&insns, setup);
            let interp = raw_interp_run(&insns, setup);
            for reg in [0usize, 2] {
                let lo = 2 * reg;
                assert_eq!(
                    hw.v[lo] as u32, interp.v[lo] as u32,
                    "raw EL0 SVE FP reduction FPCR {label} rmode {rmode} s{reg} mismatch"
                );
            }
            for reg in [4usize, 6] {
                let lo = 2 * reg;
                assert_eq!(
                    hw.v[lo], interp.v[lo],
                    "raw EL0 SVE FP reduction FPCR {label} rmode {rmode} d{reg} mismatch"
                );
            }
            assert_eq!(
                hw.fpsr as u32, interp.fpsr as u32,
                "raw EL0 SVE FP reduction FPCR {label} rmode {rmode} FPSR mismatch"
            );
        }
    }
}

#[test]
fn raw_el0_sve_permute_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x05e2_6020, // zip1 z0.d, z1.d, z2.d
        0x05a5_6483, // zip2 z3.s, z4.s, z5.s
        0x0568_68e6, // uzp1 z6.h, z7.h, z8.h
        0x052b_6d49, // uzp2 z9.b, z10.b, z11.b
        0x05ae_71ac, // trn1 z12.s, z13.s, z14.s
        0x0571_760f, // trn2 z15.h, z16.h, z17.h
        0x0520_1692, // ext  z18.b, z18.b, z20.b, #5
        0x05f8_3ad5, // rev  z21.d, z22.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (2, 0x2122_2324_2526_2728, 0x3132_3334_3536_3738),
            (4, 0x0000_0010_0000_0020, 0x0000_0030_0000_0040),
            (5, 0xffff_fff0_ffff_ffe0, 0xffff_fff0_ffff_ffc0),
            (7, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (8, 0x1001_1002_1003_1004, 0x1005_1006_1007_1008),
            (10, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (11, 0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918),
            (13, 0x0000_0010_0000_0020, 0x0000_0030_0000_0040),
            (14, 0xffff_fff0_ffff_ffe0, 0xffff_fff0_ffff_ffc0),
            (16, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (17, 0x1001_1002_1003_1004, 0x1005_1006_1007_1008),
            (18, 0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908),
            (20, 0x1716_1514_1312_1110, 0x1f1e_1d1c_1b1a_1918),
            (22, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE permute z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_ext_edge_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve") {
        eprintln!("[skip] host does not advertise SVE");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    for (label, insn) in [
        ("imm0", 0x0520_0020),  // ext z0.b, z0.b, z1.b, #0
        ("imm1", 0x0520_0420),  // ext z0.b, z0.b, z1.b, #1
        ("imm15", 0x0521_1c20), // ext z0.b, z0.b, z1.b, #15
        ("imm16", 0x0522_0020), // ext z0.b, z0.b, z1.b, #16
        ("imm31", 0x0523_1c20), // ext z0.b, z0.b, z1.b, #31
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.v[0] = 0x0706_0504_0302_0100;
            g.v[1] = 0x0f0e_0d0c_0b0a_0908;
            g.v[2] = 0x1716_1514_1312_1110;
            g.v[3] = 0x1f1e_1d1c_1b1a_1918;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE EXT edge {label} z0 low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_table_lookup_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0523_2820, // tbl z0.b, { z1.b, z2.b }, z3.b
        0x0566_2ca4, // tbx z4.h, z5.h, z6.h
        0x05a9_3107, // tbl z7.s, { z8.s }, z9.s
        0x05ec_2d6a, // tbx z10.d, z11.d, z12.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09),
            (2, 0x1817_1615_1413_1211, 0x201f_1e1d_1c1b_1a19),
            (3, 0x1f10_0f08_0700_0302, 0xff20_1a11_100f_0e0d),
            (4, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (5, 0x0004_0003_0002_0001, 0x0008_0007_0006_0005),
            (6, 0x0000_0004_0007_0008, 0x0003_0002_0001_0009),
            (8, 0x0000_0002_0000_0001, 0x0000_0004_0000_0003),
            (9, 0x0000_0000_0000_0003, 0x0000_0001_0000_0004),
            (10, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (11, 0x0000_0000_0000_0001, 0x0000_0000_0000_0002),
            (12, 0x0000_0000_0000_0001, 0x0000_0000_0000_0002),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 4, 7, 10] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE table lookup z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_bitperm_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svebitperm") {
        eprintln!("[skip] host does not advertise SVE bit-permute");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x45c2_b020, // bext z0.d, z1.d, z2.d
        0x45c5_b483, // bdep z3.d, z4.d, z5.d
        0x45c8_b8e6, // bgrp z6.d, z7.d, z8.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0xf0f0_0f0f_aaaa_5555;
        g.v[3] = 0x1357_9bdf_2468_ace0;
        g.v[4] = 0x0123_4567_89ab_cdef;
        g.v[5] = 0xfedc_ba98_7654_3210;
        g.v[8] = 0x5555_aaaa_ffff_0000;
        g.v[9] = 0x0f0f_f0f0_3333_cccc;
        g.v[10] = 0xffff_0000_5555_aaaa;
        g.v[11] = 0xf0f0_0f0f_9999_6666;
        g.v[14] = 0x0101_1010_1111_0000;
        g.v[15] = 0x1234_5678_9abc_def0;
        g.v[16] = 0x8080_7f7f_55aa_aa55;
        g.v[17] = 0x0bad_cafe_dead_beef;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 bit-permute z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_integer_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0462_7020, // sqdmulh  z0.h, z1.h, z2.h
        0x04a5_7483, // sqrdmulh z3.s, z4.s, z5.s
        0x4548_80e6, // saddlbt  z6.h, z7.b, z8.b
        0x458b_8949, // ssublbt  z9.s, z10.h, z11.h
        0x45ce_8dac, // ssubltb  z12.d, z13.s, z14.s
        0x4528_420f, // sqxtnb   z15.b, z16.h
        0x4528_462f, // sqxtnt   z15.b, z17.h
        0x4530_4a72, // uqxtnb   z18.h, z19.s
        0x4560_52b4, // sqxtunb  z20.s, z21.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (7, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (8, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (10, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (11, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (13, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (14, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (15, 0xaaaaaaaa_aaaaaaaa, 0x55555555_55555555),
            (16, 0x0100_ff00_007f_ff80, 0x1234_edcc_00ff_ff01),
            (17, 0x7fff_8000_0001_ffff, 0x0101_feff_00fe_ff02),
            (19, 0x0001_0000_ffff_ffff, 0x7fff_ffff_8000_0000),
            (21, 0xffff_ffff_ffff_ffff, 0x0000_0001_0000_0000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 20] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 integer z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_widening_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4542_3020, // sabdlb z0.h, z1.b, z2.b
        0x4585_3483, // sabdlt z3.s, z4.h, z5.h
        0x45c8_38e6, // uabdlb z6.d, z7.s, z8.s
        0x454b_4149, // saddwb z9.h, z10.h, z11.b
        0x458e_4dac, // uaddwt z12.s, z13.s, z14.h
        0x45d1_520f, // ssubwb z15.d, z16.d, z17.s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (7, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (8, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (10, 0x7f00_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (11, 0x0102_7f80_ff10_2030, 0x4050_6070_8090_a0b0),
            (13, 0x0000_0010_ffff_fff0, 0x7fff_0000_8000_0000),
            (14, 0x0001_ffff_0010_fff0, 0x7fff_8000_0100_ff00),
            (16, 0x0000_0001_0000_0000, 0xffff_ffff_0000_0000),
            (17, 0x0000_0002_ffff_fffe, 0x7fff_ffff_8000_0000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 widening z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_addsub_long_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4542_0020, // saddlb  z0.h, z1.b, z2.b
        0x4585_0483, // saddlt  z3.s, z4.h, z5.h
        0x45c8_08e6, // uaddlb  z6.d, z7.s, z8.s
        0x454b_0d49, // uaddlt  z9.h, z10.b, z11.b
        0x458e_11ac, // ssublb  z12.s, z13.h, z14.h
        0x45d1_1e0f, // usublt  z15.d, z16.s, z17.s
        0x4594_8272, // saddlbt z18.s, z19.h, z20.h
        0x45d7_8ad5, // ssublbt z21.d, z22.s, z23.s
        0x455a_8f38, // ssubltb z24.h, z25.b, z26.b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (7, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (8, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (10, 0x807f_4030_2010_00f0, 0x7e81_c0d0_e0f0_1020),
            (11, 0x0102_fe80_7f40_3020, 0xff00_807f_1122_3344),
            (13, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (14, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (16, 0xffff_ffff_0000_0000, 0x7fff_ffff_8000_0000),
            (17, 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            (19, 0x7fff_8000_4000_c000, 0x0001_ffff_7000_9000),
            (20, 0x4000_4000_8000_8000, 0x7fff_8000_2000_e000),
            (22, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (23, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (25, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (26, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 add/sub long z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_absdiff_accumulate_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4502_f820, // saba   z0.b, z1.b, z2.b
        0x4545_fc83, // uaba   z3.h, z4.h, z5.h
        0x4548_c0e6, // sabalb z6.h, z7.b, z8.b
        0x458b_c549, // sabalt z9.s, z10.h, z11.h
        0x45ce_c9ac, // uabalb z12.d, z13.s, z14.s
        0x4591_ce0f, // uabalt z15.s, z16.h, z17.h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x1010_1010_1010_1010, 0x2020_2020_2020_2020),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x0010_0020_0030_0040, 0x0050_0060_0070_0080),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (6, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (7, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (8, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (9, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (10, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (11, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (12, 0x0000_0000_0000_0010, 0xffff_ffff_ffff_fff0),
            (13, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (14, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (15, 0x0000_0010_ffff_fff0, 0x7fff_0000_8000_0000),
            (16, 0x0001_ffff_0010_fff0, 0x7fff_8000_0100_ff00),
            (17, 0x0102_7f80_ff10_2030, 0x4050_6070_8090_a0b0),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 abs-diff accumulate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_addsub_high_narrow_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4562_6020, // addhnb  z0.b, z1.h, z2.h
        0x45a5_6483, // addhnt  z3.h, z4.s, z5.s
        0x45e8_70e6, // subhnb  z6.s, z7.d, z8.d
        0x456b_7549, // subhnt  z9.b, z10.h, z11.h
        0x45ae_69ac, // raddhnb z12.h, z13.s, z14.s
        0x45f1_6e0f, // raddhnt z15.s, z16.d, z17.d
        0x4574_7a72, // rsubhnb z18.b, z19.h, z20.h
        0x45b7_7ed5, // rsubhnt z21.h, z22.s, z23.s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
            (1, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (2, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (3, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (4, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (5, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (6, 0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff),
            (7, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (8, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_ffff),
            (9, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (10, 0x8000_7fff_00ff_ff00, 0x1357_2468_aaaa_5555),
            (11, 0x0001_ffff_0100_ff00, 0x7fff_8000_0010_fff0),
            (12, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (13, 0xffff_ffff_0000_0000, 0x7fff_ffff_8000_0000),
            (14, 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            (15, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (16, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff),
            (17, 0x0000_0000_0000_0001, 0x8000_0000_0000_0000),
            (18, 0x0f0f_0f0f_0f0f_0f0f, 0xf0f0_f0f0_f0f0_f0f0),
            (19, 0xffff_0001_0100_00ff, 0x8000_7fff_1234_edcc),
            (20, 0x0100_ff00_007f_ff80, 0x1234_edcc_00ff_ff01),
            (21, 0xffff_0000_ffff_0000, 0x0000_ffff_0000_ffff),
            (22, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (23, 0x0000_0001_7fff_ffff, 0x8000_0000_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 add/sub high-narrow z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_shift_narrow_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x452c_1020, // shrnb     z0.b, z1.h, #4
        0x4538_1c83, // rshrnt    z3.h, z4.s, #8
        0x4570_20e6, // sqshrnb   z6.s, z7.d, #16
        0x452c_3d49, // uqrshrnt  z9.b, z10.h, #4
        0x4538_09ac, // sqrshrunb z12.h, z13.s, #8
        0x4570_0e0f, // sqrshrunt z15.s, z16.d, #16
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (3, 0xaaaa_5555_ffff_0000, 0x1111_2222_3333_4444),
            (4, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (7, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (9, 0x00ff_00ff_00ff_00ff, 0xff00_ff00_ff00_ff00),
            (10, 0x0001_ffff_0100_ff00, 0x7fff_8000_0010_fff0),
            (13, 0x7fff_ffff_8000_0000, 0x0000_0100_ffff_ff00),
            (15, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (16, 0x0000_0001_0000_0000, 0xffff_ffff_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 shift-narrow z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_shift_insert_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x450c_e020, // ssra  z0.b, z1.b, #4
        0x4518_e462, // usra  z2.h, z3.h, #8
        0x4550_e8a4, // srsra z4.s, z5.s, #16
        0x45c0_ece6, // ursra z6.d, z7.d, #32
        0x450f_f528, // sli   z8.b, z9.b, #7
        0x4518_f16a, // sri   z10.h, z11.h, #8
        0x455f_f5ac, // sli   z12.s, z13.s, #31
        0x45c0_f1ee, // sri   z14.d, z15.d, #32
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x1010_1010_1010_1010, 0x2020_2020_2020_2020),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0010_0020_0030_0040, 0x0050_0060_0070_0080),
            (3, 0xffff_0001_0100_00ff, 0x8000_7fff_1234_edcc),
            (4, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (7, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (8, 0x0f0f_0f0f_0f0f_0f0f, 0xf0f0_f0f0_f0f0_f0f0),
            (9, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (10, 0x00ff_00ff_00ff_00ff, 0xff00_ff00_ff00_ff00),
            (11, 0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321),
            (12, 0x0000_ffff_0000_ffff, 0xffff_0000_ffff_0000),
            (13, 0x0000_0002_0000_0001, 0x0000_0004_0000_0003),
            (14, 0xffff_0000_ffff_0000, 0x0000_ffff_0000_ffff),
            (15, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 shift insert/accumulate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_shift_imm_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue  p0.s
        0x2558_e081, // ptrue  p1.h, vl4
        0x25d8_e3e2, // ptrue  p2.d
        0x044c_83e0, // srshr  z0.s, p0/m, z0.s, #1
        0x044d_83e1, // urshr  z1.s, p0/m, z1.s, #1
        0x0406_8622, // sqshl  z2.h, p1/m, z2.h, #1
        0x0407_8623, // uqshl  z3.h, p1/m, z3.h, #1
        0x040f_8624, // sqshlu z4.h, p1/m, z4.h, #1
        0x0486_8885, // sqshl  z5.d, p2/m, z5.d, #4
        0x0487_8886, // uqshl  z6.d, p2/m, z6.d, #4
        0x048f_8887, // sqshlu z7.d, p2/m, z7.d, #4
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0000_0002_0000_0001, 0x8000_0000_ffff_ffff),
            (1, 0x0000_0003_0000_0001, 0x8000_0000_ffff_ffff),
            (2, 0xc000_4000_1234_8000, 0x1111_2222_3333_4444),
            (3, 0x8000_7fff_0001_ffff, 0xaaaa_bbbb_cccc_dddd),
            (4, 0x4000_c000_0001_ffff, 0x5555_6666_7777_8888),
            (5, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (6, 0x1000_0000_0000_0000, 0xf000_0000_0000_0000),
            (7, 0x0800_0000_0000_0000, 0xffff_ffff_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in 0usize..=7 {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 shift-immediate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_complex_add_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4500_d820, // cadd   z0.b, z0.b, z1.b, #90
        0x4540_dc83, // cadd   z3.h, z3.h, z4.h, #270
        0x4581_d8e6, // sqcadd z6.s, z6.s, z7.s, #90
        0x45c1_dd49, // sqcadd z9.d, z9.d, z10.d, #270
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (1, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (4, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (6, 0x7fff_ffff_8000_0000, 0x0000_0010_ffff_fff0),
            (7, 0x0000_0001_7fff_ffff, 0x8000_0000_ffff_ffff),
            (9, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (10, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 complex-add z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_sqrdmlah_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4442_7020, // sqrdmlah z0.h, z1.h, z2.h
        0x4485_7483, // sqrdmlsh z3.s, z4.s, z5.s
        0x44c8_70e6, // sqrdmlah z6.d, z7.d, z8.d
        0x444b_7549, // sqrdmlsh z9.h, z10.h, z11.h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (1, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (7, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (8, 0x4000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
            (9, 0x7fff_8000_0001_ffff, 0x0101_feff_00fe_ff02),
            (10, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (11, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 SQRDMLAH/SQRDMLSH z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_complex_mla_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4442_2020, // cmla      z0.h, z1.h, z2.h, #0
        0x4485_2483, // cmla      z3.s, z4.s, z5.s, #90
        0x4448_38e6, // sqrdcmlah z6.h, z7.h, z8.h, #180
        0x448b_3d49, // sqrdcmlah z9.s, z10.s, z11.s, #270
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (1, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (7, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (8, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (9, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (10, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (11, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 complex MLA z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_cdot_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4482_1020, // cdot z0.s, z1.b, z2.b, #0
        0x44c5_1483, // cdot z3.d, z4.h, z5.h, #90
        0x4488_18e6, // cdot z6.s, z7.b, z8.b, #180
        0x44cb_1d49, // cdot z9.d, z10.h, z11.h, #270
        0x44bc_41ac, // cdot z12.s, z13.b, z4.b[3], #0
        0x44f5_460f, // cdot z15.d, z16.h, z5.h[1], #90
        0x44b7_4a72, // cdot z18.s, z19.b, z7.b[2], #180
        0x44fb_4ed5, // cdot z21.d, z22.h, z11.h[1], #270
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (6, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (7, 0x807f_4030_2010_00f0, 0x7e81_c0d0_e0f0_1020),
            (8, 0x0102_fe80_7f40_3020, 0xff00_807f_1122_3344),
            (9, 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_0001),
            (10, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (11, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (12, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (13, 0x1020_3040_5060_7080, 0x90a0_b0c0_d0e0_f001),
            (15, 0x0000_0010_ffff_fff0, 0x7fff_0000_8000_0000),
            (16, 0x7fff_8000_4000_c000, 0x0001_ffff_7000_9000),
            (18, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (19, 0x0102_0304_0506_0708, 0x8081_7e7f_fefd_fcfa),
            (21, 0x0000_0000_0000_0010, 0xffff_ffff_ffff_fff0),
            (22, 0x0001_ffff_0010_fff0, 0x7fff_8000_0100_ff00),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 CDOT z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_dot_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") || !host_has_aarch64_feature("svei8mm") {
        eprintln!("[skip] host does not advertise SVE2 + SVE I8MM");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4482_0020, // sdot  z0.s, z1.b, z2.b
        0x44c5_0483, // udot  z3.d, z4.h, z5.h
        0x4488_78e6, // usdot z6.s, z7.b, z8.b
        0x44ba_0149, // sdot  z9.s, z10.b, z2.b[3]
        0x44f5_05ac, // udot  z12.d, z13.h, z5.h[1]
        0x44b4_1a0f, // usdot z15.s, z16.b, z4.b[2]
        0x44af_1e72, // sudot z18.s, z19.b, z7.b[1]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (6, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (7, 0x807f_4030_2010_00f0, 0x7e81_c0d0_e0f0_1020),
            (8, 0x0102_fe80_7f40_3020, 0xff00_807f_1122_3344),
            (9, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (10, 0x1020_3040_5060_7080, 0x90a0_b0c0_d0e0_f001),
            (12, 0x0000_0000_0000_0010, 0xffff_ffff_ffff_fff0),
            (13, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (15, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (16, 0x0102_0304_0506_0708, 0x8081_7e7f_fefd_fcfa),
            (18, 0x0000_0010_ffff_fff0, 0x7fff_0000_8000_0000),
            (19, 0x7f01_8002_7f03_8004, 0x7f05_8006_7f07_8008),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE dot z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_widening_mla_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4442_4020, // smlalb    z0.h, z1.b, z2.b
        0x4485_4483, // smlalt    z3.s, z4.h, z5.h
        0x44c8_48e6, // umlalb    z6.d, z7.s, z8.s
        0x444b_5d49, // umlslt    z9.h, z10.b, z11.b
        0x448e_51ac, // smlslb    z12.s, z13.h, z14.h
        0x44d1_4e0f, // umlalt    z15.d, z16.s, z17.s
        0x4454_6272, // sqdmlalb  z18.h, z19.b, z20.b
        0x4497_6ed5, // sqdmlslt  z21.s, z22.h, z23.h
        0x445a_0b38, // sqdmlalbt z24.h, z25.b, z26.b
        0x449d_0f9b, // sqdmlslbt z27.s, z28.h, z29.h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (5, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (6, 0x0000_0000_0000_0010, 0xffff_ffff_ffff_fff0),
            (7, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (8, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (9, 0x1010_1010_1010_1010, 0x2020_2020_2020_2020),
            (10, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (11, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (12, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (13, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (14, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (15, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (16, 0xffff_ffff_0000_0000, 0x7fff_ffff_8000_0000),
            (17, 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            (18, 0x7fff_7ffe_0001_8000, 0x0000_4000_c000_0002),
            (19, 0x7f80_7f80_8080_0101, 0x0202_fefe_4040_c0c0),
            (20, 0x8080_7f7f_8080_7f7f, 0x4040_c0c0_7f7f_8080),
            (21, 0x7fff_ffff_0000_0001, 0x8000_0000_ffff_ffff),
            (22, 0x7fff_8000_4000_c000, 0x0001_ffff_7000_9000),
            (23, 0x4000_4000_8000_8000, 0x7fff_8000_2000_e000),
            (24, 0x7fff_7ffe_0001_8000, 0x0000_4000_c000_0002),
            (25, 0x7f01_8002_7f03_8004, 0x7f05_8006_7f07_8008),
            (26, 0x017f_0280_037f_0480, 0x057f_0680_077f_0880),
            (27, 0x7fff_ffff_0000_0001, 0x8000_0000_ffff_ffff),
            (28, 0x7fff_8000_4000_c000, 0x0001_ffff_7000_9000),
            (29, 0x4000_4000_8000_8000, 0x7fff_8000_2000_e000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21, 24, 27] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 widening MLA z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_multiply_long_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4542_7020, // smullb   z0.h, z1.b, z2.b
        0x4585_7483, // smullt   z3.s, z4.h, z5.h
        0x45c8_78e6, // umullb   z6.d, z7.s, z8.s
        0x454b_7d49, // umullt   z9.h, z10.b, z11.b
        0x458e_61ac, // sqdmullb z12.s, z13.h, z14.h
        0x45d1_660f, // sqdmullt z15.d, z16.s, z17.s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (2, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (5, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (7, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (8, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
            (10, 0x807f_4030_2010_00f0, 0x7e81_c0d0_e0f0_1020),
            (11, 0x0102_fe80_7f40_3020, 0xff00_807f_1122_3344),
            (13, 0x7fff_8000_4000_c000, 0x0001_ffff_7000_9000),
            (14, 0x4000_4000_8000_8000, 0x7fff_8000_2000_e000),
            (16, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (17, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 multiply long z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_pairwise_accumulate_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2558_e060, // ptrue  p0.h, vl3
        0x4444_a020, // sadalp z0.h, p0/m, z1.b
        0x2598_e041, // ptrue  p1.s, vl2
        0x4485_a483, // uadalp z3.s, p1/m, z4.h
        0x25d8_e022, // ptrue  p2.d, vl1
        0x44c4_a8e6, // sadalp z6.d, p2/m, z7.s
        0x2558_e3e3, // ptrue  p3.h
        0x4445_ad49, // uadalp z9.h, p3/m, z10.b
        0x2598_e3e4, // ptrue  p4.s
        0x4484_b1ac, // sadalp z12.s, p4/m, z13.h
        0x25d8_e3e5, // ptrue  p5.d
        0x44c5_b60f, // uadalp z15.d, p5/m, z16.s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (6, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (7, 0x7fff_ffff_8000_0000, 0x0102_0304_fefd_fcfb),
            (9, 0x1010_1010_1010_1010, 0x2020_2020_2020_2020),
            (10, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (12, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (13, 0x8000_7fff_0100_ff00, 0x1234_edcc_4000_c000),
            (15, 0x0000_0000_0000_0010, 0xffff_ffff_ffff_fff0),
            (16, 0x0000_0001_0000_0002, 0xffff_ffff_0000_0004),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 pairwise accumulate z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_predicated_pairwise_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue p0.b, vl8
        0x4411_a020, // addp  z0.b, p0/m, z0.b, z1.b
        0x2558_e081, // ptrue p1.h, vl4
        0x4454_a483, // smaxp z3.h, p1/m, z3.h, z4.h
        0x2598_e042, // ptrue p2.s, vl2
        0x4495_a8e6, // umaxp z6.s, p2/m, z6.s, z7.s
        0x25d8_e023, // ptrue p3.d, vl1
        0x44d6_ad49, // sminp z9.d, p3/m, z9.d, z10.d
        0x2518_e3e4, // ptrue p4.b
        0x4417_b1ac, // uminp z12.b, p4/m, z12.b, z13.b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (1, 0x0102_0304_0506_0708, 0x090a_0b0c_0d0e_0f10),
            (3, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (4, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (6, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (7, 0x0000_0002_ffff_fffd, 0x8000_0000_7fff_ffff),
            (9, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (10, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_ffff),
            (12, 0x807f_4030_2010_00f0, 0x7e81_c0d0_e0f0_1020),
            (13, 0x0102_fe80_7f40_3020, 0xff00_807f_1122_3344),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 predicated pairwise z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_predicated_alu_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue  p0.b, vl8
        0x4402_8020, // srshl  z0.b, p0/m, z0.b, z1.b
        0x2558_e081, // ptrue  p1.h, vl4
        0x4443_8462, // urshl  z2.h, p1/m, z2.h, z3.h
        0x2598_e042, // ptrue  p2.s, vl2
        0x4488_88a4, // sqshl  z4.s, p2/m, z4.s, z5.s
        0x25d8_e023, // ptrue  p3.d, vl1
        0x44cb_8ce6, // uqrshl z6.d, p3/m, z6.d, z7.d
        0x2558_e3e4, // ptrue  p4.h
        0x4450_9128, // shadd  z8.h, p4/m, z8.h, z9.h
        0x4497_916a, // uhsubr z10.s, p4/m, z10.s, z11.s
        0x4418_91ac, // sqadd  z12.b, p4/m, z12.b, z13.b
        0x445f_91ee, // uqsubr z14.h, p4/m, z14.h, z15.h
        0x449c_9230, // suqadd z16.s, p4/m, z16.s, z17.s
        0x44dd_9272, // usqadd z18.d, p4/m, z18.d, z19.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (1, 0x0102_fffc_0506_00f8, 0x090a_0b0c_fefd_0201),
            (2, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (3, 0x0001_ffff_0004_fffc, 0x0008_fff8_0010_fff0),
            (4, 0x7fff_ffff_8000_0000, 0x0000_0001_ffff_ffff),
            (5, 0x0000_0001_ffff_ffff, 0x0000_0004_ffff_fffc),
            (6, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (7, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffc),
            (8, 0x7fff_8000_0100_ff00, 0x1234_edcc_4000_c000),
            (9, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
            (10, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (11, 0x0000_0002_ffff_fffd, 0x8000_0000_7fff_ffff),
            (12, 0x7f80_7f80_8080_0101, 0x0202_fefe_4040_c0c0),
            (13, 0x0102_0102_fffe_7f80, 0x8080_7f7f_4040_c0c0),
            (14, 0x0000_ffff_8000_7fff, 0x0100_00ff_f000_0fff),
            (15, 0xffff_0001_7fff_8000, 0x0001_ffff_1000_f000),
            (16, 0x7fff_ffff_0000_0001, 0x8000_0000_ffff_ffff),
            (17, 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            (18, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fff0),
            (19, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4, 6, 8, 10, 12, 14, 16, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 predicated ALU z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_predicated_unary_alu_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e100, // ptrue  p0.b, vl8
        0x4408_a020, // sqabs  z0.b, p0/m, z1.b
        0x2558_e081, // ptrue  p1.h, vl4
        0x4449_a483, // sqneg  z3.h, p1/m, z4.h
        0x2598_e3e2, // ptrue  p2.s
        0x4480_a8e6, // urecpe z6.s, p2/m, z7.s
        0x4481_a949, // ursqrte z9.s, p2/m, z10.s
        0x25d8_e3e3, // ptrue  p3.d
        0x44c8_adac, // sqabs  z12.d, p3/m, z13.d
        0x44c9_ae0f, // sqneg  z15.d, p3/m, z16.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
            (1, 0x7f80_0110_ff20_3040, 0x5060_7080_90a0_b0c0),
            (3, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (4, 0x8000_7fff_0001_ffff, 0x1234_edcc_4000_c000),
            (6, 0x0000_0001_ffff_fffe, 0x7fff_ffff_8000_0000),
            (7, 0x0000_0001_4000_0000, 0x7fff_ffff_8000_0000),
            (9, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (10, 0x0000_0001_4000_0000, 0x7fff_ffff_8000_0000),
            (12, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (13, 0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
            (15, 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_0001),
            (16, 0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 predicated unary ALU z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_indexed_multiply_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x443a_f820, // mul      z0.h, z1.h, z2.h[3]
        0x44ad_0883, // mla      z3.s, z4.s, z5.s[1]
        0x44f8_0ce6, // mls      z6.d, z7.d, z8.d[1]
        0x4434_f149, // sqdmulh  z9.h, z10.h, z4.h[2]
        0x44ad_f5ac, // sqrdmulh z12.s, z13.s, z5.s[1]
        0x4429_120f, // sqrdmlah z15.h, z16.h, z1.h[1]
        0x44a2_1672, // sqrdmlsh z18.s, z19.s, z2.s[0]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (7, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (8, 0x4000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
            (10, 0x7fff_8000_0001_ffff, 0x0101_feff_00fe_ff02),
            (12, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (13, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (15, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (16, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (18, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (19, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 indexed multiply z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_indexed_widening_multiply_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x44a2_c020, // smullb   z0.s, z1.h, z2.h[0]
        0x44e5_dc83, // umullt   z3.d, z4.s, z5.s[1]
        0x44a9_80e6, // smlalb   z6.s, z7.h, z1.h[2]
        0x44eb_b549, // umlslt   z9.d, z10.s, z11.s[0]
        0x44a2_29ac, // sqdmlalb z12.s, z13.h, z2.h[1]
        0x44e7_3e0f, // sqdmlslt z15.d, z16.s, z7.s[1]
        0x44aa_ee72, // sqdmullt z18.s, z19.h, z2.h[3]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (7, 0x7fff_8000_0001_ffff, 0x0101_feff_00fe_ff02),
            (9, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (10, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (11, 0x4000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
            (12, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (13, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (15, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (16, 0x4000_0000_0000_0000, 0x8000_0000_0000_0000),
            (19, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 indexed widening multiply z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_indexed_complex_mla_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x44aa_6020, // cmla      z0.h, z1.h, z2.h[1], #0
        0x44f5_6483, // cmla      z3.s, z4.s, z5.s[1], #90
        0x44b1_78e6, // sqrdcmlah z6.h, z7.h, z1.h[2], #180
        0x44eb_7d49, // sqrdcmlah z9.s, z10.s, z11.s[0], #270
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (1, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (2, 0x4000_4000_8000_8000, 0x2000_e000_7000_9000),
            (3, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (4, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (5, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
            (6, 0x0001_ffff_7fff_8000, 0x1234_edcc_4000_c000),
            (7, 0x4000_c000_7fff_8000, 0x1234_edcc_7000_9000),
            (9, 0x0000_0001_ffff_ffff, 0x7fff_ffff_8000_0000),
            (10, 0x4000_0000_c000_0000, 0x7fff_ffff_8000_0000),
            (11, 0x4000_0000_4000_0000, 0x7fff_ffff_8000_0000),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 indexed complex MLA z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_match_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2518_e3e1, // ptrue  p1.b
        0x4522_8420, // match  p0.b, p1/z, z1.b, z2.b
        0x0400_0083, // add    z3.b, p0/m, z3.b, z4.b
        0x2558_e3e1, // ptrue  p1.h
        0x4567_84d5, // nmatch p5.h, p1/z, z6.h, z7.h
        0x0440_1528, // add    z8.h, p5/m, z8.h, z9.h
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09),
            (2, 0x0063_0010_0008_0004, 0x00ff_00ee_00dd_00cc),
            (3, 0x1010_1010_1010_1010, 0x2020_2020_2020_2020),
            (4, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (6, 0x0004_0003_0002_0001, 0x0008_0007_0006_0005),
            (7, 0x00ff_0002_00ee_0004, 0x0007_00dd_00cc_00bb),
            (8, 0x0010_0020_0030_0040, 0x0050_0060_0070_0080),
            (9, 0x0001_0002_0003_0004, 0x0005_0006_0007_0008),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [3usize, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 MATCH/NMATCH z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.nzcv & 0xf000_0000,
        interp.nzcv & 0xf000_0000,
        "raw EL0 SVE2 MATCH/NMATCH NZCV mismatch"
    );
}

#[test]
fn raw_el0_sve2_histogram_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4522_a020, // histseg z0.b, z1.b, z2.b
        0x2598_e3e0, // ptrue   p0.s
        0x45a5_c083, // histcnt z3.s, p0/z, z4.s, z5.s
        0x25d8_e3e1, // ptrue   p1.d
        0x45e8_c4e6, // histcnt z6.d, p1/z, z7.d, z8.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (1usize, 0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09),
            (2, 0x1001_1002_1003_1004, 0x1005_1006_1007_1008),
            (4, 0x0000_0002_0000_0001, 0x0000_0002_0000_0003),
            (5, 0x0000_0001_0000_0001, 0x0000_0002_0000_0003),
            (7, 0x0000_0000_0000_0001, 0x0000_0000_0000_0002),
            (8, 0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 histogram z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_carry_eor_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4502_d020, // adclb z0.s, z1.s, z2.s
        0x4505_d483, // adclt z3.s, z4.s, z5.s
        0x45c8_d0e6, // sbclb z6.d, z7.d, z8.d
        0x45cb_d549, // sbclt z9.d, z10.d, z11.d
        0x450e_91ac, // eorbt z12.b, z13.b, z14.b
        0x4511_960f, // eortb z15.b, z16.b, z17.b
        0x4554_9272, // eorbt z18.h, z19.h, z20.h
        0x4597_96d5, // eortb z21.s, z22.s, z23.s
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0xffff_ffff_0000_0001, 0x0000_0001_ffff_fffe),
            (1, 0x0000_0002_7fff_ffff, 0xffff_ffff_8000_0000),
            (2, 0x0000_0001_0000_0000, 0x0000_0000_0000_0000),
            (3, 0x0000_0001_0000_0002, 0xffff_fffe_ffff_fffd),
            (4, 0x7fff_ffff_0000_0002, 0x8000_0000_ffff_ffff),
            (5, 0x0000_0000_0000_0000, 0x0000_0001_0000_0000),
            (6, 0x0000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            (7, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            (8, 0x0000_0000_0000_0000, 0x0000_0000_0000_0001),
            (9, 0x0000_0000_0000_0003, 0xffff_ffff_ffff_fffc),
            (10, 0x0000_0000_0000_0001, 0x7fff_ffff_ffff_ffff),
            (11, 0x0000_0000_0000_0000, 0x0000_0000_0000_0001),
            (12, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
            (13, 0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09),
            (14, 0x1817_1615_1413_1211, 0x201f_1e1d_1c1b_1a19),
            (15, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
            (16, 0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09),
            (17, 0x1817_1615_1413_1211, 0x201f_1e1d_1c1b_1a19),
            (18, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (19, 0x0004_0003_0002_0001, 0x0008_0007_0006_0005),
            (20, 0x1004_1003_1002_1001, 0x1008_1007_1006_1005),
            (21, 0xaaaa_bbbb_cccc_dddd, 0x1111_2222_3333_4444),
            (22, 0x0000_0002_0000_0001, 0x0000_0004_0000_0003),
            (23, 0x1000_0002_1000_0001, 0x1000_0004_1000_0003),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18, 21] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 carry/eor z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_bit_select_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve2") {
        eprintln!("[skip] host does not advertise SVE2");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0421_3c40, // bsl   z0.d, z0.d, z1.d, z2.d
        0x0464_3ca3, // bsl1n z3.d, z3.d, z4.d, z5.d
        0x04a7_3d06, // bsl2n z6.d, z6.d, z7.d, z8.d
        0x04ea_3d69, // nbsl  z9.d, z9.d, z10.d, z11.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x00ff_00ff_00ff_00ff, 0xff00_ff00_ff00_ff00),
            (1, 0x0f0f_0f0f_0f0f_0f0f, 0xf0f0_f0f0_f0f0_f0f0),
            (2, 0x3333_3333_3333_3333, 0xcccc_cccc_cccc_cccc),
            (3, 0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff),
            (4, 0x5555_aaaa_5555_aaaa, 0xaaaa_5555_aaaa_5555),
            (5, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (6, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (7, 0x0000_ffff_0000_ffff, 0xffff_0000_ffff_0000),
            (8, 0x1357_9bdf_2468_ace0, 0xfdb9_7531_eca8_6420),
            (9, 0x7fff_0000_8000_ffff, 0x0001_fffe_dead_beef),
            (10, 0xffff_0000_0000_ffff, 0x00ff_00ff_ff00_ff00),
            (11, 0xaaaa_5555_1234_5678, 0x8765_4321_5555_aaaa),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 bit-select z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_xar_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svesha3") {
        eprintln!("[skip] host does not advertise SVE SHA3");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x042c_3420, // xar z0.b, z0.b, z1.b, #4
        0x0438_3483, // xar z3.h, z3.h, z4.h, #8
        0x0470_34e6, // xar z6.s, z6.s, z7.s, #16
        0x04e0_3549, // xar z9.d, z9.d, z10.d, #32
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, lo, hi) in [
            (0usize, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
            (1, 0x0f0f_f0f0_3333_cccc, 0x5555_aaaa_00ff_ff00),
            (3, 0x1357_9bdf_2468_ace0, 0xfdb9_7531_eca8_6420),
            (4, 0x1111_2222_3333_4444, 0xaaaa_bbbb_cccc_dddd),
            (6, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            (7, 0x2122_2324_2526_2728, 0x3132_3334_3536_3738),
            (9, 0x4142_4344_4546_4748, 0x5152_5354_5556_5758),
            (10, 0x6162_6364_6566_6768, 0x7172_7374_7576_7778),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 XAR z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_pmull_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svepmull") {
        eprintln!("[skip] host does not advertise SVE PMULL");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4542_6820, // pmullb z0.h, z1.b, z2.b
        0x4545_6c83, // pmullt z3.h, z4.b, z5.b
        0x45c8_68e6, // pmullb z6.d, z7.s, z8.s
        0x45cb_6d49, // pmullt z9.d, z10.s, z11.s
        0x450e_69ac, // pmullb z12.q, z13.d, z14.d
        0x4511_6e0f, // pmullt z15.q, z16.d, z17.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x00ff_1020_3040_5060;
        g.v[3] = 0x7080_90a0_b0c0_d0e0;
        g.v[4] = 0xff00_efdf_cf9f_8f7f;
        g.v[5] = 0x6f5f_4f3f_2f1f_0f01;
        g.v[8] = 0x0123_4567_89ab_cdef;
        g.v[9] = 0xfedc_ba98_7654_3210;
        g.v[10] = 0x1111_2222_3333_4444;
        g.v[11] = 0x5555_6666_7777_8888;
        g.v[14] = 0x0123_4567_89ab_cdef;
        g.v[15] = 0xfedc_ba98_7654_3210;
        g.v[16] = 0x1111_2222_3333_4444;
        g.v[17] = 0x5555_6666_7777_8888;
        g.v[20] = 0x1357_9bdf_2468_ace0;
        g.v[21] = 0xfdb9_7531_eca8_6420;
        g.v[22] = 0x0f0f_f0f0_aaaa_5555;
        g.v[23] = 0x3333_cccc_7777_8888;
        g.v[26] = 0x0123_4567_89ab_cdef;
        g.v[27] = 0xfedc_ba98_7654_3210;
        g.v[28] = 0x1111_2222_3333_4444;
        g.v[29] = 0x5555_6666_7777_8888;
        g.v[32] = 0x1357_9bdf_2468_ace0;
        g.v[33] = 0xfdb9_7531_eca8_6420;
        g.v[34] = 0x0f0f_f0f0_aaaa_5555;
        g.v[35] = 0x3333_cccc_7777_8888;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 PMULL z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_aes_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sveaes") {
        eprintln!("[skip] host does not advertise SVE AES");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4522_e020, // aese   z0.b, z0.b, z1.b
        0x4522_e483, // aesd   z3.b, z3.b, z4.b
        0x4520_e006, // aesmc  z6.b, z6.b
        0x4520_e408, // aesimc z8.b, z8.b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x0011_2233_4455_6677;
        g.v[1] = 0x8899_aabb_ccdd_eeff;
        g.v[2] = 0x0f1e_2d3c_4b5a_6978;
        g.v[3] = 0x8796_a5b4_c3d2_e1f0;
        g.v[6] = 0xffee_ddcc_bbaa_9988;
        g.v[7] = 0x7766_5544_3322_1100;
        g.v[8] = 0x0123_4567_89ab_cdef;
        g.v[9] = 0xfedc_ba98_7654_3210;
        g.v[12] = 0x63ca_b704_0953_d051;
        g.v[13] = 0xcd60_e0e7_ba70_e18c;
        g.v[16] = 0x8e51_ef21_fabb_4522;
        g.v[17] = 0xe43d_7a06_543b_2b6c;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 AES z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve2_sha3_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svesha3") {
        eprintln!("[skip] host does not advertise SVE SHA3");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x0421_3840, // eor3 z0.d, z0.d, z1.d, z2.d
        0x0464_38a3, // bcax z3.d, z3.d, z4.d, z5.d
        0x04e0_34e6, // xar  z6.d, z6.d, z7.d, #32
        0x452a_f528, // rax1 z8.d, z9.d, z10.d
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x0123_4567_89ab_cdef;
        g.v[1] = 0xfedc_ba98_7654_3210;
        g.v[2] = 0x0f0f_f0f0_aaaa_5555;
        g.v[3] = 0x55aa_aa55_f0f0_0f0f;
        g.v[4] = 0x0011_2233_4455_6677;
        g.v[5] = 0x8899_aabb_ccdd_eeff;
        g.v[6] = 0x1020_3040_5060_7080;
        g.v[7] = 0x90a0_b0c0_d0e0_f001;
        g.v[8] = 0xffff_0000_3333_cccc;
        g.v[9] = 0x5555_aaaa_7777_8888;
        g.v[10] = 0x1357_9bdf_2468_ace0;
        g.v[11] = 0x0bad_cafe_dead_beef;
        g.v[12] = 0x1122_3344_5566_7788;
        g.v[13] = 0x99aa_bbcc_ddee_ff00;
        g.v[14] = 0xff00_ee11_dd22_cc33;
        g.v[15] = 0xbb44_aa55_9966_8877;
        g.v[16] = 0x0102_0304_0506_0708;
        g.v[17] = 0x1112_1314_1516_1718;
        g.v[18] = 0x2122_2324_2526_2728;
        g.v[19] = 0x3132_3334_3536_3738;
        g.v[20] = 0x4142_4344_4546_4748;
        g.v[21] = 0x5152_5354_5556_5758;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 8] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE2 SHA3 z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_i8mm_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svei8mm") {
        eprintln!("[skip] host does not advertise SVE I8MM");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x4502_9820, // smmla  z0.s, z1.b, z2.b
        0x45c5_9883, // ummla  z3.s, z4.b, z5.b
        0x4588_98e6, // usmmla z6.s, z7.b, z8.b
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x0000_0001_0000_0002;
        g.v[1] = 0x0000_0003_0000_0004;
        g.v[2] = 0x7f80_0102_0304_0506;
        g.v[3] = 0x0708_0910_1112_1314;
        g.v[4] = 0x8182_8384_8586_8788;
        g.v[5] = 0x8990_9192_9394_9596;
        g.v[6] = 0x0000_0010_0000_0020;
        g.v[7] = 0x0000_0030_0000_0040;
        g.v[8] = 0x0011_2233_4455_6677;
        g.v[9] = 0x8899_aabb_ccdd_eeff;
        g.v[10] = 0xffee_ddcc_bbaa_9988;
        g.v[11] = 0x7766_5544_3322_1100;
        g.v[12] = 0xffff_fff0_0000_0010;
        g.v[13] = 0x0000_0020_ffff_ffc0;
        g.v[14] = 0x80ff_7f01_0203_0405;
        g.v[15] = 0x0607_0809_0a0b_0c0d;
        g.v[16] = 0x1020_3040_5060_7080;
        g.v[17] = 0x90a0_b0c0_d0e0_f001;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE I8MM z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bfcvt_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("svebf16")
    {
        eprintln!("[skip] host does not advertise SVE2 + SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e040, // ptrue   p0.s, vl2
        0x658a_a020, // bfcvt   z0.h, p0/m, z1.s
        0x2598_e3e1, // ptrue   p1.s
        0x658a_a462, // bfcvt   z2.h, p1/m, z3.s
        0x648a_a4a4, // bfcvtnt z4.h, p1/m, z5.s
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };
    let setup = |g: &mut Aarch64GuestRegs| {
        for (reg, (lo, hi)) in [
            (
                0usize,
                pack_h([
                    0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
                ]),
            ),
            (
                1,
                pack_s_bits([0x3f80_7fff, 0x3f80_8000, 0x3f80_8001, 0xbf80_8000]),
            ),
            (
                2,
                pack_h([
                    0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555, 0xaaaa, 0x5555,
                ]),
            ),
            (
                3,
                pack_s_bits([0x0000_0000, 0x8000_0000, 0x7f80_0000, 0xff80_0000]),
            ),
            (
                4,
                pack_h([
                    0x0123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210,
                ]),
            ),
            (
                5,
                pack_s_bits([0x3fc0_0000, 0xc020_0000, 0x0080_0000, 0x8080_0000]),
            ),
        ] {
            g.v[2 * reg] = lo;
            g.v[2 * reg + 1] = hi;
        }
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 2, 4] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE BFCVT z{reg} low-128 mismatch"
        );
    }
    assert_eq!(
        hw.fpsr as u32, interp.fpsr as u32,
        "raw EL0 SVE BFCVT FPSR mismatch"
    );
}

#[test]
fn raw_el0_sve_bfcvt_ah_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp")
        || !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("svebf16")
    {
        eprintln!("[skip] host does not advertise AFP and SVE2 + SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    let packed = u128::from(0x7fa0_0001u32)
        | (u128::from(0x007f_ffffu32) << 32)
        | (u128::from(0x3f80_0001u32) << 64)
        | (u128::from(0x7f7f_ffffu32) << 96);

    for (label, insns) in [
        ("bfcvt", [0x2598_e3e0, 0x658a_a020]), // ptrue p0.s; bfcvt   z0.h, p0/m, z1.s
        ("bfcvtnt", [0x2598_e3e0, 0x648a_a020]), // ptrue p0.s; bfcvtnt z0.h, p0/m, z1.s
    ] {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0xaaaa_aaaa_aaaa_aaaa;
            g.v[1] = 0xbbbb_bbbb_bbbb_bbbb;
            g.v[2] = packed as u64;
            g.v[3] = (packed >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bfcvt_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("sve")
        || !host_has_aarch64_feature("sve2")
        || !host_has_aarch64_feature("svebf16")
    {
        eprintln!("[skip] host does not advertise SVE2 + SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x2598_e3e0, // ptrue   p0.s
        0x658a_a020, // bfcvt   z0.h, p0/m, z1.s
        0x2598_e3e1, // ptrue   p1.s
        0x648a_a4a4, // bfcvtnt z4.h, p1/m, z5.s
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s_bits = |xs: [u32; 4]| -> (u64, u64) {
        let lo = u64::from(xs[0]) | (u64::from(xs[1]) << 32);
        let hi = u64::from(xs[2]) | (u64::from(xs[3]) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    0usize,
                    pack_h([
                        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
                    ]),
                ),
                (
                    1,
                    pack_s_bits([0x3f80_7fff, 0x3f80_8000, 0x3f80_8001, 0xbf80_8000]),
                ),
                (
                    4,
                    pack_h([
                        0x0123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210,
                    ]),
                ),
                (
                    5,
                    pack_s_bits([0x3fc0_7fff, 0x3fc0_8000, 0x3fc0_8001, 0xbfc0_8000]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [0usize, 4] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE BFCVT FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE BFCVT FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bf16_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svebf16") {
        eprintln!("[skip] host does not advertise SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x6462_8020, // bfdot   z0.s, z1.h, z2.h
        0x6465_e483, // bfmmla  z3.s, z4.h, z5.h
        0x64e8_80e6, // bfmlalb z6.s, z7.h, z8.h
        0x64eb_8549, // bfmlalt z9.s, z10.h, z11.h
        0x647e_41ac, // bfdot   z12.s, z13.h, z6.h[3]
        0x64ec_420f, // bfmlalb z15.s, z16.h, z4.h[2]
        0x64ed_4e72, // bfmlalt z18.s, z19.h, z5.h[3]
    ];
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[0] = 0x3f80_0000_4000_0000;
        g.v[1] = 0x4040_0000_4080_0000;
        g.v[2] = 0x3f80_4000_4040_4080;
        g.v[3] = 0xbf80_c000_c040_c080;
        g.v[4] = 0x0000_0001_0000_0002;
        g.v[5] = 0x0000_0003_0000_0004;
        g.v[6] = 0x3f80_4000_4040_4080;
        g.v[7] = 0xbf80_c000_c040_c080;
        g.v[8] = 0x3f80_0000_4000_0000;
        g.v[9] = 0x4040_0000_4080_0000;
        g.v[10] = 0x3f80_4000_4040_4080;
        g.v[11] = 0xbf80_c000_c040_c080;
        g.v[12] = 0x0000_0010_0000_0020;
        g.v[13] = 0x0000_0030_0000_0040;
        g.v[14] = 0x3f80_4000_4040_4080;
        g.v[15] = 0xbf80_c000_c040_c080;
        g.v[18] = 0x0000_0100_0000_0200;
        g.v[19] = 0x0000_0300_0000_0400;
        g.v[20] = 0x3f80_4000_4040_4080;
        g.v[21] = 0xbf80_c000_c040_c080;
        g.v[22] = 0x3f80_0000_4000_0000;
        g.v[23] = 0x4040_0000_4080_0000;
        g.v[24] = 0x0000_0001_ffff_ffff;
        g.v[25] = 0x7fff_ffff_8000_0000;
        g.v[26] = 0x3f80_4000_4040_4080;
        g.v[27] = 0xbf80_c000_c040_c080;
        g.v[30] = 0x0000_0010_0000_0020;
        g.v[31] = 0x0000_0030_0000_0040;
        g.v[32] = 0x3f80_4000_4040_4080;
        g.v[33] = 0xbf80_c000_c040_c080;
        g.v[36] = 0x0000_0100_0000_0200;
        g.v[37] = 0x0000_0300_0000_0400;
        g.v[38] = 0x3f80_4000_4040_4080;
        g.v[39] = 0xbf80_c000_c040_c080;
    };

    let hw = raw_native_run_fp(&insns, setup);
    let interp = raw_interp_run(&insns, setup);
    for reg in [0usize, 3, 6, 9, 12, 15, 18] {
        let lo = 2 * reg;
        let hi = lo + 1;
        assert_eq!(
            (hw.v[lo], hw.v[hi]),
            (interp.v[lo], interp.v[hi]),
            "raw EL0 SVE BF16 z{reg} low-128 mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bf16_dot_ah_qnan_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("svebf16") {
        eprintln!("[skip] host does not advertise AFP and SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const QNAN_BF16: u128 = 0x7fc0_7fc0_7fc0_7fc0_7fc0_7fc0_7fc0_7fc0;
    let cases = [("bfdot", 0x6462_8020), ("bfmmla", 0x6462_e420)];

    for (label, insn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = 0;
            g.v[1] = 0;
            g.v[2] = QNAN_BF16 as u64;
            g.v[3] = (QNAN_BF16 >> 64) as u64;
            g.v[4] = QNAN_BF16 as u64;
            g.v[5] = (QNAN_BF16 >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE BF16 AH {label} qNaN z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE BF16 AH {label} qNaN FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bfmlal_ah_subnormal_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("svebf16") {
        eprintln!("[skip] host does not advertise AFP and SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const ZN: u128 = 0x0001_0001_0001_0001_0001_0001_0001_0001;
    const ZM: u128 = 0x3f80_3f80_3f80_3f80_3f80_3f80_3f80_3f80;
    const ACC: u128 = 0x0000_0001_0000_0001_0000_0001_0000_0001;
    let cases = [
        ("bfmlalb_product", 0x64e2_8020, 0u128, ZN),
        ("bfmlalb_acc", 0x64e2_8020, ACC, 0),
        ("bfmlalt_product", 0x64e2_8420, 0, ZN),
        ("bfmlalt_acc", 0x64e2_8420, ACC, 0),
    ];

    for (label, insn, rd, rn) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            g.v[0] = rd as u64;
            g.v[1] = (rd >> 64) as u64;
            g.v[2] = rn as u64;
            g.v[3] = (rn >> 64) as u64;
            g.v[4] = ZM as u64;
            g.v[5] = (ZM >> 64) as u64;
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bfmlal_ah_nan_status_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("afp") || !host_has_aarch64_feature("svebf16") {
        eprintln!("[skip] host does not advertise AFP and SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    const FPCR_AH: u64 = 1 << 1;
    const STATUS_PATTERN: u128 = 0x3c00_0001_7d01_7e00_3c00_0001_7d01_7e00;
    const NAN_PATTERN: u128 = 0x3f80_0000_0000_0001_7fa0_0001_7fc0_2000;
    const INF_ZERO_PATTERN: u128 = 0x3f80_0000_0000_0000_7f80_0000_0000_0001;
    let cases = [
        ("bfmlalb_status", 0x64e2_8020, STATUS_PATTERN),
        ("bfmlalt_status", 0x64e2_8420, STATUS_PATTERN),
        ("bfmlalb_idx_nan", 0x64ea_4820, NAN_PATTERN),
        ("bfmlalt_idx_nan", 0x64ea_4c20, NAN_PATTERN),
        ("bfmlalb_idx_inf_zero", 0x64ea_4820, INF_ZERO_PATTERN),
        ("bfmlalt_idx_inf_zero", 0x64ea_4c20, INF_ZERO_PATTERN),
    ];

    for (label, insn, pattern) in cases {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = FPCR_AH;
            for reg in [0usize, 1, 2] {
                g.v[2 * reg] = pattern as u64;
                g.v[2 * reg + 1] = (pattern >> 64) as u64;
            }
            g.fpsr = 0;
        };

        let hw = raw_native_run_fp(&[insn], setup);
        let interp = raw_interp_run(&[insn], setup);
        assert_eq!(
            (hw.v[0], hw.v[1]),
            (interp.v[0], interp.v[1]),
            "raw EL0 SVE AH {label} z0 low-128 mismatch"
        );
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE AH {label} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_sve_bf16_fmlal_fpcr_rounding_oracle_matches_interpreter() {
    if !host_has_aarch64_feature("svebf16") {
        eprintln!("[skip] host does not advertise SVE BF16");
        return;
    }
    assert_eq!(pin_sve_vl_128(), Some(16), "failed to pin SVE VL=128");

    let insns = [
        0x64e8_80e6, // bfmlalb z6.s, z7.h, z8.h
        0x64eb_8549, // bfmlalt z9.s, z10.h, z11.h
    ];
    let pack_h = |xs: [u16; 8]| -> (u64, u64) {
        let mut lo = 0u64;
        let mut hi = 0u64;
        for (i, &x) in xs.iter().enumerate() {
            if i < 4 {
                lo |= u64::from(x) << (16 * i);
            } else {
                hi |= u64::from(x) << (16 * (i - 4));
            }
        }
        (lo, hi)
    };
    let pack_s = |a: f32, b: f32, c: f32, d: f32| -> (u64, u64) {
        let lo = u64::from(a.to_bits()) | (u64::from(b.to_bits()) << 32);
        let hi = u64::from(c.to_bits()) | (u64::from(d.to_bits()) << 32);
        (lo, hi)
    };

    for rmode in 0..4u64 {
        let setup = |g: &mut Aarch64GuestRegs| {
            g.fpcr = rmode << 22;
            for (reg, (lo, hi)) in [
                (
                    6usize,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    7,
                    pack_h([
                        0x3f80, 0x3f80, 0xbf80, 0x3f80, 0x3f80, 0x3f80, 0xbf80, 0x3f80,
                    ]),
                ),
                (
                    8,
                    pack_h([
                        0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80,
                    ]),
                ),
                (
                    9,
                    pack_s(16_777_216.0, -16_777_216.0, 16_777_216.0, -16_777_216.0),
                ),
                (
                    10,
                    pack_h([
                        0x3f80, 0x3f80, 0xbf80, 0x3f80, 0x3f80, 0x3f80, 0xbf80, 0x3f80,
                    ]),
                ),
                (
                    11,
                    pack_h([
                        0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80,
                    ]),
                ),
            ] {
                g.v[2 * reg] = lo;
                g.v[2 * reg + 1] = hi;
            }
        };

        let hw = raw_native_run_fp(&insns, setup);
        let interp = raw_interp_run(&insns, setup);
        for reg in [6usize, 9] {
            let lo = 2 * reg;
            let hi = lo + 1;
            assert_eq!(
                (hw.v[lo], hw.v[hi]),
                (interp.v[lo], interp.v[hi]),
                "raw EL0 SVE BF16 FMLAL FPCR rmode {rmode} z{reg} low-128 mismatch"
            );
        }
        assert_eq!(
            hw.fpsr as u32, interp.fpsr as u32,
            "raw EL0 SVE BF16 FMLAL FPCR rmode {rmode} FPSR mismatch"
        );
    }
}

#[test]
fn raw_el0_control_flow_oracle_matches_interpreter() {
    let cond_branch = [
        0xeb02_003f, // cmp  x1, x2
        0x5400_0060, // b.eq +12
        0xd280_0220, // mov  x0, #0x11
        0x1400_0002, // b    +8
        0xd280_0440, // mov  x0, #0x22
    ];
    assert_raw_gpr0_to_gpr2_nzcv_matches("b.eq taken", &cond_branch, |g| {
        g.x[1] = 7;
        g.x[2] = 7;
    });
    assert_raw_gpr0_to_gpr2_nzcv_matches("b.eq not taken", &cond_branch, |g| {
        g.x[1] = 9;
        g.x[2] = 7;
    });

    let cbz = [
        0xb400_0061, // cbz x1, +12
        0xd280_0660, // mov x0, #0x33
        0x1400_0002, // b   +8
        0xd280_0880, // mov x0, #0x44
    ];
    assert_raw_gpr0_to_gpr2_nzcv_matches("cbz taken", &cbz, |g| {
        g.x[1] = 0;
    });
    assert_raw_gpr0_to_gpr2_nzcv_matches("cbz not taken", &cbz, |g| {
        g.x[1] = 1;
    });

    let cbnz = [
        0xb500_0061, // cbnz x1, +12
        0xd280_0aa0, // mov  x0, #0x55
        0x1400_0002, // b    +8
        0xd280_0cc0, // mov  x0, #0x66
    ];
    assert_raw_gpr0_to_gpr2_nzcv_matches("cbnz taken", &cbnz, |g| {
        g.x[1] = 1;
    });
    assert_raw_gpr0_to_gpr2_nzcv_matches("cbnz not taken", &cbnz, |g| {
        g.x[1] = 0;
    });

    let tbz = [
        0x3608_0061, // tbz w1, #1, +12
        0xd280_0ee0, // mov x0, #0x77
        0x1400_0002, // b   +8
        0xd280_1100, // mov x0, #0x88
    ];
    assert_raw_gpr0_to_gpr2_nzcv_matches("tbz taken", &tbz, |g| {
        g.x[1] = 0;
    });
    assert_raw_gpr0_to_gpr2_nzcv_matches("tbz not taken", &tbz, |g| {
        g.x[1] = 2;
    });

    let tbnz = [
        0x3708_0061, // tbnz w1, #1, +12
        0xd280_1320, // mov  x0, #0x99
        0x1400_0002, // b    +8
        0xd280_1540, // mov  x0, #0xaa
    ];
    assert_raw_gpr0_to_gpr2_nzcv_matches("tbnz taken", &tbnz, |g| {
        g.x[1] = 2;
    });
    assert_raw_gpr0_to_gpr2_nzcv_matches("tbnz not taken", &tbnz, |g| {
        g.x[1] = 0;
    });
}

#[test]
fn sub_register() {
    // cb020020  sub x0, x1, x2
    let r = run(&[0xcb02_0020], |g| {
        g.x[1] = 100;
        g.x[2] = 58;
    });
    assert_eq!(r.x[0], 42);
}

#[test]
fn logical_and_orr() {
    // 8a020020  and x0, x1, x2
    let r = run(&[0x8a02_0020], |g| {
        g.x[1] = 0xff0f;
        g.x[2] = 0x0ff0;
    });
    assert_eq!(r.x[0], 0x0f00);

    // aa020020  orr x0, x1, x2
    let r = run(&[0xaa02_0020], |g| {
        g.x[1] = 0xf0;
        g.x[2] = 0x0f;
    });
    assert_eq!(r.x[0], 0xff);
}

#[test]
fn multi_instruction_block_chains_through_arch_regs() {
    // 8b020023  add x3, x1, x2
    // cb010060  sub x0, x3, x1   => x0 = (x1 + x2) - x1 = x2
    let r = run(&[0x8b02_0023, 0xcb01_0060], |g| {
        g.x[1] = 1000;
        g.x[2] = 42;
    });
    assert_eq!(r.x[3], 1042);
    assert_eq!(r.x[0], 42);
}

#[test]
fn mul() {
    // 9b027c20  mul x0, x1, x2  (madd x0,x1,x2,xzr)
    let r = run(&[0x9b02_7c20], |g| {
        g.x[1] = 6;
        g.x[2] = 7;
    });
    assert_eq!(r.x[0], 42);
}

#[test]
fn flags_subs_then_cset() {
    // eb02_0020  subs x0, x1, x2   (sets NZCV)
    // 9a9f_17e3  cset x3, eq       (x3 = (x1==x2) ? 1 : 0)
    let eq = run(&[0xeb02_0020, 0x9a9f_17e3], |g| {
        g.x[1] = 7;
        g.x[2] = 7;
    });
    assert_eq!(eq.x[0], 0, "7 - 7 == 0");
    assert_eq!(eq.x[3], 1, "Z set => cset eq = 1");

    let ne = run(&[0xeb02_0020, 0x9a9f_17e3], |g| {
        g.x[1] = 9;
        g.x[2] = 7;
    });
    assert_eq!(ne.x[0], 2);
    assert_eq!(ne.x[3], 0, "Z clear => cset eq = 0");
}

#[test]
fn conditional_select_aliases_transform_on_true_condition() {
    let insns = [
        0xeb02_0020, // subs x0, x1, x2
        0x5a9f_13ea, // csetm w10, eq
        0x9a85_14a4, // cinc x4, x5, eq
        0xda87_10e6, // cinv x6, x7, eq
        0xda89_1528, // cneg x8, x9, eq
    ];

    let eq = run(&insns, |g| {
        g.x[1] = 7;
        g.x[2] = 7;
        g.x[5] = 10;
        g.x[7] = 0x55;
        g.x[9] = 5;
    });
    assert_eq!(eq.x[10], 0xffff_ffff, "csetm w10, eq");
    assert_eq!(eq.x[4], 11, "cinc x4, x5, eq");
    assert_eq!(eq.x[6], !0x55u64, "cinv x6, x7, eq");
    assert_eq!(eq.x[8], 0u64.wrapping_sub(5), "cneg x8, x9, eq");

    let ne = run(&insns, |g| {
        g.x[1] = 9;
        g.x[2] = 7;
        g.x[5] = 10;
        g.x[7] = 0x55;
        g.x[9] = 5;
    });
    assert_eq!(ne.x[10], 0, "csetm w10, eq false");
    assert_eq!(ne.x[4], 10, "cinc x4, x5, eq false");
    assert_eq!(ne.x[6], 0x55, "cinv x6, x7, eq false");
    assert_eq!(ne.x[8], 5, "cneg x8, x9, eq false");
}

#[test]
fn shifted_neg_and_mvn_aliases_execute_natively() {
    let r = run(
        &[
            0xcb01_07e0, // neg  x0, x1, lsl #1
            0x2aa3_0fe2, // mvn  w2, w3, asr #3
            0xaa65_13e4, // mvn  x4, x5, lsr #4
            0xeb07_07e6, // negs x6, x7, lsl #1
            0xaa2d_098b, // orn  x11, x12, x13, lsl #2
            0xca70_15ee, // eon  x14, x15, x16, lsr #5
        ],
        |g| {
            g.x[1] = 21;
            g.x[3] = 0xffff_fff0;
            g.x[5] = 0xf000_0000_0000_0000;
            g.x[7] = 0x4000_0000_0000_0000;
            g.x[12] = 0x80;
            g.x[13] = 0x10;
            g.x[15] = 0x1234_5678_9abc_def0;
            g.x[16] = 0xffff_0000_0000_0000;
        },
    );

    assert_eq!(r.x[0], 0u64.wrapping_sub(42));
    assert_eq!(r.x[2], 1, "32-bit mvn must zero-extend the W result");
    assert_eq!(r.x[4], !(0xf000_0000_0000_0000u64 >> 4));
    assert_eq!(r.x[6], 0x8000_0000_0000_0000);
    assert_eq!(r.x[11], 0x80 | !(0x10u64 << 2));
    assert_eq!(
        r.x[14],
        0x1234_5678_9abc_def0u64 ^ !(0xffff_0000_0000_0000u64 >> 5)
    );
    assert_eq!(r.nzcv & 0xf000_0000, 0x9000_0000, "N and V set");
}

#[test]
fn inverted_logic_register_sources_execute_natively() {
    let r = run(
        &[
            0xaa22_0020, // orn x0, x1, x2
            0xca25_0083, // eon x3, x4, x5
            0x2a28_00e6, // orn w6, w7, w8
            0x4a2b_0149, // eon w9, w10, w11
        ],
        |g| {
            g.x[1] = 0x00ff_0000_0000_00ff;
            g.x[2] = 0x0000_ffff_0000_ffff;
            g.x[4] = 0x1234_5678_9abc_def0;
            g.x[5] = 0x0f0f_0f0f_0f0f_0f0f;
            g.x[7] = 0x0000_0000_f0f0_0000;
            g.x[8] = 0xffff_ffff_00ff_00ff;
            g.x[10] = 0xffff_ffff_1234_5678;
            g.x[11] = 0xffff_ffff_f0f0_f0f0;
            g.nzcv = 0x6000_0000;
        },
    );

    assert_eq!(r.x[0], 0x00ff_0000_0000_00ff | !0x0000_ffff_0000_ffffu64);
    assert_eq!(r.x[3], 0x1234_5678_9abc_def0 ^ !0x0f0f_0f0f_0f0f_0f0fu64);
    assert_eq!(r.x[6], u64::from(0xf0f0_0000u32 | !0x00ff_00ffu32));
    assert_eq!(r.x[9], u64::from(0x1234_5678u32 ^ !0xf0f0_f0f0u32));
    assert_eq!(r.nzcv & 0xf000_0000, 0x6000_0000);
}

#[test]
fn vector_bic_executes_natively() {
    let r = fp_run(
        &[
            0x4e62_1c20, // bic v0.16b, v1.16b, v2.16b
            0x0e65_1c83, // bic v3.8b,  v4.8b,  v5.8b
        ],
        |g| {
            g.v[2] = 0x0123_4567_89ab_cdef;
            g.v[3] = 0xfedc_ba98_7654_3210;
            g.v[4] = 0x0f0f_f0f0_55aa_aa55;
            g.v[5] = 0x3333_cccc_9696_6969;
            g.v[8] = 0xffff_0000_ffff_0000;
            g.v[9] = 0x0000_ffff_0000_ffff;
            g.v[10] = 0x00ff_00ff_00ff_00ff;
            g.v[11] = 0xff00_ff00_ff00_ff00;
        },
    );

    assert_eq!(r.v[0], 0x0123_4567_89ab_cdefu64 & !0x0f0f_f0f0_55aa_aa55u64);
    assert_eq!(r.v[1], 0xfedc_ba98_7654_3210u64 & !0x3333_cccc_9696_6969u64);
    assert_eq!(r.v[6], 0xffff_0000_ffff_0000u64 & !0x00ff_00ff_00ff_00ffu64);
    assert_eq!(r.v[7], 0, "8-byte vector bic must clear the high half");
}

#[test]
fn vector_orn_executes_natively() {
    let r = fp_run(
        &[
            0x4ee2_1c20, // orn v0.16b, v1.16b, v2.16b
            0x0ee5_1c83, // orn v3.8b,  v4.8b,  v5.8b
        ],
        |g| {
            g.v[2] = 0x0123_4567_89ab_cdef;
            g.v[3] = 0xfedc_ba98_7654_3210;
            g.v[4] = 0x0f0f_f0f0_55aa_aa55;
            g.v[5] = 0x3333_cccc_9696_6969;
            g.v[8] = 0xffff_0000_ffff_0000;
            g.v[9] = 0x0000_ffff_0000_ffff;
            g.v[10] = 0x00ff_00ff_00ff_00ff;
            g.v[11] = 0xff00_ff00_ff00_ff00;
        },
    );

    assert_eq!(r.v[0], 0x0123_4567_89ab_cdefu64 | !0x0f0f_f0f0_55aa_aa55u64);
    assert_eq!(r.v[1], 0xfedc_ba98_7654_3210u64 | !0x3333_cccc_9696_6969u64);
    assert_eq!(r.v[6], 0xffff_0000_ffff_0000u64 | !0x00ff_00ff_00ff_00ffu64);
    assert_eq!(r.v[7], 0, "8-byte vector orn must clear the high half");
}

#[test]
fn vector_bit_select_ops_execute_natively() {
    let r = fp_run(
        &[
            0x6e62_1c20, // bsl v0.16b, v1.16b, v2.16b
            0x6ea5_1c83, // bit v3.16b, v4.16b, v5.16b
            0x6ee8_1ce6, // bif v6.16b, v7.16b, v8.16b
            0x2e6b_1d49, // bsl v9.8b,  v10.8b, v11.8b
        ],
        |g| {
            g.v[0] = 0x00ff_00ff_00ff_00ff;
            g.v[1] = 0xff00_ff00_ff00_ff00;
            g.v[2] = 0x1111_2222_3333_4444;
            g.v[3] = 0x5555_6666_7777_8888;
            g.v[4] = 0x9999_aaaa_bbbb_cccc;
            g.v[5] = 0xdddd_eeee_ffff_0000;
            g.v[6] = 0x0123_4567_89ab_cdef;
            g.v[7] = 0xfedc_ba98_7654_3210;
            g.v[8] = 0x0f0f_f0f0_3333_cccc;
            g.v[9] = 0xffff_0000_cccc_3333;
            g.v[10] = 0x1234_5678_9abc_def0;
            g.v[11] = 0x0f0f_f0f0_55aa_aa55;
            g.v[12] = 0x00ff_00ff_00ff_00ff;
            g.v[13] = 0xff00_ff00_ff00_ff00;
            g.v[14] = 0x1357_9bdf_2468_ace0;
            g.v[15] = 0x0f0f_f0f0_3333_cccc;
            g.v[16] = 0xaaaa_5555_ffff_0000;
            g.v[17] = 0x3333_cccc_5555_aaaa;
            g.v[18] = 0xffff_0000_ffff_0000;
            g.v[19] = 0x1111_2222_3333_4444;
            g.v[20] = 0x1234_5678_9abc_def0;
            g.v[22] = 0x0f0f_f0f0_55aa_aa55;
        },
    );

    let bsl_lo = (0x1111_2222_3333_4444u64 & 0x00ff_00ff_00ff_00ffu64)
        | (0x9999_aaaa_bbbb_ccccu64 & !0x00ff_00ff_00ff_00ffu64);
    let bsl_hi = (0x5555_6666_7777_8888u64 & 0xff00_ff00_ff00_ff00u64)
        | (0xdddd_eeee_ffff_0000u64 & !0xff00_ff00_ff00_ff00u64);
    assert_eq!(r.v[0], bsl_lo, "bsl low half");
    assert_eq!(r.v[1], bsl_hi, "bsl high half");

    let bit_lo = (0x0f0f_f0f0_3333_ccccu64 & 0x1234_5678_9abc_def0u64)
        | (0x0123_4567_89ab_cdefu64 & !0x1234_5678_9abc_def0u64);
    let bit_hi = (0xffff_0000_cccc_3333u64 & 0x0f0f_f0f0_55aa_aa55u64)
        | (0xfedc_ba98_7654_3210u64 & !0x0f0f_f0f0_55aa_aa55u64);
    assert_eq!(r.v[6], bit_lo, "bit low half");
    assert_eq!(r.v[7], bit_hi, "bit high half");

    let bif_lo = (0x00ff_00ff_00ff_00ffu64 & 0xaaaa_5555_ffff_0000u64)
        | (0x1357_9bdf_2468_ace0u64 & !0xaaaa_5555_ffff_0000u64);
    let bif_hi = (0xff00_ff00_ff00_ff00u64 & 0x3333_cccc_5555_aaaau64)
        | (0x0f0f_f0f0_3333_ccccu64 & !0x3333_cccc_5555_aaaau64);
    assert_eq!(r.v[12], bif_lo, "bif low half");
    assert_eq!(r.v[13], bif_hi, "bif high half");

    let bsl8 = (0x1234_5678_9abc_def0u64 & 0xffff_0000_ffff_0000u64)
        | (0x0f0f_f0f0_55aa_aa55u64 & !0xffff_0000_ffff_0000u64);
    assert_eq!(r.v[18], bsl8, "8-byte bsl low half");
    assert_eq!(r.v[19], 0, "8-byte bsl must clear the high half");
}

#[test]
fn fpcr_sysreg_only_block_uses_fp_trampoline() {
    // d51b4401  msr fpcr, x1
    // d53b4400  mrs x0, fpcr
    let r = run(&[0xd51b_4401, 0xd53b_4400], |g| {
        g.x[1] = 0x00c0_0000;
        g.fpcr = 0;
    });
    assert_eq!(r.x[0] & 0xffff_ffff, 0x00c0_0000);
    assert_eq!(r.fpcr & 0xffff_ffff, 0x00c0_0000);
}

#[test]
fn high_callee_saved_regs() {
    // Exercises the trampoline's single-ldr/str marshaling of x19..x29
    // (distinct from the ldp-paired x0..x17 path).
    // 8b150293  add x19, x20, x21
    // aa1303e0  mov x0, x19
    let r = run(&[0x8b15_0293, 0xaa13_03e0], |g| {
        g.x[20] = 300;
        g.x[21] = 33;
    });
    assert_eq!(r.x[19], 333);
    assert_eq!(r.x[0], 333);
}

#[test]
fn movz_builds_constant() {
    // d2824680  movz x0, #0x1234
    let r = run(&[0xd282_4680], |_g| {});
    assert_eq!(r.x[0], 0x1234);
}

// Multi-block region with a native-exit stub: the entry block computes
// `add x0, x1, x2` then unconditionally branches to a frontier block that is
// marked as a native exit. The exit stub must record its resume guest PC into
// Aarch64GuestRegs.pc and return to the trampoline, while the entry block's
// result survives. Proves: native_exits short-circuit in lower_block, the
// intra-region branch landing on the stub, the scratch spill/restore, and the
// PC marshal-back.
#[test]
fn native_exit_stub_records_resume_pc() {
    const RESUME_PC: u64 = 0x4000;

    let mut lifter = Aarch64Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch64);
    let mut builder = FunctionBuilder::new(FunctionId(0), 0);

    // Frontier/exit block (created first so the entry can branch to it).
    let exit_blk = builder.create_block(RESUME_PC);

    // Entry block: add x0, x1, x2  (8b020020), then Branch -> exit_blk.
    let lifted = lifter
        .lift_insn(0, &0x8b02_0020u32.to_le_bytes(), &mut ctx)
        .expect("lift add");
    for op in lifted.ops {
        builder.push_op(op.guest_pc, op.kind);
    }
    builder.set_terminator(Terminator::Branch { target: exit_blk });

    // Exit block body is irrelevant (replaced by the stub); give it a terminator.
    builder.switch_to_block(exit_blk);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut exits = HashMap::new();
    exits.insert(exit_blk, RESUME_PC);

    let mut lowerer = Aarch64Lowerer::new();
    lowerer.set_native_exits(exits);
    let result = lowerer.lower_function(&func).expect("lower");
    let code = lowerer.finalize().expect("finalize");
    let mem = ExecMem::new(&code).expect("map");

    let mut regs = Aarch64GuestRegs::default();
    regs.x[1] = 40;
    regs.x[2] = 2;
    regs.x[5] = 0xdead_beef; // unrelated live reg must survive
    regs.pc = 0; // proves the stub actually writes it
    mem.run_aarch64_identity(result.entry_offset, &mut regs);

    assert_eq!(regs.x[0], 42, "entry block's add executed");
    assert_eq!(regs.pc, RESUME_PC, "exit stub recorded the resume PC");
    assert_eq!(
        regs.x[5], 0xdead_beef,
        "unrelated reg preserved across the stub"
    );
}

// A conditional branch where BOTH targets are native exits with distinct resume
// PCs: verifies the structural CondBranch->stub handling (no special terminator
// code) and that the taken edge selects the right resume PC.
#[test]
fn native_exit_conditional_selects_resume_pc() {
    const PC_EQ: u64 = 0x1000;
    const PC_NE: u64 = 0x2000;

    let build_and_run = |x1: u64, x2: u64| -> Aarch64GuestRegs {
        let mut lifter = Aarch64Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch64);
        let mut builder = FunctionBuilder::new(FunctionId(0), 0);
        let blk_eq = builder.create_block(PC_EQ);
        let blk_ne = builder.create_block(PC_NE);

        // Entry: cmp x1, x2 ; b.eq blk_eq ; b blk_ne.
        // Lift `subs xzr, x1, x2` (cmp) = 0xeb02003f to set NZCV, then lift
        // `b.eq #target` to obtain the cond-branch SMIR shape... simpler: build
        // the compare op via lifting cmp, then a manual CondBranch with a folded
        // TestCondition.
        let lifted = lifter
            .lift_insn(0, &0xeb02_003fu32.to_le_bytes(), &mut ctx)
            .expect("lift cmp");
        for op in lifted.ops {
            builder.push_op(op.guest_pc, op.kind);
        }
        // TestCondition feeding the CondBranch (folded into B.eq by the lowerer).
        let cond = ctx.alloc_vreg();
        builder.push_op(
            0,
            rax::smir::ir::ops::OpKind::TestCondition {
                dst: cond,
                cond: rax::smir::ir::types::Condition::Eq,
            },
        );
        builder.set_terminator(Terminator::CondBranch {
            cond,
            true_target: blk_eq,
            false_target: blk_ne,
        });
        builder.switch_to_block(blk_eq);
        builder.set_terminator(Terminator::Return { values: vec![] });
        builder.switch_to_block(blk_ne);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();

        let mut exits = HashMap::new();
        exits.insert(blk_eq, PC_EQ);
        exits.insert(blk_ne, PC_NE);

        let mut lowerer = Aarch64Lowerer::new();
        lowerer.set_native_exits(exits);
        let result = lowerer.lower_function(&func).expect("lower");
        let code = lowerer.finalize().expect("finalize");
        let mem = ExecMem::new(&code).expect("map");

        let mut regs = Aarch64GuestRegs::default();
        regs.x[1] = x1;
        regs.x[2] = x2;
        mem.run_aarch64_identity(result.entry_offset, &mut regs);
        regs
    };

    assert_eq!(build_and_run(7, 7).pc, PC_EQ, "x1==x2 takes the eq exit");
    assert_eq!(build_and_run(9, 7).pc, PC_NE, "x1!=x2 takes the ne exit");
}

// ---- Memory-helper call-out tests (mem_helpers mode) ----------------------

/// AAPCS64 16-byte return: value in x0, ok in x1.
#[repr(C)]
struct LoadRet {
    value: u64,
    ok: u64,
}

#[repr(C)]
struct TestMemCtx {
    /// When non-zero, the helpers report a fault (ok = 0).
    fault: u64,
}

extern "C" fn test_load(ctx: *mut TestMemCtx, addr: u64, size: u32, signed: u32) -> LoadRet {
    if unsafe { (*ctx).fault } != 0 {
        return LoadRet { value: 0, ok: 0 };
    }
    let value = unsafe {
        match size {
            1 => {
                let v = *(addr as *const u8);
                if signed != 0 {
                    v as i8 as i64 as u64
                } else {
                    v as u64
                }
            }
            2 => {
                let v = *(addr as *const u16);
                if signed != 0 {
                    v as i16 as i64 as u64
                } else {
                    v as u64
                }
            }
            4 => {
                let v = *(addr as *const u32);
                if signed != 0 {
                    v as i32 as i64 as u64
                } else {
                    v as u64
                }
            }
            _ => *(addr as *const u64),
        }
    };
    LoadRet { value, ok: 1 }
}

extern "C" fn test_store(ctx: *mut TestMemCtx, addr: u64, value: u64, size: u32) -> u64 {
    if unsafe { (*ctx).fault } != 0 {
        return 0;
    }
    unsafe {
        match size {
            1 => *(addr as *mut u8) = value as u8,
            2 => *(addr as *mut u16) = value as u16,
            4 => *(addr as *mut u32) = value as u32,
            _ => *(addr as *mut u64) = value,
        }
    }
    1
}

// Load through the MMU helper, then Store through it: copies src→dst. Proves the
// full call-out path — spill-all to the struct, LR save/restore around `blr`,
// arg marshaling (ctx/addr/size/signed), the (value,ok) return, value delivery
// into the dst slot, and reload preserving unrelated live registers.
#[test]
fn mem_helper_load_store_copies() {
    let src: u64 = 0xCAFE_F00D_1234_5678;
    let mut dst: u64 = 0;
    let mut ctx = TestMemCtx { fault: 0 };

    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    let exit_blk = builder.create_block(0x9000);
    builder.push_op(
        0,
        OpKind::Load {
            dst: xr(0),
            addr: Address::Direct(xr(1)),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        4,
        OpKind::Store {
            src: xr(0),
            addr: Address::Direct(xr(2)),
            width: MemWidth::B8,
        },
    );
    builder.set_terminator(Terminator::Branch { target: exit_blk });
    builder.switch_to_block(exit_blk);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut exits = HashMap::new();
    exits.insert(exit_blk, 0x9000u64);
    let mut lowerer = Aarch64Lowerer::new();
    lowerer.set_native_exits(exits);
    lowerer.set_mem_helpers(true);
    let result = lowerer.lower_function(&func).expect("lower");
    let code = lowerer.finalize().expect("finalize");
    let mem = ExecMem::new(&code).expect("map");

    let mut regs = Aarch64GuestRegs::default();
    regs.x[1] = &src as *const u64 as u64;
    regs.x[2] = &mut dst as *mut u64 as u64;
    regs.x[7] = 0x7777_7777; // unrelated live reg must survive spill/reload
    regs.ctx = &mut ctx as *mut TestMemCtx as u64;
    regs.load_fn = test_load as usize as u64;
    regs.store_fn = test_store as usize as u64;
    mem.run_aarch64_identity(result.entry_offset, &mut regs);

    assert_eq!(dst, 0xCAFE_F00D_1234_5678, "store landed via helper");
    assert_eq!(
        regs.x[0], 0xCAFE_F00D_1234_5678,
        "loaded value delivered to x0"
    );
    assert_eq!(
        regs.x[7], 0x7777_7777,
        "unrelated reg preserved across spill/reload"
    );
    assert_eq!(regs.pc, 0x9000, "exited at the frontier resume PC");
}

// A faulting load (helper returns ok=0) must record the faulting op's guest PC
// and bail before the store, leaving guest state uncommitted.
#[test]
fn mem_helper_load_fault_records_pc() {
    const LOAD_PC: u64 = 0x40;
    let probe: u64 = 0xdead;
    let mut dst: u64 = 0;
    let mut ctx = TestMemCtx { fault: 1 }; // load will report a fault

    let mut builder = FunctionBuilder::new(FunctionId(0), 0);
    let exit_blk = builder.create_block(0x9000);
    builder.push_op(
        LOAD_PC,
        OpKind::Load {
            dst: xr(0),
            addr: Address::Direct(xr(1)),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        LOAD_PC + 4,
        OpKind::Store {
            src: xr(0),
            addr: Address::Direct(xr(2)),
            width: MemWidth::B8,
        },
    );
    builder.set_terminator(Terminator::Branch { target: exit_blk });
    builder.switch_to_block(exit_blk);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut exits = HashMap::new();
    exits.insert(exit_blk, 0x9000u64);
    let mut lowerer = Aarch64Lowerer::new();
    lowerer.set_native_exits(exits);
    lowerer.set_mem_helpers(true);
    let result = lowerer.lower_function(&func).expect("lower");
    let code = lowerer.finalize().expect("finalize");
    let mem = ExecMem::new(&code).expect("map");

    let mut regs = Aarch64GuestRegs::default();
    regs.x[0] = 0xABCD; // sentinel: must be untouched on fault
    regs.x[1] = &probe as *const u64 as u64;
    regs.x[2] = &mut dst as *mut u64 as u64;
    regs.ctx = &mut ctx as *mut TestMemCtx as u64;
    regs.load_fn = test_load as usize as u64;
    regs.store_fn = test_store as usize as u64;
    mem.run_aarch64_identity(result.entry_offset, &mut regs);

    assert_eq!(regs.pc, LOAD_PC, "faulting load recorded its own guest PC");
    assert_eq!(regs.x[0], 0xABCD, "dst register uncommitted on fault");
    assert_eq!(dst, 0, "store never executed after the load fault");
}

// ---- End-to-end: JIT tier inside the AArch64 emulator vs the interpreter ----

const PROG_BASE: u64 = 0x1000;
/// Sentinel return address: the loops end in `ret`, so once X30 lands in PC the
/// program is done. It is never executed (the harness stops first).
const DONE_PC: u64 = 0x00DE_AD00;

/// Drive `cpu` from PROG_BASE until PC reaches DONE_PC (the `ret` target) or a
/// step budget is exhausted.
fn drive_to_done(cpu: &mut AArch64Cpu) {
    cpu.set_x(30, DONE_PC); // return address for the terminating `ret`
    cpu.set_pc(PROG_BASE);
    // Runaway cap; large enough for the interpreter to finish the benchmark's
    // multi-million-iteration loop (≈3 steps/iter) without false-tripping.
    for _ in 0..64_000_000u64 {
        if cpu.get_pc() == DONE_PC {
            return;
        }
        match cpu.step_system() {
            Ok(_) => {}
            Err(e) => panic!("cpu error: {e:?}"),
        }
    }
    panic!("program did not reach DONE_PC (pc={:#x})", cpu.get_pc());
}

fn load_prog(cpu: &mut AArch64Cpu, prog: &[u32]) {
    let mut bytes = Vec::with_capacity(prog.len() * 4);
    for &w in prog {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    cpu.write_memory(PROG_BASE, &bytes).unwrap();
}

fn fresh_cpu() -> AArch64Cpu {
    let mem = FlatMemory::new(0, 0x0100_0000);
    AArch64Cpu::new(AArch64Config::default(), Box::new(mem))
}

// A register-only hot loop: x0 = sum(1..=1000). Runs >64 back-edges so the JIT
// promotes the loop head, compiles the self-looping region (CondBranch back to
// itself, `ret` frontier), and executes the tail natively. The JIT result must
// equal the pure-interpreter result.
#[test]
fn e2e_register_hot_loop_matches_interpreter() {
    // movz x0,#0 ; movz x1,#1000 ; (loop) add x0,x0,x1 ; subs x1,x1,#1 ;
    // b.ne loop ; ret
    let prog: [u32; 6] = [
        0xd280_0000, // movz x0, #0
        0xd280_7d01, // movz x1, #1000
        0x8b01_0000, // add  x0, x0, x1     ; loop head @ PROG_BASE+0x8
        0xf100_0421, // subs x1, x1, #1
        0x54ff_ffc1, // b.ne loop (-8)
        0xd65f_03c0, // ret
    ];

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    load_prog(&mut interp, &prog);
    drive_to_done(&mut interp);

    let mut jit = fresh_cpu();
    jit.set_jit_enabled(true);
    load_prog(&mut jit, &prog);
    drive_to_done(&mut jit);

    assert_eq!(interp.get_x(0), 500_500, "sum(1..=1000)");
    assert_eq!(interp.get_x(1), 0);
    for i in 0..31u8 {
        assert_eq!(
            jit.get_x(i),
            interp.get_x(i),
            "X{i} diverged: jit={:#x} interp={:#x}",
            jit.get_x(i),
            interp.get_x(i)
        );
    }
}

// A memory-touching hot loop summing an in-guest-memory array through the MMU
// helper path (set_jit_mem(true)). Validates the full memory-helper call-out
// end-to-end inside the emulator, differentially against the interpreter.
#[test]
fn e2e_memory_hot_loop_matches_interpreter() {
    const ARRAY: u64 = 0x4000;
    const N: u64 = 500;

    // x0=sum(0), x1=ptr(ARRAY), x2=count(N):
    //   loop: ldr x3,[x1] ; add x0,x0,x3 ; add x1,x1,#8 ; subs x2,x2,#1 ; b.ne loop ; ret
    let prog: [u32; 9] = [
        0xd280_0000, // movz x0, #0
        0xd288_0001, // movz x1, #0x4000   (ARRAY)
        0xd280_3e82, // movz x2, #500      (N)
        0xf940_0023, // ldr  x3, [x1]      ; loop head @ +0xC
        0x8b03_0000, // add  x0, x0, x3
        0x9100_2021, // add  x1, x1, #8
        0xf100_0442, // subs x2, x2, #1
        0x54ff_ff81, // b.ne loop (-16, back to the ldr at +0xC)
        0xd65f_03c0, // ret
    ];

    // Expected sum of the array values we fill in: a[i] = i*3 + 7.
    let fill = |cpu: &mut AArch64Cpu| {
        for i in 0..N {
            let v: u64 = i.wrapping_mul(3).wrapping_add(7);
            cpu.write_memory(ARRAY + i * 8, &v.to_le_bytes()).unwrap();
        }
    };
    let expected: u64 = (0..N).map(|i| i.wrapping_mul(3).wrapping_add(7)).sum();

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    load_prog(&mut interp, &prog);
    fill(&mut interp);
    drive_to_done(&mut interp);

    let mut jit = fresh_cpu();
    jit.set_jit_enabled(true);
    jit.set_jit_mem(true);
    load_prog(&mut jit, &prog);
    fill(&mut jit);
    drive_to_done(&mut jit);

    assert_eq!(interp.get_x(0), expected, "interpreter sums the array");
    for i in 0..31u8 {
        assert_eq!(jit.get_x(i), interp.get_x(i), "X{i} diverged (memory JIT)");
    }
}

// Self-modifying code: after a loop is JIT-compiled, a guest store into its code
// page must invalidate the cached region so a re-run reflects the patched
// instruction. The loop body `add x0,x0,#1` is rewritten to `add x0,x0,#2`
// through the guest store path (mem_write_u32, which feeds the SMC journal).
#[test]
fn e2e_smc_invalidates_stale_region() {
    // loop head @ PROG_BASE: add x0,x0,#1 ; subs x1,x1,#1 ; b.ne head ; ret
    let prog: [u32; 4] = [
        0x9100_0400, // add  x0, x0, #1   ; <- patched below
        0xf100_0421, // subs x1, x1, #1
        0x54ff_ffc1, // b.ne head (-8)
        0xd65f_03c0, // ret
    ];

    let mut cpu = fresh_cpu();
    cpu.set_jit_enabled(true);
    load_prog(&mut cpu, &prog);

    // Pass 1: 200 iterations of +1 -> x0 = 200, and the loop head is JIT'd.
    cpu.set_x(0, 0);
    cpu.set_x(1, 200);
    drive_to_done(&mut cpu);
    assert_eq!(cpu.get_x(0), 200, "pass 1: +1 x 200");

    // Patch the loop body to `add x0,x0,#2` via the guest store path. This must
    // mark the cached region stale (it covers PROG_BASE's page).
    cpu.mem_write_u32(PROG_BASE, 0x9100_0800).unwrap();

    // Pass 2: if SMC invalidation works, the re-run uses +2 -> x0 = 400. A stale
    // cached region would still apply +1 and yield 200.
    cpu.set_x(0, 0);
    cpu.set_x(1, 200);
    drive_to_done(&mut cpu);
    assert_eq!(cpu.get_x(0), 400, "pass 2: SMC picked up the +2 patch");
}

// ---- Differential harness: SMIR-lowered native code vs the interpreter -------
//
// For each instruction sequence + input vector, run it two ways and compare the
// low GPRs: (a) through the native lowerer (jit_run / run_aarch64_identity), and
// (b) through the AArch64 interpreter. Sequences the lowerer declines to lower
// are skipped (they safely deopt to the interpreter in the emulator). This is
// the gold-standard correctness check for the lowerer across op classes the
// hand-written tests above don't individually cover.

fn interp_seq(insns: &[u32], xin: &[(u8, u64)]) -> [u64; 9] {
    let mut cpu = fresh_cpu();
    cpu.set_jit_enabled(false);
    let mut bytes = Vec::new();
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes.extend_from_slice(&0xd65f_03c0u32.to_le_bytes()); // ret
    cpu.write_memory(PROG_BASE, &bytes).unwrap();
    for &(r, v) in xin {
        cpu.set_x(r, v);
    }
    cpu.set_x(30, DONE_PC);
    cpu.set_pc(PROG_BASE);
    for _ in 0..1000 {
        if cpu.get_pc() == DONE_PC {
            break;
        }
        cpu.step_system().unwrap();
    }
    let mut out = [0u64; 9];
    for i in 0..9 {
        out[i] = cpu.get_x(i as u8);
    }
    out
}

fn jit_seq(insns: &[u32], xin: &[(u8, u64)]) -> Option<[u64; 9]> {
    let mut regs = Aarch64GuestRegs::default();
    for &(r, v) in xin {
        regs.x[r as usize] = v;
    }
    jit_run(insns, &mut regs).ok()?;
    let mut out = [0u64; 9];
    for i in 0..9 {
        out[i] = regs.x[i];
    }
    Some(out)
}

fn diff_check(label: &str, insns: &[u32], inputs: &[&[(u8, u64)]]) {
    let mut lowered = false;
    for xin in inputs {
        let interp = interp_seq(insns, xin);
        if let Some(jit) = jit_seq(insns, xin) {
            lowered = true;
            assert_eq!(
                jit, interp,
                "{label}: JIT vs interpreter diverged\n  insns={insns:#010x?}\n  in={xin:?}\n  jit={jit:#x?}\n  interp={interp:#x?}"
            );
        }
    }
    // Not a hard failure if the lowerer declines (deopt is correct), but note it.
    if !lowered {
        eprintln!("[diff] {label}: lowerer declined all inputs (deopt path)");
    }
}

#[test]
fn differential_scalar_ops_vs_interpreter() {
    let vecs: &[&[(u8, u64)]] = &[
        &[(1, 0x0000_0000_0000_0003), (2, 0x0000_0000_0000_0004)],
        &[(1, 0xFFFF_FFFF_FFFF_FFFF), (2, 0x0000_0000_0000_0001)],
        &[(1, 0x8000_0000_0000_0000), (2, 0x0000_0000_0000_003F)],
        &[(1, 0x0123_4567_89AB_CDEF), (2, 0x0000_0000_0000_0011)],
    ];

    // Data-processing 2-source: shifts and divides.
    diff_check("lslv", &[0x9ac2_2020], vecs); // lsl x0,x1,x2
    diff_check("lsrv", &[0x9ac2_2420], vecs); // lsr x0,x1,x2
    diff_check("asrv", &[0x9ac2_2820], vecs); // asr x0,x1,x2
    diff_check("rorv", &[0x9ac2_2c20], vecs); // ror x0,x1,x2
    diff_check("udiv", &[0x9ac2_0820], vecs); // udiv x0,x1,x2
    diff_check("sdiv", &[0x9ac2_0c20], vecs); // sdiv x0,x1,x2

    // Data-processing 1-source: bit ops.
    diff_check("clz", &[0xdac0_1020], vecs); // clz  x0,x1
    diff_check("rbit", &[0xdac0_0020], vecs); // rbit x0,x1
    diff_check("rev", &[0xdac0_0c20], vecs); // rev  x0,x1

    // Bitfield extracts.
    diff_check("ubfx", &[0xd344_2c20], vecs); // ubfx x0,x1,#4,#8
    diff_check("sbfx", &[0x9344_2c20], vecs); // sbfx x0,x1,#4,#8
    // Bitfield insert (result depends on the dst's prior value).
    diff_check(
        "bfi",
        &[0xb37c_1c20], // bfi x0,x1,#4,#8
        &[
            &[(0, 0xFFFF_FFFF_FFFF_FFFF), (1, 0x0)],
            &[(0, 0x0), (1, 0xFF)],
            &[(0, 0xAAAA_AAAA_AAAA_AAAA), (1, 0x55)],
        ],
    );

    // Add/sub with carry (carry seeded by a preceding adds).
    // adds x3,x4,x5 ; adc x0,x1,x2
    diff_check(
        "adc",
        &[0xab05_0083, 0x9a02_0020],
        &[
            &[(1, 5), (2, 7), (4, u64::MAX), (5, 1)], // carry set
            &[(1, 5), (2, 7), (4, 1), (5, 1)],        // carry clear
        ],
    );
    // subs x3,x4,x5 ; sbc x0,x1,x2
    diff_check(
        "sbc",
        &[0xeb05_0083, 0xda02_0020],
        &[
            &[(1, 100), (2, 30), (4, 10), (5, 1)], // borrow
            &[(1, 100), (2, 30), (4, 10), (5, 10)],
        ],
    );

    // Conditional select off a compare.
    // cmp x1,x2 (subs xzr,x1,x2) ; csel x0,x3,x4,eq
    diff_check(
        "csel_eq",
        &[0xeb02_003f, 0x9a82_0060],
        &[
            &[(1, 7), (2, 7), (3, 0xAAAA), (4, 0xBBBB)], // eq -> x3
            &[(1, 9), (2, 7), (3, 0xAAAA), (4, 0xBBBB)], // ne -> x4
        ],
    );
    // cmp x1,x2 ; csinc x0,x3,x4,ne   (csinc x0,x3,x4,ne = 0x9a84_1060)
    diff_check(
        "csinc_ne",
        &[0xeb02_003f, 0x9a84_1060],
        &[
            &[(1, 7), (2, 7), (3, 0xAAAA), (4, 0xBBBB)],
            &[(1, 9), (2, 7), (3, 0xAAAA), (4, 0xBBBB)],
        ],
    );
}

// ---- Benchmark: JIT vs interpreter on a hot loop (perf evidence) ------------
//
// Not a pass/fail threshold (host-dependent, CI-flaky); it asserts the JIT
// result equals the interpreter and prints the wall-clock speedup. Run with
//   cargo test --test aarch64_smir_native bench_jit_speedup -- --nocapture
#[test]
fn bench_jit_speedup() {
    use std::time::Instant;

    // A long register-only countdown: add x0,x0,x1 ; subs x1,x1,#1 ; b.ne ; ret
    let prog: [u32; 4] = [0x8b01_0000, 0xf100_0421, 0x54ff_ffc1, 0xd65f_03c0];
    let iters: u64 = 5_000_000;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    load_prog(&mut interp, &prog);
    interp.set_x(0, 0);
    interp.set_x(1, iters);
    let t0 = Instant::now();
    drive_to_done(&mut interp);
    let interp_t = t0.elapsed();

    let mut jit = fresh_cpu();
    jit.set_jit_enabled(true);
    load_prog(&mut jit, &prog);
    jit.set_x(0, 0);
    jit.set_x(1, iters);
    let t1 = Instant::now();
    drive_to_done(&mut jit);
    let jit_t = t1.elapsed();

    let expected = iters * (iters + 1) / 2;
    assert_eq!(interp.get_x(0), expected, "interpreter sum");
    assert_eq!(jit.get_x(0), expected, "JIT sum matches");

    eprintln!(
        "[bench] {iters} iters: interp={:?} jit={:?} speedup={:.1}x",
        interp_t,
        jit_t,
        interp_t.as_secs_f64() / jit_t.as_secs_f64().max(1e-9)
    );
}

// ---- Scalar FP through the JIT (lift -> lower -> FP trampoline -> exec) ------
//
// jit_run auto-detects V-register usage and routes through the FP trampoline.
// These validate the full lift->lower->exec chain for the IEEE-exact scalar FP
// ops admitted by the clobber gate. Results are exact (no rounding ambiguity).

fn fp_run(insns: &[u32], setup: impl FnOnce(&mut Aarch64GuestRegs)) -> Aarch64GuestRegs {
    let mut regs = Aarch64GuestRegs::default();
    setup(&mut regs);
    jit_run(insns, &mut regs).expect("fp jit_run");
    regs
}

#[test]
fn e2e_vector_halving_add_matches_interpreter() {
    let prog: [u32; 2] = [
        0x4e22_0420, // shadd v0.16b, v1.16b, v2.16b
        0xd65f_03c0, // ret
    ];
    let v1 = u128::from_le_bytes([2; 16]);
    let v2 = u128::from_le_bytes([4; 16]);
    let expected = u128::from_le_bytes([3; 16]);

    let run_one = |jit: bool| -> u128 {
        let mut cpu = fresh_cpu();
        cpu.set_jit_enabled(jit);
        load_prog(&mut cpu, &prog);
        cpu.set_simd(1, v1);
        cpu.set_simd(2, v2);
        drive_to_done(&mut cpu);
        cpu.get_simd(0)
    };

    let interp = run_one(false);
    let jit = run_one(true);
    assert_eq!(interp, expected, "interpreter shadd");
    assert_eq!(jit, interp, "JIT shadd path matches interpreter");
}

// Scalar FP through the JIT, now that the decoder's 2-source opcode table is
// fixed (decoder/aarch64.rs decode_scalar_fp_2source): both single- AND
// double-precision FADD/FSUB/FMUL/FDIV (+ FSQRT) lift correctly and run via the
// FP trampoline (V0-V31 + FPCR marshaled). Double-precision was entirely
// mis-decoded before the fix. Results are IEEE-exact, so hand-expected values
// are the oracle. (V_n.f64 lives in regs.v[2*n]; V_n.f32 in its low 32 bits.)
#[test]
fn fp_scalar_arith_lift_lower_exec() {
    // Single-precision fadd s0,s1,s2 (the one encoding that decoded pre-fix too).
    let r = fp_run(&[0x1e22_2820], |g| {
        g.v[2] = (2.5_f32).to_bits() as u64;
        g.v[4] = (4.0_f32).to_bits() as u64;
    });
    assert_eq!(f32::from_bits(r.v[0] as u32), 6.5, "fadd s0,s1,s2");

    // Double-precision: previously broken, now correct.
    let r = fp_run(&[0x1e62_2820], |g| {
        // fadd d0,d1,d2
        g.v[2] = (2.5_f64).to_bits();
        g.v[4] = (4.0_f64).to_bits();
    });
    assert_eq!(f64::from_bits(r.v[0]), 6.5, "fadd d0,d1,d2");

    let r = fp_run(&[0x1e62_3820], |g| {
        // fsub d0,d1,d2
        g.v[2] = (10.0_f64).to_bits();
        g.v[4] = (3.5_f64).to_bits();
    });
    assert_eq!(f64::from_bits(r.v[0]), 6.5, "fsub d0,d1,d2");

    let r = fp_run(&[0x1e62_0820], |g| {
        // fmul d0,d1,d2
        g.v[2] = (2.0_f64).to_bits();
        g.v[4] = (3.25_f64).to_bits();
    });
    assert_eq!(f64::from_bits(r.v[0]), 6.5, "fmul d0,d1,d2");

    let r = fp_run(&[0x1e62_1820], |g| {
        // fdiv d0,d1,d2
        g.v[2] = (13.0_f64).to_bits();
        g.v[4] = (2.0_f64).to_bits();
    });
    assert_eq!(f64::from_bits(r.v[0]), 6.5, "fdiv d0,d1,d2");

    let r = fp_run(&[0x1e61_c020], |g| {
        // fsqrt d0,d1
        g.v[2] = (42.25_f64).to_bits();
    });
    assert_eq!(f64::from_bits(r.v[0]), 6.5, "fsqrt d0,d1");
}

// ---- NEON vector ops through the JIT (lift -> lower -> V-trampoline -> exec) --
#[test]
fn probe_vector_add_4s() {
    // add v0.4s, v1.4s, v2.4s  (0x4ea28420)
    // V_n.4s lanes: [lane0,lane1] in v[2n], [lane2,lane3] in v[2n+1] (each u32).
    let pack = |l0: u32, l1: u32| (l1 as u64) << 32 | l0 as u64;
    let r = fp_run(&[0x4ea2_8420], |g| {
        g.v[2] = pack(1, 2);
        g.v[3] = pack(3, 4); // V1 = [1,2,3,4]
        g.v[4] = pack(10, 20);
        g.v[5] = pack(40 - 10, 40); // V2 = [10,20,30,40]
    });
    assert_eq!(r.v[0], pack(11, 22), "V0 lanes 0,1");
    assert_eq!(r.v[1], pack(33, 44), "V0 lanes 2,3");
}

// End-to-end: a NEON vector hot loop JIT'd inside the emulator vs the
// interpreter. Each iteration accumulates v1 into v0 (per 32-bit lane); after N
// iterations v0.lane == N*v1.lane. Proves the clobber gate now admits vector
// ops, the emulator routes the region through the FP/V trampoline, and the
// 128-bit vector result matches the interpreter.
#[test]
fn e2e_vector_hot_loop_matches_interpreter() {
    // loop: add v0.4s, v0.4s, v1.4s ; subs x0,x0,#1 ; b.ne loop ; ret
    let prog: [u32; 4] = [0x4ea1_8400, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
    let pack = |l0: u32, l1: u32, l2: u32, l3: u32| -> u128 {
        (l0 as u128) | (l1 as u128) << 32 | (l2 as u128) << 64 | (l3 as u128) << 96
    };
    let v1 = pack(1, 2, 3, 4);
    const N: u64 = 300;

    let mut interp = fresh_cpu();
    interp.set_jit_enabled(false);
    load_prog(&mut interp, &prog);
    interp.set_simd(1, v1);
    interp.set_x(0, N);
    drive_to_done(&mut interp);

    let mut jit = fresh_cpu();
    jit.set_jit_enabled(true);
    load_prog(&mut jit, &prog);
    jit.set_simd(1, v1);
    jit.set_x(0, N);
    drive_to_done(&mut jit);

    let expected = pack(N as u32, 2 * N as u32, 3 * N as u32, 4 * N as u32);
    assert_eq!(
        interp.get_simd(0),
        expected,
        "interpreter accumulates the vector"
    );
    assert_eq!(
        jit.get_simd(0),
        interp.get_simd(0),
        "JIT vector result matches interp"
    );
    assert_eq!(jit.get_x(0), 0);
}

// Vector fused multiply-add (FMLA), newly emitted by the lifter -> VFma ->
// native vector fmla. v0.4s += v1.4s * v2.4s, per f32 lane.
#[test]
fn probe_vector_fmla_4s() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;
    // fmla v0.4s, v1.4s, v2.4s  (0x4e22cc20)
    let r = fp_run(&[0x4e22_cc20], |g| {
        g.v[0] = pack(1.0, 2.0);
        g.v[1] = pack(3.0, 4.0); // v0 acc = [1,2,3,4]
        g.v[2] = pack(2.0, 2.0);
        g.v[3] = pack(2.0, 2.0); // v1 = [2,2,2,2]
        g.v[4] = pack(3.0, 3.0);
        g.v[5] = pack(3.0, 3.0); // v2 = [3,3,3,3]
    });
    // v0.lane += v1.lane*v2.lane = [1+6, 2+6, 3+6, 4+6]
    assert_eq!(r.v[0], pack(7.0, 8.0), "fmla lanes 0,1");
    assert_eq!(r.v[1], pack(9.0, 10.0), "fmla lanes 2,3");
}

// End-to-end FMLA accumulation hot loop (v0 += v1*v2 each iteration) JIT'd in
// the emulator vs the interpreter — the canonical vectorized dot-product kernel.
#[test]
fn e2e_vector_fmla_hot_loop_matches_interpreter() {
    // loop: fmla v0.4s,v1.4s,v2.4s ; subs x0,x0,#1 ; b.ne loop ; ret
    let prog: [u32; 4] = [0x4e22_cc20, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
    let f = |x: f32| x.to_bits() as u128;
    let splat = |x: f32| f(x) | f(x) << 32 | f(x) << 64 | f(x) << 96;
    const N: u64 = 100;

    let run_one = |jit: bool| -> u128 {
        let mut cpu = fresh_cpu();
        cpu.set_jit_enabled(jit);
        load_prog(&mut cpu, &prog);
        cpu.set_simd(0, 0); // accumulator
        cpu.set_simd(1, splat(2.0));
        cpu.set_simd(2, splat(3.0));
        cpu.set_x(0, N);
        drive_to_done(&mut cpu);
        cpu.get_simd(0)
    };

    let interp = run_one(false);
    let jit = run_one(true);
    assert_eq!(
        interp,
        splat(N as f32 * 6.0),
        "interp: v0 = N*(2*3) per lane"
    );
    assert_eq!(jit, interp, "JIT FMLA loop matches interpreter");
}

// Interpreter must load a 128-bit vector correctly after the C1 decoder fix
// (ldr q0,[x1] now decodes to an FP-register load, not a GPR load).
#[test]
fn interp_vector_ldr_q() {
    const ADDR: u64 = 0x4000;
    let val: u128 = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00;
    let mut cpu = fresh_cpu();
    cpu.set_jit_enabled(false);
    // ldr q0, [x1] ; ret
    load_prog(&mut cpu, &[0x3dc0_0020, 0xd65f_03c0]);
    cpu.write_memory(ADDR, &val.to_le_bytes()).unwrap();
    cpu.set_x(1, ADDR);
    cpu.set_x(30, DONE_PC);
    cpu.set_pc(PROG_BASE);
    for _ in 0..100 {
        if cpu.get_pc() == DONE_PC {
            break;
        }
        cpu.step_system().unwrap();
    }
    assert_eq!(
        cpu.get_simd(0),
        val,
        "interpreter loaded the 128-bit vector"
    );
}

// End-to-end vector load/compute/store loop over guest memory, JIT'd vs the
// interpreter. Each iteration: q0 = load array[i]; q0 += v2 (per 32-bit lane);
// store array[i]; advance pointer. Exercises the full vector-memory JIT path
// (C1 decoder fix -> VLoad/VStore lift -> vec mem-helper lowering -> emulator
// 128-bit helpers) plus the FP/V trampoline.
#[test]
fn e2e_vector_loadstore_loop_matches_interpreter() {
    const ADDR: u64 = 0x4000;
    const N: u64 = 200; // > JIT hot threshold so the region actually compiles
    // loop: ldr q0,[x1]; add v0.4s,v0.4s,v2.4s; str q0,[x1]; add x1,x1,#16;
    //       subs x0,x0,#1; b.ne loop; ret
    let prog: [u32; 7] = [
        0x3dc0_0020,
        0x4ea2_8400,
        0x3d80_0020,
        0x9100_4021,
        0xf100_0400,
        0x54ff_ff61,
        0xd65f_03c0,
    ];
    let v2: u128 = 1 | 2u128 << 32 | 3u128 << 64 | 4u128 << 96; // lanes [1,2,3,4]

    let run_one = |jit: bool| -> Vec<u32> {
        let mut cpu = fresh_cpu();
        cpu.set_jit_enabled(jit);
        cpu.set_jit_mem(true); // vector memory needs the helper path
        load_prog(&mut cpu, &prog);
        for i in 0..N {
            for lane in 0..4u64 {
                let v = (10 * i) as u32;
                cpu.write_memory(ADDR + i * 16 + lane * 4, &v.to_le_bytes())
                    .unwrap();
            }
        }
        cpu.set_simd(2, v2);
        cpu.set_x(1, ADDR);
        cpu.set_x(0, N);
        drive_to_done(&mut cpu);
        let mut out = Vec::new();
        for i in 0..N {
            for lane in 0..4u64 {
                out.push(cpu.mem_read_u32(ADDR + i * 16 + lane * 4).unwrap());
            }
        }
        out
    };

    let interp = run_one(false);
    let jit = run_one(true);
    // Sanity: array[i].lane == 10*i + (lane+1).
    for i in 0..N {
        for lane in 0..4u64 {
            assert_eq!(
                interp[(i * 4 + lane) as usize],
                10 * i as u32 + lane as u32 + 1,
                "interp array[{i}].{lane}"
            );
        }
    }
    assert_eq!(
        jit, interp,
        "vector load/store loop: JIT matches interpreter"
    );
}

// Vector FP arithmetic (fadd/fmul v.4s), newly routed from the cleaned-up
// decoder + lifter bit-28 vector/scalar split, lowered to native vector fadd/fmul.
#[test]
fn probe_vector_fp_arith_4s() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;

    // fadd v0.4s, v1.4s, v2.4s (0x4e22d420): [1,2,3,4] + [10,20,30,40]
    let r = fp_run(&[0x4e22_d420], |g| {
        g.v[2] = pack(1.0, 2.0);
        g.v[3] = pack(3.0, 4.0);
        g.v[4] = pack(10.0, 20.0);
        g.v[5] = pack(30.0, 40.0);
    });
    assert_eq!(r.v[0], pack(11.0, 22.0), "fadd v.4s lanes 0,1");
    assert_eq!(r.v[1], pack(33.0, 44.0), "fadd v.4s lanes 2,3");

    // fmul v0.4s, v1.4s, v2.4s (0x6e22dc20): [2,2,2,2] * [3,4,5,6]
    let r = fp_run(&[0x6e22_dc20], |g| {
        g.v[2] = pack(2.0, 2.0);
        g.v[3] = pack(2.0, 2.0);
        g.v[4] = pack(3.0, 4.0);
        g.v[5] = pack(5.0, 6.0);
    });
    assert_eq!(r.v[0], pack(6.0, 8.0), "fmul v.4s lanes 0,1");
    assert_eq!(r.v[1], pack(10.0, 12.0), "fmul v.4s lanes 2,3");
}

// End-to-end vector FP accumulation loop JIT'd in the emulator vs interpreter:
// v0.4s += v1.4s each iteration. Validates vector FP arithmetic through the full
// emulator JIT path (gate admission + FP/V trampoline).
#[test]
fn e2e_vector_fp_hot_loop_matches_interpreter() {
    // loop: fadd v0.4s,v0.4s,v1.4s ; subs x0,x0,#1 ; b.ne loop ; ret
    let prog: [u32; 4] = [0x4e21_d400, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
    let f = |x: f32| x.to_bits() as u128;
    let v1 = f(1.0) | f(2.0) << 32 | f(3.0) << 64 | f(4.0) << 96;
    const N: u64 = 100;

    let run_one = |jit: bool| -> u128 {
        let mut cpu = fresh_cpu();
        cpu.set_jit_enabled(jit);
        load_prog(&mut cpu, &prog);
        cpu.set_simd(0, 0);
        cpu.set_simd(1, v1);
        cpu.set_x(0, N);
        drive_to_done(&mut cpu);
        cpu.get_simd(0)
    };

    let interp = run_one(false);
    let jit = run_one(true);
    let nf = N as f32;
    let expected = f(nf) | f(2.0 * nf) << 32 | f(3.0 * nf) << 64 | f(4.0 * nf) << 96;
    assert_eq!(interp, expected, "interp: v0 = N*v1 per lane");
    assert_eq!(jit, interp, "JIT vector FP loop matches interpreter");
}

// Vector FP divide / max / min (three-same, .4s) through the lift→lower→exec
// JIT path. These exercise the new OpKind::VDiv (native FDIV) and the FMAX/FMIN
// lifter emission that reuses VMax/VMin (native FMAX/FMIN).
#[test]
fn probe_vector_fp_div_max_min_4s() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;

    // fdiv v0.4s, v1.4s, v2.4s (0x6e22fc20): [12,20,30,42] / [3,4,5,6]
    let r = fp_run(&[0x6e22_fc20], |g| {
        g.v[2] = pack(12.0, 20.0);
        g.v[3] = pack(30.0, 42.0);
        g.v[4] = pack(3.0, 4.0);
        g.v[5] = pack(5.0, 6.0);
    });
    assert_eq!(r.v[0], pack(4.0, 5.0), "fdiv v.4s lanes 0,1");
    assert_eq!(r.v[1], pack(6.0, 7.0), "fdiv v.4s lanes 2,3");

    // fmax v0.4s, v1.4s, v2.4s (0x4e22f420): max([1,9,3,8],[5,2,7,4])
    let r = fp_run(&[0x4e22_f420], |g| {
        g.v[2] = pack(1.0, 9.0);
        g.v[3] = pack(3.0, 8.0);
        g.v[4] = pack(5.0, 2.0);
        g.v[5] = pack(7.0, 4.0);
    });
    assert_eq!(r.v[0], pack(5.0, 9.0), "fmax v.4s lanes 0,1");
    assert_eq!(r.v[1], pack(7.0, 8.0), "fmax v.4s lanes 2,3");

    // fmin v0.4s, v1.4s, v2.4s (0x4ea2f420): min(same inputs)
    let r = fp_run(&[0x4ea2_f420], |g| {
        g.v[2] = pack(1.0, 9.0);
        g.v[3] = pack(3.0, 8.0);
        g.v[4] = pack(5.0, 2.0);
        g.v[5] = pack(7.0, 4.0);
    });
    assert_eq!(r.v[0], pack(1.0, 2.0), "fmin v.4s lanes 0,1");
    assert_eq!(r.v[1], pack(3.0, 4.0), "fmin v.4s lanes 2,3");
}

// End-to-end differential: each new vector-FP op (fdiv/fmax/fmin) run as a hot
// loop through the emulator JIT vs the interpreter. Catches any lifter/lowerer/
// decoder disagreement with the authoritative AArch64 interpreter.
#[test]
fn e2e_vector_fp_div_max_min_matches_interpreter() {
    let f = |x: f32| x.to_bits() as u128;
    let pack = |a: f32, b: f32, c: f32, d: f32| f(a) | f(b) << 32 | f(c) << 64 | f(d) << 96;

    // Each program: <op> v0.4s,v1.4s,v2.4s ; subs x0,x0,#1 ; b.ne -8 ; ret.
    // v0 is recomputed every iteration (idempotent), so the final v0 = op(v1,v2).
    let cases: [(u32, u128, u128, u128); 3] = [
        // fdiv: [60,60,60,60] / [2,3,4,5] = [30,20,15,12]
        (
            0x6e22_fc20,
            pack(60.0, 60.0, 60.0, 60.0),
            pack(2.0, 3.0, 4.0, 5.0),
            pack(30.0, 20.0, 15.0, 12.0),
        ),
        // fmax: max([1,9,3,8],[5,2,7,4]) = [5,9,7,8]
        (
            0x4e22_f420,
            pack(1.0, 9.0, 3.0, 8.0),
            pack(5.0, 2.0, 7.0, 4.0),
            pack(5.0, 9.0, 7.0, 8.0),
        ),
        // fmin: min(same) = [1,2,3,4]
        (
            0x4ea2_f420,
            pack(1.0, 9.0, 3.0, 8.0),
            pack(5.0, 2.0, 7.0, 4.0),
            pack(1.0, 2.0, 3.0, 4.0),
        ),
    ];

    for (op, v1, v2, expected) in cases {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_simd(2, v2);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(interp, expected, "interp op={:#010x}", op);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
    }
}

// Safety regression for the two-register-misc decoder/lifter work. The vector
// forms (FABS/FNEG/FSQRT/NEG/ABS/CLZ/CLS/RBIT/CNT/NOT/REV16/REV32/REV64) all JIT
// now (see the probe_vector_* tests). This guards the converse: the SCALAR FP
// 1-source forms (bit 28 == 1), which share the FABS/FNEG/FSQRT mnemonics with
// the vector forms, must still lift and execute via the scalar path (the bit-28
// discriminator must not misroute them to the vector VUnary path).
#[test]
fn scalar_fp_one_source_still_lifts_after_vector_unary() {
    let f = |x: f32| x.to_bits() as u64;
    // fabs s0, s1 (0x1e20c020): |-3.0| = 3.0
    let mut regs = Aarch64GuestRegs::default();
    regs.v[2] = f(-3.0); // V1.lo = s1
    jit_run(&[0x1e20_c020], &mut regs).expect("scalar fabs must still lift");
    assert_eq!(regs.v[0] as u32, f(3.0) as u32, "scalar fabs s0");

    // fneg s0, s1 (0x1e214020): -(3.0) = -3.0
    let mut regs = Aarch64GuestRegs::default();
    regs.v[2] = f(3.0);
    jit_run(&[0x1e21_4020], &mut regs).expect("scalar fneg must still lift");
    assert_eq!(regs.v[0] as u32, f(-3.0) as u32, "scalar fneg s0");

    // fsqrt s0, s1 (0x1e21c020): sqrt(9.0) = 3.0
    let mut regs = Aarch64GuestRegs::default();
    regs.v[2] = f(9.0);
    jit_run(&[0x1e21_c020], &mut regs).expect("scalar fsqrt must still lift");
    assert_eq!(regs.v[0] as u32, f(3.0) as u32, "scalar fsqrt s0");
}

// Per-lane vector FP unary (FABS/FNEG/FSQRT) via OpKind::VUnary, lift→lower→exec.
#[test]
fn probe_vector_fp_unary_4s() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;

    // fabs v0.4s, v1.4s (0x4ea0f820)
    let r = fp_run(&[0x4ea0_f820], |g| {
        g.v[2] = pack(-1.0, 2.0);
        g.v[3] = pack(-3.0, 4.0);
    });
    assert_eq!(r.v[0], pack(1.0, 2.0), "fabs lanes 0,1");
    assert_eq!(r.v[1], pack(3.0, 4.0), "fabs lanes 2,3");

    // fneg v0.4s, v1.4s (0x6ea0f820)
    let r = fp_run(&[0x6ea0_f820], |g| {
        g.v[2] = pack(1.0, -2.0);
        g.v[3] = pack(3.0, -4.0);
    });
    assert_eq!(r.v[0], pack(-1.0, 2.0), "fneg lanes 0,1");
    assert_eq!(r.v[1], pack(-3.0, 4.0), "fneg lanes 2,3");

    // fsqrt v0.4s, v1.4s (0x6ea1f820)
    let r = fp_run(&[0x6ea1_f820], |g| {
        g.v[2] = pack(1.0, 4.0);
        g.v[3] = pack(9.0, 16.0);
    });
    assert_eq!(r.v[0], pack(1.0, 2.0), "fsqrt lanes 0,1");
    assert_eq!(r.v[1], pack(3.0, 4.0), "fsqrt lanes 2,3");
}

// Per-lane vector integer unary (NEG/ABS) via OpKind::VUnary, lift→lower→exec.
#[test]
fn probe_vector_int_unary_4s() {
    let packi = |a: i32, b: i32| (a as u32 as u64) | ((b as u32 as u64) << 32);

    // neg v0.4s, v1.4s (0x6ea0b820) — I32 lanes
    let r = fp_run(&[0x6ea0_b820], |g| {
        g.v[2] = packi(1, -2);
        g.v[3] = packi(3, -4);
    });
    assert_eq!(r.v[0], packi(-1, 2), "neg lanes 0,1");
    assert_eq!(r.v[1], packi(-3, 4), "neg lanes 2,3");

    // abs v0.4s, v1.4s (0x4ea0b820)
    let r = fp_run(&[0x4ea0_b820], |g| {
        g.v[2] = packi(-5, 6);
        g.v[3] = packi(-7, 8);
    });
    assert_eq!(r.v[0], packi(5, 6), "abs lanes 0,1");
    assert_eq!(r.v[1], packi(7, 8), "abs lanes 2,3");
}

// End-to-end: vector unary ops run as a hot loop through the emulator JIT vs
// the interpreter. Each loop recomputes v0 = unary(v1) (idempotent), so the
// final v0 == unary(v1) and JIT must match the interpreter.
#[test]
fn e2e_vector_unary_hot_loop_matches_interpreter() {
    let f = |x: f32| x.to_bits() as u128;
    let pf = |a: f32, b: f32, c: f32, d: f32| f(a) | f(b) << 32 | f(c) << 64 | f(d) << 96;
    let pi = |a: i32, b: i32, c: i32, d: i32| {
        (a as u32 as u128)
            | (b as u32 as u128) << 32
            | (c as u32 as u128) << 64
            | (d as u32 as u128) << 96
    };
    // (op, v1, expected): <op> v0.4s,v1.4s ; subs x0,x0,#1 ; b.ne -8 ; ret
    let cases: [(u32, u128, u128); 5] = [
        (
            0x4ea0_f820,
            pf(-1.0, 2.0, -3.0, 4.0),
            pf(1.0, 2.0, 3.0, 4.0),
        ), // fabs
        (
            0x6ea0_f820,
            pf(1.0, -2.0, 3.0, -4.0),
            pf(-1.0, 2.0, -3.0, 4.0),
        ), // fneg
        (0x6ea1_f820, pf(1.0, 4.0, 9.0, 16.0), pf(1.0, 2.0, 3.0, 4.0)), // fsqrt
        (0x6ea0_b820, pi(1, -2, 3, -4), pi(-1, 2, -3, 4)),              // neg
        (0x4ea0_b820, pi(-5, 6, -7, 8), pi(5, 6, 7, 8)),                // abs
    ];

    for (op, v1, expected) in cases {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(interp, expected, "interp op={:#010x}", op);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
    }
}

// Per-lane vector bit-manipulation unary ops (CLZ/CLS/RBIT/CNT/NOT) via
// OpKind::VUnary, lift→lower→exec, compared to independent reference closures.
#[test]
fn probe_vector_bitmanip_unary() {
    // Per-byte helpers over a u64 (lane 0 = LSB).
    let per_byte = |x: u64, f: fn(u8) -> u8| -> u64 {
        let mut out = 0u64;
        for i in 0..8 {
            out |= (f(((x >> (i * 8)) & 0xFF) as u8) as u64) << (i * 8);
        }
        out
    };
    let lo: u64 = 0x7F3F_1F0F_0703_0100;
    let hi: u64 = 0xFFAA_5580_C0E0_F0F8;

    // cnt v0.16b, v1.16b (0x4e205820): per-byte popcount.
    let r = fp_run(&[0x4e20_5820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], per_byte(lo, |b| b.count_ones() as u8), "cnt lo");
    assert_eq!(r.v[1], per_byte(hi, |b| b.count_ones() as u8), "cnt hi");

    // not v0.16b, v1.16b (0x6e205820): bitwise NOT.
    let r = fp_run(&[0x6e20_5820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], !lo, "not lo");
    assert_eq!(r.v[1], !hi, "not hi");

    // rbit v0.16b, v1.16b (0x6e605820): per-byte bit reverse.
    let r = fp_run(&[0x6e60_5820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], per_byte(lo, |b| b.reverse_bits()), "rbit lo");
    assert_eq!(r.v[1], per_byte(hi, |b| b.reverse_bits()), "rbit hi");

    // Per-32-bit-lane CLZ/CLS helpers.
    let pack32 = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);
    let cls32 = |x: u32| -> u32 {
        let sign = (x >> 31) & 1;
        let mut c = 0u32;
        for i in (0..31).rev() {
            if (x >> i) & 1 == sign {
                c += 1;
            } else {
                break;
            }
        }
        c
    };

    // clz v0.4s, v1.4s (0x6ea04820).
    let s = [0x0000_0001u32, 0x0000_FFFF, 0x8000_0000, 0x0000_0000];
    let r = fp_run(&[0x6ea0_4820], |g| {
        g.v[2] = pack32(s[0], s[1]);
        g.v[3] = pack32(s[2], s[3]);
    });
    assert_eq!(
        r.v[0],
        pack32(s[0].leading_zeros(), s[1].leading_zeros()),
        "clz 0,1"
    );
    assert_eq!(
        r.v[1],
        pack32(s[2].leading_zeros(), s[3].leading_zeros()),
        "clz 2,3"
    );

    // cls v0.4s, v1.4s (0x4ea04820).
    let s = [0x0000_0001u32, 0xFFFF_FFFF, 0x8000_0000, 0x4000_0000];
    let r = fp_run(&[0x4ea0_4820], |g| {
        g.v[2] = pack32(s[0], s[1]);
        g.v[3] = pack32(s[2], s[3]);
    });
    assert_eq!(r.v[0], pack32(cls32(s[0]), cls32(s[1])), "cls 0,1");
    assert_eq!(r.v[1], pack32(cls32(s[2]), cls32(s[3])), "cls 2,3");
}

// End-to-end: each vector bit-manip op run as a hot loop through the emulator
// JIT vs the interpreter (which decodes them via its own independent path).
#[test]
fn e2e_vector_bitmanip_hot_loop_matches_interpreter() {
    // (op, v1): <op> v0,v1 ; subs x0,x0,#1 ; b.ne -8 ; ret. v0 = op(v1) each iter.
    let v1: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
    let ops: [u32; 5] = [
        0x4e20_5820, // cnt  v0.16b, v1.16b
        0x6e20_5820, // not  v0.16b, v1.16b
        0x6e60_5820, // rbit v0.16b, v1.16b
        0x6ea0_4820, // clz  v0.4s,  v1.4s
        0x4ea0_4820, // cls  v0.4s,  v1.4s
    ];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} produced a nonzero result", op);
    }
}

// Vector REV16/REV32/REV64 (reverse elements within 16/32/64-bit containers)
// via OpKind::VUnary, lift→lower→exec, compared to reference closures.
#[test]
fn probe_vector_rev() {
    let lo: u64 = 0x0102_0304_0506_0708;
    let hi: u64 = 0x1112_1314_1516_1718;

    // rev64 v0.16b, v1.16b (0x4e200820): byte-reverse each 64-bit lane.
    let r = fp_run(&[0x4e20_0820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], lo.swap_bytes(), "rev64.16b lo");
    assert_eq!(r.v[1], hi.swap_bytes(), "rev64.16b hi");

    // rev32 v0.16b, v1.16b (0x6e200820): byte-reverse each 32-bit word.
    let rev32 =
        |x: u64| (x as u32).swap_bytes() as u64 | ((((x >> 32) as u32).swap_bytes() as u64) << 32);
    let r = fp_run(&[0x6e20_0820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], rev32(lo), "rev32.16b lo");
    assert_eq!(r.v[1], rev32(hi), "rev32.16b hi");

    // rev16 v0.16b, v1.16b (0x4e201820): byte-reverse each 16-bit halfword.
    let rev16 = |x: u64| {
        let mut out = 0u64;
        for i in 0..4 {
            let h = ((x >> (i * 16)) & 0xFFFF) as u16;
            out |= (h.swap_bytes() as u64) << (i * 16);
        }
        out
    };
    let r = fp_run(&[0x4e20_1820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], rev16(lo), "rev16.16b lo");
    assert_eq!(r.v[1], rev16(hi), "rev16.16b hi");

    // rev64 v0.4s, v1.4s (0x4ea00820): swap the two 32-bit words in each lane.
    let rev64_w = |x: u64| (x >> 32) | (x << 32);
    let r = fp_run(&[0x4ea0_0820], |g| {
        g.v[2] = lo;
        g.v[3] = hi;
    });
    assert_eq!(r.v[0], rev64_w(lo), "rev64.4s lo");
    assert_eq!(r.v[1], rev64_w(hi), "rev64.4s hi");
}

// End-to-end: vector REV ops run as a hot loop through the emulator JIT vs the
// interpreter (which reverses container elements via its own decode path).
#[test]
fn e2e_vector_rev_hot_loop_matches_interpreter() {
    let v1: u128 = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
    let ops: [u32; 4] = [
        0x4e20_0820, // rev64 v0.16b, v1.16b
        0x6e20_0820, // rev32 v0.16b, v1.16b
        0x4e20_1820, // rev16 v0.16b, v1.16b
        0x4ea0_0820, // rev64 v0.4s,  v1.4s
    ];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} produced a nonzero result", op);
    }
}

// Vector across-lanes integer reductions (ADDV/SMAXV/UMAXV/SMINV/UMINV) via
// OpKind::VReduce, lift→lower→exec. Result is a scalar in lane 0.
#[test]
fn probe_vector_reduce() {
    let pack32 = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);

    // addv s0, v1.4s (0x4eb1b820): sum of 4 i32 lanes = 1+2+3+4 = 10.
    let r = fp_run(&[0x4eb1_b820], |g| {
        g.v[2] = pack32(1, 2);
        g.v[3] = pack32(3, 4);
    });
    assert_eq!(r.v[0], 10, "addv .4s sum");
    assert_eq!(r.v[1], 0, "addv clears upper");

    // smaxv s0, v1.4s (0x4eb0a820): signed max of [-5,3,10,-2] = 10.
    let r = fp_run(&[0x4eb0_a820], |g| {
        g.v[2] = pack32((-5i32) as u32, 3);
        g.v[3] = pack32(10, (-2i32) as u32);
    });
    assert_eq!(r.v[0] as u32, 10, "smaxv .4s");

    // sminv s0, v1.4s (0x4eb1a820): signed min of [-5,3,10,-2] = -5.
    let r = fp_run(&[0x4eb1_a820], |g| {
        g.v[2] = pack32((-5i32) as u32, 3);
        g.v[3] = pack32(10, (-2i32) as u32);
    });
    assert_eq!(r.v[0] as u32, (-5i32) as u32, "sminv .4s");

    // umaxv s0, v1.4s (0x6eb0a820): unsigned max = 0xFFFFFFFF.
    let r = fp_run(&[0x6eb0_a820], |g| {
        g.v[2] = pack32(1, 0xFFFF_FFFF);
        g.v[3] = pack32(3, 4);
    });
    assert_eq!(r.v[0] as u32, 0xFFFF_FFFF, "umaxv .4s");

    // uminv b0, v1.16b (0x6e31a820): unsigned min byte = 0x01.
    let r = fp_run(&[0x6e31_a820], |g| {
        g.v[2] = 0x0807_0605_0403_0201;
        g.v[3] = 0x100F_0E0D_0C0B_0A09;
    });
    assert_eq!(r.v[0], 0x01, "uminv .16b");
}

// End-to-end: vector reductions run as a hot loop through the emulator JIT vs
// the interpreter (which reduces via its own exec_simd_across_lanes path).
#[test]
fn e2e_vector_reduce_hot_loop_matches_interpreter() {
    let p = |a: u32, b: u32, c: u32, d: u32| {
        (a as u128) | (b as u128) << 32 | (c as u128) << 64 | (d as u128) << 96
    };
    let v1 = p(7, 3, 11, 5);
    let ops: [u32; 4] = [
        0x4eb1_b820, // addv  s0, v1.4s  -> 26
        0x4eb0_a820, // smaxv s0, v1.4s  -> 11
        0x4eb1_a820, // sminv s0, v1.4s  -> 3
        0x6eb0_a820, // umaxv s0, v1.4s  -> 11
    ];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} produced a nonzero result", op);
    }
}

// Vector FP numeric min/max FMAXNM/FMINNM (three-same) via OpKind::VFMinMaxNm.
// These are NaN-quiet (return the numeric operand), unlike FMAX/FMIN.
#[test]
fn probe_vector_fp_minmax_nm_4s() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;
    let nan = f32::NAN;

    // fmaxnm v0.4s, v1.4s, v2.4s (0x4e22c420). v1=[1,NaN,3,8], v2=[4,2,7,6].
    let r = fp_run(&[0x4e22_c420], |g| {
        g.v[2] = pack(1.0, nan);
        g.v[3] = pack(3.0, 8.0);
        g.v[4] = pack(4.0, 2.0);
        g.v[5] = pack(7.0, 6.0);
    });
    assert_eq!(r.v[0], pack(4.0, 2.0), "fmaxnm 0,1 (max(NaN,2)=2 numeric)");
    assert_eq!(r.v[1], pack(7.0, 8.0), "fmaxnm 2,3");

    // fminnm v0.4s, v1.4s, v2.4s (0x4ea2c420).
    let r = fp_run(&[0x4ea2_c420], |g| {
        g.v[2] = pack(1.0, nan);
        g.v[3] = pack(3.0, 8.0);
        g.v[4] = pack(4.0, 2.0);
        g.v[5] = pack(7.0, 6.0);
    });
    assert_eq!(r.v[0], pack(1.0, 2.0), "fminnm 0,1 (min(NaN,2)=2 numeric)");
    assert_eq!(r.v[1], pack(3.0, 6.0), "fminnm 2,3");
}

// End-to-end: FMAXNM/FMINNM hot loop through the emulator JIT vs interpreter.
#[test]
fn e2e_vector_fp_minmax_nm_matches_interpreter() {
    let f = |x: f32| x.to_bits() as u128;
    let p = |a: f32, b: f32, c: f32, d: f32| f(a) | f(b) << 32 | f(c) << 64 | f(d) << 96;
    let v1 = p(1.0, 5.0, 3.0, 8.0);
    let v2 = p(4.0, 2.0, 7.0, 6.0);
    let cases: [(u32, u128); 2] = [
        (0x4e22_c420, p(4.0, 5.0, 7.0, 8.0)), // fmaxnm
        (0x4ea2_c420, p(1.0, 2.0, 3.0, 6.0)), // fminnm
    ];
    for (op, expected) in cases {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_simd(2, v2);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(interp, expected, "interp op={:#010x}", op);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
    }
}

// Vector FP across-lanes reductions FMAXV/FMINV/FMAXNMV/FMINNMV via VReduce.
#[test]
fn probe_vector_fp_reduce() {
    let f = |x: f32| x.to_bits() as u64;
    let pack = |a: f32, b: f32| f(a) | f(b) << 32;
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = pack(1.0, 5.0); // v1 = [1, 5, 3, 8]
        g.v[3] = pack(3.0, 8.0);
    };
    // fmaxv s0, v1.4s (0x4e30f820) -> 8
    let r = fp_run(&[0x6e30_f820], setup);
    assert_eq!(r.v[0], f(8.0) as u64, "fmaxv");
    // fminv s0, v1.4s (0x4eb0f820) -> 1
    let r = fp_run(&[0x6eb0_f820], setup);
    assert_eq!(r.v[0], f(1.0) as u64, "fminv");
    // fmaxnmv s0, v1.4s (0x4e30c820) -> 8
    let r = fp_run(&[0x6e30_c820], setup);
    assert_eq!(r.v[0], f(8.0) as u64, "fmaxnmv");
    // fminnmv s0, v1.4s (0x4eb0c820) -> 1
    let r = fp_run(&[0x6eb0_c820], setup);
    assert_eq!(r.v[0], f(1.0) as u64, "fminnmv");
}

#[test]
fn e2e_vector_fp_reduce_hot_loop_matches_interpreter() {
    let f = |x: f32| x.to_bits() as u128;
    let v1 = f(2.0) | f(9.0) << 32 | f(4.0) << 64 | f(7.0) << 96;
    let ops: [u32; 4] = [0x6e30_f820, 0x6eb0_f820, 0x6e30_c820, 0x6eb0_c820];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} nonzero", op);
    }
}

// Vector two-source permutes ZIP/UZP/TRN via OpKind::VPermute2, lift→lower→exec.
// v1 = [1,2,3,4], v2 = [5,6,7,8] (.4s lanes).
#[test]
fn probe_vector_permute() {
    let p = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);
    let setup = |g: &mut Aarch64GuestRegs| {
        g.v[2] = 0x0000_0002_0000_0001; // v1 lanes 0,1 = 1,2
        g.v[3] = 0x0000_0004_0000_0003; // v1 lanes 2,3 = 3,4
        g.v[4] = 0x0000_0006_0000_0005; // v2 lanes 0,1 = 5,6
        g.v[5] = 0x0000_0008_0000_0007; // v2 lanes 2,3 = 7,8
    };
    // zip1 v0.4s,v1.4s,v2.4s (0x4ea23820) -> [1,5,2,6]
    let r = fp_run(&[0x4e82_3820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(1, 5), p(2, 6)), "zip1");
    // zip2 (0x4ea27820) -> [3,7,4,8]
    let r = fp_run(&[0x4e82_7820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(3, 7), p(4, 8)), "zip2");
    // uzp1 (0x4ea21820) -> [1,3,5,7]
    let r = fp_run(&[0x4e82_1820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(1, 3), p(5, 7)), "uzp1");
    // uzp2 (0x4ea25820) -> [2,4,6,8]
    let r = fp_run(&[0x4e82_5820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(2, 4), p(6, 8)), "uzp2");
    // trn1 (0x4ea22820) -> [1,5,3,7]
    let r = fp_run(&[0x4e82_2820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(1, 5), p(3, 7)), "trn1");
    // trn2 (0x4ea26820) -> [2,6,4,8]
    let r = fp_run(&[0x4e82_6820], setup);
    assert_eq!((r.v[0], r.v[1]), (p(2, 6), p(4, 8)), "trn2");
}

#[test]
fn e2e_vector_permute_hot_loop_matches_interpreter() {
    let v1: u128 = 0x0000_0004_0000_0003_0000_0002_0000_0001;
    let v2: u128 = 0x0000_0008_0000_0007_0000_0006_0000_0005;
    let ops: [u32; 6] = [
        0x4e82_3820,
        0x4e82_7820,
        0x4e82_1820,
        0x4e82_5820,
        0x4e82_2820,
        0x4e82_6820,
    ];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_simd(2, v2);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} nonzero", op);
    }
}

// Vector table lookup TBL/TBX via OpKind::VTableLookup, lift→lower→exec.
#[test]
fn probe_vector_table_lookup() {
    // tbl v0.16b, {v1.16b}, v2.16b (0x4e020020): single table.
    // v1 = bytes 0x10..0x1f; index = [0..7, 16..23] (first 8 in range).
    let r = fp_run(&[0x4e02_0020], |g| {
        g.v[2] = 0x1716_1514_1312_1110;
        g.v[3] = 0x1f1e_1d1c_1b1a_1918;
        g.v[4] = 0x0706_0504_0302_0100; // idx 0..7 (in range)
        g.v[5] = 0x1716_1514_1312_1110; // idx 16..23 (out of range)
    });
    assert_eq!(r.v[0], 0x1716_1514_1312_1110, "tbl in-range -> v1[idx]");
    assert_eq!(r.v[1], 0, "tbl out-of-range -> 0");

    // tbx v0.16b, {v1.16b}, v2.16b (0x4e021020): out-of-range keeps dst.
    let r = fp_run(&[0x4e02_1020], |g| {
        g.v[0] = 0xCCCC_CCCC_CCCC_CCCC; // dst lo (overwritten, all in range)
        g.v[1] = 0xAAAA_AAAA_AAAA_AAAA; // dst hi (kept, all out of range)
        g.v[2] = 0x1716_1514_1312_1110;
        g.v[3] = 0x1f1e_1d1c_1b1a_1918;
        g.v[4] = 0x0706_0504_0302_0100;
        g.v[5] = 0x1716_1514_1312_1110;
    });
    assert_eq!(r.v[0], 0x1716_1514_1312_1110, "tbx in-range -> v1[idx]");
    assert_eq!(
        r.v[1], 0xAAAA_AAAA_AAAA_AAAA,
        "tbx out-of-range -> keeps dst"
    );

    // tbl v0.16b, {v1.16b, v2.16b}, v3.16b (0x4e032020): two-table (consecutive
    // regs). v1 = 0x10..0x1f, v2 = 0x20..0x2f, index = [16..31] -> table[16..32]
    // = v2.
    let r = fp_run(&[0x4e03_2020], |g| {
        g.v[2] = 0x1716_1514_1312_1110; // v1 lo
        g.v[3] = 0x1f1e_1d1c_1b1a_1918; // v1 hi
        g.v[4] = 0x2726_2524_2322_2120; // v2 lo (bytes 0x20..0x27)
        g.v[5] = 0x2f2e_2d2c_2b2a_2928; // v2 hi (bytes 0x28..0x2f)
        g.v[6] = 0x1716_1514_1312_1110; // idx 16..23
        g.v[7] = 0x1f1e_1d1c_1b1a_1918; // idx 24..31
    });
    assert_eq!(r.v[0], 0x2726_2524_2322_2120, "2-table tbl -> v2 lo");
    assert_eq!(r.v[1], 0x2f2e_2d2c_2b2a_2928, "2-table tbl -> v2 hi");
}

#[test]
fn e2e_vector_table_lookup_hot_loop_matches_interpreter() {
    let v1: u128 = 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110;
    // index: reverse byte order 15..0 (all in range).
    let idx: u128 = 0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f;
    let ops: [u32; 2] = [0x4e02_0020 /* tbl */, 0x4e02_1020 /* tbx */];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_simd(2, idx);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} nonzero", op);
    }
}

// Widening add reductions SADDLV/UADDLV via VReduce (result is 2x element width).
#[test]
fn probe_vector_widening_reduce() {
    // saddlv h0, v1.16b (0x4e303820): signed sum of 16 bytes (all -1) = -16.
    let r = fp_run(&[0x4e30_3820], |g| {
        g.v[2] = 0xFFFF_FFFF_FFFF_FFFF;
        g.v[3] = 0xFFFF_FFFF_FFFF_FFFF;
    });
    assert_eq!(r.v[0], 0xFFF0, "saddlv .16b signed sum -16 (16-bit)");
    assert_eq!(r.v[1], 0, "upper cleared");

    // uaddlv h0, v1.16b (0x6e303820): unsigned sum = 16*255 = 4080.
    let r = fp_run(&[0x6e30_3820], |g| {
        g.v[2] = 0xFFFF_FFFF_FFFF_FFFF;
        g.v[3] = 0xFFFF_FFFF_FFFF_FFFF;
    });
    assert_eq!(r.v[0], 4080, "uaddlv .16b unsigned sum 4080");

    // saddlv d0, v1.4s (0x4eb03820): widen 4 i32 [1,2,3,4] to 64-bit -> 10.
    let pack32 = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);
    let r = fp_run(&[0x4eb0_3820], |g| {
        g.v[2] = pack32(1, 2);
        g.v[3] = pack32(3, 4);
    });
    assert_eq!(r.v[0], 10, "saddlv .4s -> 64-bit sum 10");
}

#[test]
fn e2e_vector_widening_reduce_hot_loop_matches_interpreter() {
    let v1: u128 = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF; // 16 bytes of -1 / 255
    let ops: [u32; 2] = [
        0x4e30_3820, /* saddlv h0,v1.16b */
        0x6e30_3820, /* uaddlv */
    ];
    for op in ops {
        let prog: [u32; 4] = [op, 0xf100_0400, 0x54ff_ffc1, 0xd65f_03c0];
        let run_one = |jit: bool| -> u128 {
            let mut cpu = fresh_cpu();
            cpu.set_jit_enabled(jit);
            load_prog(&mut cpu, &prog);
            cpu.set_simd(0, 0);
            cpu.set_simd(1, v1);
            cpu.set_x(0, 100);
            drive_to_done(&mut cpu);
            cpu.get_simd(0)
        };
        let interp = run_one(false);
        let jit = run_one(true);
        assert_eq!(jit, interp, "JIT matches interp op={:#010x}", op);
        assert_ne!(interp, 0, "op={:#010x} nonzero", op);
    }
}
