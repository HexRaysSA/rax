//! Portable direct/SMIR restore parity under valid architectural controls.
//!
//! SMIR does not yet represent #NM precisely, so disabled-state guards are
//! intentionally outside this matrix. Raw x87 layout, legacy high-XMM behavior,
//! and the pre-existing compacted AVX initialization gap are not compared.

use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{FunctionId, SourceArch};
use crate::smir::ir::{FunctionBuilder, SmirFunction, Terminator, TrapKind};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{LiftContext, SmirLifter};
use crate::smir::optimize::{OptLevel, optimize_function};

fn function(kind: Restore, rex_w: bool, level: OptLevel) -> SmirFunction {
    let bytes = kind.bytes(rex_w);
    let result = X86_64Lifter::strict()
        .lift_insn(CODE, &bytes, &mut LiftContext::new(SourceArch::X86_64))
        .unwrap();
    assert_eq!(result.bytes_consumed, bytes.len());
    let mut builder = FunctionBuilder::new(FunctionId(0), CODE);
    builder.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut function = builder.finish();
    function.blocks[0].ops = result.ops;
    optimize_function(&mut function, level);
    assert_eq!(
        function.blocks[0]
            .ops
            .iter()
            .filter(|op| match op.kind {
                OpKind::X86FxRstor { rex_w: wide, .. } =>
                    matches!(kind, Restore::Fx) && wide == rex_w,
                OpKind::X86XRstor {
                    rex_w: wide,
                    supervisor,
                    ..
                } =>
                    !matches!(kind, Restore::Fx)
                        && wide == rex_w
                        && supervisor == matches!(kind, Restore::Supervisor),
                _ => false,
            })
            .count(),
        1,
        "{kind:?} REX.W={rex_w} {level:?}: retain one typed restore, not a fallback"
    );
    function
}

fn context(vcpu: &X86_64Vcpu) -> SmirContext {
    let mut ctx = SmirContext::new_x86_64();
    ctx.pc = CODE;
    ctx.flags.materialized = MaterializedFlags::from_rflags(vcpu.regs.rflags);
    ctx.flags.lazy = None;
    let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
        unreachable!()
    };
    for index in 0..32 {
        x86.gpr[index] = vcpu.get_reg(index as u8, 8);
    }
    x86.cr0 = vcpu.sregs.cr0;
    x86.cr4 = vcpu.sregs.cr4;
    x86.efer = vcpu.sregs.efer;
    x86.cs_l = true;
    x86.cpl = 0;
    x86.xcr0 = vcpu.xcr0;
    x86.mxcsr = vcpu.mxcsr;
    for index in 0..16 {
        x86.xmm[index][..2].copy_from_slice(&vcpu.regs.xmm[index]);
        x86.xmm[index][2..4].copy_from_slice(&vcpu.regs.ymm_high[index]);
        x86.xmm[index][4..8].copy_from_slice(&vcpu.regs.zmm_high[index]);
        x86.xmm[index + 16][..8].copy_from_slice(&vcpu.regs.zmm_ext[index]);
    }
    ctx
}

fn compare(vcpu: &X86_64Vcpu, ctx: &mut SmirContext, expected_mxcsr: u32) {
    let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
        unreachable!()
    };
    assert_eq!(vcpu.mxcsr, expected_mxcsr, "direct MXCSR");
    assert_eq!(x86.mxcsr, expected_mxcsr, "SMIR MXCSR");
    for index in 0..8 {
        assert_eq!(
            vcpu.regs.xmm[index],
            [x86.xmm[index][0], x86.xmm[index][1]],
            "XMM{index}"
        );
    }
    ctx.flags.materialize_all();
    assert_eq!(vcpu.regs.rflags, 0xCD7);
    assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7);
}

fn pair(
    kind: Restore,
    rex_w: bool,
    requested: u64,
    xstate: u64,
    mxcsr: u32,
) -> (X86_64Vcpu, SmirContext, FlatMemory) {
    let (mut vcpu, memory) = cpu(kind, rex_w);
    // Upper halves do not contribute to the architectural EDX:EAX request.
    vcpu.regs.rax = 0xA5A5_A5A5_0000_0000 | requested;
    vcpu.regs.rdx = 0x5A5A_5A5A_0000_0000;
    image(&memory, AREA, kind, xstate, mxcsr);
    let ctx = context(&vcpu);
    let mut contents = [0u8; 0xB00];
    memory
        .read_slice(&mut contents, GuestAddress(AREA))
        .unwrap();
    let mut smir_memory = FlatMemory::with_base(AREA, contents.len());
    smir_memory.write(AREA, &contents).unwrap();
    (vcpu, ctx, smir_memory)
}

fn expected_mxcsr(kind: Restore, requested: u64, xstate: u64, value: u32) -> u32 {
    // SDM 086 Vol. 1 §§13.8.1, 13.8.2, 13.12: standard MXCSR selection
    // depends on SSE OR AVX, independent of XSTATE_BV. Compacted forms use
    // requested SSE only, initializing it when the component is not present.
    if matches!(kind, Restore::Fx) {
        value
    } else if kind.compacted() {
        if requested & 2 == 0 {
            ORIGINAL_MXCSR
        } else if xstate & 2 == 0 {
            0x1F80
        } else {
            value
        }
    } else if requested & 6 != 0 {
        value
    } else {
        ORIGINAL_MXCSR
    }
}

#[test]
fn direct_smir_mxcsr_restore_selection_and_valid_values_at_o0_o1_o2() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for kind in [
            Restore::Fx,
            Restore::Standard,
            Restore::Compacted,
            Restore::Supervisor,
        ] {
            for rex_w in [false, true] {
                let function = function(kind, rex_w, level);
                for requested in 0..8 {
                    for xstate in 0..8 {
                        for value in [0x0041, 0x1F80, 0xFFFF] {
                            let (mut direct, mut ctx, mut memory) =
                                pair(kind, rex_w, requested, xstate, value);
                            assert!(direct.step().unwrap().is_none());
                            let exit = SmirInterpreter::new().execute_block(
                                &mut ctx,
                                &mut memory,
                                &function.blocks[0],
                            );
                            assert!(
                                matches!(exit, BlockResult::Exit(ExitReason::Halt)),
                                "{kind:?} {level:?}: {exit:?}"
                            );
                            compare(
                                &direct,
                                &mut ctx,
                                expected_mxcsr(kind, requested, xstate, value),
                            );
                            assert_eq!(direct.regs.rip, CODE + kind.bytes(rex_w).len() as u64);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn direct_smir_mxcsr_restore_reserved_bits_fault_only_when_loaded_at_o0_o1_o2() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for kind in [
            Restore::Fx,
            Restore::Standard,
            Restore::Compacted,
            Restore::Supervisor,
        ] {
            for rex_w in [false, true] {
                let function = function(kind, rex_w, level);
                for (requested, xstate) in [(0, 0), (1, 1), (2, 0), (2, 2), (4, 0), (4, 4), (6, 6)]
                {
                    for bit in 16..32 {
                        let value = 0x0041 | (1u32 << bit);
                        let expected = expected_mxcsr(kind, requested, xstate, value);
                        let should_fault = expected == value;
                        let (mut direct, mut ctx, mut memory) =
                            pair(kind, rex_w, requested, xstate, value);
                        let before_xmm = direct.regs.xmm;
                        if should_fault {
                            fault(&mut direct, 13);
                        } else {
                            assert!(direct.step().unwrap().is_none());
                        }
                        let exit = SmirInterpreter::new().execute_block(
                            &mut ctx,
                            &mut memory,
                            &function.blocks[0],
                        );
                        if should_fault {
                            assert!(
                                matches!(
                                    exit,
                                    BlockResult::Exit(ExitReason::GeneralProtection {
                                        addr: CODE,
                                        error_code: 0
                                    })
                                ),
                                "{kind:?} {level:?} RFBM={requested:#x} XSTATE={xstate:#x} bit={bit}: {exit:?}"
                            );
                            assert_eq!(&direct.regs.xmm[..8], &before_xmm[..8]);
                            compare(&direct, &mut ctx, ORIGINAL_MXCSR);
                        } else {
                            assert!(
                                matches!(exit, BlockResult::Exit(ExitReason::Halt)),
                                "{kind:?} {level:?}: {exit:?}"
                            );
                            compare(&direct, &mut ctx, expected);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn direct_smir_mxcsr_restore_compacted_xstate_bit63_is_allowed_at_o0_o1_o2() {
    // SDM 086 Vol. 1 §§13.8.2 and 13.12 compare all 64 XSTATE_BV bits
    // with XCOMP_BV, including its set compacted-format bit 63. Bit 63
    // does not designate a state component selected by XCR0 or EDX:EAX.
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for kind in [Restore::Compacted, Restore::Supervisor] {
            for rex_w in [false, true] {
                let function = function(kind, rex_w, level);
                for requested in [0, 2, 4, 6] {
                    for xstate in [0, 2] {
                        let (mut direct, mut ctx, mut memory) =
                            pair(kind, rex_w, requested, COMPACTED | xstate, 0x0041);
                        let direct_result = direct.step();
                        let smir_result = SmirInterpreter::new().execute_block(
                            &mut ctx,
                            &mut memory,
                            &function.blocks[0],
                        );
                        assert!(
                            matches!(direct_result, Ok(None))
                                && matches!(smir_result, BlockResult::Exit(ExitReason::Halt)),
                            "{kind:?} REX.W={rex_w} {level:?} RFBM={requested:#x} \
                             XSTATE={:#x}: direct={direct_result:?}, SMIR={smir_result:?}",
                            COMPACTED | xstate,
                        );
                        compare(
                            &direct,
                            &mut ctx,
                            expected_mxcsr(kind, requested, xstate, 0x0041),
                        );
                        assert_eq!(direct.regs.rip, CODE + kind.bytes(rex_w).len() as u64);
                    }
                }
            }
        }
    }
}

#[test]
fn direct_smir_mxcsr_restore_unsupported_header_bits_remain_gp_at_o0_o1_o2() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for kind in [Restore::Standard, Restore::Compacted, Restore::Supervisor] {
            for rex_w in [false, true] {
                let function = function(kind, rex_w, level);
                for bit in 3..64 {
                    if bit == 63 && kind.compacted() {
                        continue; // Full-XCOMP_BV bit 63 is covered by the positive test.
                    }
                    for include_in_format in [false, true] {
                        if !kind.compacted() && include_in_format {
                            continue;
                        }
                        let (mut direct, mut ctx, mut memory) =
                            pair(kind, rex_w, 2, 2 | (1u64 << bit), 0x0041);
                        if include_in_format {
                            let xcomp_bv = COMPACTED | 7 | (1u64 << bit);
                            direct.write_mem64(AREA + 520, xcomp_bv).unwrap();
                            memory.write(AREA + 520, &xcomp_bv.to_le_bytes()).unwrap();
                        }
                        fault(&mut direct, 13);
                        let exit = SmirInterpreter::new().execute_block(
                            &mut ctx,
                            &mut memory,
                            &function.blocks[0],
                        );
                        assert!(
                            matches!(
                                exit,
                                BlockResult::Exit(ExitReason::GeneralProtection {
                                    addr: CODE,
                                    error_code: 0
                                })
                            ),
                            "{kind:?} REX.W={rex_w} {level:?} bit={bit} \
                             included in XCOMP_BV={include_in_format}: {exit:?}"
                        );
                        compare(&direct, &mut ctx, ORIGINAL_MXCSR);
                    }
                }
            }
        }
    }
}

#[test]
fn direct_smir_selected_mxcsr_read_fault_classification_at_o0_o1_o2() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for kind in [Restore::Standard, Restore::Compacted, Restore::Supervisor] {
            for rex_w in [false, true] {
                for (requested, xstate) in [(2, 2), (2, 0), (4, 0), (0, 0)] {
                    let (mut direct, memory) = split_header_cpu(kind);
                    memory
                        .write_slice(&kind.bytes(rex_w), GuestAddress(CODE))
                        .unwrap();
                    direct.regs.rax = requested;
                    put(&memory, 0x3E00 + 512, xstate, 8);
                    let mut ctx = context(&direct);
                    // Match the direct fixture's mapped header page while the
                    // preceding page containing MXCSR is inaccessible.
                    let mut contents = [0u8; 0x1000];
                    memory
                        .read_slice(&mut contents, GuestAddress(0x4000))
                        .unwrap();
                    let mut smir_memory = FlatMemory::with_base(0x4000, contents.len());
                    smir_memory.write(0x4000, &contents).unwrap();
                    let function = function(kind, rex_w, level);
                    let loaded = if kind.compacted() {
                        requested & xstate & 2 != 0
                    } else {
                        requested & 6 != 0
                    };
                    let result = direct.step();
                    let exit = SmirInterpreter::new().execute_block(
                        &mut ctx,
                        &mut smir_memory,
                        &function.blocks[0],
                    );
                    if loaded {
                        assert!(
                            matches!(
                                result,
                                Err(Error::PageFault {
                                    vaddr: 0x3E18,
                                    error_code: 0
                                })
                            ),
                            "{result:?}"
                        );
                        assert!(
                            matches!(
                                exit,
                                BlockResult::Exit(ExitReason::MemoryFault {
                                    addr: 0x3E18,
                                    write: false
                                })
                            ),
                            "{exit:?}"
                        );
                        compare(&direct, &mut ctx, ORIGINAL_MXCSR);
                        assert_eq!(direct.regs.rip, CODE);
                    } else {
                        assert!(result.unwrap().is_none());
                        assert!(
                            matches!(exit, BlockResult::Exit(ExitReason::Halt)),
                            "{exit:?}"
                        );
                        compare(
                            &direct,
                            &mut ctx,
                            expected_mxcsr(kind, requested, xstate, 0x1F80),
                        );
                    }
                }
            }
        }
    }
}
