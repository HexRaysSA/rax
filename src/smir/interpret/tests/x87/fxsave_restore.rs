//! Legacy FXSAVE/FXRSTOR layout and fault-class regressions.

use super::*;
use crate::smir::optimize::{OptLevel, optimize_function};

const RESTORE_PC: u64 = 0x1234;

fn execute_fxrstor(
    rex_w: bool,
    level: OptLevel,
    ctx: &mut SmirContext,
    memory: &mut dyn SmirMemory,
) -> BlockResult {
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let bytes: &[u8] = if rex_w {
        &[0x48, 0x0F, 0xAE, 0x08]
    } else {
        &[0x0F, 0xAE, 0x08]
    };
    let mut lift_context = LiftContext::new(SourceArch::X86_64);
    let result = X86_64Lifter::strict()
        .lift_insn(RESTORE_PC, bytes, &mut lift_context)
        .unwrap();
    assert_eq!(result.bytes_consumed, bytes.len());
    let mut builder = FunctionBuilder::new(FunctionId(0), RESTORE_PC);
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
            .filter(|op| matches!(op.kind, OpKind::X86FxRstor { rex_w: wide, .. } if wide == rex_w))
            .count(),
        1,
        "{level:?}: retain one typed FXRSTOR with the selected pointer format"
    );
    SmirInterpreter::new().execute_block(ctx, memory, &function.blocks[0])
}

fn restore_context(address: u64) -> SmirContext {
    let mut ctx = SmirContext::new_x86_64();
    ctx.pc = RESTORE_PC;
    ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
    ctx.flags.lazy = None;
    let ArchRegState::X86_64(x86) = &mut ctx.arch_regs else {
        unreachable!()
    };
    x86.cr0 = 1;
    x86.cr4 = 1 << 9;
    x86.cs_l = true;
    x86.gpr.fill(0x1234_5678_9ABC_DEF0);
    x86.gpr[0] = address;
    x86.x87.control_word = 0x077F;
    x86.x87.status_word = 3 << 11;
    x86.x87.instr_ptr = 0x1234_5678_90AB_CDEF;
    x86.x87.data_ptr = 0xFEDC_BA09_8765_4321;
    x86.x87.last_opcode = 0x345;
    x86.x87.set_logical_raw(0, [0xA5; 10]);
    x86.mxcsr = 0x3FA1;
    x86.xmm = [[0xCAFE_BABE_DEAD_BEEF; 16]; 32];
    x86.k.fill(0xFEDC_BA98_7654_3210);
    ctx
}

fn assert_restore_state_unchanged(ctx: &mut SmirContext, before: &ArchRegState) {
    let (ArchRegState::X86_64(actual), ArchRegState::X86_64(before)) = (&ctx.arch_regs, before)
    else {
        unreachable!()
    };
    assert_eq!(actual.x87, before.x87);
    assert_eq!(actual.mxcsr, before.mxcsr);
    assert_eq!(actual.xmm, before.xmm);
    assert_eq!(actual.k, before.k);
    assert_eq!(actual.gpr, before.gpr);
    assert_eq!(ctx.pc, RESTORE_PC);
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7);
}

#[test]
fn fxrstor_alignment_and_reserved_mxcsr_are_gp_at_o0_o1_o2() {
    // Intel SDM 086 Vol. 2A 3-469--471: reserved MXCSR bits and 16-byte
    // misalignment raise #GP(0). CPL=0 avoids the implementation-dependent
    // #AC alternative. Each fault reports the instruction PC, not the data EA.
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for rex_w in [false, true] {
            for misalignment in [1, 8, 15] {
                // The zero-length memory also proves that the alignment check
                // occurs before any attempt to read the restore image.
                for memory_size in [0, 0x500] {
                    let mut memory = FlatMemory::new(memory_size);
                    let mut ctx = restore_context(0x200 + misalignment);
                    let before = ctx.arch_regs.clone();
                    let exit = execute_fxrstor(rex_w, level, &mut ctx, &mut memory);
                    assert!(
                        matches!(
                            exit,
                            BlockResult::Exit(ExitReason::GeneralProtection {
                                addr: RESTORE_PC,
                                error_code: 0
                            })
                        ),
                        "REX.W={rex_w} {level:?} alignment={misalignment}: {exit:?}"
                    );
                    assert_restore_state_unchanged(&mut ctx, &before);
                }
            }
            for reserved_bit in 16..32 {
                let mut image = [0xA5; 512];
                image[24..28].copy_from_slice(&(0x1F80u32 | (1 << reserved_bit)).to_le_bytes());
                let mut memory = FlatMemory::new(0x400);
                memory.write(0x200, &image).unwrap();
                let mut ctx = restore_context(0x200);
                let before = ctx.arch_regs.clone();
                let exit = execute_fxrstor(rex_w, level, &mut ctx, &mut memory);
                assert!(
                    matches!(
                        exit,
                        BlockResult::Exit(ExitReason::GeneralProtection {
                            addr: RESTORE_PC,
                            error_code: 0
                        })
                    ),
                    "REX.W={rex_w} {level:?} reserved bit={reserved_bit}: {exit:?}"
                );
                assert_restore_state_unchanged(&mut ctx, &before);
            }
        }
    }
}

#[test]
fn fxrstor_real_read_faults_remain_memory_faults_at_o0_o1_o2() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for rex_w in [false, true] {
            // The image is aligned but physically truncated, before or after
            // the MXCSR word. Unlike illegal architectural contents, a real
            // memory read failure keeps its direction and backend fault address.
            for memory_size in [0x200, 0x220, 0x3FF] {
                let mut memory = FlatMemory::new(memory_size);
                let mut ctx = restore_context(0x200);
                let before = ctx.arch_regs.clone();
                let exit = execute_fxrstor(rex_w, level, &mut ctx, &mut memory);
                // FlatMemory reports the starting address when it is already
                // outside the buffer, otherwise the requested exclusive end:
                // 0x200 bytes + 512 bytes = 0x400 bytes.
                let expected_address = if memory_size == 0x200 { 0x200 } else { 0x400 };
                assert!(
                    matches!(
                        exit,
                        BlockResult::Exit(ExitReason::MemoryFault {
                            addr,
                            write: false
                        }) if addr == expected_address
                    ),
                    "REX.W={rex_w} {level:?} memory length={memory_size:#x}: {exit:?}"
                );
                assert_restore_state_unchanged(&mut ctx, &before);
            }
        }
    }
}

#[test]
fn fxrstor_valid_mxcsr_including_unmasked_pending_status_loads_at_o0_o1_o2() {
    // Loading an unmasked exception together with its sticky status does not
    // itself raise #XM. MXCSR validation rejects reserved bits, not legal
    // exception-mask, DAZ, rounding, or FTZ combinations.
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for rex_w in [false, true] {
            for mxcsr in [0u32, 0x0041, 0x1F80, 0xFFFF] {
                let mut image = [0u8; 512];
                image[24..28].copy_from_slice(&mxcsr.to_le_bytes());
                let mut memory = FlatMemory::new(0x400);
                memory.write(0x200, &image).unwrap();
                let mut ctx = restore_context(0x200);
                let exit = execute_fxrstor(rex_w, level, &mut ctx, &mut memory);
                assert!(
                    matches!(exit, BlockResult::Exit(ExitReason::Halt)),
                    "REX.W={rex_w} {level:?} MXCSR={mxcsr:#x}: {exit:?}"
                );
                let ArchRegState::X86_64(x86) = &ctx.arch_regs else {
                    unreachable!()
                };
                assert_eq!(x86.mxcsr, mxcsr);
                assert_eq!(ctx.pc, RESTORE_PC);
                ctx.flags.materialize_all();
                assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7);
            }
        }
    }
}

#[test]
fn lifted_fxsave_fxrstor_preserve_exact_state_layout_tags_and_faults() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x1000);
    let raw_regs = [
        raw(0x8000_0000_0000_0000, 0x3FFF), // valid
        raw(0, 0x8000),                     // negative zero
        raw(0x8000_0000_0000_0000, 0x7FFF), // infinity/special
        raw(0x0123_4567_89AB_CDEF, 0x1234), // empty payload still saved
        raw(0xC000_0000_0000_0000, 0x4000), // valid 3.0
        raw(0x1111_2222_3333_4444, 0x2222),
        raw(0x5555_6666_7777_8888, 0x3333),
        raw(0x9999_AAAA_BBBB_CCCC, 0x4444),
    ];
    let tag_classes = [0u16, 1, 2, 3, 0, 3, 3, 3];
    let expected_tag_word = tag_classes
        .iter()
        .enumerate()
        .fold(0u16, |tags, (physical, tag)| {
            tags | (*tag << (physical * 2))
        });
    let xmm0 = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210];
    let xmm15 = [0xA5A5_5A5A_F0F0_0F0F, 0x1357_9BDF_2468_ACE0];

    ctx.write_vreg(rax, 0x200);
    memory.write(0x200, &[0xA5; 512]).unwrap();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word = 0x0B7F;
        x86.x87.status_word = 0x1845; // TOP=3
        x86.x87.tag_word = expected_tag_word;
        x86.x87.data_ptr = 0xFEDC_BA98_7654_3210;
        x86.x87.instr_ptr = 0x0123_4567_89AB_CDEF;
        x86.x87.last_opcode = 0xFABC;
        x86.x87.regs = raw_regs;
        x86.mxcsr = 0x5F80;
        x86.xmm[0][0..2].copy_from_slice(&xmm0);
        x86.xmm[15][0..2].copy_from_slice(&xmm15);
    }
    execute_lifted_x86(&[0x48, 0x0F, 0xAE, 0x00], &mut ctx, &mut memory); // FXSAVE64 [RAX]

    let mut image = [0u8; 512];
    memory.read(0x200, &mut image).unwrap();
    assert_eq!(u16::from_le_bytes(image[0..2].try_into().unwrap()), 0x0B7F);
    assert_eq!(u16::from_le_bytes(image[2..4].try_into().unwrap()), 0x1845);
    assert_eq!(image[4], 0x17, "abridged FTW physical order");
    assert_eq!(image[5], 0);
    assert_eq!(u16::from_le_bytes(image[6..8].try_into().unwrap()), 0x02BC);
    assert_eq!(
        u64::from_le_bytes(image[8..16].try_into().unwrap()),
        0x0123_4567_89AB_CDEF
    );
    assert_eq!(
        u64::from_le_bytes(image[16..24].try_into().unwrap()),
        0xFEDC_BA98_7654_3210
    );
    assert_eq!(
        u32::from_le_bytes(image[24..28].try_into().unwrap()),
        0x5F80
    );
    assert_eq!(
        u32::from_le_bytes(image[28..32].try_into().unwrap()),
        0xFFFF
    );
    // TOP=3 means the ST0 slot contains physical R3 and ST1 contains R4.
    assert_eq!(&image[32..42], &raw_regs[3]);
    assert_eq!(&image[48..58], &raw_regs[4]);
    assert_eq!(&image[112..122], &raw_regs[0]); // ST5 wraps to physical R0
    assert_eq!(
        u64::from_le_bytes(image[160..168].try_into().unwrap()),
        xmm0[0]
    );
    assert_eq!(
        u64::from_le_bytes(image[408..416].try_into().unwrap()),
        xmm15[1]
    );
    assert!(image[464..].iter().all(|byte| *byte == 0xA5));

    let upper_sentinel = 0xCAFE_BABE_DEAD_BEEFu64;
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.mxcsr = 0x1F80;
        for register in 0..16 {
            x86.xmm[register][0] = 0;
            x86.xmm[register][1] = 0;
            x86.xmm[register][2] = upper_sentinel;
        }
    }
    execute_lifted_x86(&[0x48, 0x0F, 0xAE, 0x08], &mut ctx, &mut memory); // FXRSTOR64 [RAX]
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.control_word, 0x0B7F);
        assert_eq!(x86.x87.status_word, 0x1845);
        assert_eq!(x86.x87.tag_word, expected_tag_word);
        assert_eq!(x86.x87.regs, raw_regs);
        assert_eq!(x86.x87.instr_ptr, 0x0123_4567_89AB_CDEF);
        assert_eq!(x86.x87.data_ptr, 0xFEDC_BA98_7654_3210);
        assert_eq!(x86.x87.last_opcode, 0x02BC);
        assert_eq!(x86.mxcsr, 0x5F80);
        assert_eq!(&x86.xmm[0][0..2], &xmm0);
        assert_eq!(&x86.xmm[15][0..2], &xmm15);
        assert!(x86.xmm[..16].iter().all(|value| value[2] == upper_sentinel));
    }

    // REX.W=0 uses low 32-bit FIP/FDP fields and clears selector/reserved slots.
    ctx.write_vreg(rax, 0x500);
    memory.write(0x500, &[0xCC; 512]).unwrap();
    execute_lifted_x86(&[0x0F, 0xAE, 0x00], &mut ctx, &mut memory);
    memory.read(0x500, &mut image).unwrap();
    assert_eq!(
        u32::from_le_bytes(image[8..12].try_into().unwrap()),
        0x89AB_CDEF
    );
    assert_eq!(&image[12..16], &[0; 4]);
    assert_eq!(
        u32::from_le_bytes(image[16..20].try_into().unwrap()),
        0x7654_3210
    );
    assert_eq!(&image[20..24], &[0; 4]);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.instr_ptr = u64::MAX;
        x86.x87.data_ptr = u64::MAX;
    }
    execute_lifted_x86(&[0x0F, 0xAE, 0x08], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.instr_ptr, 0x89AB_CDEF);
        assert_eq!(x86.x87.data_ptr, 0x7654_3210);
    }

    // Keep the existing FXSAVE alignment behavior outside this restore fix.
    // FXRSTOR alignment is architectural #GP(0), not a memory-read fault.
    ctx.write_vreg(rax, 0x201);
    let exit = execute_lifted_x86(&[0x0F, 0xAE, 0x00], &mut ctx, &mut memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    let exit = execute_lifted_x86(&[0x0F, 0xAE, 0x08], &mut ctx, &mut memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::GeneralProtection {
            addr: 0x1000,
            error_code: 0
        })
    ));

    // Reserved MXCSR bits reject the image before any component commits.
    image[24..28].copy_from_slice(&0x0001_1F80u32.to_le_bytes());
    memory.write(0x700, &image).unwrap();
    ctx.write_vreg(rax, 0x700);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word = 0x077F;
        x86.mxcsr = 0x3F80;
        x86.xmm[0][0] = 0xDEAD_BEEF;
    }
    let exit = execute_lifted_x86(&[0x48, 0x0F, 0xAE, 0x08], &mut ctx, &mut memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::GeneralProtection {
            addr: 0x1000,
            error_code: 0
        })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.control_word, 0x077F);
        assert_eq!(x86.mxcsr, 0x3F80);
        assert_eq!(x86.xmm[0][0], 0xDEAD_BEEF);
    }

    let mut short_memory = FlatMemory::new(0x200);
    ctx.write_vreg(rax, 0x100);
    let exit = execute_lifted_x86(&[0x48, 0x0F, 0xAE, 0x00], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
}
