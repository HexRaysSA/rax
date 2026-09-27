//! tests.rs

use super::*;
use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{FlatMemory, MemoryError};

fn make_cpu() -> Armv7Cpu {
    Armv7Cpu::new()
}

fn make_mem() -> FlatMemory {
    FlatMemory::new(0x10000, 0)
}

fn make_insn(mnemonic: Mnemonic, raw: u32, sets_flags: bool) -> DecodedInsn {
    let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Arm, raw, 4);
    if sets_flags {
        insn = insn.with_flags();
    }
    insn
}

fn a32_bitfield_raw(rd: u32, rn: u32, lsb: u32, top: u32) -> u32 {
    (rd << 12) | (lsb << 7) | (top << 16) | rn
}

fn cp15_transfer_raw(rt: u32, crn: u32, opc1: u32, crm: u32, opc2: u32) -> u32 {
    (opc1 << 21) | (crn << 16) | (rt << 12) | (15 << 8) | (opc2 << 5) | crm
}

fn rfe_raw(rn: u32, p: bool, u: bool, w: bool) -> u32 {
    ((p as u32) << 24) | ((u as u32) << 23) | ((w as u32) << 21) | (rn << 16)
}

fn srs_raw(mode: ProcessorMode, p: bool, u: bool, w: bool) -> u32 {
    ((p as u32) << 24) | ((u as u32) << 23) | ((w as u32) << 21) | mode as u32
}

#[test]
fn test_add_immediate() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[1] = 100;

    let insn = make_insn(Mnemonic::ADD, 0xE2810032, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 150);
}

#[test]
fn t32_literal_load_uses_aligned_pc_plus_four_and_signed_u_offset() {
    for (raw, rt, address, value) in [
        (0xf8df_0123, 0, 0x1127, 0x1122_3344),
        (0xf85f_1123, 1, 0x0ee1, 0x5566_7788),
    ] {
        let mut cpu = make_cpu();
        cpu.regs[15] = 0x1002;
        cpu.cpsr.t = true;
        let mut mem = make_mem();
        mem.write_word(address, value).unwrap();
        let insn = crate::isa::arm::decoder::ThumbDecoder::decode_32bit(raw).unwrap();
        let result = Executor::new(&mut cpu, &mut mem).execute(&insn);
        assert!(matches!(result, ExecResult::Continue), "{raw:#010x}");
        assert_eq!(cpu.regs[rt], value, "{raw:#010x}");
    }
}

#[test]
fn test_adds_sets_flags() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[1] = 0xFFFFFFFF;

    let insn = make_insn(Mnemonic::ADDS, 0xE2910001, true);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0);
    assert!(cpu.cpsr.z);
    assert!(cpu.cpsr.c);
}

#[test]
fn test_sub_immediate() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[1] = 100;

    let insn = make_insn(Mnemonic::SUB, 0xE241001E, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 70);
}

#[test]
fn test_mov_immediate() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    let insn = make_insn(Mnemonic::MOV, 0xE3A000FF, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0xFF);
}

#[test]
fn test_cmp_sets_flags() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[0] = 50;

    let insn = make_insn(Mnemonic::CMP, 0xE3500032, true);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert!(cpu.cpsr.z);
    assert!(cpu.cpsr.c);
}

#[test]
fn test_branch() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[15] = 0x1000;

    let insn = make_insn(Mnemonic::B, 0xEA000040, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    if let ExecResult::Branch(target) = result {
        assert_eq!(target, 0x1000 + 8 + 0x100);
    } else {
        panic!("Expected Branch result");
    }
}

#[test]
fn test_a32_blx_immediate_preserves_halfword_target() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[15] = 0xc016_0864;

    let insn = DecodedInsn::new(Mnemonic::BLX, ExecutionState::Aarch32, 0xfbff_fa91, 4)
        .with_operand(crate::isa::arm::decoder::Operand::Label(-0x15ba));
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    if let ExecResult::Branch(target) = result {
        assert_eq!(target, 0xc015_f2b2);
        assert_eq!(cpu.regs[14], 0xc016_0868);
        assert!(cpu.cpsr.t);
    } else {
        panic!("Expected Branch result");
    }
}

#[test]
fn test_thumb_undefined_exception_lr_points_after_halfword() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[15] = 0x2000;
    cpu.cpsr.t = true;
    cpu.cpsr.mode = ProcessorMode::Supervisor as u8;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    exec.take_exception(ExceptionType::UndefinedInstruction);

    assert_eq!(cpu.regs[14], 0x2002);
    assert_eq!(cpu.regs[15], 0x04);
    assert_eq!(cpu.cpsr.mode, ProcessorMode::Undefined as u8);
    assert!(!cpu.cpsr.t);
    assert_eq!(cpu.spsr_und.t, true);
}

#[test]
fn test_msr_cpsr_control_does_not_change_execution_state() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.t = false;
    cpu.cpsr.mode = ProcessorMode::Irq as u8;
    cpu.regs_irq[0] = 0x2000;
    cpu.regs_svc[0] = 0x3000;
    cpu.regs[0] = (ProcessorMode::Supervisor as u32) | (1 << 7) | (1 << 6) | (1 << 5);

    let insn = DecodedInsn::new(Mnemonic::MSR, ExecutionState::Aarch32, 0xe121_07f0, 4);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.cpsr.mode, ProcessorMode::Supervisor as u8);
    assert!(cpu.cpsr.i);
    assert!(cpu.cpsr.f);
    assert!(!cpu.cpsr.t);
    assert_eq!(cpu.regs[13], 0x3000);
}

#[test]
fn test_user_mode_mcr_cp15_is_undefined_and_does_not_mutate_state() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::User as u8;
    cpu.regs[0] = 0xffff_ffff;
    let original_sctlr = cpu.cp15.sctlr.bits();

    let insn = make_insn(Mnemonic::MCR, cp15_transfer_raw(0, 1, 0, 0, 0), false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Undefined));
    assert_eq!(cpu.cp15.sctlr.bits(), original_sctlr);
}

#[test]
fn test_user_mode_mrc_cp15_is_undefined_and_does_not_expose_state() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::User as u8;
    cpu.cp15.ttbr0 = 0x1234_5000;
    cpu.regs[1] = 0xdead_beef;

    let insn = make_insn(Mnemonic::MRC, cp15_transfer_raw(1, 2, 0, 0, 0), false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Undefined));
    assert_eq!(cpu.regs[1], 0xdead_beef);
}

/// PL0's CP15 transfers: the thread ID registers (TPIDRURO read-only)
/// and, when SCTLR.CP15BEN is set, the barriers; never the MCR2/MRC2
/// forms, nor another coprocessor.
#[test]
fn pl0_cp15_reaches_only_the_thread_ids_and_enabled_barriers() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.cpsr.mode = ProcessorMode::User as u8;
    cpu.cp15.tpidruro = 0x1111_2222;
    cpu.regs[0] = 0x3333_4444;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let mut run = |mnemonic, raw| exec.execute(&make_insn(mnemonic, raw, false));
    // MCR TPIDRURW, MRC it back; MRC TPIDRURO; MCR TPIDRURO is UNDEFINED.
    assert!(matches!(
        run(Mnemonic::MCR, cp15_transfer_raw(0, 13, 0, 0, 2)),
        ExecResult::Continue
    ));
    assert!(matches!(
        run(Mnemonic::MRC, cp15_transfer_raw(1, 13, 0, 0, 2)),
        ExecResult::Continue
    ));
    assert!(matches!(
        run(Mnemonic::MRC, cp15_transfer_raw(2, 13, 0, 0, 3)),
        ExecResult::Continue
    ));
    assert!(matches!(
        run(Mnemonic::MCR, cp15_transfer_raw(0, 13, 0, 0, 3)),
        ExecResult::Undefined
    ));
    // TPIDRPRW, another opc1, and MRC2 are UNDEFINED.
    for (mnemonic, raw) in [
        (Mnemonic::MRC, cp15_transfer_raw(3, 13, 0, 0, 4)),
        (Mnemonic::MRC, cp15_transfer_raw(3, 13, 1, 0, 3)),
        (
            Mnemonic::MRC,
            0xF000_0000 | cp15_transfer_raw(3, 13, 0, 0, 3),
        ),
    ] {
        assert!(
            matches!(run(mnemonic, raw), ExecResult::Undefined),
            "{raw:#010x}"
        );
    }
    // DMB, DSB, and ISB with SCTLR.CP15BEN clear.
    let barriers = [
        cp15_transfer_raw(0, 7, 0, 10, 5),
        cp15_transfer_raw(0, 7, 0, 10, 4),
        cp15_transfer_raw(0, 7, 0, 5, 4),
    ];
    for raw in barriers {
        assert!(
            matches!(run(Mnemonic::MCR, raw), ExecResult::Undefined),
            "{raw:#010x}"
        );
    }
    // Another coprocessor's transfer.
    let cp14 = (cp15_transfer_raw(3, 0, 0, 1, 0) & !(0xF << 8)) | (14 << 8);
    assert!(matches!(run(Mnemonic::MRC, cp14), ExecResult::Undefined));
    assert_eq!(cpu.cp15.tpidrurw, 0x3333_4444);
    assert_eq!(cpu.cp15.tpidruro, 0x1111_2222);
    assert_eq!(cpu.regs[1..4], [0x3333_4444, 0x1111_2222, 0]);

    // With SCTLR.CP15BEN set, the barriers execute.
    cpu.cp15.sctlr = crate::isa::arm::aarch32::cp15::Sctlr::from_bits(1 << 5);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    for raw in barriers {
        let result = exec.execute(&make_insn(Mnemonic::MCR, raw, false));
        assert!(matches!(result, ExecResult::Continue), "{raw:#010x}");
    }
}

/// MSR's byte mask selects GE[3:0] (bits 19:16) at any privilege
/// (`CPSRWriteByInstr`, `SPSRWriteByInstr`); at PL0 the mode and the
/// interrupt masks stay.
#[test]
fn msr_writes_ge_by_its_byte_mask() {
    // MSR CPSR_<mask>, r0; bit 22 selects the SPSR.
    let msr = |mask: u32| make_insn(Mnemonic::MSR, 0xE120_F000 | (mask << 16), false);
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.cpsr.mode = ProcessorMode::User as u8;
    // N, Z, C, V, GE = 0b1010; System mode with I, F, and E clear.
    cpu.regs[0] = 0xF00A_001F;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    assert!(matches!(exec.execute(&msr(0b0100)), ExecResult::Continue));
    assert_eq!((exec.cpu.cpsr.ge, exec.cpu.cpsr.n), (0xA, false));
    // At PL0 only NZCVQ (31:27), GE (19:16), and E (9) are written.
    let before = exec.cpu.cpsr.to_u32();
    assert!(matches!(exec.execute(&msr(0b1111)), ExecResult::Continue));
    let written = 0xF80F_0200;
    assert_eq!(
        cpu.cpsr.to_u32(),
        (before & !written) | (0xF00A_001F & written)
    );
    assert_eq!(cpu.cpsr.mode, ProcessorMode::User as u8);

    cpu.cpsr.mode = ProcessorMode::Supervisor as u8;
    let mut spsr_g = msr(0b0100);
    spsr_g.raw |= 1 << 22;
    let result = Executor::new(&mut cpu, &mut mem).execute(&spsr_g);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.get_current_spsr().map(|s| s.ge), Some(0xA));
}

/// Runs T16 halfwords as the instruction cycle does: the IT state advances
/// after each instruction in an IT block.
fn run_t16(cpu: &mut Armv7Cpu, mem: &mut FlatMemory, code: &[u16]) -> Vec<ExecResult> {
    code.iter()
        .map(|&hw| {
            let insn = crate::isa::arm::decoder::ThumbDecoder::decode_16bit(hw).unwrap();
            let in_it = cpu.cpsr.in_it_block();
            let result = Executor::new(cpu, mem).execute(&insn);
            if in_it {
                cpu.cpsr.advance_it_state();
            }
            result
        })
        .collect()
}

/// Inside an IT block a 16-bit data-processing instruction leaves the flags
/// (`setflags = !InITBlock()`), so `itt eq; moveq; moveq` runs both; CMP
/// still sets them, and outside the block the same encodings do.
#[test]
fn t16_data_processing_in_an_it_block_leaves_the_flags() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.cpsr.t = true;
    cpu.cpsr.z = true;
    // itt eq; moveq r2, #1; moveq r3, #7
    let results = run_t16(&mut cpu, &mut mem, &[0xbf04, 0x2201, 0x2307]);
    assert!(results.iter().all(|r| matches!(r, ExecResult::Continue)));
    assert_eq!((cpu.regs[2], cpu.regs[3]), (1, 7));
    assert!(cpu.cpsr.z && !cpu.cpsr.in_it_block());
    // it eq; cmpeq r2, #2 (1 - 2: N, not Z or C); it ne; addne r4, r2, #1
    run_t16(&mut cpu, &mut mem, &[0xbf08, 0x2a02, 0xbf18, 0x1c54]);
    assert_eq!(cpu.regs[4], 2);
    assert_eq!((cpu.cpsr.n, cpu.cpsr.z, cpu.cpsr.c), (true, false, false));
    // movs r5, #0 outside a block.
    run_t16(&mut cpu, &mut mem, &[0x2500]);
    assert_eq!((cpu.cpsr.n, cpu.cpsr.z), (false, true));
}

/// SVC and BKPT immediates: A1's imm24 and imm12:imm4, T1's imm8
/// (`llvm-mc`: `svc #0x123456` = 0xef123456, `bkpt #0x1234` = 0xe1212374,
/// `svc #0x12` = 0xdf12, `bkpt #0x34` = 0xbe34).
#[test]
fn svc_and_bkpt_immediates_follow_the_instruction_set() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    let a32 = |raw| crate::isa::arm::decoder::Aarch32Decoder::decode(raw).unwrap();
    let t16 = |hw| crate::isa::arm::decoder::ThumbDecoder::decode_16bit(hw).unwrap();
    let mut exec = Executor::new(&mut cpu, &mut mem);
    assert!(matches!(
        exec.execute(&a32(0xef12_3456)),
        ExecResult::Exception(ExceptionType::SupervisorCall(0x12_3456))
    ));
    assert!(matches!(
        exec.execute(&a32(0xe121_2374)),
        ExecResult::Exception(ExceptionType::Breakpoint(0x1234))
    ));
    assert!(matches!(
        exec.execute(&t16(0xdf12)),
        ExecResult::Exception(ExceptionType::SupervisorCall(0x12))
    ));
    assert!(matches!(
        exec.execute(&t16(0xbe34)),
        ExecResult::Exception(ExceptionType::Breakpoint(0x34))
    ));
}

/// ARMv8's LDA/STL and LDAEX/STLEX (one thread sees plain loads, stores,
/// and exclusives), and the natural alignment every exclusive and ordered
/// access requires whatever SCTLR.A says.
#[test]
fn acquire_release_and_exclusive_accesses_are_aligned() {
    let dec = |raw| crate::isa::arm::decoder::Aarch32Decoder::decode(raw).unwrap();
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    mem.write_word(0x100, 0x8765_4321).unwrap();
    cpu.regs[1] = 0x100;
    cpu.regs[3] = 0x101;
    cpu.regs[5] = 0x102;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    // lda r0, [r1]; ldab r2, [r3]; ldah r4, [r5]
    for raw in [0xe191_0c9f, 0xe1d3_2c9f, 0xe1f5_4c9f] {
        assert!(matches!(exec.execute(&dec(raw)), ExecResult::Continue));
    }
    assert_eq!(
        (exec.cpu.regs[0], exec.cpu.regs[2], exec.cpu.regs[4]),
        (0x8765_4321, 0x43, 0x8765)
    );
    // stlh r4, [r5]: the halfword at 0x102.
    exec.cpu.regs[4] = 0xAAAA_1234;
    assert!(matches!(
        exec.execute(&dec(0xe1e5_fc94)),
        ExecResult::Continue
    ));
    // ldaex r0, [r1]; stlex r9, r0, [r1]: the pair succeeds.
    assert!(matches!(
        exec.execute(&dec(0xe191_0e9f)),
        ExecResult::Continue
    ));
    assert!(matches!(
        exec.execute(&dec(0xe181_9e90)),
        ExecResult::Continue
    ));
    assert_eq!(exec.cpu.regs[9], 0);
    // Unaligned: lda r0, [r3]; stl r0, [r3]; ldrex r0, [r3]; strex r2,
    // r0, [r3]; ldah r4, [r3].
    for raw in [
        0xe193_0c9f,
        0xe183_fc90,
        0xe193_0f9f,
        0xe183_2f90,
        0xe1f3_4c9f,
    ] {
        assert_eq!(
            match exec.execute(&dec(raw)) {
                ExecResult::MemoryFault(e) => Some(e),
                _ => None,
            },
            Some(MemoryError::Unaligned(0x101)),
            "{raw:#010x}"
        );
    }
    assert_eq!(mem.read_word(0x100).unwrap(), 0x1234_4321);
}

/// VMRS and VMSR reach only FPSCR at PL0; FPSID, MVFR0-2, and FPEXC need
/// PL1.
#[test]
fn pl0_vmrs_and_vmsr_reach_only_fpscr() {
    let vmrs = |reg: u32, rt: u32| 0x0EF0_0A10 | (reg << 16) | (rt << 12);
    let vmsr = |reg: u32, rt: u32| 0x0EE0_0A10 | (reg << 16) | (rt << 12);
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.cpsr.mode = ProcessorMode::User as u8;
    cpu.vfp.fpexc = 0x4000_0000;
    cpu.regs[0] = 0x0300_0000;
    cpu.regs[5] = 0x5555_5555;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let mut run = |mnemonic, raw| exec.execute(&make_insn(mnemonic, raw, false));
    assert!(matches!(
        run(Mnemonic::VMSR, vmsr(1, 0)),
        ExecResult::Continue
    ));
    assert!(matches!(
        run(Mnemonic::VMRS, vmrs(1, 1)),
        ExecResult::Continue
    ));
    for reg in [0, 5, 6, 7, 8] {
        assert!(
            matches!(run(Mnemonic::VMRS, vmrs(reg, 5)), ExecResult::Undefined),
            "{reg}"
        );
        assert!(
            matches!(run(Mnemonic::VMSR, vmsr(reg, 5)), ExecResult::Undefined),
            "{reg}"
        );
    }
    assert_eq!(cpu.regs[1], 0x0300_0000);
    assert_eq!((cpu.regs[5], cpu.vfp.fpexc), (0x5555_5555, 0x4000_0000));

    // PL1 still reads FPEXC and MVFR0.
    cpu.cpsr.mode = ProcessorMode::Supervisor as u8;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    assert!(matches!(
        exec.execute(&make_insn(Mnemonic::VMRS, vmrs(8, 5), false)),
        ExecResult::Continue
    ));
    assert_eq!(cpu.regs[5], 0x4000_0000);
}

#[test]
fn test_privileged_mcr_mrc_cp15_still_access_state() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::Supervisor as u8;
    cpu.regs[0] = 0x1;

    let write_sctlr = make_insn(Mnemonic::MCR, cp15_transfer_raw(0, 1, 0, 0, 0), false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&write_sctlr);
    assert!(matches!(result, ExecResult::Continue));

    let read_sctlr = make_insn(Mnemonic::MRC, cp15_transfer_raw(1, 1, 0, 0, 0), false);
    let result = exec.execute(&read_sctlr);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[1], 0x1);
}

#[test]
fn test_user_or_system_mode_rfe_is_undefined_and_does_not_change_mode() {
    for mode in [ProcessorMode::User, ProcessorMode::System] {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.cpsr.mode = mode as u8;
        cpu.regs[0] = 0x200;
        mem.write_word(0x200, 0x1234_5678).unwrap();
        mem.write_word(0x204, ProcessorMode::Supervisor as u32)
            .unwrap();

        let insn = make_insn(Mnemonic::RFE, rfe_raw(0, false, true, true), false);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Undefined), "{mode:?}");
        assert_eq!(cpu.cpsr.mode, mode as u8, "{mode:?}");
        assert_eq!(cpu.regs[0], 0x200, "{mode:?}");
    }
}

#[test]
fn test_user_or_system_mode_srs_is_undefined_and_does_not_write_memory() {
    for mode in [ProcessorMode::User, ProcessorMode::System] {
        let mut cpu = make_cpu();
        let mut mem = make_mem();

        cpu.cpsr.mode = mode as u8;
        cpu.regs[14] = 0x1234_5678;
        cpu.regs_svc[0] = 0x200;
        mem.write_word(0x200, 0xfeed_face).unwrap();
        mem.write_word(0x204, 0xcafe_beef).unwrap();

        let insn = make_insn(
            Mnemonic::SRS,
            srs_raw(ProcessorMode::Supervisor, false, true, true),
            false,
        );
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&insn);

        assert!(matches!(result, ExecResult::Undefined), "{mode:?}");
        assert_eq!(cpu.cpsr.mode, mode as u8, "{mode:?}");
        assert_eq!(cpu.regs_svc[0], 0x200, "{mode:?}");
        assert_eq!(mem.read_word(0x200).unwrap(), 0xfeed_face, "{mode:?}");
        assert_eq!(mem.read_word(0x204).unwrap(), 0xcafe_beef, "{mode:?}");
    }
}

#[test]
fn test_privileged_rfe_still_restores_cpsr_and_branches() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::Irq as u8;
    cpu.regs[0] = 0x200;
    mem.write_word(0x200, 0x1234_5678).unwrap();
    mem.write_word(0x204, ProcessorMode::Supervisor as u32)
        .unwrap();

    let insn = make_insn(Mnemonic::RFE, rfe_raw(0, false, true, true), false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Branch(0x1234_5678)));
    assert_eq!(cpu.cpsr.mode, ProcessorMode::Supervisor as u8);
    assert_eq!(cpu.regs[0], 0x208);
}

#[test]
fn test_fiq_stm_user_bank_stores_shared_high_registers() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::Fiq as u8;
    cpu.regs[8] = 0xf100_0008;
    cpu.regs[9] = 0xc006_163c;
    cpu.regs_usr_high[0] = 0x1111_2222;
    cpu.regs_usr_high[1] = 0x3333_4444;
    cpu.regs[13] = 0x200;

    // A32 STMDB sp!, {r8,r9}^, decoded as a PUSH alias.
    let insn = DecodedInsn::new(Mnemonic::PUSH, ExecutionState::Aarch32, 0xe96d_0300, 4);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[13], 0x1f8);
    assert_eq!(mem.read_word(0x1f8).unwrap(), 0x1111_2222);
    assert_eq!(mem.read_word(0x1fc).unwrap(), 0x3333_4444);
    assert_eq!(cpu.regs[8], 0xf100_0008);
    assert_eq!(cpu.regs[9], 0xc006_163c);
}

#[test]
fn test_fiq_ldm_user_bank_restores_shared_high_registers() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.mode = ProcessorMode::Fiq as u8;
    cpu.regs[8] = 0xf100_0008;
    cpu.regs[9] = 0xc006_163c;
    cpu.regs_usr_high[0] = 0xaaaa_bbbb;
    cpu.regs_usr_high[1] = 0xcccc_dddd;
    cpu.regs[13] = 0x200;
    mem.write_word(0x200, 0x1111_2222).unwrap();
    mem.write_word(0x204, 0x3333_4444).unwrap();

    // A32 LDMIA sp!, {r8,r9}^, decoded as a POP alias.
    let insn = DecodedInsn::new(Mnemonic::POP, ExecutionState::Aarch32, 0xe8fd_0300, 4);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[13], 0x208);
    assert_eq!(cpu.regs_usr_high[0], 0x1111_2222);
    assert_eq!(cpu.regs_usr_high[1], 0x3333_4444);
    assert_eq!(cpu.regs[8], 0xf100_0008);
    assert_eq!(cpu.regs[9], 0xc006_163c);
}

#[test]
fn test_thumb_it_instruction_does_not_retire_its_own_state() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    let decoder = crate::isa::arm::decoder::Decoder::new_thumb();
    let insn = decoder.decode(&0xbf08u16.to_le_bytes()).unwrap(); // it eq

    cpu.cpsr.t = true;
    let advance_it = cpu.cpsr.t && cpu.cpsr.in_it_block();
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert!(!advance_it);
    assert!(cpu.cpsr.in_it_block());
    assert_eq!(cpu.cpsr.it_condition(), Condition::EQ as u8);
}

#[test]
fn test_thumb_it_false_predicate_skips_following_instruction() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    let decoder = crate::isa::arm::decoder::Decoder::new_thumb();
    let insn = decoder.decode(&0x2001u16.to_le_bytes()).unwrap(); // movs r0, #1

    cpu.cpsr.t = true;
    cpu.cpsr.z = false;
    cpu.cpsr.set_it_state(Condition::EQ as u8, 0b1000);
    cpu.regs[0] = 0x55;

    let advance_it = cpu.cpsr.t && cpu.cpsr.in_it_block();
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0x55);
    assert!(advance_it);
    cpu.cpsr.advance_it_state();
    assert!(!cpu.cpsr.in_it_block());
}

#[test]
fn test_ldr_str() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    mem.write_word(0x100, 0xDEADBEEF).unwrap();

    cpu.regs[1] = 0x100;

    let insn = make_insn(Mnemonic::LDR, 0xE5910000, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0xDEADBEEF);
}

#[test]
fn test_mul() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[1] = 7;
    cpu.regs[2] = 6;

    let insn = make_insn(Mnemonic::MUL, 0xE0000291, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 42);
}

#[test]
fn test_condition_ne() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.cpsr.z = true;
    cpu.regs[0] = 0;

    let mut insn = make_insn(Mnemonic::MOV, 0x13A00001, false);
    insn.cond = Some(Condition::NE);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0);
}

#[test]
fn test_svc() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    let insn = make_insn(Mnemonic::SVC, 0xEF00007B, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&insn);

    if let ExecResult::Exception(ExceptionType::SupervisorCall(imm)) = result {
        assert_eq!(imm, 123);
    } else {
        panic!("Expected SupervisorCall exception");
    }
}

#[test]
fn test_a64_noop_hints_continue() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    for (mnemonic, raw) in [
        (Mnemonic::DGH, 0xd503_20df),
        (Mnemonic::BTI, 0xd503_241f),
        (Mnemonic::WFET, 0xd503_1000),
        (Mnemonic::WFIT, 0xd503_1021),
    ] {
        let insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);
        let result = Executor::new(&mut cpu, &mut mem).execute(&insn);
        assert!(matches!(result, ExecResult::Continue));
    }
}

#[test]
fn test_a64_barriers_continue() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    for (mnemonic, raw) in [
        (Mnemonic::DSB, 0xd503_3f9f),
        (Mnemonic::DMB, 0xd503_3fbf),
        (Mnemonic::ISB, 0xd503_3fdf),
        (Mnemonic::SB, 0xd503_30ff),
    ] {
        let insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);
        let result = Executor::new(&mut cpu, &mut mem).execute(&insn);
        assert!(matches!(result, ExecResult::Continue));
    }
}

#[test]
fn test_ldrex_strex() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    mem.write_word(0x100, 0x12345678).unwrap();
    cpu.regs[1] = 0x100;
    cpu.regs[3] = 0xDEADBEEF; // Set this before creating executor

    // LDREX R0, [R1] followed by STREX R2, R3, [R1]
    // Must use same executor to maintain exclusive monitor state
    let ldrex = make_insn(Mnemonic::LDXR, 0xE1910F9F, false);
    let strex = make_insn(Mnemonic::STXR, 0xE1812F93, false);

    let mut exec = Executor::new(&mut cpu, &mut mem);

    // Execute LDREX
    let result = exec.execute(&ldrex);
    assert!(matches!(result, ExecResult::Continue));

    // Execute STREX - should succeed because LDREX was just done
    let result = exec.execute(&strex);
    assert!(matches!(result, ExecResult::Continue));

    // Drop executor to check cpu/mem state
    drop(exec);

    assert_eq!(cpu.regs[0], 0x12345678); // LDREX loaded value
    assert_eq!(cpu.regs[2], 0); // STREX success
    assert_eq!(mem.read_word(0x100).unwrap(), 0xDEADBEEF); // Memory updated
}

#[test]
fn test_strex_fails_without_ldrex() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    mem.write_word(0x100, 0x12345678).unwrap();
    cpu.regs[1] = 0x100;
    cpu.regs[3] = 0xDEADBEEF;

    // STREX without LDREX should fail
    let strex = make_insn(Mnemonic::STXR, 0xE1812F93, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&strex);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[2], 1); // Failure

    // Memory should be unchanged
    assert_eq!(mem.read_word(0x100).unwrap(), 0x12345678);
}

#[test]
fn test_sdiv_udiv() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[1] = 100;
    cpu.regs[2] = 7;

    // SDIV R0, R1, R2
    let sdiv = make_insn(Mnemonic::SDIV, 0xE710F211, false);
    {
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&sdiv);
        assert!(matches!(result, ExecResult::Continue));
    }
    assert_eq!(cpu.regs[0], 14);

    // Test division by zero
    cpu.regs[2] = 0;
    {
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&sdiv);
        assert!(matches!(result, ExecResult::Continue));
    }
    assert_eq!(cpu.regs[0], 0);
}

#[test]
fn test_exception_handling() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.regs[15] = 0x1000;

    let mut exec = Executor::new(&mut cpu, &mut mem);
    exec.take_exception(ExceptionType::SupervisorCall(0));

    // Should be in SVC mode
    assert_eq!(cpu.cpsr.mode, ProcessorMode::Supervisor as u8);
    // IRQ should be disabled
    assert!(cpu.cpsr.i);
    // Should be in ARM mode
    assert!(!cpu.cpsr.t);
    // PC should be at SVC vector
    assert_eq!(cpu.regs[15], 0x08);
}

#[test]
fn test_bfc_bfi() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[0] = 0xFFFFFFFF;

    // BFC R0, #4, #8 - clear bits 4-11
    let bfc = make_insn(Mnemonic::BFC, 0xE7CB021F, false);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let result = exec.execute(&bfc);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0xFFFFF00F);
}

#[test]
fn test_bitfield_full_width_bounds() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[0] = 0xFFFF_FFFF;
    let bfc = make_insn(Mnemonic::BFC, a32_bitfield_raw(0, 15, 0, 31), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&bfc);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0);

    cpu.regs[0] = 0;
    cpu.regs[1] = 0x89AB_CDEF;
    let bfi = make_insn(Mnemonic::BFI, a32_bitfield_raw(0, 1, 0, 31), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&bfi);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[0], 0x89AB_CDEF);

    cpu.regs[1] = 0x7654_3210;
    let ubfx = make_insn(Mnemonic::UBFX, a32_bitfield_raw(2, 1, 0, 31), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&ubfx);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[2], 0x7654_3210);

    cpu.regs[1] = 0x8000_0001;
    let sbfx = make_insn(Mnemonic::SBFX, a32_bitfield_raw(3, 1, 0, 31), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&sbfx);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(cpu.regs[3], 0x8000_0001);
}

#[test]
fn test_bitfield_invalid_bounds_are_undefined() {
    let mut cpu = make_cpu();
    let mut mem = make_mem();

    cpu.regs[0] = 0xDEAD_BEEF;
    cpu.regs[1] = 0xFFFF_FFFF;
    let bfi = make_insn(Mnemonic::BFI, a32_bitfield_raw(0, 1, 8, 3), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&bfi);
    assert!(matches!(result, ExecResult::Undefined));
    assert_eq!(cpu.regs[0], 0xDEAD_BEEF);

    let ubfx = make_insn(Mnemonic::UBFX, a32_bitfield_raw(0, 1, 16, 31), false);
    let result = Executor::new(&mut cpu, &mut mem).execute(&ubfx);
    assert!(matches!(result, ExecResult::Undefined));
    assert_eq!(cpu.regs[0], 0xDEAD_BEEF);
}

/// The accesses the pseudocode makes with `MemA` (LDM/STM in every mode,
/// PUSH/POP of a list, LDRD/STRD, VLDR/VSTR, VLDM/VSTM) fault on an address
/// that is not word-aligned whatever SCTLR.A says, at the lowest address
/// accessed and before anything is written; a plain LDR is `MemU`, and
/// LDRD needs only word alignment.
#[test]
fn multi_word_accesses_need_word_alignment() {
    let a32 = |raw| crate::isa::arm::decoder::Aarch32Decoder::decode(raw).unwrap();
    let t16 = |hw| crate::isa::arm::decoder::ThumbDecoder::decode_16bit(hw).unwrap();
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    for a in (0x100..0x140).step_by(4) {
        mem.write_word(a, 0x1111_1111 * (a / 4 % 16)).unwrap();
    }
    cpu.regs[2] = 0x2222;
    cpu.regs[3] = 0x3333;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let fault = |r: ExecResult| match r {
        ExecResult::MemoryFault(MemoryError::Unaligned(a)) => Some(a),
        _ => None,
    };
    // (instruction, base in r1, the fault address)
    for (raw, base, at) in [
        (0xE891_000C, 0x102, 0x102), // ldm r1, {r2, r3}
        (0xE8B1_000C, 0x102, 0x102), // ldm r1!, {r2, r3}
        (0xE931_000C, 0x10A, 0x102), // ldmdb r1!, {r2, r3}
        (0xE981_0004, 0x101, 0x105), // stmib r1, {r2}
        (0xE881_000C, 0x103, 0x103), // stm r1, {r2, r3}
        (0xE1C1_20D0, 0x102, 0x102), // ldrd r2, r3, [r1]
        (0xE1E1_20D8, 0x0FA, 0x102), // ldrd r2, r3, [r1, #8]!
        (0xE1C1_20F0, 0x102, 0x102), // strd r2, r3, [r1]
        (0xED91_0B00, 0x102, 0x102), // vldr d0, [r1]
        (0xED81_0B00, 0x102, 0x102), // vstr d0, [r1]
        (0xED91_0A00, 0x101, 0x101), // vldr s0, [r1]
        (0xEC91_0B02, 0x106, 0x106), // vldmia r1, {d0}
        (0xECA1_0B02, 0x106, 0x106), // vstmia r1!, {d0}
    ] {
        exec.cpu.regs[1] = base;
        assert_eq!(fault(exec.execute(&a32(raw))), Some(at), "{raw:#010x}");
        assert_eq!(exec.cpu.regs[1], base, "{raw:#010x}: no writeback");
        assert_eq!((exec.cpu.regs[2], exec.cpu.regs[3]), (0x2222, 0x3333));
    }
    // T16 PUSH and POP take the list's words from SP (POP {r0} too).
    exec.cpu.regs[13] = 0x122;
    assert_eq!(fault(exec.execute(&t16(0xB50C))), Some(0x116)); // push {r2, r3, lr}
    assert_eq!(fault(exec.execute(&t16(0xBC04))), Some(0x122)); // pop {r2}
    assert_eq!(exec.cpu.regs[13], 0x122);
    // Word-aligned LDRD, and a plain LDR anywhere.
    exec.cpu.regs[1] = 0x104;
    assert!(matches!(
        exec.execute(&a32(0xE1C1_20D0)),
        ExecResult::Continue
    ));
    assert_eq!(
        (exec.cpu.regs[2], exec.cpu.regs[3]),
        (0x1111_1111, 0x2222_2222)
    );
    exec.cpu.regs[1] = 0x101;
    assert!(matches!(
        exec.execute(&a32(0xE591_4000)),
        ExecResult::Continue
    ));
    assert_eq!(exec.cpu.regs[4], 0x1100_0000);
    assert!(mem.read_word(0x100).unwrap() == 0 && mem.read_word(0x104).unwrap() == 0x1111_1111);
}

/// MRRC and MCRR (not LDC/STC): CNTPCT and CNTVCT (CNTPCT less CNTVOFF)
/// through MRRC, which PL0 reaches as CNTKCTL's PL0PCTEN and PL0VCTEN
/// allow, as it reaches CNTFRQ with either; CNTKCTL and MCRR need PL1; an
/// MRRC with Rt or Rt2 the PC, or both the same, is UNDEFINED.
#[test]
fn mrrc_reads_the_generic_counters_as_cntkctl_allows() {
    let dec = |raw| crate::isa::arm::decoder::Aarch32Decoder::decode(raw).unwrap();
    assert_eq!(dec(0xEC51_0F1E).mnemonic, Mnemonic::MRRC);
    assert_eq!(dec(0xEC41_0F1E).mnemonic, Mnemonic::MCRR);
    let mut cpu = make_cpu();
    let mut mem = make_mem();
    cpu.cpsr.mode = ProcessorMode::User as u8;
    cpu.cp15.cntpct = 0x1_2345_6789;
    cpu.cp15.cntvoff = 0x100;
    let mut exec = Executor::new(&mut cpu, &mut mem);
    let (vct, pct) = (0xEC51_0F1E, 0xEC51_0F0E); // mrrc p15, {1, 0}, r0, r1, c14
    let (frq, kctl) = (0xEE1E_2F10, 0xEE1E_2F11); // mrc p15, 0, r2, c14, {c0, c1}, 0
    let undef = |r: ExecResult| matches!(r, ExecResult::Undefined);
    for raw in [vct, pct, frq, kctl] {
        assert!(
            undef(exec.execute(&dec(raw))),
            "{raw:#010x} without CNTKCTL"
        );
    }
    exec.cpu.cp15.cntkctl = 1 << 1; // PL0VCTEN, as Linux sets it
    assert!(matches!(exec.execute(&dec(vct)), ExecResult::Continue));
    assert_eq!((exec.cpu.regs[0], exec.cpu.regs[1]), (0x2345_6689, 1));
    assert!(matches!(exec.execute(&dec(frq)), ExecResult::Continue));
    assert_eq!(exec.cpu.regs[2], exec.cpu.cp15.cntfrq);
    for raw in [pct, kctl, 0xEC41_0F1E, 0xEC50_0F1E, 0xEC5F_0F1E] {
        assert!(undef(exec.execute(&dec(raw))), "{raw:#010x}");
    }
    exec.cpu.cp15.cntkctl = 1 << 0; // PL0PCTEN
    assert!(matches!(exec.execute(&dec(pct)), ExecResult::Continue));
    assert_eq!((exec.cpu.regs[0], exec.cpu.regs[1]), (0x2345_6789, 1));
    // PL1 reaches all of them, and writes CNTKCTL.
    exec.cpu.cpsr.mode = ProcessorMode::Supervisor as u8;
    exec.cpu.cp15.cntkctl = 0;
    exec.cpu.regs[3] = 3;
    assert!(matches!(
        exec.execute(&dec(0xEE0E_3F11)), // mcr p15, 0, r3, c14, c1, 0
        ExecResult::Continue
    ));
    assert!(matches!(exec.execute(&dec(kctl)), ExecResult::Continue));
    assert_eq!(exec.cpu.regs[2], 3);
    assert!(matches!(exec.execute(&dec(vct)), ExecResult::Continue));
    assert_eq!(exec.cpu.regs[0], 0x2345_6689);
}
