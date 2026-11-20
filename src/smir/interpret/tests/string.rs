//! tests::string tests

use super::*;
use crate::smir::interpret::*;
use crate::smir::ir::FunctionBuilder;
use crate::smir::ir::flags::{FlagSet, FlagUpdate, MaterializedFlags};
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::ir::types::ShiftOp;

#[test]
fn lifted_movzx_movsx_read_legacy_high_bytes_and_rex_low_bytes() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let mut memory = FlatMemory::new(0x1000);
    let mut ctx = SmirContext::new_x86_64();

    ctx.write_vreg(rax, 0x1122_3344_5566_ABCD);
    execute_lifted_x86(&[0x0F, 0xB6, 0xC4], &mut ctx, &mut memory); // MOVZX EAX,AH
    assert_eq!(ctx.read_vreg(rax), 0xAB);

    ctx.write_vreg(rax, 0x0000_0000_0000_80FF);
    execute_lifted_x86(&[0x0F, 0xBE, 0xCC], &mut ctx, &mut memory); // MOVSX ECX,AH
    assert_eq!(ctx.read_vreg(rcx), 0xFFFF_FF80);

    ctx.write_vreg(rsp, 0x1234_5678_9ABC_DE7E);
    execute_lifted_x86(&[0x40, 0x0F, 0xB6, 0xC4], &mut ctx, &mut memory); // MOVZX EAX,SPL
    assert_eq!(ctx.read_vreg(rax), 0x7E);
    assert_eq!(ctx.read_vreg(rsp), 0x1234_5678_9ABC_DE7E);
}
#[test]
fn lifted_string_movs_stos_lods_execute_rep_df_segment_and_addr32() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rsi = VReg::Arch(ArchReg::X86(X86Reg::Rsi));
    let rdi = VReg::Arch(ArchReg::X86(X86Reg::Rdi));
    let fs = VReg::Arch(ArchReg::X86(X86Reg::FsBase));
    let mut memory = FlatMemory::new(0x5000);
    let mut ctx = SmirContext::new_x86_64();

    memory.write(0x100, &[1, 2, 3]).unwrap();
    ctx.write_vreg(rsi, 0x100);
    ctx.write_vreg(rdi, 0x200);
    ctx.write_vreg(rcx, 3);
    execute_lifted_x86(&[0xF3, 0xA4], &mut ctx, &mut memory);
    let mut copied = [0u8; 3];
    memory.read(0x200, &mut copied).unwrap();
    assert_eq!(copied, [1, 2, 3]);
    assert_eq!(ctx.read_vreg(rsi), 0x103);
    assert_eq!(ctx.read_vreg(rdi), 0x203);
    assert_eq!(ctx.read_vreg(rcx), 0);

    ctx.flags.materialized = MaterializedFlags::from_rflags(0x402); // DF
    ctx.flags.lazy = None;
    ctx.write_vreg(rax, 0xBBAA);
    ctx.write_vreg(rdi, 0x300);
    ctx.write_vreg(rcx, 0xCAFE);
    execute_lifted_x86(&[0x66, 0xAB], &mut ctx, &mut memory); // STOSW, no REP
    let mut word = [0u8; 2];
    memory.read(0x300, &mut word).unwrap();
    assert_eq!(word, [0xAA, 0xBB]);
    assert_eq!(ctx.read_vreg(rdi), 0x2FE);
    assert_eq!(ctx.read_vreg(rcx), 0xCAFE, "non-REP must not touch RCX");

    memory.write(0x410, &[0x5A]).unwrap();
    ctx.flags.materialized = MaterializedFlags::from_rflags(0x2);
    ctx.flags.lazy = None;
    ctx.write_vreg(fs, 0x400);
    ctx.write_vreg(rsi, 0x10);
    ctx.write_vreg(rax, 0x1122_3344_5566_7788);
    execute_lifted_x86(&[0x64, 0xAC], &mut ctx, &mut memory); // LODSB FS:[RSI]
    assert_eq!(ctx.read_vreg(rax), 0x1122_3344_5566_775A);
    assert_eq!(ctx.read_vreg(rsi), 0x11);

    memory.write(0x120, &[0xCC]).unwrap();
    ctx.write_vreg(rsi, 0xDEAD_BEEF_0000_0120);
    ctx.write_vreg(rdi, 0xAAAA_BBBB_0000_0220);
    ctx.write_vreg(rcx, 0xFFFF_0000_0000_0001);
    execute_lifted_x86(&[0x67, 0xF3, 0xA4], &mut ctx, &mut memory);
    let mut byte = [0u8; 1];
    memory.read(0x220, &mut byte).unwrap();
    assert_eq!(byte[0], 0xCC);
    assert_eq!(ctx.read_vreg(rsi), 0x121);
    assert_eq!(ctx.read_vreg(rdi), 0x221);
    assert_eq!(ctx.read_vreg(rcx), 0);

    ctx.write_vreg(rsi, 0xDEAD_BEEF_0000_0120);
    ctx.write_vreg(rdi, 0xAAAA_BBBB_0000_0220);
    ctx.write_vreg(rcx, 0xFFFF_0000_0000_0000);
    execute_lifted_x86(&[0x67, 0xF3, 0xA4], &mut ctx, &mut memory);
    assert_eq!(ctx.read_vreg(rsi), 0x120);
    assert_eq!(ctx.read_vreg(rdi), 0x220);
    assert_eq!(ctx.read_vreg(rcx), 0);
}
#[test]
fn lifted_string_scas_cmps_rep_termination_and_flags() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rsi = VReg::Arch(ArchReg::X86(X86Reg::Rsi));
    let rdi = VReg::Arch(ArchReg::X86(X86Reg::Rdi));
    let mut memory = FlatMemory::new(0x5000);
    let mut ctx = SmirContext::new_x86_64();

    memory.write(0x300, &[1, 1, 2, 1]).unwrap();
    ctx.write_vreg(rax, 1);
    ctx.write_vreg(rdi, 0x300);
    ctx.write_vreg(rcx, 4);
    execute_lifted_x86(&[0xF3, 0xAE], &mut ctx, &mut memory); // REPE SCASB
    assert_eq!(ctx.read_vreg(rdi), 0x303);
    assert_eq!(ctx.read_vreg(rcx), 1);
    ctx.flags.materialize_all();
    assert!(!ctx.flags.materialized.zf);

    memory.write(0x320, &[2, 2, 1, 2]).unwrap();
    ctx.write_vreg(rdi, 0x320);
    ctx.write_vreg(rcx, 4);
    execute_lifted_x86(&[0xF2, 0xAE], &mut ctx, &mut memory); // REPNE SCASB
    assert_eq!(ctx.read_vreg(rdi), 0x323);
    assert_eq!(ctx.read_vreg(rcx), 1);
    ctx.flags.materialize_all();
    assert!(ctx.flags.materialized.zf);

    memory.write(0x100, &[7, 8, 9, 10]).unwrap();
    memory.write(0x200, &[7, 8, 0, 10]).unwrap();
    ctx.write_vreg(rsi, 0x100);
    ctx.write_vreg(rdi, 0x200);
    ctx.write_vreg(rcx, 4);
    execute_lifted_x86(&[0xF3, 0xA6], &mut ctx, &mut memory); // REPE CMPSB
    assert_eq!(ctx.read_vreg(rsi), 0x103);
    assert_eq!(ctx.read_vreg(rdi), 0x203);
    assert_eq!(ctx.read_vreg(rcx), 1);
    ctx.flags.materialize_all();
    assert!(!ctx.flags.materialized.zf);
}
#[test]
fn lifted_string_faults_preserve_current_element_restart_state() {
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rsi = VReg::Arch(ArchReg::X86(X86Reg::Rsi));
    let rdi = VReg::Arch(ArchReg::X86(X86Reg::Rdi));
    let mut inner = FlatMemory::new(0x1000);
    inner.write(0x100, &[0x5A]).unwrap();
    let mut memory = StoreFaultMemory {
        inner,
        stores_before_fault: 0,
    };
    let mut ctx = SmirContext::new_x86_64();
    ctx.write_vreg(rsi, 0x100);
    ctx.write_vreg(rdi, 0x200);
    ctx.write_vreg(rcx, 2);
    let exit = execute_lifted_x86(&[0xF3, 0xA4], &mut ctx, &mut memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    assert_eq!(ctx.read_vreg(rsi), 0x100);
    assert_eq!(ctx.read_vreg(rdi), 0x200);
    assert_eq!(ctx.read_vreg(rcx), 2);

    let mut inner = FlatMemory::new(0x1000);
    inner.write(0x100, &[0x11, 0x22]).unwrap();
    let mut partial_memory = StoreFaultMemory {
        inner,
        stores_before_fault: 1,
    };
    ctx.write_vreg(rsi, 0x100);
    ctx.write_vreg(rdi, 0x200);
    ctx.write_vreg(rcx, 2);
    let exit = execute_lifted_x86(&[0xF3, 0xA4], &mut ctx, &mut partial_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    let mut first = [0u8; 1];
    partial_memory.inner.read(0x200, &mut first).unwrap();
    assert_eq!(first[0], 0x11);
    assert_eq!(ctx.read_vreg(rsi), 0x101);
    assert_eq!(ctx.read_vreg(rdi), 0x201);
    assert_eq!(ctx.read_vreg(rcx), 1);
}

#[test]
fn lifted_repeated_comparison_faults_restore_entry_flags_and_keep_completed_elements() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rsi = VReg::Arch(ArchReg::X86(X86Reg::Rsi));
    let rdi = VReg::Arch(ArchReg::X86(X86Reg::Rdi));
    let status = 0x8d5;
    for opcode in [0xa6, 0xae] {
        for prefix in [0xf2, 0xf3] {
            let first = u8::from(prefix == 0xf2);
            let initial = 0x13 | if prefix == 0xf2 { 0x40 } else { 0 };
            let mut memory = FlatMemory::new(0x2000);
            memory.write(0x300, &[0, 0]).unwrap();
            memory.write(0x1fff, &[first]).unwrap();
            let mut ctx = SmirContext::new_x86_64();
            ctx.flags.materialized = MaterializedFlags::from_rflags(initial);
            ctx.write_vreg(rax, 0);
            ctx.write_vreg(rcx, 3);
            ctx.write_vreg(rsi, 0x300);
            ctx.write_vreg(rdi, 0x1fff);
            let code = [prefix, opcode];
            let exit = execute_lifted_x86(&code, &mut ctx, &mut memory);
            assert!(matches!(
                exit,
                BlockResult::Exit(ExitReason::MemoryFault {
                    addr: 0x2000,
                    write: false,
                    ..
                })
            ));
            assert_eq!(ctx.read_vreg(rcx), 2);
            assert_eq!(ctx.read_vreg(rdi), 0x2000);
            ctx.flags.materialize_all();
            assert_eq!(
                ctx.flags.materialized.to_rflags() & status,
                initial & status
            );

            let mut memory = FlatMemory::new(0x3000);
            memory.write(0x2000, &[1 - first]).unwrap();
            assert!(matches!(
                execute_lifted_x86(&code, &mut ctx, &mut memory),
                BlockResult::Exit(ExitReason::Halt)
            ));
            ctx.flags.materialize_all();
            let final_flags = if prefix == 0xf2 { 0x44 } else { 0x95 };
            assert_eq!(ctx.flags.materialized.to_rflags() & status, final_flags);
            assert_eq!(ctx.read_vreg(rcx), 1);
            assert_eq!(ctx.read_vreg(rdi), 0x2001);
            assert_eq!(
                ctx.read_vreg(rsi),
                if opcode == 0xa6 { 0x302 } else { 0x300 }
            );
        }
    }
}
