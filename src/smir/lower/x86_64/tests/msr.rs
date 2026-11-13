//! Fault-precise helper-backed native lowering for RDMSR/WRMSR.

use super::*;
use crate::smir::ir::ops::X86MsrOp;
use crate::smir::lower::X86_GUEST_MSR_FN_OFFSET;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn msr(eax: VReg, ecx: VReg, edx: VReg, write: bool, next_pc: u64) -> OpKind {
    OpKind::X86Msr(X86MsrOp {
        eax,
        ecx,
        edx,
        write,
        next_pc,
    })
}

fn exact_msr(write: bool, next_pc: u64) -> OpKind {
    msr(
        x86(X86Reg::Rax),
        x86(X86Reg::Rcx),
        x86(X86Reg::Rdx),
        write,
        next_pc,
    )
}

fn lower_msr(kind: OpKind, fault_guards: bool) -> Result<(Vec<u8>, usize), LowerError> {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, kind);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(fault_guards);
    let lowered = lowerer.lower_function(&builder.finish())?;
    assert!(lowered.relocations.is_empty());
    Ok((lowerer.finalize()?, lowered.entry_offset))
}

#[test]
fn lower_msr_requires_guards_calls_only_the_guest_helper_and_serializes_writes() {
    assert!(matches!(
        lower_msr(exact_msr(false, 0x1002), false),
        Err(LowerError::UnsupportedOp { .. })
    ));

    for write in [false, true] {
        let (code, _) = lower_msr(exact_msr(write, 0x1002), true).expect("guarded MSR lowering");
        let helper_call = host_c_helper_reference(X86_GUEST_MSR_FN_OFFSET);
        assert!(
            code.windows(helper_call.len())
                .any(|window| window == helper_call),
            "missing canonical MSR helper: {code:02X?}"
        );
        assert!(
            !code.windows(2).any(|window| window == [0x0F, 0x30]),
            "guest WRMSR must never execute against the host: {code:02X?}"
        );
        assert!(
            !code.windows(2).any(|window| window == [0x0F, 0x32]),
            "guest RDMSR must never execute against the host: {code:02X?}"
        );
        assert_eq!(
            code.windows(2)
                .filter(|window| *window == [0x0F, 0xA2])
                .count(),
            usize::from(write),
            "only WRMSR needs the conservative host serialization barrier"
        );
        assert!(
            code.windows(4)
                .any(|window| window == 0x1000u32.to_le_bytes()),
            "fault exit must retain the original guest PC"
        );
        if write {
            assert!(
                code.windows(4)
                    .any(|window| window == 0x1002u32.to_le_bytes()),
                "successful WRMSR must hand off at its exact next PC"
            );
        }
    }
}

#[test]
fn lower_msr_rejects_every_non_lifter_register_hint_and_frontier_shape() {
    for malformed in [
        msr(
            VReg::virt(0),
            x86(X86Reg::Rcx),
            x86(X86Reg::Rdx),
            false,
            0x1002,
        ),
        msr(
            x86(X86Reg::Rax),
            VReg::virt(1),
            x86(X86Reg::Rdx),
            false,
            0x1002,
        ),
        msr(
            x86(X86Reg::Rax),
            x86(X86Reg::Rcx),
            VReg::Imm(0),
            true,
            0x1002,
        ),
        msr(
            x86(X86Reg::Rbx),
            x86(X86Reg::Rcx),
            x86(X86Reg::Rdx),
            false,
            0x1002,
        ),
        msr(
            x86(X86Reg::Rax),
            x86(X86Reg::Rbx),
            x86(X86Reg::Rdx),
            true,
            0x1002,
        ),
        msr(
            x86(X86Reg::Rax),
            x86(X86Reg::Rcx),
            x86(X86Reg::Rbx),
            true,
            0x1002,
        ),
        exact_msr(false, 0x1001),
        exact_msr(false, 0x1010),
        exact_msr(true, 0x0FFF),
    ] {
        assert!(matches!(
            lower_msr(malformed, true),
            Err(LowerError::InvalidOperand { .. })
        ));
    }

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, exact_msr(false, 0x1002));
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(matches!(
        lowerer.lower_function(&hinted),
        Err(LowerError::InvalidOperand { .. })
    ));
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn deterministic_test_msr(
    state: *mut crate::smir::lower::runtime::GuestRegs,
    write: u64,
) -> u64 {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    let calls = unsafe { (state.ctx as *const AtomicUsize).as_ref() }
        .expect("MSR test helper requires a call counter");
    calls.fetch_add(1, Ordering::SeqCst);
    if state.gpr[1] as u32 == 0xDEAD_BEEF {
        return 0;
    }
    if write != 0 {
        state.star =
            ((state.gpr[2] & u64::from(u32::MAX)) << 32) | (state.gpr[0] & u64::from(u32::MAX));
    } else {
        state.gpr[0] = u64::from(state.star as u32);
        state.gpr[2] = u64::from((state.star >> 32) as u32);
    }
    1
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn execute_native(
    ops: &[(u64, OpKind)],
    configure: impl FnOnce(&mut crate::smir::lower::runtime::GuestRegs),
) -> (crate::smir::lower::runtime::GuestRegs, usize) {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    for (pc, op) in ops {
        builder.push_op(*pc, op.clone());
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    let lowered = lowerer
        .lower_function(&builder.finish())
        .expect("lower helper-backed MSR sequence");
    let code = lowerer.finalize().expect("finalize MSR sequence");
    let exec = ExecMem::new(&code).expect("map MSR sequence");
    let helper_calls = AtomicUsize::new(0);
    let mut regs = GuestRegs::default();
    for (index, value) in regs.gpr.iter_mut().enumerate() {
        *value = 0xA500_0000_0000_0000 | index as u64;
    }
    regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    regs.ac_flag = 1;
    regs.exit_pc = 0xDEAD_BEEF;
    regs.cr0 = 1;
    regs.cpl = 0;
    regs.msr_fn = deterministic_test_msr as usize as u64;
    configure(&mut regs);
    regs.ctx = (&helper_calls as *const AtomicUsize) as u64;
    exec.run(lowered.entry_offset, &mut regs);
    (regs, helper_calls.load(Ordering::SeqCst))
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_rdmsr_zero_extends_outputs_and_preserves_every_nonoutput() {
    let value = 0xCAFE_BABE_DEAD_BEEF;
    let (regs, calls) = execute_native(&[(0x1000, exact_msr(false, 0x1002))], |regs| {
        regs.gpr[1] = 0xFFFF_FFFF_C000_0081;
        regs.star = value;
    });
    assert_eq!(regs.gpr[0], 0xDEAD_BEEF);
    assert_eq!(regs.gpr[2], 0xCAFE_BABE);
    assert_eq!(regs.gpr[1], 0xFFFF_FFFF_C000_0081);
    for index in 3..32 {
        assert_eq!(regs.gpr[index], 0xA500_0000_0000_0000 | index as u64);
    }
    assert_eq!(regs.rflags & (0x08D5 | (1 << 10)), 0x08D5 | (1 << 10));
    assert_eq!(regs.ac_flag, 1);
    assert_eq!(regs.exit_pc, 0xDEAD_BEEF);
    assert_eq!(calls, 1);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_wrmsr_commits_once_and_ends_before_later_ops() {
    let value = 0x0123_4567_89AB_CDEF;
    let (regs, calls) = execute_native(
        &[
            (0x1000, exact_msr(true, 0x1002)),
            (
                0x1002,
                OpKind::Mov {
                    dst: x86(X86Reg::Rbx),
                    src: SrcOperand::Imm(0x7777),
                    width: OpWidth::W64,
                },
            ),
        ],
        |regs| {
            regs.gpr[0] = 0xFFFF_FFFF_89AB_CDEF;
            regs.gpr[1] = 0xC000_0081;
            regs.gpr[2] = 0xAAAA_AAAA_0123_4567;
            regs.star = 0x1111;
        },
    );
    assert_eq!(regs.star, value);
    assert_eq!(regs.gpr[0], 0xFFFF_FFFF_89AB_CDEF);
    assert_eq!(regs.gpr[1], 0xC000_0081);
    assert_eq!(regs.gpr[2], 0xAAAA_AAAA_0123_4567);
    assert_eq!(
        regs.gpr[3], 0xA500_0000_0000_0003,
        "later op is unreachable"
    );
    assert_eq!(regs.exit_pc, 0x1002);
    assert_eq!(calls, 1);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_msr_privilege_and_helper_faults_restart_without_committing() {
    let value = 0x0123_4567_89AB_CDEF;
    for (name, cr0, cpl, index, expected_calls) in [
        ("protected CPL3", 1, 3, 0xC000_0081, 0),
        ("unknown selector", 1, 0, 0xDEAD_BEEF, 1),
    ] {
        let (regs, calls) = execute_native(&[(0x2345, exact_msr(true, 0x2347))], |regs| {
            regs.cr0 = cr0;
            regs.cpl = cpl;
            regs.gpr[0] = value as u32 as u64;
            regs.gpr[1] = index;
            regs.gpr[2] = value >> 32;
            regs.star = 0x1111;
        });
        assert_eq!(regs.exit_pc, 0x2345, "{name}");
        assert_eq!(regs.star, 0x1111, "{name}");
        assert_eq!(regs.gpr[0], value as u32 as u64, "{name}");
        assert_eq!(regs.gpr[1], index, "{name}");
        assert_eq!(regs.gpr[2], value >> 32, "{name}");
        assert_eq!(calls, expected_calls, "{name}");
    }

    let (real_mode, calls) = execute_native(&[(0x3000, exact_msr(true, 0x3002))], |regs| {
        regs.cr0 = 0;
        regs.cpl = 3;
        regs.gpr[0] = value as u32 as u64;
        regs.gpr[1] = 0xC000_0081;
        regs.gpr[2] = value >> 32;
    });
    assert_eq!(real_mode.star, value);
    assert_eq!(real_mode.exit_pc, 0x3002);
    assert_eq!(calls, 1);
}
