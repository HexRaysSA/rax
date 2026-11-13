//! Helper-backed native lowering for RDPMC.

use super::*;
use crate::smir::ir::ops::{SmirOp, X86ReadPmcOp};
use crate::smir::ir::types::OpId;
use crate::smir::lower::X86_GUEST_PMC_FN_OFFSET;
use crate::smir::lower::x86_64::test_support::{
    host_c_helper_reference, host_c_helper_reference_opcode,
};

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn pmc_kind(selector: VReg, dst_lo: VReg, dst_hi: VReg) -> OpKind {
    OpKind::X86ReadPmc(X86ReadPmcOp {
        dst_lo,
        dst_hi,
        selector,
    })
}

fn exact_pmc_kind() -> OpKind {
    pmc_kind(x86(X86Reg::Rcx), x86(X86Reg::Rax), x86(X86Reg::Rdx))
}

fn pmc_op(kind: OpKind) -> SmirOp {
    SmirOp::new(OpId(0), 0x1000, kind)
}

fn lower_pmc(kind: OpKind, fault_guards: bool) -> Result<(Vec<u8>, usize), LowerError> {
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
fn lower_pmc_requires_precise_fault_guards_and_calls_guest_helper() {
    assert!(matches!(
        lower_pmc(exact_pmc_kind(), false),
        Err(LowerError::UnsupportedOp { .. })
    ));

    let (code, _) = lower_pmc(exact_pmc_kind(), true).expect("RDPMC lowering");
    let helper_call = host_c_helper_reference(X86_GUEST_PMC_FN_OFFSET);
    assert!(
        code.windows(helper_call.len())
            .any(|window| window == helper_call),
        "missing guest-PMC helper call: {code:02X?}"
    );
    let mut helper_boundary = vec![0xFC, 0x48, 0x89, 0xC7];
    helper_boundary.extend_from_slice(host_c_helper_reference_opcode());
    assert!(
        code.windows(helper_boundary.len())
            .any(|window| window == helper_boundary),
        "guest DF must be clear at the Rust helper boundary"
    );
    assert!(
        !code.windows(2).any(|window| window == [0x0F, 0x33]),
        "guest RDPMC must not expose host PMCs: {code:02X?}"
    );
}

#[test]
fn lower_pmc_rejects_every_malformed_implicit_register_shape() {
    for malformed in [
        pmc_kind(x86(X86Reg::Rbx), x86(X86Reg::Rax), x86(X86Reg::Rdx)),
        pmc_kind(x86(X86Reg::Rcx), x86(X86Reg::Rbx), x86(X86Reg::Rdx)),
        pmc_kind(x86(X86Reg::Rcx), x86(X86Reg::Rax), x86(X86Reg::Rbx)),
        pmc_kind(
            VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            x86(X86Reg::Rax),
            x86(X86Reg::Rdx),
        ),
    ] {
        assert!(!x86_read_pmc_shape_valid(&pmc_op(malformed.clone())));
        assert!(matches!(
            lower_pmc(malformed, true),
            Err(LowerError::InvalidOperand { .. })
        ));
    }

    let mut hinted = pmc_op(exact_pmc_kind());
    hinted.x86_hint = Some(X86OpHint::RexByteReg);
    assert!(!x86_read_pmc_shape_valid(&hinted));

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, exact_pmc_kind());
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(matches!(
        lowerer.lower_function(&function),
        Err(LowerError::InvalidOperand { .. })
    ));
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn deterministic_test_pmc(
    state: *mut crate::smir::lower::runtime::GuestRegs,
) -> u64 {
    use crate::isa::x86_64::execute::system::{X86PmcState, read_x86_pmc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    let calls = unsafe { (state.ctx as *const AtomicUsize).as_ref() }
        .expect("RDPMC test helper requires a per-execution call counter");
    calls.fetch_add(1, Ordering::SeqCst);
    let Ok(value) = read_x86_pmc(
        state.gpr[1] as u32,
        X86PmcState {
            cr0: state.cr0,
            cr4: state.cr4,
            cpl: state.cpl as u8,
        },
        0xABCD_EF12_3456_7890,
    ) else {
        return 0;
    };
    state.gpr[0] = u64::from(value as u32);
    state.gpr[2] = u64::from((value >> 32) as u32);
    1
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn execute_native(
    configure: impl FnOnce(&mut crate::smir::lower::runtime::GuestRegs),
) -> (crate::smir::lower::runtime::GuestRegs, usize) {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (code, entry) = lower_pmc(exact_pmc_kind(), true).expect("lower RDPMC");
    let exec = ExecMem::new(&code).expect("map RDPMC block");
    let helper_calls = AtomicUsize::new(0);
    let mut regs = GuestRegs::default();
    for (index, value) in regs.gpr.iter_mut().enumerate() {
        *value = 0xA500_0000_0000_0000 | index as u64;
    }
    regs.gpr[1] = 7;
    regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    regs.exit_pc = 0xDEAD_BEEF;
    regs.cr0 = 1;
    regs.cr4 = 0;
    regs.cpl = 0;
    regs.pmc_fn = deterministic_test_pmc as usize as u64;
    configure(&mut regs);
    regs.ctx = (&helper_calls as *const AtomicUsize) as u64;
    exec.run(entry, &mut regs);
    (regs, helper_calls.load(Ordering::SeqCst))
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_pmc_reads_guest_profile_and_preserves_nonoutputs() {
    let (normal, calls) = execute_native(|_| {});
    assert_eq!(normal.gpr[0], 0x3456_7890);
    assert_eq!(normal.gpr[2], 0x12);
    assert_eq!(normal.gpr[1], 7);
    assert_eq!(normal.exit_pc, 0xDEAD_BEEF);
    for index in 3..32 {
        assert_eq!(normal.gpr[index], 0xA500_0000_0000_0000 | index as u64);
    }
    assert_eq!(normal.rflags & (0x08D5 | (1 << 10)), 0x08D5 | (1 << 10));
    assert_eq!(calls, 1);

    let (fast, calls) = execute_native(|regs| regs.gpr[1] = 0x8000_0000);
    assert_eq!(fast.gpr[0], 0x3456_7890);
    assert_eq!(fast.gpr[2], 0);
    assert_eq!(fast.gpr[1], 0x8000_0000);
    assert_eq!(calls, 1);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_pmc_dynamic_faults_are_precise_and_noncommitting() {
    for configure in [
        (8_u64, 1_u64, 1_u64 << 8, 3_u64),
        (0, 1, 0, 3),
        (0x4000_0000, 1, 0, 0),
    ] {
        let (selector, cr0, cr4, cpl) = configure;
        let (regs, calls) = execute_native(|regs| {
            regs.gpr[0] = 0x1111;
            regs.gpr[1] = selector;
            regs.gpr[2] = 0x3333;
            regs.cr0 = cr0;
            regs.cr4 = cr4;
            regs.cpl = cpl;
        });
        assert_eq!(regs.exit_pc, 0x1000);
        assert_eq!(regs.gpr[0], 0x1111);
        assert_eq!(regs.gpr[1], selector);
        assert_eq!(regs.gpr[2], 0x3333);
        assert_eq!(calls, 1);
    }

    for (cr0, cr4, cpl) in [(0, 0, 3), (1, 1 << 8, 3), (1, 0, 0)] {
        let (regs, calls) = execute_native(|regs| {
            regs.cr0 = cr0;
            regs.cr4 = cr4;
            regs.cpl = cpl;
        });
        assert_eq!(regs.exit_pc, 0xDEAD_BEEF);
        assert_eq!(calls, 1);
    }
}
