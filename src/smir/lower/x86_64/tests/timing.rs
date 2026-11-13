//! Helper-backed native lowering for RDTSC/RDTSCP.

use super::*;
use crate::smir::ir::ops::X86ReadTscOp;
use crate::smir::lower::X86_GUEST_TSC_FN_OFFSET;
use crate::smir::lower::x86_64::test_support::{
    host_c_helper_reference, host_c_helper_reference_opcode,
};

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn timestamp_kind(aux: bool) -> OpKind {
    OpKind::X86ReadTsc(X86ReadTscOp {
        dst_lo: x86(X86Reg::Rax),
        dst_hi: x86(X86Reg::Rdx),
        dst_aux: aux.then(|| x86(X86Reg::Rcx)),
    })
}

fn lower_timestamp(kind: OpKind, fault_guards: bool) -> Result<(Vec<u8>, usize), LowerError> {
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
fn lower_timestamp_requires_precise_fault_guards_and_calls_guest_clock_helper() {
    assert!(matches!(
        lower_timestamp(timestamp_kind(false), false),
        Err(LowerError::UnsupportedOp { .. })
    ));

    for aux in [false, true] {
        let (code, _) = lower_timestamp(timestamp_kind(aux), true).expect("timestamp lowering");
        let helper_call = host_c_helper_reference(X86_GUEST_TSC_FN_OFFSET);
        assert!(
            code.windows(helper_call.len())
                .any(|window| window == helper_call),
            "missing guest-clock helper call: {code:02X?}"
        );
        let mut helper_boundary = vec![0xFC, 0x48, 0x89, 0xC7];
        helper_boundary.extend_from_slice(host_c_helper_reference_opcode());
        assert!(
            code.windows(helper_boundary.len())
                .any(|window| window == helper_boundary),
            "guest DF must be cleared before the Rust helper boundary"
        );
        assert!(
            !code.windows(2).any(|window| window == [0x0F, 0x31]),
            "guest RDTSC must not expose the host TSC: {code:02X?}"
        );
        assert!(
            !code.windows(3).any(|window| window == [0x0F, 0x01, 0xF9]),
            "guest RDTSCP must not expose host TSC_AUX: {code:02X?}"
        );
        assert_eq!(
            code.windows(3)
                .filter(|window| *window == [0x0F, 0xAE, 0xE8])
                .count(),
            usize::from(aux),
            "only RDTSCP requires the prior-load LFENCE"
        );
    }
}

#[test]
fn lower_timestamp_rejects_every_malformed_destination_shape() {
    for malformed in [
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo: x86(X86Reg::Rbx),
            dst_hi: x86(X86Reg::Rdx),
            dst_aux: None,
        }),
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo: x86(X86Reg::Rax),
            dst_hi: x86(X86Reg::Rcx),
            dst_aux: None,
        }),
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo: x86(X86Reg::Rax),
            dst_hi: x86(X86Reg::Rdx),
            dst_aux: Some(x86(X86Reg::Rbx)),
        }),
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo: x86(X86Reg::Rax),
            dst_hi: x86(X86Reg::Rdx),
            dst_aux: Some(VReg::Virtual(crate::smir::ir::types::VirtualId(0))),
        }),
    ] {
        assert!(!x86_read_tsc_shape_valid(&malformed));
        assert!(matches!(
            lower_timestamp(malformed, true),
            Err(LowerError::InvalidOperand { .. })
        ));
    }
}

#[test]
fn lower_timestamp_wraps_helper_with_vector_state_when_requested() {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, timestamp_kind(true));
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    lowerer.set_preserve_vector_system_helpers(true);
    lowerer
        .lower_function(&builder.finish())
        .expect("lower vector-preserving RDTSCP");
    let code = lowerer
        .finalize()
        .expect("finalize vector-preserving RDTSCP");

    let store_zmm0 = [0x62, 0xF1, 0xFE, 0x48, 0x7F, 0x40, 0x05];
    let load_zmm0 = [0x62, 0xF1, 0xFE, 0x48, 0x6F, 0x41, 0x05];
    assert_eq!(
        code.windows(store_zmm0.len())
            .filter(|window| *window == store_zmm0)
            .count(),
        1
    );
    assert_eq!(
        code.windows(load_zmm0.len())
            .filter(|window| *window == load_zmm0)
            .count(),
        1
    );
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn deterministic_test_tsc(state: *mut crate::smir::lower::runtime::GuestRegs) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let Some(state) = (unsafe { state.as_mut() }) else {
        return;
    };
    let calls = state.ctx as *const AtomicUsize;
    let calls = unsafe {
        calls
            .as_ref()
            .expect("timestamp test helper requires a per-execution call counter")
    };
    calls.fetch_add(1, Ordering::SeqCst);
    state.gpr[0] = 0x89AB_CDEF;
    state.gpr[2] = 0x0123_4567;
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn execute_native(
    aux: bool,
    configure: impl FnOnce(&mut crate::smir::lower::runtime::GuestRegs),
) -> (crate::smir::lower::runtime::GuestRegs, usize) {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (code, entry) = lower_timestamp(timestamp_kind(aux), true).expect("lower timestamp read");
    let exec = ExecMem::new(&code).expect("map timestamp read");
    let helper_calls = AtomicUsize::new(0);
    let mut regs = GuestRegs::default();
    for (index, value) in regs.gpr.iter_mut().enumerate() {
        *value = 0xA500_0000_0000_0000 | index as u64;
    }
    regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    regs.exit_pc = 0xDEAD_BEEF;
    regs.cr0 = 1;
    regs.cr4 = 0;
    regs.cpl = 3;
    regs.tsc_aux = 0xCAFE_BABE;
    regs.tsc_fn = deterministic_test_tsc as usize as u64;
    configure(&mut regs);
    regs.ctx = (&helper_calls as *const AtomicUsize) as u64;
    exec.run(entry, &mut regs);
    (regs, helper_calls.load(Ordering::SeqCst))
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_timestamp_reads_guest_clock_and_aux_and_preserves_nonoutputs() {
    let (rdtsc, rdtsc_helper_calls) = execute_native(false, |_| {});
    assert_eq!(rdtsc.gpr[0], 0x89AB_CDEF);
    assert_eq!(rdtsc.gpr[2], 0x0123_4567);
    assert_eq!(rdtsc.gpr[1], 0xA500_0000_0000_0001);
    assert_eq!(rdtsc.exit_pc, 0xDEAD_BEEF);

    let (rdtscp, rdtscp_helper_calls) = execute_native(true, |_| {});
    assert_eq!(rdtscp.gpr[0], 0x89AB_CDEF);
    assert_eq!(rdtscp.gpr[2], 0x0123_4567);
    assert_eq!(rdtscp.gpr[1], 0xCAFE_BABE);
    assert_eq!(rdtscp.exit_pc, 0xDEAD_BEEF);
    for index in 3..32 {
        assert_eq!(rdtscp.gpr[index], 0xA500_0000_0000_0000 | index as u64);
    }
    assert_eq!(rdtscp.rflags & (0x08D5 | (1 << 10)), 0x08D5 | (1 << 10));
    assert_eq!(rdtsc_helper_calls, 1);
    assert_eq!(rdtscp_helper_calls, 1);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_timestamp_tsd_guard_is_dynamic_precise_and_noncommitting() {
    for aux in [false, true] {
        let (regs, helper_calls) = execute_native(aux, |regs| {
            regs.cr0 = 1;
            regs.cr4 = 1 << 2;
            regs.cpl = 3;
            regs.gpr[0] = 0x1111;
            regs.gpr[1] = 0x2222;
            regs.gpr[2] = 0x3333;
        });
        assert_eq!(regs.exit_pc, 0x1000);
        assert_eq!(regs.gpr[0], 0x1111);
        assert_eq!(regs.gpr[1], 0x2222);
        assert_eq!(regs.gpr[2], 0x3333);
        assert_eq!(helper_calls, 0);
    }

    for (cr0, cr4, cpl) in [(0, 1 << 2, 3), (1, 0, 3), (1, 1 << 2, 0)] {
        let (regs, helper_calls) = execute_native(true, |regs| {
            regs.cr0 = cr0;
            regs.cr4 = cr4;
            regs.cpl = cpl;
        });
        assert_eq!(regs.exit_pc, 0xDEAD_BEEF);
        assert_eq!(regs.gpr[1], 0xCAFE_BABE);
        assert_eq!(helper_calls, 1);
    }
}
