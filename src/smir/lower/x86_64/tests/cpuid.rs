//! Helper-backed native lowering for deterministic guest CPUID.

use super::*;
use crate::smir::lower::X86_GUEST_CPUID_FN_OFFSET;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;

fn x86_gpr(index: u8) -> VReg {
    VReg::Arch(ArchReg::X86(X86Reg::gpr(index)))
}

fn cpuid_kind() -> OpKind {
    OpKind::X86Cpuid {
        dst_eax: x86_gpr(0),
        dst_ebx: x86_gpr(3),
        dst_ecx: x86_gpr(1),
        dst_edx: x86_gpr(2),
        leaf: x86_gpr(0),
        subleaf: x86_gpr(1),
    }
}

#[test]
fn lower_cpuid_emits_guest_helper_call_and_host_serialization_barrier() {
    let code = lower_single_op(cpuid_kind());
    let helper_call = host_c_helper_reference(X86_GUEST_CPUID_FN_OFFSET);
    assert!(
        code.windows(helper_call.len())
            .any(|window| window == helper_call),
        "missing CPUID guest-profile helper call: {code:02X?}"
    );
    assert!(
        code.windows(7)
            .any(|window| window == [0xB8, 0, 0, 0, 0, 0x0F, 0xA2]),
        "missing fixed host-CPUID serialization barrier: {code:02X?}"
    );
}

#[test]
fn lower_cpuid_wraps_the_helper_with_vector_state_when_requested() {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, cpuid_kind());
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_preserve_vector_system_helpers(true);
    lowerer
        .lower_function(&builder.finish())
        .expect("lower vector-preserving CPUID");
    let code = lowerer
        .finalize()
        .expect("finalize vector-preserving CPUID");

    let store_zmm0 = [0x62, 0xF1, 0xFE, 0x48, 0x7F, 0x40, 0x05];
    let load_zmm0 = [0x62, 0xF1, 0xFE, 0x48, 0x6F, 0x41, 0x05];
    assert_eq!(
        code.windows(store_zmm0.len())
            .filter(|window| *window == store_zmm0)
            .count(),
        1,
        "CPUID helper must publish vector state once"
    );
    assert_eq!(
        code.windows(load_zmm0.len())
            .filter(|window| *window == load_zmm0)
            .count(),
        1,
        "CPUID helper must restore vector state once"
    );
}

#[test]
fn lower_cpuid_rejects_every_malformed_implicit_register_class() {
    let valid = cpuid_kind();
    let OpKind::X86Cpuid {
        dst_eax,
        dst_ebx,
        dst_ecx,
        dst_edx,
        leaf,
        subleaf,
    } = valid
    else {
        unreachable!()
    };
    for malformed in [
        OpKind::X86Cpuid {
            dst_eax: x86_gpr(8),
            dst_ebx,
            dst_ecx,
            dst_edx,
            leaf,
            subleaf,
        },
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx: x86_gpr(9),
            dst_ecx,
            dst_edx,
            leaf,
            subleaf,
        },
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx,
            dst_ecx: x86_gpr(10),
            dst_edx,
            leaf,
            subleaf,
        },
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx,
            dst_ecx,
            dst_edx: x86_gpr(11),
            leaf,
            subleaf,
        },
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx,
            dst_ecx,
            dst_edx,
            leaf: x86_gpr(12),
            subleaf,
        },
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx,
            dst_ecx,
            dst_edx,
            leaf,
            subleaf: x86_gpr(13),
        },
    ] {
        assert!(matches!(
            lower_single_op_err(malformed),
            LowerError::InvalidOperand { .. }
        ));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
unsafe extern "C" fn deterministic_test_cpuid(state: *mut crate::smir::lower::runtime::GuestRegs) {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return;
    };
    let leaf = state.gpr[0] as u32;
    let subleaf = state.gpr[1] as u32;
    state.gpr[0] = u64::from(leaf.rotate_left(5));
    state.gpr[3] = u64::from(subleaf.rotate_right(3));
    state.gpr[1] = u64::from(leaf ^ subleaf);
    state.gpr[2] = u64::from(leaf.wrapping_add(subleaf));
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_cpuid_commits_zero_extended_outputs_and_preserves_flags_and_other_gprs() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, cpuid_kind());
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&builder.finish())
        .expect("lower helper-backed CPUID");
    let code = lowerer.finalize().expect("finalize helper-backed CPUID");
    let exec = ExecMem::new(&code).expect("map helper-backed CPUID");

    let mut regs = GuestRegs::default();
    for (index, value) in regs.gpr.iter_mut().enumerate() {
        *value = 0xA5A5_0000_0000_0000 | (index as u64 * 0x0101_0101);
    }
    let leaf = 0xF123_4567u32;
    let subleaf = 0x89AB_CDEFu32;
    regs.gpr[0] = 0xFFFF_FFFF_0000_0000 | u64::from(leaf);
    regs.gpr[1] = 0xEEEE_EEEE_0000_0000 | u64::from(subleaf);
    regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    regs.cpuid_fn = deterministic_test_cpuid as usize as u64;
    let unchanged = regs.gpr[4..].to_vec();
    let flags = regs.rflags;

    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.gpr[0], u64::from(leaf.rotate_left(5)));
    assert_eq!(regs.gpr[3], u64::from(subleaf.rotate_right(3)));
    assert_eq!(regs.gpr[1], u64::from(leaf ^ subleaf));
    assert_eq!(regs.gpr[2], u64::from(leaf.wrapping_add(subleaf)));
    assert_eq!(&regs.gpr[4..], unchanged.as_slice());
    assert_eq!(
        regs.rflags & (0x08D5 | (1 << 10)),
        flags & (0x08D5 | (1 << 10))
    );
}
