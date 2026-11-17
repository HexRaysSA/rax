//! CPU reconstruction must replace every memory view and preserve user state.
//! Load/store encodings match the LLVM-MC provenance in the parent test module.

use super::*;
use crate::user::linux::arch::GuestCpu;

fn storage(code: &[u8], value: u64) -> AddressSpace {
    let space = space(code);
    space.write(DATA, &value.to_le_bytes()).unwrap();
    space
}

fn value(space: &AddressSpace) -> u64 {
    let mut bytes = [0; 8];
    space.read(DATA, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

#[test]
fn x86_rebinding_replaces_fetch_data_and_nested_storage() {
    let original = storage(&[0x0f, 0x05], 5);
    let target = storage(&[0x48, 0x8b, 0x07, 0x0f, 0x05], 77);
    let mut parent = X86UserCpu::new(&original);
    parent.vcpu_mut().user_regs_mut().rip = CODE;
    parent.vcpu_mut().user_regs_mut().rdi = DATA;
    parent.vcpu_mut().user_regs_mut().r12 = 0xfeed;
    parent.vcpu_mut().user_regs_mut().xmm[3] = [1, u64::MAX];
    parent.vcpu_mut().set_fs_base(0x7000);
    parent.vcpu_mut().set_gs_base(0x8000);
    parent.vcpu_mut().set_mxcsr(0x9fc0).unwrap();
    parent.vcpu_mut().set_user_tsc_disabled(true);
    let parent = GuestCpu::X86_64(parent);
    let GuestCpu::X86_64(mut child) = parent.clone_to_space(&target) else {
        unreachable!()
    };
    assert!(child.space().same_space(&target));
    assert!(!child.space().same_space(&original));
    assert_eq!(child.vcpu().user_regs().r12, 0xfeed);
    assert_eq!(child.vcpu().user_regs().xmm[3], [1, u64::MAX]);
    assert_eq!(child.vcpu().fs_base(), 0x7000);
    assert_eq!(child.vcpu().gs_base(), 0x8000);
    assert_eq!(child.vcpu().mxcsr(), 0x9fc0);
    assert!(child.vcpu().user_tsc_disabled());
    assert!(matches!(child.run(), X86Exit::Syscall { .. }));
    assert_eq!(child.vcpu().user_regs().rax, 77);
    assert_eq!(value(&original), 5);

    // A code replacement at the same VA uses the new space's invalidations.
    target
        .write_raw(CODE, &[0x48, 0x89, 0x07, 0x0f, 0x05])
        .unwrap();
    child.vcpu_mut().user_regs_mut().rip = CODE;
    child.vcpu_mut().user_regs_mut().rax = 99;
    assert!(matches!(child.run(), X86Exit::Syscall { .. }));
    assert_eq!(value(&target), 99);
    assert_eq!(value(&original), 5);
    target.protect(DATA, PAGE_SIZE, Perms::READ).unwrap();
    child.vcpu_mut().user_regs_mut().rip = CODE;
    assert!(matches!(
        child.run(),
        X86Exit::Fault(AccessFault {
            kind: AccessFaultKind::Permission,
            ..
        })
    ));

    let nested = storage(&[0x48, 0x8b, 0x07, 0x0f, 0x05], 31);
    child.vcpu_mut().user_regs_mut().rip = CODE;
    let mut grandchild = child.clone_to_space(&nested);
    assert!(grandchild.clone_thread().space().same_space(&nested));
    drop(child);
    drop(parent);
    drop(target);
    drop(original);
    assert!(matches!(grandchild.run(), X86Exit::Syscall { .. }));
    assert_eq!(grandchild.vcpu().user_regs().rax, 31);
}

#[test]
fn a64_rebinding_preserves_registers_and_selects_new_memory() {
    let original = storage(&words(&[A64_SVC_0]), 5);
    let target = storage(&words(&[A64_LDR_X0_X1, A64_SVC_0]), 77);
    let mut parent = A64UserCpu::new(&original);
    parent.core_mut().set_pc(CODE);
    parent.set_sp(DATA + 0x800);
    parent.core_mut().set_x(1, DATA);
    parent.core_mut().set_x(19, 0xfeed);
    parent.core_mut().set_simd(31, u128::MAX - 1);
    parent.core_mut().set_fpcr_value(1 << 22);
    parent.core_mut().set_fpsr_value(1);
    parent.core_mut().set_tpidr_el0(0x7000);
    parent.core_mut().set_tpidrro_el0(0x8000);
    parent.core_mut().set_counter_frequency(24_000_000);
    assert!(parent.core_mut().set_el0_spsr(0x9000_0000));
    let parent = GuestCpu::Aarch64(parent);
    let GuestCpu::Aarch64(mut child) = parent.clone_to_space(&target) else {
        unreachable!()
    };
    assert!(child.space().same_space(&target));
    assert_eq!(child.pc(), CODE);
    assert_eq!(child.sp(), DATA + 0x800);
    assert_eq!(child.core().get_x(19), 0xfeed);
    assert_eq!(child.core().get_simd(31), u128::MAX - 1);
    assert_eq!(child.core().fpcr_value(), 1 << 22);
    assert_eq!(child.core().fpsr_value(), 1);
    assert_eq!(child.core().tpidr_el0(), 0x7000);
    assert_eq!(child.core().tpidrro_el0(), 0x8000);
    assert_eq!(child.core().counter_frequency(), 24_000_000);
    assert_eq!(child.core().el0_spsr(), 0x9000_0000);
    assert!(matches!(child.run(10), A64Exit::Svc { .. }));
    assert_eq!(child.core().get_x(0), 77);
    target
        .write_raw(CODE, &words(&[A64_STR_X0_X1, A64_SVC_0]))
        .unwrap();
    child.core_mut().set_pc(CODE);
    child.core_mut().set_x(0, 99);
    assert!(matches!(child.run(10), A64Exit::Svc { .. }));
    assert_eq!(value(&target), 99);
    assert_eq!(value(&original), 5);
    target.protect(DATA, PAGE_SIZE, Perms::READ).unwrap();
    child.core_mut().set_pc(CODE);
    assert!(matches!(
        child.run(10),
        A64Exit::Fault(AccessFault {
            kind: AccessFaultKind::Permission,
            ..
        })
    ));
    assert!(child.clone_thread().space().same_space(&target));
}

#[test]
fn a32_rebinding_preserves_user_state_and_uses_target_permissions() {
    let original = storage(&words(&[A32_SVC_0]), 5);
    let target = storage(&words(&[A32_LDR_R0_R1, A32_SVC_0]), 77);
    let mut parent = A32UserCpu::new(&original);
    parent.set_pc(CODE);
    parent.set_sp(DATA + 0x800);
    parent.core_mut().regs[1] = DATA as u32;
    parent.core_mut().regs[5] = 0xfeed;
    parent.core_mut().cpsr.ge = 0b0101;
    parent.core_mut().cpsr.n = true;
    parent.core_mut().vfp.dregs[31] = u64::MAX - 1;
    parent.core_mut().vfp.fpscr = crate::isa::arm::aarch32::vfp::Fpscr::from_bits(1 << 22);
    parent.core_mut().cp15.tpidrurw = 0x7000;
    parent.core_mut().cp15.tpidruro = 0x8000;
    let parent = GuestCpu::Arm(parent);
    let GuestCpu::Arm(mut child) = parent.clone_to_space(&target) else {
        unreachable!()
    };
    assert!(child.space().same_space(&target));
    assert_eq!(child.pc(), CODE);
    assert_eq!(child.sp(), DATA + 0x800);
    assert_eq!(child.core().regs[5], 0xfeed);
    assert!(child.core().cpsr.n);
    assert_eq!(child.core().cpsr.ge, 0b0101);
    assert_eq!(child.core().vfp.dregs[31], u64::MAX - 1);
    assert_eq!(child.core().vfp.fpscr.bits(), 1 << 22);
    assert_eq!(child.core().cp15.tpidrurw, 0x7000);
    assert_eq!(child.core().cp15.tpidruro, 0x8000);
    assert!(matches!(child.run(10), A32Exit::Svc { .. }));
    assert_eq!(child.core().regs[0], 77);
    target
        .write_raw(CODE, &words(&[A32_STR_R0_R1, A32_SVC_0]))
        .unwrap();
    child.set_pc(CODE);
    child.core_mut().regs[0] = 99;
    assert!(matches!(child.run(10), A32Exit::Svc { .. }));
    assert_eq!(value(&target), 99);
    assert_eq!(value(&original), 5);
    target.protect(DATA, PAGE_SIZE, Perms::READ).unwrap();
    child.set_pc(CODE);
    assert!(matches!(
        child.run(10),
        A32Exit::Fault(AccessFault {
            kind: AccessFaultKind::Permission,
            ..
        })
    ));
    assert!(child.clone_thread().space().same_space(&target));
}

#[test]
fn rv_rebinding_preserves_scalar_vector_state_and_uses_new_memory() {
    let original = storage(&RV_ECALL, 5);
    let target = storage(&cat(&[&RV_LD_A0_A1, &RV_ECALL]), 77);
    let mut parent = RvUserCpu::new(&original, RiscVConfig::rv64gc());
    parent.core_mut().set_pc(CODE);
    parent.core_mut().set_x(2, DATA + 0x800);
    parent.core_mut().set_x(4, 0x7000);
    parent.core_mut().set_x(11, DATA);
    parent.core_mut().set_x(19, 0xfeed);
    parent.core_mut().set_f(0, u64::MAX - 1);
    parent.core_mut().set_f(31, 0x1234);
    parent.core_mut().set_fcsr((2 << 5) | 1);
    let vector = [0x55; crate::isa::riscv::cpu::VLENB as usize];
    parent.core_mut().set_vreg(31, &vector);
    parent.core_mut().set_vl_vtype(2, 2 << 3);
    parent.core_mut().set_vcsr(3);
    parent.core_mut().set_vstart(1);
    let parent = GuestCpu::Riscv64(parent);
    let GuestCpu::Riscv64(mut child) = parent.clone_to_space(&target) else {
        unreachable!()
    };
    assert!(child.space().same_space(&target));
    assert_eq!(child.pc(), CODE);
    assert_eq!(child.core().x(2), DATA + 0x800);
    assert_eq!(child.core().x(4), 0x7000);
    assert_eq!(child.core().x(19), 0xfeed);
    assert_eq!(child.core().f(0), u64::MAX - 1);
    assert_eq!(child.core().f(31), 0x1234);
    assert_eq!(child.core().fcsr(), (2 << 5) | 1);
    assert_eq!(child.core().vreg(31), vector);
    assert_eq!(child.core().vl(), 2);
    assert_eq!(child.core().vtype(), 2 << 3);
    assert_eq!(child.core().vcsr(), 3);
    assert_eq!(child.core().vstart(), 1);
    assert!(matches!(child.run(10), RvExit::Ecall { .. }));
    assert_eq!(child.core().x(10), 77);
    target
        .write_raw(CODE, &cat(&[&RV_SD_A0_A1, &RV_ECALL]))
        .unwrap();
    child.core_mut().set_pc(CODE);
    child.core_mut().set_x(10, 99);
    assert!(matches!(child.run(10), RvExit::Ecall { .. }));
    assert_eq!(value(&target), 99);
    assert_eq!(value(&original), 5);
    target.protect(DATA, PAGE_SIZE, Perms::READ).unwrap();
    child.core_mut().set_pc(CODE);
    assert!(matches!(
        child.run(10),
        RvExit::Fault(AccessFault {
            kind: AccessFaultKind::Permission,
            ..
        })
    ));
    assert!(child.clone_thread().space().same_space(&target));
}

#[test]
fn a64_rebinding_does_not_transfer_exclusive_store_rights() {
    let code = words(&[A64_LDXR_X0_X1, A64_STXR_W2_X0_X1]);
    let original = storage(&code, 5);
    let target = storage(&code, 77);
    let mut parent = A64UserCpu::new(&original);
    parent.core_mut().set_pc(CODE);
    parent.core_mut().set_x(1, DATA);
    assert_eq!(parent.run(1), A64Exit::Yield);
    let mut child = parent.clone_to_space(&target);
    child.core_mut().set_x(0, 99);
    assert_eq!(child.run(1), A64Exit::Yield);
    assert_eq!(child.core().get_x(2), 1);
    assert_eq!(value(&target), 77);
    parent.core_mut().set_x(0, 31);
    assert_eq!(parent.run(1), A64Exit::Yield);
    assert_eq!(parent.core().get_x(2), 0);
    assert_eq!(value(&original), 31);
}

#[test]
fn a32_rebinding_does_not_transfer_exclusive_store_rights() {
    let code = words(&[A32_LDREX_R0_R1, A32_STREX_R2_R0_R1]);
    let original = storage(&code, 5);
    let target = storage(&code, 77);
    let mut parent = A32UserCpu::new(&original);
    parent.set_pc(CODE);
    parent.core_mut().regs[1] = DATA as u32;
    assert!(parent.step_instruction().is_none());
    assert_eq!(parent.exclusive_monitor().address, Some(DATA as u32));
    let mut child = parent.clone_to_space(&target);
    assert!(child.exclusive_monitor().address.is_none());
    child.core_mut().regs[0] = 99;
    assert!(child.step_instruction().is_none());
    assert_eq!(child.core().regs[2], 1);
    assert_eq!(value(&target), 77);
    parent.core_mut().regs[0] = 31;
    assert!(parent.step_instruction().is_none());
    assert_eq!(parent.core().regs[2], 0);
    assert_eq!(value(&original), 31);
}

#[test]
fn rv_rebinding_does_not_transfer_lr_sc_reservations() {
    use crate::isa::riscv::RiscVExit;
    let code = cat(&[&RV_LR_D, &RV_SC_D]);
    let original = storage(&code, 5);
    let target = storage(&code, 77);
    let mut parent = RvUserCpu::new(&original, RiscVConfig::rv64gc());
    parent.core_mut().set_pc(CODE);
    parent.core_mut().set_x(11, DATA);
    assert_eq!(parent.core_mut().step(), RiscVExit::Continue);
    let mut child = parent.clone_to_space(&target);
    child.core_mut().set_x(10, 99);
    assert_eq!(child.core_mut().step(), RiscVExit::Continue);
    assert_eq!(child.core().x(12), 1);
    assert_eq!(value(&target), 77);
    parent.core_mut().set_x(10, 31);
    assert_eq!(parent.core_mut().step(), RiscVExit::Continue);
    assert_eq!(parent.core().x(12), 0);
    assert_eq!(value(&original), 31);
}
