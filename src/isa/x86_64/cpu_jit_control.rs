//! Helper-backed native MOV-to-control-register state transitions.

use super::X86_64Vcpu;
use crate::isa::x86_64::execute::system::{X86ControlWriteState, validate_x86_control_write};
use crate::smir::lower::runtime::GuestRegs;

/// Validate and commit one native MOV-to-control-register operation.
///
/// CR8 writes also update the attached task-priority owner. CR0/CR3/CR4
/// writes additionally invalidate the owning vCPU's software TLB before native
/// execution returns to the exact next-instruction frontier.
///
/// # Safety
///
/// `state` must reference the live [`GuestRegs`] image for the owning
/// [`X86_64Vcpu`], and `state.ctx` must contain that vCPU's valid address.
pub(super) unsafe extern "C" fn rax_jit_write_control(
    state: *mut GuestRegs,
    control: u64,
    value: u64,
) -> u64 {
    if !matches!(control, 0 | 2 | 3 | 4 | 8) {
        return 0;
    }
    // SAFETY: the native caller exclusively owns this aligned, initialized
    // frame for the synchronous callback and does not retain a Rust alias.
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    // Real-address mode permits MOV-to-CR. Protected, compatibility, and
    // 64-bit execution require effective CPL0; GuestRegs.cpl maps VM86 to 3.
    if state.cr0 & 1 != 0 && state.cpl != 0 {
        return 0;
    }
    let Ok(effect) = validate_x86_control_write(
        control as u8,
        value,
        X86ControlWriteState {
            cr0: state.cr0,
            cr3: state.cr3,
            cr4: state.cr4,
            efer: state.efer,
            cs_l: state.cs_l != 0,
            tr_type: state.tr_type as u8,
        },
    ) else {
        return 0;
    };

    // Resolve every fallible runtime dependency before committing state.
    let vcpu = if effect.flush_tlb || (control == 8 && state.ctx != 0) {
        // SAFETY: a nonzero ctx names the owning live CPU; the frame is a
        // separate stack allocation. This synchronous callback exclusively
        // accesses its MMU and retains no reference after returning.
        let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
            return 0;
        };
        Some(vcpu)
    } else {
        None
    };

    if control == 8 {
        if let Some(vcpu) = vcpu.as_ref() {
            if vcpu
                .mmu
                .set_task_priority((effect.value << 4) as u32)
                .is_err()
            {
                return 0;
            }
        }
    }
    match control {
        0 => state.cr0 = effect.value,
        2 => state.cr2 = effect.value,
        3 => state.cr3 = effect.value,
        4 => state.cr4 = effect.value,
        8 => state.cr8 = effect.value,
        _ => unreachable!("validated control selector changed"),
    }
    state.efer = effect.efer;
    if effect.flush_tlb {
        if let Some(vcpu) = vcpu {
            vcpu.mmu.flush_tlb();
        }
    }
    1
}

/// Return CR8+1, reserving zero for a non-committing runtime binding failure.
///
/// # Safety
/// `state` is the live frame and a nonzero ctx is its owning live CPU address.
pub(super) unsafe extern "C" fn rax_jit_read_cr8(state: *mut GuestRegs) -> u64 {
    // SAFETY: the native entry owns this live, aligned frame exclusively for
    // the synchronous callback; no Rust alias accesses it during native entry.
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if state.ctx == 0 {
        return (state.cr8 & 15) + 1;
    }
    // SAFETY: the caller-provided ctx is the owning live CPU and the frame is
    // a separate stack allocation. The callback only reads its stable MMU
    // binding/atomic priority and does not retain either reference.
    let Some(cpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_ref() }) else {
        return 0;
    };
    match cpu.mmu.task_priority() {
        Ok(tpr) => u64::from((tpr >> 4) & 15) + 1,
        Err(_) => 0,
    }
}
