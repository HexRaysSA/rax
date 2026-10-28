//! Fault-precise helper-backed native x86 PUSHF/POPF transactions.

use super::jit_state::merge_native_rflags;
use super::{X86_64Vcpu, rax_jit_mem_store};
use crate::isa::x86_64::execute::system::{
    X86_INTERRUPT_CONTROL_RFLAGS_MASK, X86StackFlagsFault, X86StackFlagsState,
    evaluate_x86_pop_flags, evaluate_x86_push_flags, is_canonical_48,
    validate_x86_stack_flags_access,
};
use crate::isa::x86_64::flags;
use crate::smir::lower::runtime::GuestRegs;

const CR0_AM: u64 = 1 << 18;

fn canonical_range(address: u64, size: u32) -> bool {
    address
        .checked_add(u64::from(size) - 1)
        .is_some_and(|last| is_canonical_48(address) && is_canonical_48(last))
}

/// Execute one complete long-mode PUSHF/POPF transaction against ordinary
/// guest RAM. Zero requests exact direct replay. Every zero path leaves the
/// marshalled state, memory log, and access trace without an architectural
/// stack or flag commit.
pub(super) unsafe extern "C" fn rax_jit_stack_flags(
    state: *mut GuestRegs,
    kind: u32,
    width: u32,
    requires_apx: u32,
    native_rflags: u64,
) -> u64 {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if kind > 1
        || !matches!(width, 2 | 8)
        || requires_apx > 1
        || state.cpl > 3
        || state.efer & (1 << 10) == 0
        || state.cs_l == 0
        || state.stack_flags_rflags_valid != 0
        || (requires_apx != 0 && state.apx_enabled == 0)
    {
        return 0;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    if vcpu.sregs.efer & (1 << 10) == 0
        || !vcpu.sregs.cs.l
        || (requires_apx != 0 && !vcpu.apx_enabled())
    {
        return 0;
    }

    let current_rflags = merge_native_rflags(
        state.rflags,
        native_rflags,
        state.ac_flag != 0,
        state.interrupt_flags,
    );
    let architectural = X86StackFlagsState {
        cr0: state.cr0,
        cr4: state.cr4,
        rflags: current_rflags,
        cpl: state.cpl as u8,
    };
    if validate_x86_stack_flags_access(architectural, width as u8).is_err() {
        return 0;
    }

    let old_rsp = state.gpr[4];
    let address = if kind == 0 {
        old_rsp.wrapping_sub(u64::from(width))
    } else {
        old_rsp
    };
    if !canonical_range(address, width) {
        return 0;
    }
    if address & (u64::from(width) - 1) != 0
        && state.cr0 & CR0_AM != 0
        && state.ac_flag != 0
        && state.cpl == 3
    {
        return 0;
    }

    if kind == 0 {
        let Ok(image) = evaluate_x86_push_flags(architectural, width as u8) else {
            return 0;
        };
        let Some(last) = address.checked_add(u64::from(width) - 1) else {
            return 0;
        };
        if vcpu.mmu.is_code_page(address)
            || vcpu.mmu.is_code_page(last)
            || !vcpu
                .mmu
                .write_range_is_plain_ram(address, width as usize, &vcpu.sregs)
            || unsafe { rax_jit_mem_store(vcpu as *mut X86_64Vcpu, address, image, width) } == 0
        {
            return 0;
        }
        state.gpr[4] = address;
        return 1;
    }

    if !vcpu
        .mmu
        .read_range_is_plain_ram(address, width as usize, &vcpu.sregs)
    {
        return 0;
    }
    // Delay publication of the read trace until the post-read VME checks pass;
    // direct replay must be the sole traced execution on #GP(0).
    let staged_trace = vcpu.jit_mem_trace.take();
    let popped = match vcpu.read_mem(address, width as u8) {
        Ok(value) => value,
        Err(_) => {
            vcpu.jit_mem_trace = staged_trace;
            return 0;
        }
    };
    vcpu.jit_mem_trace = staged_trace;
    let new_rflags = match evaluate_x86_pop_flags(architectural, width as u8, popped) {
        Ok(rflags) => rflags,
        Err(X86StackFlagsFault::GeneralProtection | X86StackFlagsFault::InvalidWidth) => {
            return 0;
        }
    };
    if vcpu.user_mode_enabled() && new_rflags & flags::bits::TF != 0 {
        // Enabling TF must return to direct execution at this POPF, before
        // its stack/flag commit. Replay then arms the following instruction;
        // a native region must not execute past that new debug frontier.
        return 0;
    }
    vcpu.push_jit_mem_trace((0, address, width as u8, popped));

    state.gpr[4] = old_rsp.wrapping_add(u64::from(width));
    state.rflags = new_rflags & !flags::bits::AC;
    state.ac_flag = u64::from(new_rflags & flags::bits::AC != 0);
    state.interrupt_flags = new_rflags & X86_INTERRUPT_CONTROL_RFLAGS_MASK;
    state.stack_flags_rflags = new_rflags;
    state.stack_flags_rflags_valid = 1;
    1
}
