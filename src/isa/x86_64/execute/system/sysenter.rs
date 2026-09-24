//! SYSENTER/SYSEXIT instructions.

use crate::error::Result;
use crate::vm::vcpu::{Segment, VcpuExit};

use super::control_regs::{current_cpl, raise_gp0};
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

const CR0_PE: u64 = 1 << 0;
const EFER_LMA: u64 = 1 << 10;

/// Architectural inputs shared by Intel SYSENTER and SYSEXIT.
///
/// RAX exposes the `GenuineIntel` CPUID profile and does not expose LA57 or
/// CET. Consequently, 64-bit targets use 48-bit paging canonicality and the
/// CET shadow-stack/IBT state transitions are inapplicable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86FastSystemTransferState {
    pub cr0: u64,
    pub efer: u64,
    /// Effective CPL; virtual-8086 mode is represented as CPL3.
    pub cpl: u8,
    pub rflags: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub rcx: u64,
    pub rdx: u64,
}

/// Complete state committed by a successful fast system transfer. Segment
/// descriptor caches are fixed by the instruction and are reconstructed from
/// `cpl`, `cs_long`, and `cs_default_big` by each execution plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86FastSystemTransferEffect {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs_selector: u16,
    pub ss_selector: u16,
    pub cpl: u8,
    pub cs_long: bool,
    pub cs_default_big: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86FastSystemTransferFault {
    GeneralProtection,
}

/// Evaluate Intel SYSENTER without committing any state.
pub(crate) fn evaluate_x86_sysenter(
    state: X86FastSystemTransferState,
) -> core::result::Result<X86FastSystemTransferEffect, X86FastSystemTransferFault> {
    let cs_selector = (state.sysenter_cs as u16) & 0xFFFC;
    if state.cr0 & CR0_PE == 0 || cs_selector == 0 {
        return Err(X86FastSystemTransferFault::GeneralProtection);
    }

    let ia32e_active = state.efer & EFER_LMA != 0;
    let (rip, rsp) = if ia32e_active {
        // Architectural WRMSR validation normally makes these invariants. The
        // explicit checks keep externally supplied SMIR/vCPU state precise and
        // match this emulator's fixed four-level paging model.
        if !super::msr::is_canonical_48(state.sysenter_eip)
            || !super::msr::is_canonical_48(state.sysenter_esp)
        {
            return Err(X86FastSystemTransferFault::GeneralProtection);
        }
        (state.sysenter_eip, state.sysenter_esp)
    } else {
        (
            u64::from(state.sysenter_eip as u32),
            u64::from(state.sysenter_esp as u32),
        )
    };

    Ok(X86FastSystemTransferEffect {
        rip,
        rsp,
        rflags: state.rflags & !(flags::bits::VM | flags::bits::IF),
        cs_selector,
        ss_selector: cs_selector.wrapping_add(8),
        cpl: 0,
        cs_long: ia32e_active,
        cs_default_big: !ia32e_active,
    })
}

/// Evaluate Intel SYSEXIT without committing any state. `operand64` is true
/// only for the REX.W form decoded in 64-bit mode.
pub(crate) fn evaluate_x86_sysexit(
    state: X86FastSystemTransferState,
    operand64: bool,
) -> core::result::Result<X86FastSystemTransferEffect, X86FastSystemTransferFault> {
    let cs_base = (state.sysenter_cs as u16) & 0xFFFC;
    if state.cr0 & CR0_PE == 0 || cs_base == 0 || state.cpl != 0 {
        return Err(X86FastSystemTransferFault::GeneralProtection);
    }

    let (rip, rsp) = if operand64 {
        if !super::msr::is_canonical_48(state.rdx) || !super::msr::is_canonical_48(state.rcx) {
            return Err(X86FastSystemTransferFault::GeneralProtection);
        }
        (state.rdx, state.rcx)
    } else {
        (u64::from(state.rdx as u32), u64::from(state.rcx as u32))
    };

    let cs_selector = cs_base.wrapping_add(if operand64 { 32 } else { 16 }) | 3;
    Ok(X86FastSystemTransferEffect {
        rip,
        rsp,
        rflags: state.rflags,
        cs_selector,
        ss_selector: cs_selector.wrapping_add(8),
        cpl: 3,
        cs_long: operand64,
        cs_default_big: !operand64,
    })
}

fn build_cs(selector: u16, dpl: u8, l: bool, db: bool) -> Segment {
    Segment {
        base: 0,
        limit: 0xFFFFF,
        selector,
        type_: 0x0B, // Execute/Read, accessed
        present: true,
        dpl,
        db,
        s: true,
        l,
        g: true,
        avl: false,
        unusable: false,
    }
}

fn build_ss(selector: u16, dpl: u8) -> Segment {
    Segment {
        base: 0,
        limit: 0xFFFFF,
        selector,
        type_: 0x03, // Read/Write, accessed
        present: true,
        dpl,
        db: true,
        s: true,
        l: false,
        g: true,
        avl: false,
        unusable: false,
    }
}

/// Commit the fixed CS/SS cache image shared by direct and helper-backed
/// native execution. GPR, RIP, and RFLAGS commits remain execution-plane local
/// so a native helper never overwrites status flags still resident in host
/// RFLAGS.
pub(crate) fn commit_x86_fast_system_transfer_segments(
    vcpu: &mut X86_64Vcpu,
    effect: X86FastSystemTransferEffect,
) {
    vcpu.sregs.cs = build_cs(
        effect.cs_selector,
        effect.cpl,
        effect.cs_long,
        effect.cs_default_big,
    );
    vcpu.sregs.ss = build_ss(effect.ss_selector, effect.cpl);
}

fn transfer_state(vcpu: &X86_64Vcpu) -> X86FastSystemTransferState {
    X86FastSystemTransferState {
        cr0: vcpu.sregs.cr0,
        efer: vcpu.sregs.efer,
        cpl: current_cpl(vcpu),
        rflags: vcpu.regs.rflags,
        sysenter_cs: vcpu.sregs.sysenter_cs,
        sysenter_esp: vcpu.sregs.sysenter_esp,
        sysenter_eip: vcpu.sregs.sysenter_eip,
        rcx: vcpu.regs.rcx,
        rdx: vcpu.regs.rdx,
    }
}

fn commit_direct_transfer(vcpu: &mut X86_64Vcpu, effect: X86FastSystemTransferEffect) {
    vcpu.regs.rsp = effect.rsp;
    vcpu.regs.rip = effect.rip;
    vcpu.regs.rflags = effect.rflags;
    commit_x86_fast_system_transfer_segments(vcpu, effect);
}

/// SYSENTER (0x0F 0x34)
pub fn sysenter(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    // User mode: the embedder applies its own SYSENTER ABI. No register is
    // modified; RIP moves past the instruction.
    if vcpu.user_mode_enabled() {
        let insn_rip = vcpu.regs.rip;
        vcpu.regs.rip = insn_rip.wrapping_add(ctx.cursor as u64);
        vcpu.record_user_trap(crate::isa::x86_64::user_mode::X86UserTrap::SystemCall {
            insn: crate::isa::x86_64::user_mode::X86SyscallInsn::Sysenter,
            insn_rip,
        });
        return Ok(Some(VcpuExit::SystemCall));
    }
    let effect = match evaluate_x86_sysenter(transfer_state(vcpu)) {
        Ok(effect) => effect,
        Err(X86FastSystemTransferFault::GeneralProtection) => return raise_gp0(vcpu),
    };
    commit_direct_transfer(vcpu, effect);
    Ok(None)
}

/// SYSEXIT (0x0F 0x35)
pub fn sysexit(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let effect = match evaluate_x86_sysexit(transfer_state(vcpu), ctx.rex_w()) {
        Ok(effect) => effect,
        Err(X86FastSystemTransferFault::GeneralProtection) => return raise_gp0(vcpu),
    };
    commit_direct_transfer(vcpu, effect);
    Ok(None)
}
