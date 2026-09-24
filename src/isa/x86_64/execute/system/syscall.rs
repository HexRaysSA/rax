//! SYSCALL/SYSRET instruction support.

use crate::error::{Error, Result};
use crate::vm::vcpu::{Segment, VcpuExit};

use super::control_regs::raise_gp0;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::user_mode::{X86SyscallInsn, X86UserTrap};

const EFER_SCE: u64 = 1 << 0;
const EFER_LMA: u64 = 1 << 10;
const SYSRET_RFLAGS_MASK: u64 = 0x3C7FD7;

#[inline(always)]
fn is_canonical_48(addr: u64) -> bool {
    ((addr as i64) << 16 >> 16) as u64 == addr
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

/// SYSCALL (0x0F 0x05)
pub fn syscall(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let in_long_mode = (vcpu.sregs.efer & EFER_LMA) != 0 && vcpu.sregs.cs.l;
    if !in_long_mode || (vcpu.sregs.efer & EFER_SCE) == 0 {
        return vcpu.inject_undefined_instruction();
    }

    // Optional fork/clone/vfork tracing — opt-in via RAX_TRACE_FORK so it does
    // not spam the guest console (the env read is cached after first use).
    {
        use std::sync::OnceLock;
        static TRACE_FORK: OnceLock<bool> = OnceLock::new();
        if *TRACE_FORK.get_or_init(|| std::env::var_os("RAX_TRACE_FORK").is_some()) {
            let syscall_nr = vcpu.regs.rax;
            if syscall_nr == 56 || syscall_nr == 57 || syscall_nr == 58 || syscall_nr == 435 {
                // 56=clone, 57=fork, 58=vfork, 435=clone3
                eprintln!(
                    "[FORK/CLONE] syscall={} (clone=56,fork=57,vfork=58,clone3=435) RIP={:#x}",
                    syscall_nr, vcpu.regs.rip
                );
            }
        }
    }

    // Materialize any pending lazy flags BEFORE snapshotting RFLAGS into R11, or
    // the saved (and later SYSRET-restored) flags would be stale. This also
    // clears the lazy-op so the kernel entry starts from authoritative RFLAGS.
    // (Same lazy-flags-staleness class as the IRET fix.)
    vcpu.materialize_flags();
    let next_rip = vcpu.regs.rip + ctx.cursor as u64;
    vcpu.regs.rcx = next_rip;
    vcpu.regs.r11 = vcpu.regs.rflags;

    // User mode: the embedder services the call. Leave the vCPU in the state
    // the handler's SYSRET would restore (RIP = RCX, RFLAGS from R11 through
    // the SYSRET mask) and report the trap.
    if vcpu.user_mode_enabled() {
        let insn_rip = vcpu.regs.rip;
        vcpu.regs.rflags = (vcpu.regs.r11 & SYSRET_RFLAGS_MASK) | 0x2;
        vcpu.regs.rip = next_rip;
        vcpu.record_user_trap(X86UserTrap::SystemCall {
            insn: X86SyscallInsn::Syscall,
            insn_rip,
        });
        return Ok(Some(VcpuExit::SystemCall));
    }

    vcpu.regs.rflags &= !vcpu.sregs.fmask;

    let star = vcpu.sregs.star;
    let cs_selector = ((star >> 32) as u16) & 0xFFFC;
    let ss_selector = cs_selector.wrapping_add(8);
    vcpu.sregs.cs = build_cs(cs_selector, 0, true, false);
    vcpu.sregs.ss = build_ss(ss_selector, 0);

    vcpu.regs.rip = vcpu.sregs.lstar;
    Ok(None)
}

/// SYSRET (0x0F 0x07)
pub fn sysret(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let in_long_mode = (vcpu.sregs.efer & EFER_LMA) != 0 && vcpu.sregs.cs.l;
    if !in_long_mode || (vcpu.sregs.efer & EFER_SCE) == 0 {
        return vcpu.inject_undefined_instruction();
    }

    // SDM Vol. 2B SYSRET operation: #GP(0) when CPL != 0, checked after the
    // #UD conditions and before RCX canonicality.
    let cpl = (vcpu.sregs.cs.selector & 0x3) as u8;
    if cpl != 0 {
        return raise_gp0(vcpu);
    }

    let is_64 = ctx.rex_w();

    let new_rip = if is_64 {
        vcpu.regs.rcx
    } else {
        (vcpu.regs.rcx as u32) as u64
    };
    if is_64 && !is_canonical_48(new_rip) {
        return raise_gp0(vcpu);
    }

    vcpu.regs.rip = new_rip;
    vcpu.regs.rflags = (vcpu.regs.r11 & SYSRET_RFLAGS_MASK) | 0x2;
    // RFLAGS is restored wholesale from R11; discard any pending lazy-flags op so
    // the kernel's last ALU result does not leak into user-mode flag evaluation.
    vcpu.clear_lazy_flags();

    let star = vcpu.sregs.star;
    let base_selector = (star >> 48) as u16;
    let cs_selector = if is_64 {
        base_selector.wrapping_add(16)
    } else {
        base_selector
    } | 0x3;
    let ss_selector = base_selector.wrapping_add(8) | 0x3;
    vcpu.sregs.cs = build_cs(cs_selector, 3, is_64, !is_64);
    vcpu.sregs.ss = build_ss(ss_selector, 3);
    Ok(None)
}
