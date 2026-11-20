//! String instructions: MOVS, STOS, LODS, SCAS, CMPS with REP prefix support.

mod cmps;
mod lods;
mod movs;
mod scas;
mod stos;

use crate::error::Result;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::flags;

// Re-export all instruction functions
pub use cmps::*;
pub use lods::*;
pub use movs::*;
pub use scas::*;
pub use stos::*;

// ---------------------------------------------------------------------------
// Address-size helpers, shared by all string instructions.
//
// In 64-bit mode (CS.L=1) a 0x67 prefix selects 32-bit addressing: the index
// registers (RSI/RDI) and the REP counter (RCX) are used as the 32-bit
// ESI/EDI/ECX. The effective offset is the low 32 bits, and any write back to
// an index/counter register clears the upper 32 bits (just like writing a
// 32-bit GPR). Outside 64-bit mode, CS.DB selects the default 16-bit or 32-bit
// address size and 0x67 toggles it. 16-bit index/counter updates touch only
// SI/DI/CX and preserve the rest of the host-visible 64-bit register value.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StringAddressSize {
    Addr16,
    Addr32,
    Addr64,
}

#[inline(always)]
pub(super) fn address_size(vcpu: &X86_64Vcpu, ctx: &InsnContext) -> StringAddressSize {
    let in_long_mode = (vcpu.sregs.efer & 0x400) != 0;
    let in_64bit_mode = in_long_mode && vcpu.sregs.cs.l;

    if in_64bit_mode {
        if ctx.address_size_override {
            StringAddressSize::Addr32
        } else {
            StringAddressSize::Addr64
        }
    } else {
        let default_16bit = !vcpu.sregs.cs.db;
        let is_16bit = default_16bit ^ ctx.address_size_override;
        if is_16bit {
            StringAddressSize::Addr16
        } else {
            StringAddressSize::Addr32
        }
    }
}

/// Effective address offset contributed by an index register (RSI/RDI):
/// the low 16, low 32, or full 64 bits according to address size.
#[inline(always)]
pub(super) fn index(reg: u64, addr_size: StringAddressSize) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 => reg & 0xffff,
        StringAddressSize::Addr32 => reg & 0xffff_ffff,
        StringAddressSize::Addr64 => reg,
    }
}

/// Normalize an index register when a zero-count REP string instruction
/// retires without advancing. This preserves the established 32-bit
/// zero-extension behavior while leaving 16-bit and 64-bit values untouched.
#[inline(always)]
pub(super) fn normalize_index(reg: u64, addr_size: StringAddressSize) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 | StringAddressSize::Addr64 => reg,
        StringAddressSize::Addr32 => reg & 0xffff_ffff,
    }
}

/// Advance an index register by `delta`, honoring DF (forward => add) and the
/// selected address size.
#[inline(always)]
pub(super) fn advance_index(
    reg: u64,
    delta: u64,
    forward: bool,
    addr_size: StringAddressSize,
) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 => {
            let cur = reg as u16;
            let next = if forward {
                cur.wrapping_add(delta as u16)
            } else {
                cur.wrapping_sub(delta as u16)
            };
            (reg & !0xffff) | u64::from(next)
        }
        StringAddressSize::Addr32 => {
            let cur = reg as u32;
            let next = if forward {
                cur.wrapping_add(delta as u32)
            } else {
                cur.wrapping_sub(delta as u32)
            };
            u64::from(next)
        }
        StringAddressSize::Addr64 => {
            if forward {
                reg.wrapping_add(delta)
            } else {
                reg.wrapping_sub(delta)
            }
        }
    }
}

/// REP iteration count from RCX, masked to the selected address size.
#[inline(always)]
pub(super) fn rep_count(rcx: u64, addr_size: StringAddressSize) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 => rcx & 0xffff,
        StringAddressSize::Addr32 => rcx & 0xffff_ffff,
        StringAddressSize::Addr64 => rcx,
    }
}

/// Normalize a REP counter for a zero-count instruction that does not advance.
#[inline(always)]
pub(super) fn normalize_count(rcx: u64, addr_size: StringAddressSize) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 | StringAddressSize::Addr64 => rcx,
        StringAddressSize::Addr32 => rcx & 0xffff_ffff,
    }
}

/// Decrement the REP counter using the selected address-size width.
#[inline(always)]
pub(super) fn dec_count(rcx: u64, addr_size: StringAddressSize) -> u64 {
    match addr_size {
        StringAddressSize::Addr16 => {
            let next = (rcx as u16).wrapping_sub(1);
            (rcx & !0xffff) | u64::from(next)
        }
        StringAddressSize::Addr32 => u64::from((rcx as u32).wrapping_sub(1)),
        StringAddressSize::Addr64 => rcx.wrapping_sub(1),
    }
}

fn finish_comparison(
    vcpu: &mut X86_64Vcpu,
    prefix: Option<u8>,
    addr_size: StringAddressSize,
    lhs: u64,
    rhs: u64,
    size: u8,
) -> Result<bool> {
    let repeat = prefix.is_some_and(|prefix| {
        vcpu.regs.rcx = dec_count(vcpu.regs.rcx, addr_size);
        let condition = match prefix {
            0xf2 => lhs != rhs,
            0xf3 => lhs == rhs,
            _ => true,
        };
        condition && rep_count(vcpu.regs.rcx, addr_size) != 0
    });
    // Faults on later elements keep the entry flags. Retain the existing
    // intermediate user single-step trap boundary when one is requested.
    if !repeat || vcpu.user_single_step_enabled() {
        flags::update_flags_sub(&mut vcpu.regs.rflags, lhs, rhs, lhs.wrapping_sub(rhs), size);
        vcpu.clear_lazy_flags();
    }
    if repeat {
        vcpu.user_repeat_step_trap()?;
    }
    Ok(repeat)
}
