//! x87 FPU instruction implementations.

mod escape_d8;
mod escape_d9;
mod escape_da;
mod escape_db;
mod escape_dc;
mod escape_dd;
mod escape_de;
mod escape_df;
pub mod helpers;

// Re-export escape functions
pub use escape_d8::escape_d8;
pub use escape_d9::escape_d9;
pub use escape_da::escape_da;
pub use escape_db::escape_db;
pub use escape_dc::escape_dc;
pub use escape_dd::escape_dd;
pub use escape_de::escape_de;
pub use escape_df::escape_df;

// Re-export public helper functions
pub use helpers::{f64_to_f80_pub, f80_to_f64_pub};

const CR0_EM: u64 = 1 << 2;
const CR0_NE: u64 = 1 << 5;
const CR0_TS: u64 = 1 << 3;
const FSW_ES: u16 = 1 << 7;
const FSW_B: u16 = 1 << 15;
const FSW_C1: u16 = 1 << 9;
const FSW_IE: u16 = 1;
const FSW_SF: u16 = 1 << 6;

/// Deliver x87 device-not-available before a decoded instruction observes or
/// commits architectural state. Encoding and LOCK/REX2 validity are resolved
/// by the caller and common decoder first, preserving #UD priority.
fn require_x87_available(
    vcpu: &mut crate::isa::x86_64::cpu::X86_64Vcpu,
) -> crate::error::Result<bool> {
    if vcpu.sregs.cr0 & (CR0_EM | CR0_TS) != 0 {
        vcpu.inject_exception(7, None)?;
        return Ok(false);
    }
    Ok(true)
}

/// Deliver the two pre-execution faults shared by waiting x87 operations.
/// Device-not-available has priority over a pending floating-point error.
fn require_waiting_x87_available(
    vcpu: &mut crate::isa::x86_64::cpu::X86_64Vcpu,
) -> crate::error::Result<bool> {
    if !require_x87_available(vcpu)? {
        return Ok(false);
    }
    if vcpu.sregs.cr0 & CR0_NE != 0 && vcpu.fpu.status_word & FSW_ES != 0 {
        vcpu.inject_exception(16, None)?;
        return Ok(false);
    }
    Ok(true)
}

/// Record the deterministic profile's successful x87 non-control instruction
/// provenance. Faulting waiting instructions call this only after all guards.
fn record_x87_data_op(vcpu: &mut crate::isa::x86_64::cpu::X86_64Vcpu, fop: u16) {
    vcpu.fpu.instr_ptr = vcpu.regs.rip;
    vcpu.fpu.last_opcode = fop & 0x07FF;
}

/// Record one x87 stack underflow and report whether FCW.IM selects the masked
/// response. An unmasked response leaves the operand/tag untouched while B/ES
/// become pending for precise delivery by a later waiting instruction.
fn signal_x87_stack_underflow(vcpu: &mut crate::isa::x86_64::cpu::X86_64Vcpu) -> bool {
    vcpu.fpu.status_word = (vcpu.fpu.status_word | FSW_IE | FSW_SF) & !FSW_C1;
    let masked = vcpu.fpu.control_word & 1 != 0;
    if !masked {
        vcpu.fpu.status_word |= FSW_B | FSW_ES;
    }
    masked
}

/// Copy the physical payload/tag selected before any pop. The caller has
/// completed encoding and waiting-instruction checks. In particular, FSTP
/// ST(0) must leave its old physical slot empty, including masked underflow.
fn store_x87_register(vcpu: &mut crate::isa::x86_64::cpu::X86_64Vcpu, st: u8, pop: bool, fop: u16) {
    let source = vcpu.fpu.st_index(0);
    let destination = vcpu.fpu.st_index(st);
    let source_shift = (source as u16) * 2;
    let destination_shift = (destination as u16) * 2;
    let tag = (vcpu.fpu.tag_word >> source_shift) & 3;
    let (payload, tag) = if tag == 3 {
        if !signal_x87_stack_underflow(vcpu) {
            record_x87_data_op(vcpu, fop);
            return;
        }
        (f64::from_bits(0xFFF8_0000_0000_0000), 2)
    } else {
        vcpu.fpu.status_word &= !FSW_C1;
        (vcpu.fpu.st[source], tag)
    };
    vcpu.fpu.st[destination] = payload;
    vcpu.fpu.tag_word =
        (vcpu.fpu.tag_word & !(3 << destination_shift)) | (tag << destination_shift);
    if pop {
        vcpu.fpu.tag_word |= 3 << source_shift;
        vcpu.fpu.top = (vcpu.fpu.top + 1) & 7;
        vcpu.fpu.status_word = (vcpu.fpu.status_word & !0x3800) | (u16::from(vcpu.fpu.top) << 11);
    }
    record_x87_data_op(vcpu, fop);
}
