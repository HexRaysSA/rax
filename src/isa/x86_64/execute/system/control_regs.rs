//! Control register instructions: MOV r, CRn, MOV CRn, r, and Group 7.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};

const CR0_PE: u64 = 1 << 0;
const CR0_ET: u64 = 1 << 4;
const CR0_NW: u64 = 1 << 29;
const CR0_CD: u64 = 1 << 30;
const CR0_PG: u64 = 1 << 31;
const CR0_DEFINED_MASK: u64 = 0xE005_003F;
const CR0_HIGH_RESERVED_MASK: u64 = 0xFFFF_FFFF_0000_0000;
const CR4_DE: u64 = 1 << 3;
const CR4_PAE: u64 = 1 << 5;
const CR4_UMIP: u64 = 1 << 11;
const CR4_PCIDE: u64 = 1 << 17;
/// CR4 fields implemented by the deterministic CPUID/CPU profile.
///
/// Feature-dependent fields that this profile does not enumerate (VME/PVI,
/// MCE, LA57, VMX/SMX, Key Locker, SMEP, CET, PKS, UINTR, LASS, and LAM) are
/// architecturally reserved and therefore fault when software attempts to set
/// them. TSD, DE, PCE, and the enumerated paging/OS-support fields below have
/// corresponding direct semantics or architectural state in this emulator.
const CR4_SUPPORTED_MASK: u64 = (1 << 2)
    | CR4_DE
    | (1 << 4)
    | CR4_PAE
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | CR4_UMIP
    | (1 << 16)
    | CR4_PCIDE
    | (1 << 18)
    | (1 << 21)
    | (1 << 22);
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const PHYSICAL_ADDRESS_BITS: u32 = 48;
const DR6_BD: u64 = 1 << 13;
const DR7_GD: u64 = 1 << 13;

/// Architectural state required to validate one MOV-to-control-register
/// candidate without committing any part of the write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86ControlWriteState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub cs_l: bool,
    /// Low four bits of the current task-register descriptor type. Values 1
    /// and 3 identify available/busy 16-bit TSS descriptors.
    pub tr_type: u8,
}

/// Fully validated, normalized result of one MOV-to-control-register write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86ControlWriteEffect {
    pub value: u64,
    pub efer: u64,
    pub flush_tlb: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86ControlWriteFault {
    GeneralProtection,
}

/// Validate and normalize the value written by `MOV CRn, r32/r64`.
///
/// This function is deliberately pure: direct execution, standalone SMIR
/// interpretation, and the native helper all use the same non-committing
/// decision. Selector/decode validity and CPL checks occur before this helper.
pub(crate) fn validate_x86_control_write(
    control: u8,
    value: u64,
    state: X86ControlWriteState,
) -> core::result::Result<X86ControlWriteEffect, X86ControlWriteFault> {
    let gp = || Err(X86ControlWriteFault::GeneralProtection);

    match control {
        0 => {
            if value & CR0_HIGH_RESERVED_MASK != 0 {
                return gp();
            }

            // Intel ignores writes to reserved CR0[31:0] fields. ET is fixed
            // at one on this processor profile, including when software writes
            // it as zero.
            let normalized = (value & CR0_DEFINED_MASK) | CR0_ET;
            if normalized & CR0_PG != 0 && normalized & CR0_PE == 0 {
                return gp();
            }
            if normalized & CR0_NW != 0 && normalized & CR0_CD == 0 {
                return gp();
            }

            let old_pg = state.cr0 & CR0_PG != 0;
            let new_pg = normalized & CR0_PG != 0;
            let mut efer = state.efer;

            // Enabling paging while LME is set activates IA-32e mode only from
            // a non-64-bit code segment, with PAE enabled and a non-16-bit TSS.
            if !old_pg && new_pg && efer & EFER_LME != 0 && efer & EFER_LMA == 0 {
                if state.cr4 & CR4_PAE == 0 || state.cs_l || matches!(state.tr_type & 0x0F, 1 | 3) {
                    return gp();
                }
                efer |= EFER_LMA;
            }

            // Paging cannot be disabled from 64-bit code or while PCIDs are
            // enabled. Compatibility-mode software may leave IA-32e mode; LMA
            // is then cleared by the processor rather than by software.
            if old_pg && !new_pg && efer & EFER_LMA != 0 {
                if state.cs_l || state.cr4 & CR4_PCIDE != 0 {
                    return gp();
                }
                efer &= !EFER_LMA;
            }

            Ok(X86ControlWriteEffect {
                value: normalized,
                efer,
                flush_tlb: true,
            })
        }
        2 => Ok(X86ControlWriteEffect {
            value,
            efer: state.efer,
            flush_tlb: false,
        }),
        3 => {
            let pcide = state.cr4 & CR4_PCIDE != 0;
            let no_flush = value & (1 << 63) != 0;
            let high_reserved_mask =
                ((1u64 << (63 - PHYSICAL_ADDRESS_BITS)) - 1) << PHYSICAL_ADDRESS_BITS;
            if value & high_reserved_mask != 0 || (no_flush && !pcide) {
                return gp();
            }

            let address_mask = (1u64 << PHYSICAL_ADDRESS_BITS) - 1;
            let normalized = if pcide {
                value & address_mask
            } else {
                // Without PCIDs, PWT/PCD are the only stored low CR3 bits;
                // attempts to set bits 2:0 and 11:5 are ignored.
                value & (address_mask & !0xFFF | 0x18)
            };
            Ok(X86ControlWriteEffect {
                value: normalized,
                efer: state.efer,
                // Retaining translations is only a performance hint. Eager
                // eviction remains architecturally invisible and keeps the
                // emulator's untagged software TLB coherent.
                flush_tlb: true,
            })
        }
        4 => {
            if value & !CR4_SUPPORTED_MASK != 0 {
                return gp();
            }
            if state.efer & EFER_LMA != 0 && value & CR4_PAE == 0 {
                return gp();
            }
            if value & CR4_PCIDE != 0 && state.cr4 & CR4_PCIDE == 0 {
                if state.efer & EFER_LMA == 0 || state.cr3 & 0xFFF != 0 {
                    return gp();
                }
            }
            Ok(X86ControlWriteEffect {
                value,
                efer: state.efer,
                flush_tlb: true,
            })
        }
        8 => {
            if value & !0xF != 0 {
                return gp();
            }
            Ok(X86ControlWriteEffect {
                value,
                efer: state.efer,
                flush_tlb: false,
            })
        }
        _ => unreachable!("control selector must be decode-validated"),
    }
}

/// Current Privilege Level of the executing code.
///
/// The CPL is the low two bits of the CS selector in protected mode, except
/// that virtual-8086 mode always executes with effective CPL 3. In real mode
/// (CR0.PE=0) there is no privilege concept and the processor effectively runs
/// as ring 0; many rax test fixtures also leave CS unset (selector 0) while
/// exercising privileged instructions, so a non-protected-mode vCPU must be
/// treated as CPL 0 to avoid spurious faults.
#[inline]
pub(super) fn current_cpl(vcpu: &X86_64Vcpu) -> u8 {
    // CR0.PE (bit 0) distinguishes protected mode from real mode.
    if vcpu.sregs.cr0 & 1 == 0 {
        return 0;
    }
    // RFLAGS.VM (bit 17) identifies virtual-8086 mode. CS.RPL is not an
    // authoritative privilege indicator there.
    if vcpu.regs.rflags & (1 << 17) != 0 {
        return 3;
    }
    (vcpu.sregs.cs.selector & 0x3) as u8
}

/// Returns true if the current code is privileged (CPL == 0).
#[inline]
pub(super) fn is_cpl0(vcpu: &X86_64Vcpu) -> bool {
    current_cpl(vcpu) == 0
}

#[inline]
pub(super) fn umip_blocks_user_instruction(vcpu: &X86_64Vcpu) -> bool {
    vcpu.sregs.cr4 & CR4_UMIP != 0 && current_cpl(vcpu) > 0
}

fn write_descriptor_table(vcpu: &mut X86_64Vcpu, addr: u64, limit: u16, base: u64) -> Result<()> {
    vcpu.write_descriptor_table_mem(addr, limit, base)
}

/// Inject a #GP(0) (General Protection fault, vector 13, error code 0).
///
/// Exception delivery sets RIP to the fault handler, so callers MUST return
/// without advancing RIP past the faulting instruction.
#[inline]
pub(super) fn raise_gp0(vcpu: &mut X86_64Vcpu) -> Result<Option<VcpuExit>> {
    vcpu.inject_exception(13, Some(0))?;
    Ok(None)
}

/// Raise the fault-class #DB caused by DR7.GD on a debug-register access.
///
/// Intel specifies that DR6.BD is set before exception generation and that
/// DR7.GD is cleared upon entry to the #DB handler. Keep GD set if exception
/// delivery itself fails: no handler was entered in that case.
#[inline]
fn raise_debug_register_access(vcpu: &mut X86_64Vcpu) -> Result<Option<VcpuExit>> {
    vcpu.sregs.dr6 |= DR6_BD;
    vcpu.inject_exception(1, None)?;
    vcpu.sregs.dr7 &= !DR7_GD;
    Ok(None)
}

/// Group 7 - SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG, etc. (0x0F 0x01)
/// Note: Register-form (mod=11) instructions like MONITOR, MWAIT, SWAPGS are
/// handled in twobyte.rs dispatch before reaching this function.
pub fn group7(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm_start = ctx.cursor;
    let modrm = ctx.consume_u8()?;
    let reg_op = (modrm >> 3) & 0x07;

    match reg_op {
        // SGDT m16&64 - Store Global Descriptor Table
        0 => {
            if modrm >> 6 == 3 {
                return vcpu.inject_undefined_instruction();
            }
            if umip_blocks_user_instruction(vcpu) {
                return raise_gp0(vcpu);
            }
            let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            write_descriptor_table(vcpu, addr, vcpu.sregs.gdt.limit, vcpu.sregs.gdt.base)?;
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // SIDT m16&64 - Store Interrupt Descriptor Table
        1 => {
            if modrm >> 6 == 3 {
                return vcpu.inject_undefined_instruction();
            }
            if umip_blocks_user_instruction(vcpu) {
                return raise_gp0(vcpu);
            }
            let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            write_descriptor_table(vcpu, addr, vcpu.sregs.idt.limit, vcpu.sregs.idt.base)?;
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // LGDT m16&64
        2 => {
            // Privileged: loading the GDTR requires CPL 0.
            if !is_cpl0(vcpu) {
                return raise_gp0(vcpu);
            }
            if modrm >> 6 == 3 {
                return vcpu.inject_undefined_instruction();
            }
            let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            let (limit, base) = vcpu.read_descriptor_table_mem(addr, ctx.op_size)?;
            vcpu.sregs.gdt.limit = limit;
            vcpu.sregs.gdt.base = base;
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // LIDT m16&64
        3 => {
            // Privileged: loading the IDTR requires CPL 0.
            if !is_cpl0(vcpu) {
                return raise_gp0(vcpu);
            }
            if modrm >> 6 == 3 {
                return vcpu.inject_undefined_instruction();
            }
            let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            let (limit, base) = vcpu.read_descriptor_table_mem(addr, ctx.op_size)?;
            vcpu.sregs.idt.limit = limit;
            vcpu.sregs.idt.base = base;
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // SMSW r16/r32/r64 or m16 - Store Machine Status Word from CR0
        4 => {
            if umip_blocks_user_instruction(vcpu) {
                return raise_gp0(vcpu);
            }
            let rm = (modrm & 0x07) | ctx.any_rex_b();
            let is_memory = modrm >> 6 != 3;
            if is_memory {
                let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
                ctx.cursor = modrm_start + 1 + extra;
                vcpu.mmu
                    .write_u16(addr, (vcpu.sregs.cr0 & 0xFFFF) as u16, &vcpu.sregs)?;
            } else {
                let value = match ctx.op_size {
                    2 => vcpu.sregs.cr0 & 0xFFFF,
                    4 => vcpu.sregs.cr0 & 0xFFFF_FFFF,
                    8 => vcpu.sregs.cr0,
                    _ => unreachable!(),
                };
                vcpu.set_reg(rm, value, ctx.op_size);
            }
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // LMSW r/m16 - replace CR0[3:0] from a fixed 16-bit source.
        6 => {
            if !is_cpl0(vcpu) {
                return raise_gp0(vcpu);
            }
            let rm = (modrm & 0x07) | ctx.any_rex_b();
            let is_memory = modrm >> 6 != 3;
            let msw = if is_memory {
                let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
                ctx.cursor = modrm_start + 1 + extra;
                vcpu.mmu.read_u16(addr, &vcpu.sregs)?
            } else {
                vcpu.get_reg(rm, 2) as u16
            };
            // LMSW can set PE (bit 0) but cannot clear it
            // It only affects bits 0-3 of CR0
            let mask = 0x000F_u64;
            let old_pe = vcpu.sregs.cr0 & 1;
            vcpu.sregs.cr0 = (vcpu.sregs.cr0 & !mask) | ((msw as u64) & mask) | old_pe;
            vcpu.regs.rip += ctx.cursor as u64;
        }
        // INVLPG m (reg_op=7 with memory operand)
        // Note: SWAPGS (F8) and RDTSCP (F9) are handled in twobyte.rs
        7 => {
            if modrm >> 6 == 3 {
                return vcpu.inject_undefined_instruction();
            }
            if !is_cpl0(vcpu) {
                return raise_gp0(vcpu);
            }
            let (addr, extra) = vcpu.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;
            // In 64-bit mode Intel defines a non-canonical address as a
            // successful NOP. Compatibility mode follows protected-mode
            // behavior; its ordinary 32-bit offsets are already canonical.
            if !vcpu.sregs.cs.l || super::is_canonical_48(addr) {
                vcpu.invalidate_linear_translation(addr);
            }
            vcpu.regs.rip += ctx.cursor as u64;
        }
        _ => {
            return vcpu.inject_undefined_instruction();
        }
    }
    Ok(None)
}

/// CLTS - Clear Task-Switched Flag in CR0 (0x0F 0x06)
pub fn clts(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    // Real-address mode is explicitly permitted. Protected, compatibility,
    // and 64-bit modes require CPL0; virtual-8086 mode has effective CPL3.
    if !is_cpl0(vcpu) {
        return raise_gp0(vcpu);
    }
    vcpu.sregs.cr0 &= !(1u64 << 3);
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r32/r64, CRn (0x0F 0x20)
pub fn mov_r_cr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    // REX2.R4/R3 extend the control-register selector, while REX2.B4/B3
    // extend the GPR operand through R31. Nonexistent CR selectors #UD before
    // privilege checks or any destination commit.
    let cr = ((modrm >> 3) & 0x07) | ctx.any_rex_r();
    let rm = (modrm & 0x07) | ctx.any_rex_b();
    if !matches!(cr, 0 | 2 | 3 | 4 | 8) || (cr == 8 && !vcpu.sregs.cs.l) {
        return vcpu.inject_undefined_instruction();
    }
    // Real-address mode is permitted. Protected, compatibility, and 64-bit
    // modes require CPL0; virtual-8086 mode has effective CPL3.
    if !is_cpl0(vcpu) {
        return raise_gp0(vcpu);
    }
    let value = match cr {
        0 => vcpu.sregs.cr0,
        2 => vcpu.sregs.cr2,
        3 => vcpu.sregs.cr3,
        4 => vcpu.sregs.cr4,
        8 => u64::from(vcpu.mmu.task_priority()? >> 4),
        _ => unreachable!("validated readable control register changed"),
    };
    // Outside 64-bit mode this instruction always has a 32-bit operand; 66H
    // is ignored. A 32-bit GPR write zero-extends in the canonical register
    // state, while 64-bit mode writes the complete r64 destination.
    vcpu.set_reg(rm, value, if vcpu.sregs.cs.l { 8 } else { 4 });
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV r32/r64, DRn (0x0F 0x21)
pub fn mov_r_dr(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    let dr = ((modrm >> 3) & 0x07) | ctx.any_rex_r();
    let rm = (modrm & 0x07) | ctx.any_rex_b();

    // Legacy REX.R and either REX2.R extension select nonexistent DR8-DR31.
    // This decode-time #UD precedes GD, DE, CPL, and destination effects.
    if dr >= 8 {
        return vcpu.inject_undefined_instruction();
    }

    // General detect protects every debug-register access and faults before
    // the MOV commits. DR6.BD is set before delivery; successful handler entry
    // clears DR7.GD so the handler can inspect the debug registers.
    if vcpu.sregs.dr7 & DR7_GD != 0 {
        return raise_debug_register_access(vcpu);
    }

    // DR4/DR5 are invalid when debug extensions are enabled. Otherwise they
    // retain the Intel386/Intel486 aliases to DR6/DR7.
    if matches!(dr, 4 | 5) && vcpu.sregs.cr4 & CR4_DE != 0 {
        return vcpu.inject_undefined_instruction();
    }

    // Real-address mode is permitted. Protected, compatibility, and 64-bit
    // modes require CPL0; virtual-8086 mode has effective CPL3.
    if !is_cpl0(vcpu) {
        return raise_gp0(vcpu);
    }

    let value = match dr {
        0 => vcpu.sregs.dr0,
        1 => vcpu.sregs.dr1,
        2 => vcpu.sregs.dr2,
        3 => vcpu.sregs.dr3,
        4 => vcpu.sregs.dr6,
        5 => vcpu.sregs.dr7,
        6 => vcpu.sregs.dr6,
        7 => vcpu.sregs.dr7,
        _ => unreachable!("three-bit debug-register selector changed"),
    };

    // Outside 64-bit mode the operand is always 32 bits and the 66H prefix is
    // ignored. Preserve the existing deterministic policy for the six status
    // flags that Intel documents as undefined.
    vcpu.set_reg(rm, value, if vcpu.sregs.cs.l { 8 } else { 4 });
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV DRn, r32/r64 (0x0F 0x23)
pub fn mov_dr_r(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    let dr = ((modrm >> 3) & 0x07) | ctx.any_rex_r();
    let rm = (modrm & 0x07) | ctx.any_rex_b();

    // Legacy REX.R and either REX2.R extension select nonexistent DR8-DR31.
    // This decode-time #UD precedes GD, DE, CPL, source reads, and writes.
    if dr >= 8 {
        return vcpu.inject_undefined_instruction();
    }

    // General detect protects every debug-register access and faults before
    // the MOV commits. DR6.BD is set before delivery; successful handler entry
    // clears DR7.GD so the handler can inspect the debug registers.
    if vcpu.sregs.dr7 & DR7_GD != 0 {
        return raise_debug_register_access(vcpu);
    }

    // DR4/DR5 are invalid when debug extensions are enabled. Otherwise they
    // retain the Intel386/Intel486 aliases to DR6/DR7.
    if matches!(dr, 4 | 5) && vcpu.sregs.cr4 & CR4_DE != 0 {
        return vcpu.inject_undefined_instruction();
    }

    // Real-address mode is permitted. Protected, compatibility, and 64-bit
    // modes require CPL0; virtual-8086 mode has effective CPL3.
    if !is_cpl0(vcpu) {
        return raise_gp0(vcpu);
    }

    // Outside 64-bit mode the source is always r32 and 66H is ignored. In
    // 64-bit mode, setting any high-half bit while writing effective DR6/DR7
    // raises #GP(0); DR4/DR5 inherit the rule through their legacy aliases.
    let value = vcpu.get_reg(rm, if vcpu.sregs.cs.l { 8 } else { 4 });
    if vcpu.sregs.cs.l && matches!(dr, 4..=7) && value >> 32 != 0 {
        return raise_gp0(vcpu);
    }

    match dr {
        0 => vcpu.sregs.dr0 = value,
        1 => vcpu.sregs.dr1 = value,
        2 => vcpu.sregs.dr2 = value,
        3 => vcpu.sregs.dr3 = value,
        4 | 5 => {
            if dr == 4 {
                vcpu.sregs.dr6 = value;
            } else {
                vcpu.sregs.dr7 = value;
            }
        }
        6 => vcpu.sregs.dr6 = value,
        7 => vcpu.sregs.dr7 = value,
        _ => unreachable!("three-bit debug-register selector changed"),
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

/// MOV CRn, r32/r64 (0x0F 0x22)
pub fn mov_cr_r(vcpu: &mut X86_64Vcpu, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
    let modrm = ctx.consume_u8()?;
    // REX2.R4/R3 extend the control-register selector, while REX2.B4/B3
    // extend the GPR operand through R31. Nonexistent CR selectors #UD before
    // privilege checks, source-dependent validation, or architectural writes.
    let cr = ((modrm >> 3) & 0x07) | ctx.any_rex_r();
    let rm = (modrm & 0x07) | ctx.any_rex_b();
    if !matches!(cr, 0 | 2 | 3 | 4 | 8) || (cr == 8 && !vcpu.sregs.cs.l) {
        return vcpu.inject_undefined_instruction();
    }
    // Real-address mode is permitted. Protected, compatibility, and 64-bit
    // modes require CPL0; virtual-8086 mode has effective CPL3.
    if !is_cpl0(vcpu) {
        return raise_gp0(vcpu);
    }

    // Outside 64-bit mode the source operand is fixed at 32 bits and 66H is
    // ignored. The upper half of the control register is consequently zeroed.
    let value = vcpu.get_reg(rm, if vcpu.sregs.cs.l { 8 } else { 4 });
    let effect = match validate_x86_control_write(
        cr,
        value,
        X86ControlWriteState {
            cr0: vcpu.sregs.cr0,
            cr3: vcpu.sregs.cr3,
            cr4: vcpu.sregs.cr4,
            efer: vcpu.sregs.efer,
            cs_l: vcpu.sregs.cs.l,
            tr_type: vcpu.sregs.tr.type_,
        },
    ) {
        Ok(effect) => effect,
        Err(X86ControlWriteFault::GeneralProtection) => return raise_gp0(vcpu),
    };

    match cr {
        0 => vcpu.sregs.cr0 = effect.value,
        2 => vcpu.sregs.cr2 = effect.value,
        3 => vcpu.sregs.cr3 = effect.value,
        4 => vcpu.sregs.cr4 = effect.value,
        8 => {
            vcpu.mmu.set_task_priority((effect.value << 4) as u32)?;
            vcpu.sregs.cr8 = effect.value;
        }
        _ => unreachable!("validated writable control register changed"),
    }
    vcpu.sregs.efer = effect.efer;
    if effect.flush_tlb {
        vcpu.mmu.flush_tlb();
    }
    vcpu.regs.rip += ctx.cursor as u64;
    Ok(None)
}

#[cfg(test)]
mod control_write_validation_tests {
    use super::*;

    fn state() -> X86ControlWriteState {
        X86ControlWriteState {
            cr0: CR0_PE | CR0_ET,
            cr3: 0,
            cr4: CR4_PAE,
            efer: 0,
            cs_l: false,
            tr_type: 9,
        }
    }

    #[test]
    fn compatibility_mode_can_leave_ia32e_but_64_bit_code_and_pcide_cannot() {
        let mut compatibility = state();
        compatibility.cr0 |= CR0_PG;
        compatibility.efer = EFER_LME | EFER_LMA;
        let effect = validate_x86_control_write(0, CR0_PE, compatibility).unwrap();
        assert_eq!(effect.value, CR0_PE | CR0_ET);
        assert_eq!(effect.efer & EFER_LMA, 0);

        let mut long_mode = compatibility;
        long_mode.cs_l = true;
        assert_eq!(
            validate_x86_control_write(0, CR0_PE, long_mode),
            Err(X86ControlWriteFault::GeneralProtection)
        );

        let mut pcide = compatibility;
        pcide.cr4 |= CR4_PCIDE;
        assert_eq!(
            validate_x86_control_write(0, CR0_PE, pcide),
            Err(X86ControlWriteFault::GeneralProtection)
        );
    }

    #[test]
    fn supported_cr4_profile_is_explicit_and_reserved_fields_fault() {
        let mut long_mode = state();
        long_mode.efer = EFER_LMA;
        let supported = CR4_PAE | CR4_DE | CR4_UMIP | (1 << 16) | (1 << 18) | (1 << 21);
        assert_eq!(
            validate_x86_control_write(4, supported, long_mode)
                .unwrap()
                .value,
            supported
        );
        for reserved in [0, 1, 6, 12, 13, 14, 15, 19, 20, 23, 24, 25, 27, 28, 32] {
            assert_eq!(
                validate_x86_control_write(4, supported | (1 << reserved), long_mode),
                Err(X86ControlWriteFault::GeneralProtection),
                "CR4 bit {reserved}"
            );
        }
    }
}
