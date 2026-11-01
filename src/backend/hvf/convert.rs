//! Conversion between CpuState and HVF/VMCS types.
//!
//! This module handles translation between our internal CPU state representation
//! and the Hypervisor.framework VMCS fields and register values.

use super::bindings::*;
use crate::error::{Error, Result};
use crate::vm::vcpu::{Registers, Segment, SystemRegisters};

fn try_vmcs_read(vcpu: hv_vcpuid_t, field: u32) -> core::result::Result<u64, hv_return_t> {
    let mut value = 0;
    let ret = unsafe { hv_vmx_vcpu_read_vmcs(vcpu, field, &mut value) };
    if ret == HV_SUCCESS {
        Ok(value)
    } else {
        Err(ret)
    }
}

/// Read a typed VMCS field, preserving the existing diagnostic shape.
#[inline]
pub fn vmcs_read(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_field_t) -> Result<u64> {
    try_vmcs_read(vcpu, field as u32).map_err(|ret| {
        Error::Emulator(format!(
            "Failed to read VMCS field {:?}: {}",
            field,
            hv_error_string(ret)
        ))
    })
}

/// Read a field selected by a shared boundary whose encoding the SDK probe checks.
#[inline]
pub fn vmcs_read_raw(vcpu: hv_vcpuid_t, field: u32) -> Result<u64> {
    try_vmcs_read(vcpu, field).map_err(|ret| {
        Error::Emulator(format!(
            "Failed to read VMCS field {field:#x}: {}",
            hv_error_string(ret)
        ))
    })
}

/// Write a VMCS field, returning an error if the operation fails.
#[inline]
pub fn vmcs_write(vcpu: hv_vcpuid_t, field: hv_vmx_vmcs_field_t, value: u64) -> Result<()> {
    let ret = unsafe { hv_vmx_vcpu_write_vmcs(vcpu, field as u32, value) };
    if ret != HV_SUCCESS {
        return Err(Error::Emulator(format!(
            "Failed to write VMCS field {:?}={:#x}: {}",
            field,
            value,
            hv_error_string(ret)
        )));
    }
    Ok(())
}

/// Read a vCPU register.
#[inline]
pub fn read_register(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t) -> Result<u64> {
    let mut value: u64 = 0;
    let ret = unsafe { hv_vcpu_read_register(vcpu, reg as u32, &mut value) };
    if ret != HV_SUCCESS {
        return Err(Error::Emulator(format!(
            "Failed to read register {:?}: {}",
            reg,
            hv_error_string(ret)
        )));
    }
    Ok(value)
}

/// Write a vCPU register.
#[inline]
pub fn write_register(vcpu: hv_vcpuid_t, reg: hv_x86_reg_t, value: u64) -> Result<()> {
    let ret = unsafe { hv_vcpu_write_register(vcpu, reg as u32, value) };
    if ret != HV_SUCCESS {
        return Err(Error::Emulator(format!(
            "Failed to write register {:?}={:#x}: {}",
            reg,
            value,
            hv_error_string(ret)
        )));
    }
    Ok(())
}

/// Read architectural GPRs through the shared portable projection.
pub fn regs_from_hvf(vcpu: hv_vcpuid_t) -> Result<Registers> {
    crate::backend::intel_hvf_projection::registers(&Native(vcpu))
}

/// Write general-purpose registers to HVF vCPU.
pub fn regs_to_hvf(vcpu: hv_vcpuid_t, regs: &Registers) -> Result<()> {
    use hv_x86_reg_t::*;

    write_register(vcpu, HV_X86_RAX, regs.rax)?;
    write_register(vcpu, HV_X86_RBX, regs.rbx)?;
    write_register(vcpu, HV_X86_RCX, regs.rcx)?;
    write_register(vcpu, HV_X86_RDX, regs.rdx)?;
    write_register(vcpu, HV_X86_RSI, regs.rsi)?;
    write_register(vcpu, HV_X86_RDI, regs.rdi)?;
    write_register(vcpu, HV_X86_RSP, regs.rsp)?;
    write_register(vcpu, HV_X86_RBP, regs.rbp)?;
    write_register(vcpu, HV_X86_R8, regs.r8)?;
    write_register(vcpu, HV_X86_R9, regs.r9)?;
    write_register(vcpu, HV_X86_R10, regs.r10)?;
    write_register(vcpu, HV_X86_R11, regs.r11)?;
    write_register(vcpu, HV_X86_R12, regs.r12)?;
    write_register(vcpu, HV_X86_R13, regs.r13)?;
    write_register(vcpu, HV_X86_R14, regs.r14)?;
    write_register(vcpu, HV_X86_R15, regs.r15)?;
    write_register(vcpu, HV_X86_RIP, regs.rip)?;
    write_register(vcpu, HV_X86_RFLAGS, regs.rflags)?;

    Ok(())
}

/// Convert our Segment format to VMCS access rights.
fn segment_to_access_rights(seg: &Segment) -> u64 {
    let mut ar: u64 = seg.type_ as u64;
    if seg.s {
        ar |= 1 << 4;
    }
    ar |= (seg.dpl as u64) << 5;
    if seg.present {
        ar |= 1 << 7;
    }
    if seg.avl {
        ar |= 1 << 12;
    }
    if seg.l {
        ar |= 1 << 13;
    }
    if seg.db {
        ar |= 1 << 14;
    }
    if seg.g {
        ar |= 1 << 15;
    }
    if seg.unusable {
        ar |= 1 << 16;
    }
    ar
}

/// Read architectural system state through the shared portable projection.
pub fn sregs_from_hvf(vcpu: hv_vcpuid_t) -> Result<SystemRegisters> {
    crate::backend::intel_hvf_projection::systems(&Native(vcpu))
}

/// Write system registers to HVF vCPU via VMCS.
pub fn sregs_to_hvf(vcpu: hv_vcpuid_t, sregs: &SystemRegisters) -> Result<()> {
    use hv_vmx_vmcs_field_t::*;
    use hv_x86_reg_t::*;

    let tpr = super::cr8::tpr_value(sregs.cr8)
        .ok_or_else(|| Error::InvalidConfig(format!("invalid CR8 value {:#x}", sregs.cr8)))?;

    // CS segment
    vmcs_write(vcpu, VMCS_GUEST_CS_SELECTOR, sregs.cs.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_CS_BASE, sregs.cs.base)?;
    vmcs_write(vcpu, VMCS_GUEST_CS_LIMIT, sregs.cs.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_CS_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.cs),
    )?;

    // DS segment
    vmcs_write(vcpu, VMCS_GUEST_DS_SELECTOR, sregs.ds.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_DS_BASE, sregs.ds.base)?;
    vmcs_write(vcpu, VMCS_GUEST_DS_LIMIT, sregs.ds.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_DS_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.ds),
    )?;

    // ES segment
    vmcs_write(vcpu, VMCS_GUEST_ES_SELECTOR, sregs.es.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_ES_BASE, sregs.es.base)?;
    vmcs_write(vcpu, VMCS_GUEST_ES_LIMIT, sregs.es.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_ES_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.es),
    )?;

    // FS segment
    vmcs_write(vcpu, VMCS_GUEST_FS_SELECTOR, sregs.fs.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_FS_BASE, sregs.fs.base)?;
    vmcs_write(vcpu, VMCS_GUEST_FS_LIMIT, sregs.fs.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_FS_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.fs),
    )?;

    // GS segment
    vmcs_write(vcpu, VMCS_GUEST_GS_SELECTOR, sregs.gs.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_GS_BASE, sregs.gs.base)?;
    vmcs_write(vcpu, VMCS_GUEST_GS_LIMIT, sregs.gs.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_GS_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.gs),
    )?;

    // SS segment
    vmcs_write(vcpu, VMCS_GUEST_SS_SELECTOR, sregs.ss.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_SS_BASE, sregs.ss.base)?;
    vmcs_write(vcpu, VMCS_GUEST_SS_LIMIT, sregs.ss.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_SS_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.ss),
    )?;

    // TR segment
    vmcs_write(vcpu, VMCS_GUEST_TR_SELECTOR, sregs.tr.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_TR_BASE, sregs.tr.base)?;
    vmcs_write(vcpu, VMCS_GUEST_TR_LIMIT, sregs.tr.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_TR_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.tr),
    )?;

    // LDT segment
    vmcs_write(vcpu, VMCS_GUEST_LDTR_SELECTOR, sregs.ldt.selector as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_LDTR_BASE, sregs.ldt.base)?;
    vmcs_write(vcpu, VMCS_GUEST_LDTR_LIMIT, sregs.ldt.limit as u64)?;
    vmcs_write(
        vcpu,
        VMCS_GUEST_LDTR_ACCESS_RIGHTS,
        segment_to_access_rights(&sregs.ldt),
    )?;

    // Descriptor tables
    vmcs_write(vcpu, VMCS_GUEST_GDTR_BASE, sregs.gdt.base)?;
    vmcs_write(vcpu, VMCS_GUEST_GDTR_LIMIT, sregs.gdt.limit as u64)?;
    vmcs_write(vcpu, VMCS_GUEST_IDTR_BASE, sregs.idt.base)?;
    vmcs_write(vcpu, VMCS_GUEST_IDTR_LIMIT, sregs.idt.limit as u64)?;

    // Control registers
    vmcs_write(vcpu, VMCS_GUEST_CR0, sregs.cr0)?;
    vmcs_write(vcpu, VMCS_GUEST_CR3, sregs.cr3)?;
    vmcs_write(vcpu, VMCS_GUEST_CR4, sregs.cr4)?;
    write_register(vcpu, HV_X86_CR2, sregs.cr2)?;

    // CR8 is the high priority nibble of the SDK's full TPR byte.
    write_register(vcpu, HV_X86_TPR, tpr)?;

    // EFER
    vmcs_write(vcpu, VMCS_GUEST_IA32_EFER, sregs.efer)?;

    // Debug registers
    write_register(vcpu, HV_X86_DR0, sregs.dr0)?;
    write_register(vcpu, HV_X86_DR1, sregs.dr1)?;
    write_register(vcpu, HV_X86_DR2, sregs.dr2)?;
    write_register(vcpu, HV_X86_DR3, sregs.dr3)?;
    write_register(vcpu, HV_X86_DR6, sregs.dr6)?;
    vmcs_write(vcpu, VMCS_GUEST_DR7, sregs.dr7)?;

    // The SDK execution bank is also the public syscall-register backing.
    super::native_msr::write(vcpu, super::native_msr::STAR, sregs.star)?;
    super::native_msr::write(vcpu, super::native_msr::LSTAR, sregs.lstar)?;
    super::native_msr::write(vcpu, super::native_msr::CSTAR, sregs.cstar)?;
    super::native_msr::write(vcpu, super::native_msr::FMASK, sregs.fmask)?;

    // SYSENTER MSRs
    vmcs_write(vcpu, VMCS_GUEST_IA32_SYSENTER_CS, sregs.sysenter_cs)?;
    vmcs_write(vcpu, VMCS_GUEST_IA32_SYSENTER_ESP, sregs.sysenter_esp)?;
    vmcs_write(vcpu, VMCS_GUEST_IA32_SYSENTER_EIP, sregs.sysenter_eip)?;

    Ok(())
}

/// Map Intel architectural GPR indices to the SDK register enum.
pub fn general_register(index: u8) -> Result<hv_x86_reg_t> {
    use hv_x86_reg_t::*;
    const REGISTERS: [hv_x86_reg_t; 16] = [
        HV_X86_RAX, HV_X86_RCX, HV_X86_RDX, HV_X86_RBX, HV_X86_RSP, HV_X86_RBP, HV_X86_RSI,
        HV_X86_RDI, HV_X86_R8, HV_X86_R9, HV_X86_R10, HV_X86_R11, HV_X86_R12, HV_X86_R13,
        HV_X86_R14, HV_X86_R15,
    ];
    REGISTERS
        .get(usize::from(index))
        .copied()
        .ok_or_else(|| Error::Emulator(format!("invalid VMX general-register index {index}")))
}

/// Typed SDK access for the common native projection and capture code.
pub(super) struct Native(pub hv_vcpuid_t);
impl crate::backend::intel_hvf_projection::Read for Native {
    fn register(&self, id: u32) -> Result<u64> {
        let register = register_from_raw(id)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown native register {id:#x}")))?;
        read_register(self.0, register)
    }
    fn vmcs(&self, id: u32) -> Result<u64> {
        let field = vmcs_from_raw(id)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown native VMCS field {id:#x}")))?;
        vmcs_read(self.0, field)
    }
    fn msr(&self, id: u32) -> Result<u64> {
        super::native_msr::read(self.0, id)
    }
}
