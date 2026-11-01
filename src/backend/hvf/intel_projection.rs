//! One portable architectural projection shared by SDK capture and record admission.
use super::intel_hvf_registers::{hv_vmx_vmcs_field_t, hv_x86_reg_t};
use crate::error::Result;
use crate::vm::vcpu::{DescriptorTable, Registers, Segment, SystemRegisters};

pub(crate) trait Read {
    fn register(&self, id: u32) -> Result<u64>;
    fn vmcs(&self, id: u32) -> Result<u64>;
    fn msr(&self, id: u32) -> Result<u64>;
}
fn read_register(host: &impl Read, register: hv_x86_reg_t) -> Result<u64> {
    host.register(register as u32)
}
fn vmcs_read(host: &impl Read, field: hv_vmx_vmcs_field_t) -> Result<u64> {
    host.vmcs(field as u32)
}

/// Read general-purpose registers from HVF vCPU.
pub(crate) fn registers(host: &impl Read) -> Result<Registers> {
    use hv_x86_reg_t::*;

    Ok(Registers {
        rax: read_register(host, HV_X86_RAX)?,
        rbx: read_register(host, HV_X86_RBX)?,
        rcx: read_register(host, HV_X86_RCX)?,
        rdx: read_register(host, HV_X86_RDX)?,
        rsi: read_register(host, HV_X86_RSI)?,
        rdi: read_register(host, HV_X86_RDI)?,
        rsp: read_register(host, HV_X86_RSP)?,
        rbp: read_register(host, HV_X86_RBP)?,
        r8: read_register(host, HV_X86_R8)?,
        r9: read_register(host, HV_X86_R9)?,
        r10: read_register(host, HV_X86_R10)?,
        r11: read_register(host, HV_X86_R11)?,
        r12: read_register(host, HV_X86_R12)?,
        r13: read_register(host, HV_X86_R13)?,
        r14: read_register(host, HV_X86_R14)?,
        r15: read_register(host, HV_X86_R15)?,
        rip: read_register(host, HV_X86_RIP)?,
        rflags: read_register(host, HV_X86_RFLAGS)?,
        // SIMD registers will be read via FP state; APX EGPRs are not
        // exposed by HVF.
        ..Default::default()
    })
}

/// Convert VMCS segment access rights to our Segment format.
/// VMX access rights format:
/// Bits 0-3: Type
/// Bit 4: S (descriptor type)
/// Bits 5-6: DPL
/// Bit 7: Present
/// Bits 8-11: Reserved
/// Bit 12: Available
/// Bit 13: L (64-bit mode)
/// Bit 14: D/B
/// Bit 15: G (granularity)
/// Bit 16: Unusable
fn segment_from_vmcs(selector: u64, base: u64, limit: u64, access_rights: u64) -> Segment {
    Segment {
        base,
        limit: limit as u32,
        selector: selector as u16,
        type_: (access_rights & 0xF) as u8,
        s: (access_rights & (1 << 4)) != 0,
        dpl: ((access_rights >> 5) & 0x3) as u8,
        present: (access_rights & (1 << 7)) != 0,
        avl: (access_rights & (1 << 12)) != 0,
        l: (access_rights & (1 << 13)) != 0,
        db: (access_rights & (1 << 14)) != 0,
        g: (access_rights & (1 << 15)) != 0,
        unusable: (access_rights & (1 << 16)) != 0,
    }
}

/// Read system registers from HVF vCPU via VMCS.
pub(crate) fn systems(host: &impl Read) -> Result<SystemRegisters> {
    use hv_vmx_vmcs_field_t::*;
    use hv_x86_reg_t::*;

    // Read segment registers from VMCS
    let cs = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_CS_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_CS_BASE)?,
        vmcs_read(host, VMCS_GUEST_CS_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_CS_ACCESS_RIGHTS)?,
    );
    let ds = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_DS_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_DS_BASE)?,
        vmcs_read(host, VMCS_GUEST_DS_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_DS_ACCESS_RIGHTS)?,
    );
    let es = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_ES_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_ES_BASE)?,
        vmcs_read(host, VMCS_GUEST_ES_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_ES_ACCESS_RIGHTS)?,
    );
    let fs = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_FS_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_FS_BASE)?,
        vmcs_read(host, VMCS_GUEST_FS_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_FS_ACCESS_RIGHTS)?,
    );
    let gs = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_GS_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_GS_BASE)?,
        vmcs_read(host, VMCS_GUEST_GS_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_GS_ACCESS_RIGHTS)?,
    );
    let ss = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_SS_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_SS_BASE)?,
        vmcs_read(host, VMCS_GUEST_SS_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_SS_ACCESS_RIGHTS)?,
    );
    let tr = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_TR_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_TR_BASE)?,
        vmcs_read(host, VMCS_GUEST_TR_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_TR_ACCESS_RIGHTS)?,
    );
    let ldt = segment_from_vmcs(
        vmcs_read(host, VMCS_GUEST_LDTR_SELECTOR)?,
        vmcs_read(host, VMCS_GUEST_LDTR_BASE)?,
        vmcs_read(host, VMCS_GUEST_LDTR_LIMIT)?,
        vmcs_read(host, VMCS_GUEST_LDTR_ACCESS_RIGHTS)?,
    );

    // Descriptor tables
    let gdt = DescriptorTable {
        base: vmcs_read(host, VMCS_GUEST_GDTR_BASE)?,
        limit: vmcs_read(host, VMCS_GUEST_GDTR_LIMIT)? as u16,
    };
    let idt = DescriptorTable {
        base: vmcs_read(host, VMCS_GUEST_IDTR_BASE)?,
        limit: vmcs_read(host, VMCS_GUEST_IDTR_LIMIT)? as u16,
    };

    // Control registers
    let cr0 = vmcs_read(host, VMCS_GUEST_CR0)?;
    let cr3 = vmcs_read(host, VMCS_GUEST_CR3)?;
    let cr4 = vmcs_read(host, VMCS_GUEST_CR4)?;
    let cr2 = read_register(host, HV_X86_CR2)?;

    // EFER is accessible via VMCS
    let efer = vmcs_read(host, VMCS_GUEST_IA32_EFER)?;

    // Debug registers via direct register access
    let dr0 = read_register(host, HV_X86_DR0)?;
    let dr1 = read_register(host, HV_X86_DR1)?;
    let dr2 = read_register(host, HV_X86_DR2)?;
    let dr3 = read_register(host, HV_X86_DR3)?;
    let dr6 = read_register(host, HV_X86_DR6)?;
    let dr7 = vmcs_read(host, VMCS_GUEST_DR7)?;

    // SYSENTER MSRs from VMCS
    let sysenter_cs = vmcs_read(host, VMCS_GUEST_IA32_SYSENTER_CS)?;
    let sysenter_esp = vmcs_read(host, VMCS_GUEST_IA32_SYSENTER_ESP)?;
    let sysenter_eip = vmcs_read(host, VMCS_GUEST_IA32_SYSENTER_EIP)?;

    Ok(SystemRegisters {
        cs,
        ds,
        es,
        fs,
        gs,
        ss,
        tr,
        ldt,
        gdt,
        idt,
        cr0,
        cr2,
        cr3,
        cr4,
        cr8: (read_register(host, HV_X86_TPR)? >> 4) & 0x0f,
        efer,
        star: host.msr(super::intel_hvf_context::STAR)?,
        lstar: host.msr(super::intel_hvf_context::LSTAR)?,
        cstar: host.msr(super::intel_hvf_context::CSTAR)?,
        fmask: host.msr(super::intel_hvf_context::FMASK)?,
        sysenter_cs,
        sysenter_esp,
        sysenter_eip,
        dr0,
        dr1,
        dr2,
        dr3,
        dr6,
        dr7,
    })
}
