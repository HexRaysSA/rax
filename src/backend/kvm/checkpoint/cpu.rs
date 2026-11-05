//! Owned native CPU banks at an already-settled, exclusively stopped boundary.
use super::super::xsave;
use super::{bank::Bank, bounded, msrs, nested, profile, sregs2};
use crate::backend::intel_hvf_xsave::{Layout, MAX_IMAGE};
use crate::error::{Error, Result};
use kvm_bindings::{
    CpuId, KVM_MAX_CPUID_ENTRIES, kvm_cpuid_entry2, kvm_debugregs, kvm_lapic_state, kvm_mp_state,
    kvm_regs, kvm_sregs, kvm_sregs2, kvm_vcpu_events, kvm_xcrs,
};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use serde::{Deserialize, Deserializer, Serialize};
use std::os::fd::AsRawFd;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Xsave {
    #[serde(deserialize_with = "xsave_layout")]
    layout: Layout,
    #[serde(deserialize_with = "xsave_bytes")]
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::backend::kvm) struct Image {
    version: u16,
    pub(in crate::backend::kvm) id: u32,
    irqchip: bool,
    pub(in crate::backend::kvm) userspace_halted: bool,
    #[serde(deserialize_with = "cpuid_entries")]
    profile: Vec<Bank<kvm_cpuid_entry2>>,
    #[serde(deserialize_with = "cpuid_entries")]
    observed_cpuid: Vec<Bank<kvm_cpuid_entry2>>,
    regs: Bank<kvm_regs>,
    special: Bank<kvm_sregs>,
    extended: Option<sregs2::Image>,
    debug: Bank<kvm_debugregs>,
    events: Bank<kvm_vcpu_events>,
    mp: Bank<kvm_mp_state>,
    xcrs: Option<Bank<kvm_xcrs>>,
    lapic: Option<Bank<kvm_lapic_state>>,
    xsave: Xsave,
    msrs: msrs::Image,
    nested_capacity: u32,
    nested: Option<nested::Image>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native KVM CPU record: {message}"))
}

fn cpuid_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Bank<kvm_cpuid_entry2>>, D::Error> {
    bounded::sequence::<_, _, { KVM_MAX_CPUID_ENTRIES }>(deserializer)
}

fn xsave_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    bounded::sequence::<_, _, MAX_IMAGE>(deserializer)
}

fn xsave_layout<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Layout, D::Error> {
    use crate::backend::intel_hvf_xsave::Component;
    fn components<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<Component>, D::Error> {
        bounded::sequence::<_, _, 61>(deserializer)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fields {
        mask: u64,
        size: u32,
        #[serde(deserialize_with = "components")]
        components: Vec<Component>,
        mxcsr_mask: u32,
    }
    let fields = Fields::deserialize(deserializer)?;
    Ok(Layout {
        mask: fields.mask,
        size: fields.size,
        components: fields.components,
        mxcsr_mask: fields.mxcsr_mask,
    })
}

fn native_cpuid(banks: &[Bank<kvm_cpuid_entry2>]) -> Result<CpuId> {
    let entries = banks
        .iter()
        .map(|bank| bank.decode().map_err(invalid))
        .collect::<Result<Vec<_>>>()?;
    if entries.is_empty() || entries.len() > KVM_MAX_CPUID_ENTRIES {
        return Err(invalid("CPUID record count is outside the native bound"));
    }
    CpuId::from_entries(&entries).map_err(invalid)
}

fn capability(vm: &VmFd, kind: u32) -> Result<u32> {
    let value = vm.check_extension_raw(kind.into());
    u32::try_from(value).map_err(|_| invalid("native capability query failed"))
}

fn get_extended(cpu: &VcpuFd) -> Result<kvm_sregs2> {
    let mut value = kvm_sregs2::default();
    // SAFETY: the retained x86 UAPI defines GET_SREGS2 and this initialized,
    // aligned output. The stopped CPU FD and exclusive local remain live for
    // the synchronous copy; no native entry occurs and no pointer escapes.
    let status = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOR::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcc),
            &mut value as *mut kvm_sregs2,
        )
    };
    if status < 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    Ok(value)
}

fn set_extended(cpu: &VcpuFd, value: &kvm_sregs2) -> Result<()> {
    // SAFETY: the x86 UAPI defines SET_SREGS2 with this initialized, aligned
    // integer-only input. The stopped CPU FD and immutable input remain live
    // throughout the synchronous copy. No pointer escapes or aliases mutate.
    let status = unsafe {
        libc::ioctl(
            cpu.as_raw_fd(),
            libc::_IOW::<kvm_sregs2>(kvm_bindings::KVMIO, 0xcd),
            value as *const kvm_sregs2,
        )
    };
    if status < 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    Ok(())
}

impl Image {
    /// Caller owns the VM-wide stopped boundary and has completed every native
    /// userspace-I/O continuation. This function performs no KVM_RUN and cannot
    /// establish that boundary from an immutable descriptor alone.
    pub(in crate::backend::kvm) fn capture(
        kvm: &Kvm,
        vm: &VmFd,
        cpu: &VcpuFd,
        id: u32,
        configured: &CpuId,
        irqchip: bool,
        userspace_halted: bool,
    ) -> Result<Self> {
        // GET_MP_STATE accepts INIT/SIPI. Observe it before the other banks.
        let mp = cpu.get_mp_state()?;
        let special = cpu.get_sregs()?;
        let extended = (capability(vm, kvm_bindings::KVM_CAP_SREGS2)? != 0)
            .then(|| {
                get_extended(cpu).and_then(|value| sregs2::Image::capture(&value).map_err(invalid))
            })
            .transpose()?;
        let observed = cpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?;
        let plan = msrs::Plan::capture(kvm, configured, irqchip)?;
        let xsave = xsave::Image::read(vm, cpu)?;
        let image = Self {
            version: 2,
            id,
            irqchip,
            userspace_halted,
            profile: configured
                .as_slice()
                .iter()
                .map(Bank::capture)
                .collect::<std::result::Result<_, _>>()
                .map_err(invalid)?,
            observed_cpuid: observed
                .as_slice()
                .iter()
                .map(Bank::capture)
                .collect::<std::result::Result<_, _>>()
                .map_err(invalid)?,
            regs: Bank::capture(&cpu.get_regs()?).map_err(invalid)?,
            special: Bank::capture(&special).map_err(invalid)?,
            extended,
            debug: Bank::capture(&cpu.get_debug_regs()?).map_err(invalid)?,
            events: Bank::capture(&cpu.get_vcpu_events()?).map_err(invalid)?,
            mp: Bank::capture(&mp).map_err(invalid)?,
            xcrs: (capability(vm, kvm_bindings::KVM_CAP_XCRS)? != 0)
                .then(|| {
                    cpu.get_xcrs()
                        .map_err(Error::from)
                        .and_then(|value| Bank::capture(&value).map_err(invalid))
                })
                .transpose()?,
            lapic: irqchip
                .then(|| {
                    cpu.get_lapic()
                        .map_err(Error::from)
                        .and_then(|value| Bank::capture(&value).map_err(invalid))
                })
                .transpose()?,
            xsave: Xsave {
                layout: xsave.layout,
                bytes: xsave.bytes,
            },
            msrs: msrs::Image::capture(cpu, &plan)?,
            nested_capacity: capability(vm, kvm_bindings::KVM_CAP_NESTED_STATE)?,
            nested: None,
        };
        let mut image = image;
        image.nested = nested::Image::capture(cpu, image.nested_capacity as usize)?;
        image.validate(kvm, vm, cpu, id, configured, irqchip)?;
        Ok(image)
    }

    /// All structural/profile checks precede any native setter. GET operations
    /// do not provide a rollback transaction; the stopped boundary remains the
    /// caller's responsibility. Migration across different XSAVE layouts is
    /// unsupported rather than reinterpreting component offsets.
    pub(in crate::backend::kvm) fn validate(
        &self,
        kvm: &Kvm,
        vm: &VmFd,
        cpu: &VcpuFd,
        id: u32,
        configured: &CpuId,
        irqchip: bool,
    ) -> Result<msrs::Plan> {
        if self.version != 2
            || self.id != id
            || self.irqchip != irqchip
            || self.lapic.is_some() != irqchip
            || (irqchip && self.userspace_halted)
        {
            return Err(invalid(
                "version, CPU identity or controller profile differs",
            ));
        }
        let saved_profile = native_cpuid(&self.profile)?;
        let observed = native_cpuid(&self.observed_cpuid)?;
        if saved_profile.as_slice() != configured.as_slice()
            || !profile::immutable_equal(&observed, &cpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?)
        {
            return Err(invalid(
                "destination CPUID differs from the saved CPU profile",
            ));
        }
        self.regs.decode().map_err(invalid)?;
        self.debug.decode().map_err(invalid)?;
        self.events.decode().map_err(invalid)?;
        self.mp.decode().map_err(invalid)?;
        if let Some(lapic) = &self.lapic {
            lapic.decode().map_err(invalid)?;
        }
        let special = self.special.decode().map_err(invalid)?;
        if self.extended.is_some() != (capability(vm, kvm_bindings::KVM_CAP_SREGS2)? != 0) {
            return Err(invalid("SREGS2 capability profile differs"));
        }
        if let Some(extended) = &self.extended {
            if !extended.agrees_with(&special).map_err(invalid)? {
                return Err(invalid("legacy and extended special registers disagree"));
            }
        } else if special.cr0 & (1 << 31) != 0
            && special.cr4 & (1 << 5) != 0
            && special.efer & (1 << 10) == 0
        {
            return Err(invalid("legacy PAE record cannot retain cached PDPTRs"));
        }
        if self.xcrs.is_some() != (capability(vm, kvm_bindings::KVM_CAP_XCRS)? != 0) {
            return Err(invalid("XCR capability profile differs"));
        }
        let xcrs = self
            .xcrs
            .as_ref()
            .map(Bank::decode)
            .transpose()
            .map_err(invalid)?;
        self.xsave.layout.validate_image(&self.xsave.bytes)?;
        if self.xsave.layout != xsave::Image::read(vm, cpu)?.layout {
            return Err(invalid("destination XSAVE component layout differs"));
        }
        profile::validate(
            &saved_profile,
            &observed,
            &special,
            xcrs.as_ref(),
            &self.xsave.layout,
        )?;
        let plan = msrs::Plan::capture(kvm, configured, irqchip)?;
        self.msrs.validate(&plan)?;
        if self.nested_capacity != capability(vm, kvm_bindings::KVM_CAP_NESTED_STATE)?
            || self.nested.is_some() != (self.nested_capacity != 0)
        {
            return Err(invalid("nested-state capacity or presence differs"));
        }
        if let Some(nested) = &self.nested {
            nested.validate_envelope(self.nested_capacity as usize)?;
        }
        Ok(plan)
    }

    /// Applies the stored CPU banks to a disposable destination or within a
    /// complete VM rollback transaction. Shared IRQ controllers, RAM, advancing
    /// clocks and the first-entry gate belong to the enclosing VM producer.
    /// A native setter can mutate a prefix before returning an error.
    pub(in crate::backend::kvm) fn restore_stored(
        &self,
        kvm: &Kvm,
        vm: &VmFd,
        cpu: &mut VcpuFd,
        id: u32,
        configured: &CpuId,
        irqchip: bool,
    ) -> Result<()> {
        let plan = self.validate(kvm, vm, cpu, id, configured, irqchip)?;
        // Preserve the legacy pending-interrupt bitmap as well as SREGS2's
        // PDPTR cache: the second setter replaces the common register fields,
        // while the legacy setter owns the interrupt bitmap omitted by SREGS2.
        let special = self.special.decode().map_err(invalid)?;
        cpu.set_sregs(&special)?;
        if let Some(extended) = &self.extended {
            set_extended(cpu, &extended.decode().map_err(invalid)?)?;
        }
        if let Some(xcrs) = &self.xcrs {
            cpu.set_xcrs(&xcrs.decode().map_err(invalid)?)?;
        }
        xsave::Image {
            layout: self.xsave.layout.clone(),
            bytes: self.xsave.bytes.clone(),
        }
        .write(vm, cpu)?;
        self.msrs.restore_stored_registers(cpu, &plan)?;
        if let Some(lapic) = &self.lapic {
            cpu.set_lapic(&lapic.decode().map_err(invalid)?)?;
        }
        cpu.set_debug_regs(&self.debug.decode().map_err(invalid)?)?;
        cpu.set_regs(&self.regs.decode().map_err(invalid)?)?;
        if let Some(nested) = &self.nested {
            nested.restore(cpu, self.nested_capacity as usize)?;
        }
        cpu.set_vcpu_events(&self.events.decode().map_err(invalid)?)?;
        // SREGS and event installation can make a reset CPU runnable.
        cpu.set_mp_state(self.mp.decode().map_err(invalid)?)?;
        // No native entry may import the fresh target's old CR8 over this
        // restored bank. The stopped owner exclusively retains this mapping.
        cpu.get_kvm_run().cr8 = special.cr8;
        Ok(())
    }

    /// Derive public state from this same stopped capture, not another ioctl
    /// observation that could acknowledge pending startup events.
    pub(in crate::backend::kvm) fn public(
        &self,
    ) -> Result<(
        crate::vm::vcpu::X86_64CpuState,
        crate::vm::snapshot::EmulatorState,
    )> {
        let mut regs = super::super::convert::regs_from_kvm(&self.regs.decode().map_err(invalid)?);
        let emulator = self.xsave.layout.project(&self.xsave.bytes, &mut regs)?;
        let mut sregs =
            super::super::convert::sregs_from_kvm(&self.special.decode().map_err(invalid)?);
        let debug = self.debug.decode().map_err(invalid)?;
        [sregs.dr0, sregs.dr1, sregs.dr2, sregs.dr3] = debug.db;
        sregs.dr6 = debug.dr6;
        sregs.dr7 = debug.dr7;
        for register in self.msrs.registers() {
            match register.index {
                0xc000_0081 => sregs.star = register.value,
                0xc000_0082 => sregs.lstar = register.value,
                0xc000_0083 => sregs.cstar = register.value,
                0xc000_0084 => sregs.fmask = register.value,
                0x174 => sregs.sysenter_cs = register.value,
                0x175 => sregs.sysenter_esp = register.value,
                0x176 => sregs.sysenter_eip = register.value,
                _ => {}
            }
        }
        Ok((crate::vm::vcpu::X86_64CpuState { regs, sregs }, emulator))
    }
}
