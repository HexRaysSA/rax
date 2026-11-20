//! Owned native CPU banks at an already-settled, exclusively stopped boundary.
use super::super::xsave;
use super::{bank::Bank, bounded, lapic_timer::Countdown, msrs, nested, profile, sregs2};
use crate::backend::intel_hvf_xsave::{Layout, MAX_IMAGE};
use crate::error::{Error, Result};
use kvm_bindings::{
    CpuId, KVM_CAP_EXCEPTION_PAYLOAD, KVM_CAP_X86_TRIPLE_FAULT_EVENT, KVM_MAX_CPUID_ENTRIES,
    KVM_VCPUEVENT_VALID_PAYLOAD, KVM_VCPUEVENT_VALID_SMM, KVM_VCPUEVENT_VALID_TRIPLE_FAULT,
    kvm_cpuid_entry2, kvm_debugregs, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs,
    kvm_sregs2, kvm_vcpu_events, kvm_xcrs,
};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use serde::{Deserialize, Deserializer, Serialize};
use std::os::fd::AsRawFd;

const VERSION: u16 = 4;
const REQUIRED_EVENT_FLAGS: u32 = KVM_VCPUEVENT_VALID_PAYLOAD | KVM_VCPUEVENT_VALID_TRIPLE_FAULT;

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

fn require_precise_events(vm: &VmFd) -> Result<()> {
    if capability(vm, KVM_CAP_EXCEPTION_PAYLOAD)? == 0
        || capability(vm, KVM_CAP_X86_TRIPLE_FAULT_EVENT)? == 0
    {
        return Err(invalid(
            "host cannot retain precise exception and shutdown events",
        ));
    }
    Ok(())
}

fn validate_exception_events(events: &kvm_vcpu_events, vm: &VmFd) -> Result<()> {
    require_precise_events(vm)?;
    if events.flags & REQUIRED_EVENT_FLAGS != REQUIRED_EVENT_FLAGS {
        return Err(invalid("missing precise exception or shutdown event flags"));
    }
    let exception = &events.exception;
    let active = exception.injected != 0 || exception.pending != 0;
    if exception.pending > 1
        || exception.injected > 1
        || (exception.pending != 0 && exception.injected != 0)
        || (active && (exception.nr == 2 || exception.nr > 31))
        || exception.has_error_code > 1
        || events.exception_has_payload > 1
        || (events.exception_has_payload != 0
            && (exception.pending == 0 || !matches!(exception.nr, 1 | 14)))
        || events.triple_fault.pending > 1
    {
        return Err(invalid("invalid precise exception or shutdown event"));
    }
    Ok(())
}

fn validate_smm_events(events: &kvm_vcpu_events) -> Result<()> {
    if events.flags & KVM_VCPUEVENT_VALID_SMM == 0 || events.smi.smm > 1 {
        return Err(invalid("missing or invalid SMM event state"));
    }
    Ok(())
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
        // Check before native getters: legacy GET_VCPU_EVENTS can commit a
        // payload as an observation side effect.
        require_precise_events(vm)?;
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
        // A posted timer interrupt becomes visible before KVM clears the
        // deadline MSR. GET_LAPIC folds posted interrupts into IRR, so read
        // it after the MSR sample used to admit a quiescent timer.
        let msrs = msrs::Image::capture(cpu, &plan)?;
        let image = Self {
            version: VERSION,
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
            msrs,
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
        // Older records omitted the independent triple-fault request. Even an
        // empty exception slot in such a record cannot establish its absence.
        if self.version != VERSION {
            return Err(invalid(
                "CPU record version cannot retain all shutdown events",
            ));
        }
        if self.id != id
            || self.irqchip != irqchip
            || self.lapic.is_some() != irqchip
            || (irqchip && self.userspace_halted)
        {
            return Err(invalid("CPU identity or controller profile differs"));
        }
        let saved_profile = native_cpuid(&self.profile)?;
        let observed = native_cpuid(&self.observed_cpuid)?;
        if let Some(difference) =
            profile::destination_difference(&saved_profile, configured, &observed, || {
                Ok(cpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES)?)
            })?
        {
            return Err(invalid(format_args!(
                "destination CPUID differs from the saved CPU profile for vCPU {id}: {difference}"
            )));
        }
        self.regs.decode().map_err(invalid)?;
        self.debug.decode().map_err(invalid)?;
        let events = self.events.decode().map_err(invalid)?;
        validate_exception_events(&events, vm)?;
        validate_smm_events(&events)?;
        self.mp.decode().map_err(invalid)?;
        let special = self.special.decode().map_err(invalid)?;
        let lapic = self
            .lapic
            .as_ref()
            .map(Bank::decode)
            .transpose()
            .map_err(invalid)?;
        if self.deadline().is_some_and(|deadline| deadline != 0)
            && !lapic
                .as_ref()
                .is_some_and(|lapic| msrs::deadline_mode(lapic, special.apic_base))
        {
            return Err(invalid(
                "armed TSC deadline requires an enabled LAPIC in deadline mode",
            ));
        }
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
            nested.validate_event_mode(self.nested_capacity as usize, events.smi.smm != 0)?;
        }
        Ok(plan)
    }

    pub(super) fn requires_restore_smi(
        &self,
        kvm: &Kvm,
        configured: &CpuId,
        fresh: bool,
    ) -> Result<bool> {
        let Some(nested) = &self.nested else {
            return Ok(false);
        };
        let required = nested.requires_smi(
            kvm,
            configured,
            self.nested_capacity as usize,
            fresh,
            self.irqchip,
        )?;
        if required
            && !self
                .msrs
                .registers()
                .iter()
                .any(|msr| msr.index == super::smm::IA32_SMBASE)
        {
            return Err(invalid("missing SMBASE after temporary SMM entry"));
        }
        Ok(required)
    }

    pub(super) fn materialize_smm(&self, cpu: &mut VcpuFd) -> Result<()> {
        self.nested
            .as_ref()
            .ok_or_else(|| invalid("missing nested SMM record"))?
            .materialize_smm(cpu, self.nested_capacity as usize)
    }

    pub(super) fn deadline(&self) -> Option<u64> {
        self.msrs.deadline()
    }

    /// Check timer admission and read the native TPR for its public projection.
    pub(super) fn checkpoint_priority(&self) -> Result<Option<u8>> {
        let Some(lapic) = &self.lapic else {
            return Ok(None);
        };
        if self.special.decode().map_err(invalid)?.apic_base & (1 << 11) == 0 {
            return Err(invalid("disabled LAPIC can conceal a TSC deadline"));
        }
        if self.deadline().is_some_and(|deadline| deadline != 0) {
            return Err(invalid("armed TSC deadline requires verified expiry state"));
        }
        let lapic = lapic.decode().map_err(invalid)?;
        if super::lapic_timer::has_countdown(&lapic) {
            return Err(invalid(
                "programmed LAPIC countdown requires verified expiry state",
            ));
        }
        const TASK_PRIORITY: usize = 0x80;
        let tpr = u32::from_le_bytes(std::array::from_fn(|byte| {
            lapic.regs[TASK_PRIORITY + byte] as u8
        }));
        u8::try_from(tpr).map(Some).map_err(invalid)
    }

    #[cfg(test)]
    pub(super) fn break_debug_setter(&mut self) {
        let mut debug = self.debug.decode().unwrap();
        // Linux rejects nonzero flags in KVM_SET_DEBUGREGS. Flags have no
        // public projection, so preflight still reaches the native setters.
        debug.flags = 1;
        self.debug = Bank::capture(&debug).unwrap();
    }

    pub(super) fn retain_stopped_deadline(&mut self, deadline: Option<u64>) -> Result<()> {
        self.msrs.retain_stopped_deadline(deadline)
    }

    pub(super) fn countdown(&self) -> Result<Option<Countdown>> {
        let Some(lapic) = &self.lapic else {
            return Ok(None);
        };
        Ok(Countdown::capture(
            &lapic.decode().map_err(invalid)?,
            self.special.decode().map_err(invalid)?.apic_base,
        ))
    }

    pub(super) fn retain_stopped_countdown(&mut self, countdown: Countdown) -> Result<()> {
        let bank = self
            .lapic
            .as_mut()
            .ok_or_else(|| invalid("stopped countdown requires a LAPIC bank"))?;
        let mut lapic = bank.decode().map_err(invalid)?;
        countdown.restore_into(
            &mut lapic,
            self.special.decode().map_err(invalid)?.apic_base,
        )?;
        *bank = Bank::capture(&lapic).map_err(invalid)?;
        Ok(())
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
        prepared_smm: bool,
    ) -> Result<()> {
        let plan = self.validate(kvm, vm, cpu, id, configured, irqchip)?;
        if self.deadline().is_some() {
            // SET_LAPIC may start a timer from the target's previous MSR.
            // Keep the replacement deadline inert until common clock activation.
            msrs::clear_deadline(cpu)?;
        }
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
            let mut lapic = lapic.decode().map_err(invalid)?;
            if Countdown::capture(&lapic, special.apic_base).is_some() {
                Countdown::disarm(&mut lapic);
            }
            cpu.set_lapic(&lapic)?;
        }
        cpu.set_debug_regs(&self.debug.decode().map_err(invalid)?)?;
        cpu.set_regs(&self.regs.decode().map_err(invalid)?)?;
        cpu.set_vcpu_events(&self.events.decode().map_err(invalid)?)?;
        // SREGS and event installation can make a reset CPU runnable.
        cpu.set_mp_state(self.mp.decode().map_err(invalid)?)?;
        // Setting events can change SMM and discard nested state. KVM also
        // checks the current SMM mode when loading a suspended VMX guest.
        if let Some(nested) = &self.nested {
            if prepared_smm {
                nested.verify_suspended_root(cpu, self.nested_capacity as usize)?;
            } else {
                nested.restore(cpu, self.nested_capacity as usize)?;
            }
        }
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
