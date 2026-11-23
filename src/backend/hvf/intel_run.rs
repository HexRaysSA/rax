//! Owner-thread Intel entry with call-local host deadlines.
use super::*;
use crate::backend::intel_hvf_deadline::{self as deadline, TimerPolicy};
use std::time::Duration;

enum EntryError {
    Fatal(Error),
    EventDeliveryStopped { gpa: u64 },
}

impl From<Error> for EntryError {
    fn from(error: Error) -> Self {
        Self::Fatal(error)
    }
}

impl HvfCore {
    pub(super) fn run(&mut self) -> Result<VcpuExit> {
        self.execution_ready()?;
        let result =
            run_loop::run_with_entry(self, |core| core.enter_native(None)).and_then(|exit| {
                exit.ok_or_else(|| {
                    Error::Emulator("unbounded native entry returned a scheduling yield".into())
                        .into()
                })
            });
        self.entry_result(result)
    }

    pub(super) fn run_host_slice(&mut self, limit: Duration) -> Result<Option<VcpuExit>> {
        self.run_coordinated_host_slice(limit, false, false)
    }

    pub(super) fn run_coordinated_host_slice(
        &mut self,
        limit: Duration,
        pending_maskable_irq: bool,
        pending_nmi: bool,
    ) -> Result<Option<VcpuExit>> {
        self.execution_ready()?;
        let end = deadline::mach::after(limit)?;
        use interrupt_window::{MASKABLE, NMI};
        let profile = self.native_profile()?;
        let primary = profile.capabilities.primary;
        let watch_irq = pending_maskable_irq && interrupt_window::can_toggle(primary, MASKABLE);
        let watch_nmi =
            pending_nmi && profile.virtual_nmis() && interrupt_window::can_toggle(primary, NMI);
        let mut release = 0;
        let result = run_loop::run_with_entry(self, |core| {
            if watch_irq
                && release & MASKABLE == 0
                && deadline::mach::now() < end
                && event_injection::should_watch_maskable_window(&mut core.event_access())?
                && core.set_interrupt_windows(MASKABLE, true)?
            {
                release |= MASKABLE;
            }
            if watch_nmi
                && release & NMI == 0
                && deadline::mach::now() < end
                && !event_injection::available(
                    &mut core.event_access(),
                    event_injection::Event::Nmi,
                )?
                && core.set_interrupt_windows(NMI, true)?
            {
                release |= NMI;
            }
            let reason = core.enter_native(Some(end))?;
            let window = match reason.map(|raw| raw & (deadline::FAIL_ENTRY | 0xffff)) {
                Some(run_loop::reason::VMX_EXIT_REASON_IRQ_WINDOW) if watch_irq => MASKABLE,
                Some(run_loop::reason::VMX_EXIT_REASON_NMI_WINDOW) if watch_nmi => NMI,
                _ => 0,
            };
            if window != 0 {
                release |= window;
                return Ok(None);
            }
            Ok(reason)
        });
        let result = if release != 0 {
            // The controller still owns its events. The request belongs to
            // this slice and never needs to be reconstructed from a record.
            match (result, self.set_interrupt_windows(release, false)) {
                (result, Ok(_)) | (result @ Err(EntryError::Fatal(_)), Err(_)) => result,
                (_, Err(error)) => Err(error.into()),
            }
        } else {
            result
        };
        self.entry_result(result)
    }

    fn entry_result<T>(&mut self, result: std::result::Result<T, EntryError>) -> Result<T> {
        result.map_err(|error| match error {
            EntryError::Fatal(error) => {
                let failure =
                    format!("HVF native execution failed; guest entry prohibited: {error}");
                self.execution_failure = Some(failure.clone());
                Error::Emulator(failure)
            }
            EntryError::EventDeliveryStopped { gpa } => Error::Emulator(format!(
                "HVF guest event delivery stopped at EPT GPA {gpa:#x} (event retained for retry)"
            )),
        })
    }

    /// Normalize copied control state while leaving the SDK timer under SDK
    /// ownership. The producer's client policy never includes host timer bit6.
    pub(super) fn checkpoint_vmcs_value(&self, field: u32, value: u64) -> Result<u64> {
        if field != hv_vmx_vmcs_field_t::VMCS_CTRL_PIN_BASED as u32 {
            return Ok(value);
        }
        let original = self
            .native_profile()?
            .controls
            .iter()
            .find(|register| register.id == field)
            .ok_or_else(|| Error::InvalidConfig("native pin-control policy is absent".into()))?
            .value;
        TimerPolicy::new(original, value)
            .and_then(|policy| policy.record_value(value))
            .map_err(|error| Error::Emulator(format!("native SDK timer policy: {error:?}")))
    }

    fn enter_native(&mut self, end: Option<u64>) -> std::result::Result<Option<u32>, EntryError> {
        self.execution_ready()?;
        if end.is_some_and(|end| deadline::mach::now() >= end) {
            return Ok(None);
        }
        let pin = hv_vmx_vmcs_field_t::VMCS_CTRL_PIN_BASED;
        let id = self.vcpu_id;
        let memory = self.memory_layout.clone();
        let prepared = native_memory::enter(&memory, || -> Result<_> {
            // A skipped entry must not consume a pending restored clock epoch.
            // Once preparation begins, submit this same deadline to the SDK
            // even if the host interval expires during that preparation.
            if end.is_some_and(|end| deadline::mach::now() >= end) {
                return Ok(None);
            }
            self.checkpoint_vmcs_value(pin as u32, vmcs_read(id, pin)?)?;
            self.prepare_native_clock()?;
            self.priority
                .prepare_entry(&mut priority_native::Host(id))
                .map_err(Error::Emulator)?;
            // SAFETY: this permanent owner holds its live SDK vCPU. enter()
            // retains the admitted RAM/layout guard throughout this synchronous
            // call. The scalar deadline is finite or the documented FOREVER;
            // the SDK retains no borrowed pointer and cannot unwind into Rust.
            Ok(Some(unsafe {
                hv_vcpu_run_until(id, end.unwrap_or(u64::MAX))
            }))
        })?;
        let result = prepared?;
        let Some(result) = result else {
            return Ok(None);
        };
        self.checkpoint_vmcs_value(pin as u32, vmcs_read(self.vcpu_id, pin)?)?;
        if result != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "hv_vcpu_run_until failed: {}",
                hv_error_string(result)
            ))
            .into());
        }
        let raw = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_EXIT_REASON)?;
        let reason = u32::try_from(raw)
            .map_err(|_| Error::Emulator("native exit reason exceeds 32 bits".into()))?;
        if reason & deadline::FAIL_ENTRY != 0 {
            // IDT-vectoring data is not defined for this failed-entry boundary.
            return Ok(Some(reason));
        }
        let vectoring = vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_IDT_VECTORING_INFO)?;
        let vectoring = u32::try_from(vectoring)
            .map_err(|_| Error::Emulator("native IDT-vectoring data exceeds 32 bits".into()))?;
        match deadline::classify(reason, vectoring)
            .map_err(|error| Error::Emulator(format!("native exit admission: {error:?}")))?
        {
            deadline::Exit::HostYield if end.is_some() => Ok(None),
            deadline::Exit::HostYield => Ok(Some(reason)),
            deadline::Exit::Dispatch(reason) => Ok(Some(reason)),
            deadline::Exit::InterruptedEpt => {
                let gpa = self.retain_interrupted_event(vectoring)?;
                Err(EntryError::EventDeliveryStopped { gpa })
            }
        }
    }

    /// SDM Vol. 3C §§28.2.1.3 and 29.2.4–5. Transfer ownership from the
    /// volatile exit record to the checkpointed entry fields before returning
    /// to the caller. Another entry attempts delivery after layout admission.
    fn retain_interrupted_event(&self, vectoring: u32) -> Result<u64> {
        use hv_vmx_vmcs_field_t::*;
        const VALID: u64 = 1 << 31;
        const ERROR_CODE: u64 = 1 << 11;
        const ZERO_LENGTH_INJECTION: u64 = 1 << 30;
        let id = self.vcpu_id;
        let qualification = vmcs_read(id, VMCS_EXIT_QUALIFICATION)?;
        // The continuation covers synchronous data accesses, including IDT
        // reads and delivery stack writes.
        if qualification & 3 == 0 || qualification & ((1 << 2) | (1 << 13) | (3 << 15)) != 0 {
            return Err(Error::Emulator(format!(
                "unsupported EPT qualification {qualification:#x} during event delivery"
            )));
        }
        let gpa = vmcs_read(id, VMCS_GUEST_PHYSICAL_ADDRESS)?;
        // Bit 12 is undefined on exit and reserved on entry.
        let information = u64::from(vectoring & !(1 << 12));
        let event_type = (information >> 8) & 7;
        let vector = information & 0xff;
        let carries_error = information & ERROR_CODE != 0;
        if information & !(VALID | 0xfff) != 0
            || !matches!(event_type, 0 | 2..=6)
            || (event_type == 2 && vector != 2)
            || (event_type == 3 && vector > 31)
            || (carries_error && (event_type != 3 || vmcs_read(id, VMCS_GUEST_CR0)? & 1 == 0))
        {
            return Err(Error::Emulator(format!(
                "invalid VMX IDT-vectoring event {vectoring:#x}"
            )));
        }
        if vmcs_read(id, VMCS_CTRL_VMENTRY_IRQ_INFO)? & VALID != 0 {
            return Err(Error::Emulator(
                "HVF entry event slot occupied after interrupted delivery".into(),
            ));
        }
        let write = |field, value| -> Result<()> {
            vmcs_write(id, field, value)?;
            let observed = vmcs_read(id, field)?;
            if observed != value {
                return Err(Error::Emulator(format!(
                    "HVF event replay field {field:?} readback differs: {observed:#x} != {value:#x}"
                )));
            }
            Ok(())
        };
        if carries_error {
            let error = vmcs_read(id, VMCS_IDT_VECTORING_ERROR_CODE)?;
            if error > u64::from(u16::MAX) {
                return Err(Error::Emulator(
                    "VMX vectoring error code exceeds 16 bits".into(),
                ));
            }
            write(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, error)?;
        }
        if matches!(event_type, 4..=6) {
            let length = vmcs_read(id, VMCS_EXIT_INSTRUCTION_LENGTH)?;
            if length > 15
                || (length == 0
                    && self.native_profile()?.capabilities.misc & ZERO_LENGTH_INJECTION == 0)
            {
                return Err(Error::Emulator(
                    "invalid VMX vectoring instruction length".into(),
                ));
            }
            write(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, length)?;
        }
        if event_type == 2 {
            let state = vmcs_read(id, VMCS_GUEST_INTERRUPTIBILITY_STATE)?;
            // A delivery attempt establishes NMI blocking. Clear only that
            // bit so the same NMI can re-enter and establish blocking again.
            if state & 8 != 0 {
                write(VMCS_GUEST_INTERRUPTIBILITY_STATE, state & !8)?;
            }
        }
        write(VMCS_CTRL_VMENTRY_IRQ_INFO, information)?;
        Ok(gpa)
    }
}
