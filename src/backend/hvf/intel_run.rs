//! Owner-thread Intel entry with call-local host deadlines.
use super::*;
use crate::backend::intel_hvf_deadline::{self as deadline, TimerPolicy};
use std::time::Duration;

impl HvfCore {
    pub(super) fn run(&mut self) -> Result<VcpuExit> {
        self.execution_ready()?;
        let result = run_loop::run(self);
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
            let cleared = self.set_interrupt_windows(release, false);
            result.and_then(|exit| cleared.map(|_| exit))
        } else {
            result
        };
        self.entry_result(result)
    }

    fn entry_result<T>(&mut self, result: Result<T>) -> Result<T> {
        result.map_err(|error| {
            let failure = format!("HVF native execution failed; guest entry prohibited: {error}");
            self.execution_failure = Some(failure.clone());
            Error::Emulator(failure)
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

    pub(super) fn next_unbounded_reason(&mut self) -> Result<u32> {
        self.enter_native(None)?.ok_or_else(|| {
            Error::Emulator("unbounded native entry returned an unexpected scheduling yield".into())
        })
    }

    fn enter_native(&mut self, end: Option<u64>) -> Result<Option<u32>> {
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
            )));
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
        }
    }
}
