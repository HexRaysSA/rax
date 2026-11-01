//! Host-owned VMX monitor-trap control, independent of guest RFLAGS.TF.
//! Intel SDM December 2024: Vol.3C 27.5.2; Vol.3D Appendix A.3.
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) const MONITOR_TRAP: u64 = 1 << 27;

pub(crate) trait Access {
    fn capability(&mut self) -> Result<u64, String>;
    fn read_control(&mut self) -> Result<u64, String>;
    fn write_control(&mut self, value: u64) -> Result<(), String>;
}

#[derive(Default)]
pub(crate) struct State {
    enabled: AtomicBool,
    completed: AtomicBool,
    failure: Mutex<Option<String>>,
}

impl State {
    pub(crate) fn checkpoint(&self) -> Result<(bool, bool, Option<String>), String> {
        let failure = self
            .failure
            .lock()
            .map_err(|_| "HVF debug failure latch poisoned".to_string())?
            .clone();
        Ok((
            self.enabled(),
            self.completed.load(Ordering::Acquire),
            failure,
        ))
    }
    pub(crate) fn from_checkpoint(
        enabled: bool,
        completed: bool,
        failure: Option<String>,
    ) -> Result<Self, String> {
        if (completed && !enabled)
            || failure
                .as_ref()
                .is_some_and(|error| error.len() > 16 * 1024)
        {
            return Err("invalid native debug checkpoint".into());
        }
        Ok(Self {
            enabled: AtomicBool::new(enabled),
            completed: AtomicBool::new(completed),
            failure: Mutex::new(failure),
        })
    }
    pub(crate) fn ready(&self) -> Result<(), String> {
        self.failure
            .lock()
            .map_err(|_| "HVF debug failure latch poisoned".to_string())?
            .clone()
            .map_or(Ok(()), Err)
    }

    pub(crate) fn poison(&self, reason: String) -> String {
        let error = format!("HVF debug control failed; entry and capture prohibited: {reason}");
        if let Ok(mut failure) = self.failure.lock() {
            if failure.is_none() {
                *failure = Some(error.clone());
            }
        }
        error
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Unsupported enable requests leave ordinary execution available. Host
    /// failures fence the owner unless the original full control word is proved
    /// restored. No guest-register access exists in this interface.
    pub(crate) fn configure(&self, host: &mut impl Access, enabled: bool) -> Result<(), String> {
        self.ready()?;
        let capability = host.capability().map_err(|error| self.poison(error))?;
        let required = u64::from(capability as u32);
        let allowed = capability >> 32;
        if required & !allowed != 0 {
            return Err(self.poison("inconsistent VMX processor capability masks".into()));
        }
        if enabled && allowed & MONITOR_TRAP == 0 {
            return Err("VMX monitor-trap control is unavailable".into());
        }
        if !enabled && required & MONITOR_TRAP != 0 {
            return Err(self.poison("VMX monitor-trap control cannot be disabled".into()));
        }
        let before = host.read_control().map_err(|error| self.poison(error))?;
        if before >> 32 != 0 || before & required != required || before & !allowed != 0 {
            return Err(self.poison("VMCS processor controls violate capability masks".into()));
        }
        if (before & MONITOR_TRAP != 0) != self.enabled() {
            return Err(self.poison("VMCS monitor-trap ownership differs from host state".into()));
        }
        let after = if enabled {
            before | MONITOR_TRAP
        } else {
            before & !MONITOR_TRAP
        };
        if after != before {
            let write = host.write_control(after);
            let verified = if write.is_ok() {
                host.read_control()
            } else {
                Err("write failed".into())
            };
            if write.is_err()
                || verified.as_ref().is_ok_and(|value| *value != after)
                || verified.is_err()
            {
                let reason = write
                    .err()
                    .or_else(|| verified.err())
                    .unwrap_or_else(|| "VMCS monitor-trap readback differs".into());
                let restored = host.write_control(before).is_ok()
                    && host.read_control().is_ok_and(|value| value == before);
                return if restored {
                    Err(format!(
                        "VMX monitor-trap update rejected; original controls restored: {reason}"
                    ))
                } else {
                    Err(self.poison(format!("{reason}; control rollback could not be verified")))
                };
            }
        }
        self.enabled.store(enabled, Ordering::Release);
        self.discard_completion();
        Ok(())
    }

    /// Called only after every architectural write for an emulated instruction
    /// has succeeded. Fault injection and incomplete device requests do not call it.
    pub(crate) fn complete_instruction(&self) {
        if self.enabled() {
            self.completed.store(true, Ordering::Release);
        }
    }

    pub(crate) fn take_completion(&self) -> Result<bool, String> {
        self.ready()?;
        Ok(self.completed.swap(false, Ordering::AcqRel) && self.enabled())
    }

    pub(crate) fn discard_completion(&self) {
        self.completed.store(false, Ordering::Release);
    }

    /// MTF can stop after an instruction, a REP iteration, or event delivery;
    /// it is a debug boundary and is not an exact retirement counter.
    pub(crate) fn monitor_trap(&self) -> Result<(), String> {
        self.ready()?;
        if !self.enabled() {
            return Err(self.poison("unexpected monitor-trap exit without a host request".into()));
        }
        self.discard_completion();
        Ok(())
    }
}
