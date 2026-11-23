//! One resume epoch for the SDK virtual counters of all native vCPUs.
use super::*;
use crate::backend::arm64_hvf_context::VtimerSnapshot;
use crate::backend::intel_hvf_deadline::mach;

#[derive(Default)]
pub(super) enum VtimerClock {
    #[default]
    Host,
    Restored {
        source_tick: u64,
        adjustment: Option<u64>,
    },
}

impl VtimerClock {
    pub(super) fn restore(snapshot: Option<VtimerSnapshot>, rollback: bool) -> Self {
        match snapshot {
            Some(snapshot) if !rollback || snapshot.waiting_for_entry => Self::Restored {
                source_tick: snapshot.tick,
                adjustment: None,
            },
            // Shared GIC rollback is available only in an unentered target.
            // Its original clock either still awaited entry or used host time.
            _ => Self::Host,
        }
    }

    pub(super) fn capture(&self) -> Result<VtimerSnapshot> {
        let (tick, waiting_for_entry) = match self {
            Self::Host => (mach::now(), false),
            Self::Restored {
                adjustment: Some(value),
                ..
            } => (mach::now().wrapping_sub(*value), false),
            Self::Restored {
                source_tick,
                adjustment: None,
            } => (*source_tick, true),
        };
        Ok(VtimerSnapshot {
            tick,
            timebase: mach::timebase()?,
            waiting_for_entry,
        })
    }
}

impl NativeVmLifetime {
    pub(super) fn lock_vtimer_clock(&self) -> Result<std::sync::MutexGuard<'_, VtimerClock>> {
        self.vtimer_clock
            .lock()
            .map_err(|_| Error::Emulator("native virtual timer clock lock poisoned".into()))
    }
}

impl HvfArm64Core {
    pub(super) fn checkpoint_vtimer_offset(&self) -> Result<u64> {
        let mut offset = 0;
        // SAFETY: the permanent owner retains the SDK CPU and output word.
        checkpoint_api::check(
            unsafe { hv_vcpu_get_vtimer_offset(self.vcpu, &mut offset) },
            "capture virtual timer offset",
        )?;
        Ok(offset.wrapping_sub(self.vtimer_offset_adjustment))
    }

    pub(super) fn restore_vtimer_offset(&mut self, offset: u64) -> Result<()> {
        // SAFETY: the permanent owner retains the live SDK CPU.
        checkpoint_api::check(
            unsafe { hv_vcpu_set_vtimer_offset(self.vcpu, offset) },
            "restore virtual timer offset",
        )?;
        self.vtimer_offset_adjustment = 0;
        Ok(())
    }

    pub(super) fn prepare_vtimer_entry(&mut self) -> Result<()> {
        let mut clock = self._vm.lock_vtimer_clock()?;
        let VtimerClock::Restored {
            source_tick,
            adjustment,
        } = &mut *clock
        else {
            return Ok(());
        };
        // Apple defines CNTVCT_EL0 as mach_absolute_time minus the SDK offset.
        // Use one adjustment for every PE and keep each original CVAL in its
        // guest tick domain. Retain the epoch only after the first SDK write.
        let value = adjustment.unwrap_or_else(|| mach::now().wrapping_sub(*source_tick));
        if self.vtimer_offset_adjustment != value {
            let offset = self.checkpoint_vtimer_offset()?.wrapping_add(value);
            // SAFETY: this owner holds its live SDK CPU under entry exclusion.
            checkpoint_api::check(
                unsafe { hv_vcpu_set_vtimer_offset(self.vcpu, offset) },
                "rebase virtual timer at first entry",
            )?;
            self.vtimer_offset_adjustment = value;
        }
        *adjustment = Some(value);
        Ok(())
    }
}
