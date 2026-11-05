//! VM-owned selectable clock, diagnostic tick counter and pending-timer flag.
use super::{ClockMode, ClockState};
use crate::error::{Error, Result};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

enum ClockSource {
    Wall { base: u64, start: Option<Instant> },
    Retired { nanos: u64, units: u64, phase: u8 },
}
impl ClockSource {
    fn mode(&self) -> ClockMode {
        match self {
            Self::Wall { .. } => ClockMode::Wall,
            Self::Retired { .. } => ClockMode::Retired,
        }
    }
    fn advance_retired(&mut self, delta: u64) -> bool {
        let Self::Retired {
            nanos,
            units,
            phase,
        } = self
        else {
            return false;
        };
        let quanta = u128::from(delta) + u128::from(*phase);
        *nanos = nanos.wrapping_add((quanta / 3) as u64);
        *units = units.wrapping_add(delta);
        *phase = (quanta % 3) as u8;
        true
    }
    fn state(&self) -> (u64, u64, u8) {
        match self {
            Self::Wall { base, start } => {
                let elapsed = start.map_or(0, |start| start.elapsed().as_nanos() as u64);
                (base.wrapping_add(elapsed), 0, 0)
            }
            Self::Retired {
                nanos,
                units,
                phase,
            } => (*nanos, *units, *phase),
        }
    }
}
/// A VM's explicitly selected time domain. Clone its Arc into a worker and enter it
/// there explicitly; ambient bindings are local to the calling thread.
pub struct TimingContext {
    clock: Mutex<ClockSource>,
    instructions: AtomicU64,
    timer_pending: AtomicBool,
}
impl Default for TimingContext {
    fn default() -> Self {
        Self::new()
    }
}
impl TimingContext {
    pub fn new() -> Self {
        Self::with_mode(ClockMode::Wall)
    }
    pub fn with_mode(mode: ClockMode) -> Self {
        let clock = match mode {
            ClockMode::Wall => ClockSource::Wall {
                base: 0,
                start: Some(Instant::now()),
            },
            ClockMode::Retired => ClockSource::Retired {
                nanos: 0,
                units: 0,
                phase: 0,
            },
        };
        Self {
            clock: Mutex::new(clock),
            instructions: AtomicU64::new(0),
            timer_pending: AtomicBool::new(false),
        }
    }
    pub fn mode(&self) -> ClockMode {
        self.clock.lock().unwrap_or_else(|p| p.into_inner()).mode()
    }
    pub fn elapsed_nanos(&self) -> u64 {
        self.clock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .state()
            .0
    }
    /// Counter ticks at a caller-supplied platform frequency in Hz.
    /// Samples elapsed nanoseconds and the one-third-nanosecond phase together.
    /// The result is rounded down and wraps at 64 bits; zero Hz returns zero.
    /// The frequency argument does not change the clock or its saved state.
    pub fn counter_ticks(&self, frequency_hz: u64) -> u64 {
        let (nanos, _, phase) = self.clock.lock().unwrap_or_else(|p| p.into_inner()).state();
        super::retired::counter_ticks(nanos, phase, frequency_hz)
    }
    /// Integer rebase: re-anchor wall time or clear only the retirement phase.
    /// Complete checkpoint import uses restore_checkpoint_state to retain phase.
    pub fn set_resume_base(&self, base: u64) {
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        match &mut *clock {
            ClockSource::Wall {
                base: anchor,
                start,
            } => {
                *anchor = base;
                if start.is_some() {
                    *start = Some(Instant::now());
                }
            }
            ClockSource::Retired { nanos, phase, .. } => {
                *nanos = base;
                *phase = 0;
            }
        }
    }
    /// Advance exact thirds of a nanosecond over the entire u64 delta domain.
    /// Wall mode rejects before changing state. Totals/nanoseconds wrap as u64.
    pub fn advance_retired(&self, delta: u64) -> Result<()> {
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        if !clock.advance_retired(delta) {
            return Err(Error::InvalidConfig(
                "retirement advancement requires retired clock mode".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn record_retirement(&self, delta: u64) {
        self.clock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .advance_retired(delta);
    }
    pub fn retirement_count(&self) -> Option<u64> {
        let clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        match &*clock {
            ClockSource::Retired { units, .. } => Some(*units),
            ClockSource::Wall { .. } => None,
        }
    }
    /// Exact at a caller-established quiescent boundary. Tick/notification
    /// writers are independent atomics and must be quiescent during capture.
    pub fn checkpoint_state(&self) -> ClockState {
        let clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        let (elapsed_nanos, retired_units, subnanosecond_quanta) = clock.state();
        ClockState {
            mode: clock.mode(),
            elapsed_nanos,
            retired_units,
            subnanosecond_quanta,
            diagnostic_ticks: self.instructions.load(Ordering::Relaxed),
            timer_pending: self.timer_pending.load(Ordering::Acquire),
        }
    }
    pub fn validate_checkpoint_state(&self, state: &ClockState) -> Result<()> {
        state.validate()?;
        if self.mode() != state.mode {
            return Err(Error::InvalidConfig(
                "clock checkpoint mode does not match target".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn prepare_checkpoint_state(
        &self,
        state: &ClockState,
    ) -> Result<PreparedClockRestore<'_>> {
        self.validate_checkpoint_state(state)?;
        Ok(PreparedClockRestore {
            target: self,
            state: *state,
            stopped: false,
        })
    }
    /// Prepare a wall-clock import that remains frozen through RAM and device
    /// publication. Its native owner resumes it at the common first-entry gate.
    pub(crate) fn prepare_stopped_checkpoint_state(
        &self,
        state: &ClockState,
    ) -> Result<PreparedClockRestore<'_>> {
        let mut prepared = self.prepare_checkpoint_state(state)?;
        if state.mode != ClockMode::Wall {
            return Err(Error::InvalidConfig(
                "stopped native publication requires wall clock mode".into(),
            ));
        }
        prepared.stopped = true;
        Ok(prepared)
    }
    /// Check the canonical phase before applying any native clock setters.
    /// The owner excludes independent clock writers through activation.
    pub(crate) fn is_stopped_at(&self, nanos: u64) -> bool {
        matches!(
            &*self.clock.lock().unwrap_or_else(|p| p.into_inner()),
            ClockSource::Wall { base, start: None } if *base == nanos
        )
    }
    /// Resume once at the owner's measured entry instant. Publication work
    /// since that instant counts as runtime; repeated calls do not re-anchor.
    pub(crate) fn resume_wall_at(&self, at: Instant) -> bool {
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        let ClockSource::Wall { start, .. } = &mut *clock else {
            return false;
        };
        if start.is_some() {
            return false;
        }
        *start = Some(at);
        true
    }
    pub fn restore_checkpoint_state(&self, state: &ClockState) -> Result<()> {
        self.prepare_checkpoint_state(state)?.commit();
        Ok(())
    }
    fn apply_checkpoint_state(&self, state: &ClockState, stopped: bool) {
        // Mode is immutable after construction; the prepared token admitted it.
        let mut clock = self.clock.lock().unwrap_or_else(|p| p.into_inner());
        *clock = match state.mode {
            ClockMode::Wall => ClockSource::Wall {
                base: state.elapsed_nanos,
                start: (!stopped).then(Instant::now),
            },
            ClockMode::Retired => ClockSource::Retired {
                nanos: state.elapsed_nanos,
                units: state.retired_units,
                phase: state.subnanosecond_quanta,
            },
        };
        self.instructions
            .store(state.diagnostic_ticks, Ordering::Relaxed);
        self.timer_pending
            .store(state.timer_pending, Ordering::Release);
    }
    pub fn tick(&self) -> u64 {
        self.instructions
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
    pub fn instruction_count(&self) -> u64 {
        self.instructions.load(Ordering::Relaxed)
    }
    pub fn set_timer_pending(&self) {
        self.timer_pending.store(true, Ordering::Release);
    }
    pub fn take_timer_pending(&self) -> bool {
        self.timer_pending.swap(false, Ordering::AcqRel)
    }
    pub fn is_timer_pending(&self) -> bool {
        self.timer_pending.load(Ordering::Acquire)
    }
    /// Preserve the old reset contract: diagnostic ticks/notification only.
    /// Neither wall nor retirement time/phase/units are changed.
    pub fn reset(&self) {
        self.instructions.store(0, Ordering::Relaxed);
        self.timer_pending.store(false, Ordering::Release);
    }
    pub fn enter(self: &Arc<Self>) -> TimingGuard {
        let token = Rc::new(());
        CURRENT.with(|stack| {
            stack.borrow_mut().push(Binding {
                token: token.clone(),
                clock: self.clone(),
            })
        });
        TimingGuard { token }
    }

    /// Capture the caller's binding for an explicitly dispatched worker request.
    /// The worker must enter and drop its own guard; guards remain thread-bound.
    pub(crate) fn current() -> Option<Arc<Self>> {
        CURRENT.with(|stack| stack.borrow().last().map(|binding| binding.clock.clone()))
    }
}
struct Binding {
    token: Rc<()>,
    clock: Arc<TimingContext>,
}
thread_local! { static CURRENT: RefCell<Vec<Binding>> = const { RefCell::new(Vec::new()) }; }
/// Thread-bound scope. Dropping nested guards out of order removes only the
/// matching binding, leaving the latest surviving context active.
pub struct TimingGuard {
    token: Rc<()>,
}
impl Drop for TimingGuard {
    fn drop(&mut self) {
        let _ = CURRENT.try_with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(index) = stack.iter().position(|b| Rc::ptr_eq(&b.token, &self.token)) {
                stack.remove(index);
            }
        });
    }
}
pub(super) fn with_current<T>(f: impl FnOnce(&TimingContext) -> T) -> Option<T> {
    // Release the TLS borrow before calling code that can enter another scope.
    let clock = CURRENT.with(|stack| stack.borrow().last().map(|b| b.clock.clone()));
    clock.map(|clock| f(&clock))
}

/// Validated target/mode binding; publication allocates nothing and cannot fail.
pub(crate) struct PreparedClockRestore<'a> {
    target: &'a TimingContext,
    state: ClockState,
    stopped: bool,
}
impl PreparedClockRestore<'_> {
    pub(crate) fn commit(self) {
        self.target
            .apply_checkpoint_state(&self.state, self.stopped);
    }
}

#[cfg(test)]
#[path = "stopped_tests.rs"]
mod tests;
