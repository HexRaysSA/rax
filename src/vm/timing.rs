//! Explicit VM wall/retirement clocks and the legacy unbound wall fallback.
//!
//! Bound contexts select their clock source explicitly. Existing VMM constructors
//! default to wall time; explicit constructors and saved bundles select retirement
//! time before device construction.
//! Standalone callers without a binding retain the previous wall-time behavior.

mod context;
mod retired;
pub use context::{TimingContext, TimingGuard};
pub use retired::{ClockMode, ClockState, RETIREMENT_FREQUENCY_HZ};

use crate::host::time::Instant;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Start time of the emulator - all timing is relative to this
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Nanoseconds added to `elapsed_nanos()` so a machine resumed from a checkpoint
/// continues its clock from where the checkpoint was taken, rather than jumping
/// back to ~0 (which would move the real-time TSC backwards and confuse guest
/// timer math). Set once, early, by [`set_resume_base`].
static RESUME_BASE_NANOS: AtomicU64 = AtomicU64::new(0);

/// Instruction counter - still useful for debugging/profiling
static INSTRUCTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Flag indicating a timer interrupt is pending from the timer thread
static TIMER_PENDING: AtomicBool = AtomicBool::new(false);

/// Simulated CPU frequency in Hz (3 GHz - typical modern CPU)
pub const CPU_FREQUENCY_HZ: u64 = 3_000_000_000;

/// LAPIC timer base frequency in Hz (typically 1 GHz for modern systems)
pub const LAPIC_TIMER_FREQ_HZ: u64 = 1_000_000_000;

/// PIT oscillator frequency (1.193182 MHz - fixed by hardware design)
pub const PIT_FREQUENCY_HZ: u64 = 1193182;

/// Initialize timing (call once at startup)
pub fn init() {
    if context::with_current(|_| ()).is_some() {
        return;
    }
    START_TIME.get_or_init(Instant::now);
}

/// Get elapsed time since emulator start in nanoseconds (plus any resume base,
/// so a restored machine's clock is continuous with the checkpoint).
#[inline(always)]
pub fn elapsed_nanos() -> u64 {
    if let Some(value) = context::with_current(TimingContext::elapsed_nanos) {
        return value;
    }
    let start = START_TIME.get_or_init(Instant::now);
    RESUME_BASE_NANOS
        .load(Ordering::Relaxed)
        .wrapping_add(start.elapsed().as_nanos() as u64)
}

/// Anchor the clock for a checkpoint resume: subsequent `elapsed_nanos()` will
/// read `base + (wall-clock since now)`. Call this once, early in the resume
/// path (before the run loop), with the `elapsed_nanos` captured in the
/// checkpoint. This keeps the real-time TSC and restored device timestamps
/// monotonic across save/restore.
pub fn set_resume_base(base_nanos: u64) {
    if context::with_current(|clock| clock.set_resume_base(base_nanos)).is_some() {
        return;
    }
    // START_TIME is (re-)anchored to "now" if it has not been pinned yet; in the
    // resume path it is first touched here, so `start.elapsed()` begins near 0
    // and `base + elapsed` ~= base at the resume point.
    START_TIME.get_or_init(Instant::now);
    RESUME_BASE_NANOS.store(base_nanos, Ordering::Relaxed);
}

/// Retired contexts expose the exact wrapping retirement-unit counter.
/// Wall/unbound contexts retain the legacy 3000-cycle diagnostic conversion.
#[inline(always)]
pub fn tsc() -> u64 {
    if let Some(value) = retired_counter() {
        return value;
    }
    // Each instruction is worth 3000 TSC cycles (~1000 loop iterations per 1ms delay)
    instruction_count() * 3000
}

/// Exact cycle domain for a selected retirement clock; legacy callers use None.
pub(crate) fn retired_counter() -> Option<u64> {
    context::with_current(TimingContext::retirement_count).flatten()
}

/// Publish one validated successful step to the explicitly bound retired clock.
/// Wall and unbound callers retain their existing time source. Failed attempts,
/// state changes without retirement and diagnostic ticks do not advance time.
pub(crate) fn record_retirement(delta: u64) {
    if delta != 0 {
        context::with_current(|clock| clock.record_retirement(delta));
    }
}

/// Increment the instruction counter (for profiling/debugging)
#[inline(always)]
pub fn tick() -> u64 {
    if let Some(value) = context::with_current(TimingContext::tick) {
        return value;
    }
    INSTRUCTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

/// Get current instruction count
#[inline(always)]
pub fn instruction_count() -> u64 {
    if let Some(value) = context::with_current(TimingContext::instruction_count) {
        return value;
    }
    INSTRUCTION_COUNT.load(Ordering::Relaxed)
}

/// Signal that a timer interrupt is pending
pub fn set_timer_pending() {
    if context::with_current(TimingContext::set_timer_pending).is_some() {
        return;
    }
    TIMER_PENDING.store(true, Ordering::Release);
}

/// Check and clear timer pending flag
pub fn take_timer_pending() -> bool {
    if let Some(value) = context::with_current(TimingContext::take_timer_pending) {
        return value;
    }
    TIMER_PENDING.swap(false, Ordering::AcqRel)
}

/// Check if timer is pending (without clearing)
pub fn is_timer_pending() -> bool {
    if let Some(value) = context::with_current(TimingContext::is_timer_pending) {
        return value;
    }
    TIMER_PENDING.load(Ordering::Acquire)
}

/// Convert nanoseconds to PIT ticks
#[inline(always)]
pub fn nanos_to_pit_ticks(nanos: u64) -> u64 {
    // ticks = nanos * PIT_FREQUENCY_HZ / 1_000_000_000
    // Use 128-bit math to avoid overflow
    ((nanos as u128 * PIT_FREQUENCY_HZ as u128) / 1_000_000_000) as u64
}

/// Reset timing (for VM reset)
pub fn reset() {
    if context::with_current(TimingContext::reset).is_some() {
        return;
    }
    INSTRUCTION_COUNT.store(0, Ordering::Relaxed);
    TIMER_PENDING.store(false, Ordering::Release);
    // Note: START_TIME cannot be reset (OnceLock)
}

// Legacy compatibility - keep these for code that still uses instruction-based timing
pub fn current() -> u64 {
    instruction_count()
}

pub fn insn_to_nanos(insn_count: u64) -> u64 {
    insn_count / 3
}

pub fn nanos_to_insn(nanos: u64) -> u64 {
    nanos.saturating_mul(3)
}

mod epoch;
pub(crate) use epoch::ClockEpoch;

pub(crate) mod calendar;
pub(crate) use calendar::{CalendarClock, DateTime};
