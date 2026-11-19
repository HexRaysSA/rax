//! Intel 8253/8254 Programmable Interval Timer (PIT) emulation.
//!
//! The PIT provides three independent 16-bit counters (channels 0-2):
//! - Channel 0: System timer, generates IRQ 0
//! - Channel 1: Originally DRAM refresh (not used in modern systems)
//! - Channel 2: PC speaker (gated by port 0x61 bit 0, OUT readable at bit 5)
//!
//! I/O ports:
//! - 0x40: Channel 0 data
//! - 0x41: Channel 1 data
//! - 0x42: Channel 2 data
//! - 0x43: Mode/Command register
//!
//! Timing is based on wall-clock time for real-time behavior: each channel's
//! current count and OUT level are derived from the number of PIT oscillator
//! ticks elapsed since the counter was (re)loaded.
//!
//! ## Operating modes implemented
//! - Mode 0 (interrupt on terminal count): OUT low after reload, goes high when
//!   the count reaches 0 and stays high.
//! - Mode 1 (hardware retriggerable one-shot): a GATE rising edge starts or
//!   reloads a low OUT pulse on the following oscillator tick.
//! - Mode 2 (rate generator): OUT high, pulses low for one tick at terminal
//!   count, reloads and repeats.
//! - Mode 3 (square wave): OUT toggles, ~50% duty cycle, reloads each half period.
//! - Mode 4 (software-triggered strobe): OUT high, strobes low for one tick when
//!   the count reaches 0, then stays high until reprogrammed.
//! - Mode 5 (hardware-triggered strobe): a GATE rising edge schedules one low
//!   OUT tick at terminal count.

use crate::vm::timing;
use serde::{Deserialize, Serialize};

use super::bus::IoDevice;

mod periodic;
#[cfg(test)]
mod periodic_tests;
mod software_loaded;
mod triggered;
use periodic::{PeriodicCounter, PeriodicMode};
use software_loaded::{SoftwareCounter, SoftwareMode};
use triggered::{TriggeredCounter, TriggeredMode};

/// PIT oscillator frequency (1.193182 MHz). Re-exported from [`timing`] so the
/// constant is documented alongside the device; the actual nanos<->tick math
/// lives in [`timing::nanos_to_pit_ticks`].
#[cfg(test)]
const PIT_FREQUENCY: u64 = timing::PIT_FREQUENCY_HZ;

/// Default reload value for ~100 Hz (10ms period)
const DEFAULT_RELOAD: u16 = 11932;

/// Counter access mode (control-word bits 5:4). The latch command (RW field 0)
/// is handled as a transient action and never becomes a persistent access mode,
/// so it is not represented here.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum AccessMode {
    LowByteOnly,
    HighByteOnly,
    LowHighByte,
}

impl AccessMode {
    /// Encode this access mode into the 2-bit RW field used in the control
    /// word / read-back status byte (bits 5:4).
    fn rw_bits(self) -> u8 {
        match self {
            AccessMode::LowByteOnly => 1,
            AccessMode::HighByteOnly => 2,
            AccessMode::LowHighByte => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum OperatingMode {
    InterruptOnTerminalCount,     // Legacy mode 0 record
    HardwareRetriggerableOneShot, // Legacy mode 1 record
    RateGenerator,                // Legacy mode 2 record and power-on default
    SquareWaveGenerator,          // Legacy mode 3 record
    SoftwareTriggeredStrobe,      // Legacy mode 4 record
    HardwareTriggeredStrobe,      // Legacy mode 5 record
    GateTriggered(TriggeredCounter),
    SoftwareLoaded(SoftwareCounter),
    Periodic(PeriodicCounter),
}

impl OperatingMode {
    /// The 3-bit mode field as it appears in the control / status byte.
    /// Modes 6/7 are aliases of 2/3 and are normalised to 2/3 here.
    fn mode_bits(self) -> u8 {
        match self {
            OperatingMode::InterruptOnTerminalCount => 0,
            OperatingMode::HardwareRetriggerableOneShot => 1,
            OperatingMode::RateGenerator => 2,
            OperatingMode::SquareWaveGenerator => 3,
            OperatingMode::SoftwareTriggeredStrobe => 4,
            OperatingMode::HardwareTriggeredStrobe => 5,
            OperatingMode::GateTriggered(counter) => counter.mode_bits(),
            OperatingMode::SoftwareLoaded(counter) => counter.mode_bits(),
            OperatingMode::Periodic(counter) => counter.mode_bits(),
        }
    }

    fn tracks_oscillator_phase(self) -> bool {
        matches!(
            self,
            Self::GateTriggered(_) | Self::SoftwareLoaded(_) | Self::Periodic(_)
        )
    }
}

/// Tracks which byte of a lo/hi access the read or write flip-flop expects next.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum BytePhase {
    Low,
    High,
}

/// The 8254 can latch the status byte and counter independently.
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(try_from = "Option<u32>", into = "Option<u32>")]
struct ReadBackLatch {
    count: Option<u32>,
    status: Option<u8>,
    /// A low byte was read from the live counter before this count was latched.
    live_high: bool,
}

impl ReadBackLatch {
    // The existing wire slot holds a 16-bit count, or bit 16 plus a pending
    // high byte. Use otherwise unused high bits for the new status latch.
    const COUNT_MASK: u32 = 0x1ffff;
    const NO_COUNT: u32 = Self::COUNT_MASK;
    const STATUS_SHIFT: u32 = 17;
    const STATUS_PENDING: u32 = 1 << 25;
    const LIVE_HIGH: u32 = 1 << 26;
    const HIGH_BYTE_ONLY: u32 = 1 << 16;
    const MAX_COUNT: u32 = Self::HIGH_BYTE_ONLY | 0xff;

    fn finish_count(&mut self) -> BytePhase {
        self.count = None;
        if std::mem::take(&mut self.live_high) {
            BytePhase::High
        } else {
            BytePhase::Low
        }
    }
}

impl TryFrom<Option<u32>> for ReadBackLatch {
    type Error = &'static str;

    fn try_from(saved: Option<u32>) -> Result<Self, Self::Error> {
        let Some(word) = saved else {
            return Ok(Self::default());
        };
        let live_high = word & Self::LIVE_HIGH != 0;
        let status_pending = word & Self::STATUS_PENDING != 0;
        let (count, status) = if live_high || status_pending {
            let status = (word >> Self::STATUS_SHIFT) as u8;
            if word >> 27 != 0 || (!status_pending && status != 0) {
                return Err("reserved PIT read-back latch bits are set");
            }
            let count = word & Self::COUNT_MASK;
            (
                (count != Self::NO_COUNT).then_some(count),
                status_pending.then_some(status),
            )
        } else {
            (Some(word), None)
        };
        if count.is_some_and(|count| count > Self::MAX_COUNT) || (live_high && count.is_none()) {
            return Err("invalid PIT counter latch");
        }
        Ok(Self {
            count,
            status,
            live_high,
        })
    }
}

impl From<ReadBackLatch> for Option<u32> {
    fn from(latch: ReadBackLatch) -> Self {
        if latch.status.is_none() && !latch.live_high {
            return latch.count;
        }
        let mut word = latch.count.unwrap_or(ReadBackLatch::NO_COUNT);
        if let Some(status) = latch.status {
            word |=
                ReadBackLatch::STATUS_PENDING | (u32::from(status) << ReadBackLatch::STATUS_SHIFT);
        }
        if latch.live_high {
            word |= ReadBackLatch::LIVE_HIGH;
        }
        Some(word)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Channel {
    reload_value: u16,
    count: u16,
    access_mode: AccessMode,
    operating_mode: OperatingMode,
    /// BCD counting selected (control word bit 0).
    bcd: bool,
    read_latch: ReadBackLatch,
    write_latch: Option<u8>,
    /// Read flip-flop phase for LowHighByte access (which byte is next).
    read_phase: BytePhase,
    gate: bool,
    output: bool,
    /// Null-count flag: set when a new reload value is written into the control
    /// logic but not yet transferred into the actual counting element. Cleared
    /// once counting actually starts. Reported by the read-back status command.
    null_count: bool,
    /// Wall-clock nanoseconds at which the current count period started. The
    /// live count/OUT level is derived from the ticks elapsed since this point.
    loaded_at_nanos: u64,
}

impl Default for Channel {
    fn default() -> Self {
        Channel {
            reload_value: DEFAULT_RELOAD,
            count: DEFAULT_RELOAD,
            access_mode: AccessMode::LowHighByte,
            operating_mode: OperatingMode::RateGenerator,
            bcd: false,
            read_latch: ReadBackLatch::default(),
            write_latch: None,
            read_phase: BytePhase::Low,
            gate: true,
            output: false,
            null_count: false,
            loaded_at_nanos: 0,
        }
    }
}

impl Channel {
    /// Effective reload period in PIT ticks. Zero denotes the full count range.
    fn period(&self) -> u32 {
        if self.reload_value == 0 {
            if self.bcd { 10_000 } else { 65_536 }
        } else {
            self.reload_value as u32
        }
    }

    fn advance_clocked(&mut self, now: u64) -> Option<u64> {
        if !self.operating_mode.tracks_oscillator_phase() {
            return None;
        }
        let tick = timing::nanos_to_pit_ticks(now);
        let period = self.period();
        let (edges, loaded, sample) = match &mut self.operating_mode {
            OperatingMode::GateTriggered(counter) => {
                let loaded = counter.transfer(tick, self.reload_value);
                let sample = counter
                    .sample(tick, self.reload_value, self.bcd)
                    .unwrap_or((self.count, true));
                (0, loaded, sample)
            }
            OperatingMode::SoftwareLoaded(counter) => {
                let partial = self.write_latch.is_some();
                let (edges, loaded) = counter.advance(tick, period, self.gate, partial);
                (edges, loaded, counter.sample(self.count, self.bcd, partial))
            }
            OperatingMode::Periodic(counter) => {
                let (edges, loaded) = counter.advance(tick, period, self.gate, self.null_count);
                (
                    edges,
                    loaded,
                    counter.sample(self.count, self.gate, self.bcd),
                )
            }
            _ => return None,
        };
        if loaded {
            self.null_count = false;
        }
        (self.count, self.output) = sample;
        Some(edges)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Pit {
    channels: [Channel; 3],
    /// Wall-clock nanoseconds at last tick
    last_tick_nanos: u64,
    irq_pending: bool,
    tick_count: u64,
}

impl Pit {
    pub fn new() -> Self {
        let now = timing::elapsed_nanos();
        let mut channels = [Channel::default(), Channel::default(), Channel::default()];
        for ch in &mut channels {
            ch.loaded_at_nanos = now;
        }
        // Channel 2's gate is driven externally (port 0x61 bit 0) and starts low.
        channels[2].gate = false;
        Pit {
            channels,
            last_tick_nanos: now,
            irq_pending: false,
            tick_count: 0,
        }
    }

    /// The managed native PC starts with no scheduled timer until the guest
    /// programs a count. Keep the software machines' historical boot default.
    pub(crate) fn new_unprogrammed() -> Self {
        let mut pit = Self::new();
        for channel in &mut pit.channels {
            channel.reload_value = 0;
            channel.count = 0;
            channel.operating_mode =
                OperatingMode::SoftwareLoaded(SoftwareCounter::new(SoftwareMode::TerminalCount));
            channel.null_count = true;
        }
        pit
    }

    /// Legacy managed KVM files serialized the untouched userspace placeholder
    /// while kernel PIT2 owned all timer ports. Treat that precise placeholder
    /// as an unprogrammed timer, the historical result of rebuilding KVM PIT2.
    pub(crate) fn admit_legacy_native_phase(&mut self) {
        if self.tick_count == 0
            && !self.irq_pending
            && self.channels.iter().enumerate().all(|(index, channel)| {
                channel.operating_mode == OperatingMode::RateGenerator
                    && channel.access_mode == AccessMode::LowHighByte
                    && channel.reload_value == DEFAULT_RELOAD
                    && channel.count == DEFAULT_RELOAD
                    && channel.gate == (index != 2)
                    && !channel.bcd
                    && !channel.output
                    && !channel.null_count
                    && channel.loaded_at_nanos == self.last_tick_nanos
                    && channel.read_latch.count.is_none()
                    && channel.read_latch.status.is_none()
                    && channel.write_latch.is_none()
                    && channel.read_phase == BytePhase::Low
            })
        {
            *self = Self::new_unprogrammed();
        }
    }

    pub(crate) fn has_latched_status(&self) -> bool {
        self.channels
            .iter()
            .any(|ch| ch.read_latch.status.is_some())
    }

    pub(crate) fn has_latched_live_high(&self) -> bool {
        self.channels.iter().any(|ch| ch.read_latch.live_high)
    }

    pub(crate) fn has_gate_triggered_counter(&self) -> bool {
        self.channels
            .iter()
            .any(|ch| matches!(ch.operating_mode, OperatingMode::GateTriggered(_)))
    }

    pub(crate) fn valid_gate_trigger_state(&self) -> bool {
        self.channels.iter().enumerate().all(|(channel, ch)| {
            if let OperatingMode::GateTriggered(counter) = ch.operating_mode {
                counter.valid(channel == 2, ch.null_count)
            } else {
                true
            }
        })
    }

    pub(crate) fn has_software_loaded_counter(&self) -> bool {
        self.channels
            .iter()
            .any(|ch| matches!(ch.operating_mode, OperatingMode::SoftwareLoaded(_)))
    }

    pub(crate) fn valid_software_loaded_state(&self) -> bool {
        self.channels.iter().all(|ch| {
            if let OperatingMode::SoftwareLoaded(counter) = ch.operating_mode {
                let partial = ch.write_latch.is_some();
                (!partial || ch.access_mode == AccessMode::LowHighByte)
                    && counter.valid(ch.null_count, partial, ch.bcd)
            } else {
                true
            }
        })
    }

    pub(crate) fn has_periodic_counter(&self) -> bool {
        self.channels
            .iter()
            .any(|ch| matches!(ch.operating_mode, OperatingMode::Periodic(_)))
    }

    pub(crate) fn valid_periodic_state(&self) -> bool {
        self.channels.iter().all(|ch| match ch.operating_mode {
            OperatingMode::Periodic(counter) => {
                (ch.write_latch.is_none() || ch.access_mode == AccessMode::LowHighByte)
                    && counter.valid(ch.null_count, ch.bcd)
            }
            _ => true,
        })
    }

    /// Sample before changing GATE or the count register so the old inputs
    /// apply through the last completed oscillator edge.
    fn advance_clocked_channel(&mut self, channel: usize, now: u64) -> Option<bool> {
        let edges = self.channels[channel].advance_clocked(now)?;
        let fired = channel == 0 && edges != 0;
        if fired {
            self.irq_pending = true;
            self.tick_count += edges;
        }
        Some(fired)
    }

    /// Check if a timer interrupt is pending
    pub fn has_pending_interrupt(&self) -> bool {
        self.irq_pending
    }

    /// Clear the pending interrupt
    pub fn clear_interrupt(&mut self) {
        self.irq_pending = false;
    }

    /// Earliest time channel 0 will raise its next IRQ in VM nanoseconds.
    /// A native host slice can yield for that boundary even when its current
    /// CPU is blocked in HLT. Rounding up avoids polling before the PIT edge.
    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn next_irq_nanos(&self) -> Option<u64> {
        if self.irq_pending {
            return Some(self.last_tick_nanos);
        }
        let channel = &self.channels[0];
        let period = channel.period();
        let to_nanos = |tick: u64| {
            (u128::from(tick) * 1_000_000_000).div_ceil(u128::from(timing::PIT_FREQUENCY_HZ))
        };
        let deadline = match channel.operating_mode {
            OperatingMode::Periodic(counter) if channel.gate => {
                to_nanos(counter.next_rise(period, channel.null_count)?)
            }
            OperatingMode::SoftwareLoaded(counter) => {
                to_nanos(counter.next_rise(period, channel.gate, channel.write_latch.is_some())?)
            }
            OperatingMode::Periodic(_) | OperatingMode::GateTriggered(_) => return None,
            mode if channel.gate => {
                // Legacy banks track relative time since the load.
                let start = channel.loaded_at_nanos;
                let ticks = timing::nanos_to_pit_ticks(self.last_tick_nanos.saturating_sub(start));
                let period = u64::from(period);
                let next = match mode {
                    OperatingMode::InterruptOnTerminalCount
                    | OperatingMode::HardwareRetriggerableOneShot => period,
                    OperatingMode::SoftwareTriggeredStrobe => period + 1,
                    _ => (ticks / period + 1) * period,
                };
                if next <= ticks {
                    return None;
                }
                u128::from(start) + to_nanos(next)
            }
            _ => return None,
        };
        u64::try_from(deadline).ok()
    }

    // ---- Channel 2 gate / OUT wiring (driven by the 0x61 sysctl device) -----

    /// Set channel 2's GATE input (port 0x61 bit 0).
    pub fn set_channel2_gate(&mut self, level: bool) {
        self.set_channel2_gate_at(level, timing::elapsed_nanos());
    }

    pub(crate) fn set_channel2_gate_at(&mut self, level: bool, elapsed_nanos: u64) {
        let ch = &mut self.channels[2];
        ch.advance_clocked(elapsed_nanos);
        if ch.gate == level {
            return;
        }
        ch.gate = level;
        let tick = timing::nanos_to_pit_ticks(elapsed_nanos);
        match &mut ch.operating_mode {
            OperatingMode::GateTriggered(counter) if level => counter.trigger(tick),
            OperatingMode::Periodic(counter) if level => counter.trigger(tick),
            mode if !mode.tracks_oscillator_phase() => {
                ch.loaded_at_nanos = elapsed_nanos;
                ch.count = ch.reload_value;
            }
            _ => {}
        }
    }

    /// Current channel 2 GATE input level.
    pub fn channel2_gate(&self) -> bool {
        self.channels[2].gate
    }

    /// Current channel 2 OUT level (readable via port 0x61 bit 5).
    ///
    /// Computed from elapsed wall-clock time so polling reflects the live
    /// square-wave / strobe output that calibration loops expect.
    pub fn channel2_out(&self) -> bool {
        self.compute(2).1
    }

    /// Tick the timer - should be called periodically.
    /// Returns true if a (channel 0) timer interrupt should be generated.
    pub fn tick(&mut self) -> bool {
        let now = timing::elapsed_nanos();
        let mut software_edge = false;

        // Refresh the live count/OUT for every channel from elapsed time.
        for channel in 0..3 {
            if let Some(fired) = self.advance_clocked_channel(channel, now) {
                software_edge |= fired;
                continue;
            }
            let (count, output) = self.compute_at(channel, now);
            let ch = &mut self.channels[channel];
            ch.count = count;
            // Once counting has progressed past the initial load the new count
            // has been transferred into the counting element.
            if ch.loaded_at_nanos != now {
                ch.null_count = false;
            }
            ch.output = output;
        }

        // Channel 0 drives IRQ 0. Determine whether the OUT line produced a
        // rising edge (mode 0) or a terminal-count event (modes 2/3/4) since the
        // last tick, using the number of completed periods.
        let fired = self.channels[0].gate && self.channel0_interrupt(now);

        self.last_tick_nanos = now;

        if fired {
            self.irq_pending = true;
            self.tick_count += 1;
        }
        software_edge || fired
    }

    /// Decide whether channel 0 should raise IRQ 0 this tick.
    ///
    /// We compare the elapsed time at the previous tick and at `now`: if at
    /// least one terminal-count boundary was crossed, the timer fired.
    fn channel0_interrupt(&self, now: u64) -> bool {
        let ch = &self.channels[0];
        let period = ch.period() as u64;
        if period == 0 {
            return false;
        }

        let start = ch.loaded_at_nanos;
        let prev = self.last_tick_nanos.max(start);
        if now <= prev {
            return false;
        }

        let ticks_prev = timing::nanos_to_pit_ticks(prev.saturating_sub(start));
        let ticks_now = timing::nanos_to_pit_ticks(now.saturating_sub(start));

        match ch.operating_mode {
            OperatingMode::InterruptOnTerminalCount
            | OperatingMode::HardwareRetriggerableOneShot => {
                // One-shot: fires exactly once, when the count first reaches 0.
                ticks_prev < period && ticks_now >= period
            }
            OperatingMode::SoftwareTriggeredStrobe => {
                // IRQ0 is driven by OUT's rising edge after the one-clock strobe.
                ticks_prev <= period && ticks_now > period
            }
            OperatingMode::RateGenerator
            | OperatingMode::SquareWaveGenerator
            | OperatingMode::HardwareTriggeredStrobe => {
                // Periodic: count how many terminal counts elapsed in (prev, now].
                (ticks_now / period) > (ticks_prev / period)
            }
            // The oscillator-phase modes were advanced before the legacy bank.
            OperatingMode::GateTriggered(_)
            | OperatingMode::SoftwareLoaded(_)
            | OperatingMode::Periodic(_) => false,
        }
    }

    /// Compute the live (count, OUT) pair for a channel from elapsed wall-clock
    /// time, without mutating state. This is the heart of the timing model.
    fn compute(&self, channel: usize) -> (u16, bool) {
        self.compute_at(channel, timing::elapsed_nanos())
    }

    fn compute_at(&self, channel: usize, now: u64) -> (u16, bool) {
        let ch = &self.channels[channel];
        let elapsed = now.saturating_sub(ch.loaded_at_nanos);
        let elapsed_ticks = if ch.operating_mode.tracks_oscillator_phase() {
            timing::nanos_to_pit_ticks(now)
        } else {
            timing::nanos_to_pit_ticks(elapsed)
        };
        self.compute_from_ticks(channel, elapsed_ticks)
    }

    /// Pure (count, OUT) computation for a channel given an explicit number of
    /// PIT oscillator ticks. Legacy modes take ticks since the last reload.
    /// Modes with oscillator phase take ticks since the VM clock epoch. Split out from
    /// [`Self::compute`] so the mode behavior is deterministically testable
    /// without depending on real wall-clock time.
    fn compute_from_ticks(&self, channel: usize, elapsed_ticks: u64) -> (u16, bool) {
        let ch = &self.channels[channel];
        let period = ch.period();

        // With the gate low, level-gated modes (2/3) freeze counting and force a
        // defined OUT level; the count holds at its last value.
        if !ch.gate {
            match ch.operating_mode {
                // For the rate/square modes a low gate forces OUT high.
                OperatingMode::RateGenerator | OperatingMode::SquareWaveGenerator => {
                    return (ch.count, true);
                }
                mode if mode.tracks_oscillator_phase() => {}
                _ => return (ch.count, ch.output),
            }
        }

        match ch.operating_mode {
            OperatingMode::InterruptOnTerminalCount
            | OperatingMode::HardwareRetriggerableOneShot => {
                // Counts down once to 0; OUT starts low, goes high at 0 and holds.
                if elapsed_ticks >= period as u64 {
                    (0, true)
                } else {
                    let remaining = period - elapsed_ticks as u32;
                    (Self::to_count(remaining, period, ch.bcd), false)
                }
            }
            OperatingMode::RateGenerator => {
                // OUT is high except for the single tick where the count is 1->0.
                let pos = (elapsed_ticks % period as u64) as u32;
                let remaining = period - pos; // counts period..1
                let out = remaining != 1;
                (Self::to_count(remaining, period, ch.bcd), out)
            }
            OperatingMode::SquareWaveGenerator => {
                // Square wave: OUT high for the first half, low for the second.
                // The counter is reloaded each half period.
                let half = period / 2;
                let in_period = (elapsed_ticks % period as u64) as u32;
                let out = in_period < half.max(1);
                // Count decrements by 2 each tick (approximated to the half-period
                // window for the purpose of reads).
                let pos_in_half = if out { in_period } else { in_period - half };
                let span = if out { half.max(1) } else { period - half };
                let remaining = span.saturating_sub(pos_in_half).max(1);
                (Self::to_count(remaining * 2, period, ch.bcd), out)
            }
            OperatingMode::SoftwareTriggeredStrobe => {
                let count = wrapped_count(u64::from(period), elapsed_ticks, ch.bcd);
                (count, elapsed_ticks != u64::from(period))
            }
            OperatingMode::HardwareTriggeredStrobe => {
                // OUT high until terminal count, strobes low for exactly one tick.
                if elapsed_ticks >= period as u64 {
                    let pos = (elapsed_ticks % period as u64) as u32;
                    let out = pos != 0; // low only on the exact terminal-count tick
                    let remaining = if pos == 0 { period } else { period - pos };
                    (Self::to_count(remaining, period, ch.bcd), out)
                } else {
                    let remaining = period - elapsed_ticks as u32;
                    (Self::to_count(remaining, period, ch.bcd), true)
                }
            }
            OperatingMode::GateTriggered(counter) => counter
                .sample(elapsed_ticks, ch.reload_value, ch.bcd)
                .unwrap_or((ch.count, true)),
            OperatingMode::SoftwareLoaded(mut counter) => {
                let partial = ch.write_latch.is_some();
                counter.advance(elapsed_ticks, period, ch.gate, partial);
                counter.sample(ch.count, ch.bcd, partial)
            }
            OperatingMode::Periodic(mut counter) => {
                counter.advance(elapsed_ticks, period, ch.gate, ch.null_count);
                counter.sample(ch.count, ch.gate, ch.bcd)
            }
        }
    }

    /// Clamp a raw binary count into the 16-bit counter, honoring BCD when set.
    fn to_count(value: u32, period: u32, bcd: bool) -> u16 {
        let v = value.min(period).max(if value == 0 { 0 } else { 1 });
        if bcd {
            Self::bin_to_bcd(v as u16 % 10000)
        } else {
            v as u16
        }
    }

    /// Convert a binary value (0..=9999) into packed BCD.
    fn bin_to_bcd(mut v: u16) -> u16 {
        v %= 10000;
        ((v / 1000) << 12) | (((v / 100) % 10) << 8) | (((v / 10) % 10) << 4) | (v % 10)
    }

    /// Convert packed BCD back into binary (for written reload values).
    fn bcd_to_bin(v: u16) -> u16 {
        (v >> 12) * 1000 + ((v >> 8) & 0xF) * 100 + ((v >> 4) & 0xF) * 10 + (v & 0xF)
    }

    /// Build the read-back status byte for a channel:
    /// bit7 = OUT, bit6 = null-count, bits5:4 = RW mode, bits3:1 = mode, bit0 = BCD.
    fn status_byte(&self, channel: usize, out: bool) -> u8 {
        let ch = &self.channels[channel];
        let mut status = 0u8;
        if out {
            status |= 1 << 7;
        }
        if ch.null_count {
            status |= 1 << 6;
        }
        status |= ch.access_mode.rw_bits() << 4;
        status |= ch.operating_mode.mode_bits() << 1;
        if ch.bcd {
            status |= 1;
        }
        status
    }

    /// Latch the current (time-computed) count of a channel for reading, unless
    /// a latch is already pending (spec: a second latch before reading is
    /// ignored).
    fn latch_count(&mut self, channel: usize, count: u16) {
        let ch = &mut self.channels[channel];
        if ch.read_latch.count.is_none() {
            ch.read_latch.count = Some(count as u32);
            ch.read_latch.live_high = matches!(ch.read_phase, BytePhase::High);
            ch.read_phase = BytePhase::Low;
        }
    }

    fn read_channel(&mut self, channel: usize) -> u8 {
        // Intel 8254, Read-Back Command: a pending status byte precedes any
        // count bytes, even if the count was latched by an earlier command.
        if let Some(status) = self.channels[channel].read_latch.status.take() {
            return status;
        }
        if let Some(latch) = self.channels[channel].read_latch.count {
            let ch = &mut self.channels[channel];
            match ch.access_mode {
                AccessMode::LowByteOnly => {
                    ch.read_phase = ch.read_latch.finish_count();
                    (latch & 0xFF) as u8
                }
                AccessMode::LowHighByte => {
                    // Check if this is a high-byte-only latch (after first read)
                    // Bit 16 is set for high-byte-only, clear for full 16-bit latch
                    if latch & ReadBackLatch::HIGH_BYTE_ONLY != 0 {
                        // Second read: return the high byte, clear latch
                        ch.read_phase = ch.read_latch.finish_count();
                        (latch & 0xFF) as u8
                    } else {
                        // First read: return low byte, keep high byte for next read
                        ch.read_latch.count = Some(ReadBackLatch::HIGH_BYTE_ONLY | (latch >> 8));
                        ch.read_phase = BytePhase::High;
                        (latch & 0xFF) as u8
                    }
                }
                AccessMode::HighByteOnly => {
                    ch.read_phase = ch.read_latch.finish_count();
                    ((latch >> 8) & 0xFF) as u8
                }
            }
        } else {
            // Calculate current count based on wall-clock time
            let count = self.compute(channel).0;
            let ch = &mut self.channels[channel];
            match ch.access_mode {
                AccessMode::LowByteOnly => (count & 0xFF) as u8,
                AccessMode::HighByteOnly => (count >> 8) as u8,
                AccessMode::LowHighByte => match ch.read_phase {
                    BytePhase::Low => {
                        ch.read_phase = BytePhase::High;
                        (count & 0xFF) as u8
                    }
                    BytePhase::High => {
                        ch.read_phase = BytePhase::Low;
                        (count >> 8) as u8
                    }
                },
            }
        }
    }

    fn write_channel(&mut self, channel: usize, value: u8) {
        let now = timing::elapsed_nanos();
        self.advance_clocked_channel(channel, now);
        let ch = &mut self.channels[channel];

        let mut reloaded = false;
        match ch.access_mode {
            AccessMode::LowByteOnly => {
                // Per spec: "the respective other 8 bits are zeroed"
                ch.reload_value = value as u16;
                reloaded = true;
            }
            AccessMode::HighByteOnly => {
                // Per spec: "the respective other 8 bits are zeroed"
                ch.reload_value = (value as u16) << 8;
                reloaded = true;
            }
            AccessMode::LowHighByte => {
                if let Some(low) = ch.write_latch {
                    // Second byte (high)
                    ch.reload_value = (low as u16) | ((value as u16) << 8);
                    ch.write_latch = None;
                    reloaded = true;
                } else {
                    // First byte (low). The count register and its null flag
                    // update on the second byte in modes with oscillator phase.
                    ch.write_latch = Some(value);
                    match &mut ch.operating_mode {
                        OperatingMode::SoftwareLoaded(counter) => counter.begin_write(),
                        OperatingMode::GateTriggered(_) | OperatingMode::Periodic(_) => {}
                        _ => ch.null_count = true,
                    }
                }
            }
        }

        if reloaded {
            // Decode BCD reload values into a binary divisor for the timing math.
            let mut reload = ch.reload_value;
            if ch.bcd {
                reload = Self::bcd_to_bin(reload);
            }
            ch.reload_value = reload;
            match &mut ch.operating_mode {
                OperatingMode::GateTriggered(counter) => {
                    counter.write_count();
                    ch.null_count = true;
                    return;
                }
                OperatingMode::SoftwareLoaded(counter) => {
                    counter.write_count(timing::nanos_to_pit_ticks(now));
                    ch.null_count = true;
                    return;
                }
                OperatingMode::Periodic(counter) => {
                    counter.write_count(timing::nanos_to_pit_ticks(now));
                    ch.null_count = true;
                    return;
                }
                _ => {}
            }
            ch.count = ch.reload_value;
            ch.loaded_at_nanos = now;
            // The count is now loaded into the counting element.
            ch.null_count = false;
            // Establish the initial OUT level for the new mode.
            ch.output = matches!(
                ch.operating_mode,
                OperatingMode::RateGenerator
                    | OperatingMode::SquareWaveGenerator
                    | OperatingMode::SoftwareTriggeredStrobe
                    | OperatingMode::HardwareTriggeredStrobe
            );
        }
    }

    fn write_command(&mut self, value: u8) {
        let channel = ((value >> 6) & 0x03) as usize;

        if channel == 3 {
            self.read_back(value);
            return;
        }

        let access = (value >> 4) & 0x03;
        let mode = (value >> 1) & 0x07;
        let bcd = value & 0x01 != 0;

        // Access == 0 is the counter-latch command and does NOT reprogram mode.
        if access == 0 {
            self.latch_count(channel, self.compute(channel).0);
            return;
        }

        let now = timing::elapsed_nanos();
        let clocked_counter = self.advance_clocked_channel(channel, now).is_some();
        let ch = &mut self.channels[channel];
        let previous_output = ch.output;

        ch.access_mode = match access {
            1 => AccessMode::LowByteOnly,
            2 => AccessMode::HighByteOnly,
            3 => AccessMode::LowHighByte,
            _ => unreachable!(),
        };

        ch.operating_mode = match mode {
            0 => OperatingMode::SoftwareLoaded(SoftwareCounter::new(SoftwareMode::TerminalCount)),
            1 => OperatingMode::GateTriggered(TriggeredCounter::new(TriggeredMode::OneShot)),
            2 | 6 => OperatingMode::Periodic(PeriodicCounter::new(PeriodicMode::Rate)),
            3 | 7 => OperatingMode::Periodic(PeriodicCounter::new(PeriodicMode::Square)),
            4 => OperatingMode::SoftwareLoaded(SoftwareCounter::new(SoftwareMode::Strobe)),
            5 => OperatingMode::GateTriggered(TriggeredCounter::new(TriggeredMode::Strobe)),
            _ => unreachable!(),
        };

        ch.bcd = bcd;
        ch.write_latch = None;
        ch.read_phase = BytePhase::Low;
        ch.read_latch.live_high = false;
        // A control word sets null count and establishes the initial OUT level.
        ch.null_count = true;
        ch.output = mode != 0;
        if channel == 0 && clocked_counter && !previous_output && ch.output {
            self.irq_pending = true;
            self.tick_count += 1;
        }
    }

    /// Read-back command (8254): control word 0b11xxxxxx.
    /// bit5 = !latch-count, bit4 = !latch-status, bits3:1 = channel select.
    fn read_back(&mut self, value: u8) {
        let latch_count = value & (1 << 5) == 0;
        let latch_status = value & (1 << 4) == 0;
        let now = timing::elapsed_nanos();

        for (channel, bit) in [(0usize, 1u8 << 1), (1, 1 << 2), (2, 1 << 3)] {
            if value & bit == 0 {
                continue;
            }
            let (count, out) = if self.advance_clocked_channel(channel, now).is_some() {
                let ch = &self.channels[channel];
                (ch.count, ch.output)
            } else {
                self.compute_at(channel, now)
            };
            if latch_status {
                let status = self.status_byte(channel, out);
                self.channels[channel]
                    .read_latch
                    .status
                    .get_or_insert(status);
            }
            if latch_count {
                self.latch_count(channel, count);
            }
        }
    }
}

fn wrapped_count(period: u64, elapsed: u64, bcd: bool) -> u16 {
    let modulus = if bcd { 10_000 } else { 65_536 };
    let count = ((period + modulus - elapsed % modulus) % modulus) as u16;
    if bcd { Pit::bin_to_bcd(count) } else { count }
}

impl IoDevice for Pit {
    fn read(&mut self, port: u16) -> u8 {
        match port {
            0x40 => self.read_channel(0),
            0x41 => self.read_channel(1),
            0x42 => self.read_channel(2),
            0x43 => 0xFF, // Command register is write-only
            _ => 0xFF,
        }
    }

    fn write(&mut self, port: u16, value: u8) {
        match port {
            0x40 => self.write_channel(0, value),
            0x41 => self.write_channel(1, value),
            0x42 => self.write_channel(2, value),
            0x43 => self.write_command(value),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a fresh PIT for testing
    fn make_pit() -> Pit {
        // Initialize timing to ensure consistent behavior
        crate::vm::timing::init();
        Pit::new()
    }

    // ========== Basic Construction and Defaults ==========

    #[test]
    fn test_pit_new_default_state() {
        let pit = make_pit();
        assert!(!pit.irq_pending);
        assert_eq!(pit.tick_count, 0);
        assert_eq!(pit.channels[0].reload_value, DEFAULT_RELOAD);
        assert_eq!(pit.channels[0].count, DEFAULT_RELOAD);
    }

    #[test]
    fn test_default_channel_settings() {
        let pit = make_pit();
        // Channels 0 and 1 default gate high; channel 2's gate is externally
        // driven (port 0x61) and starts low.
        for (i, ch) in pit.channels.iter().enumerate() {
            assert_eq!(ch.access_mode, AccessMode::LowHighByte);
            assert!(matches!(ch.operating_mode, OperatingMode::RateGenerator));
            if i == 2 {
                assert!(!ch.gate);
            } else {
                assert!(ch.gate);
            }
            assert!(!ch.output);
            assert!(ch.read_latch.count.is_none());
            assert!(ch.read_latch.status.is_none());
            assert!(ch.write_latch.is_none());
        }
    }

    // ========== I/O Port Mapping ==========

    #[test]
    fn test_io_port_mapping() {
        let mut pit = make_pit();
        assert_eq!(pit.read(0x43), 0xFF);
        assert_eq!(pit.read(0x44), 0xFF);
        assert_eq!(pit.read(0x50), 0xFF);
    }

    // ========== Command Register Parsing ==========

    #[test]
    fn test_command_channel_selection() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        assert_eq!(pit.channels[0].operating_mode.mode_bits(), 3);
        pit.write(0x43, 0x74);
        assert_eq!(pit.channels[1].operating_mode.mode_bits(), 2);
        pit.write(0x43, 0xB0);
        assert_eq!(pit.channels[2].operating_mode.mode_bits(), 0);
    }

    #[test]
    fn test_command_access_mode_parsing() {
        let mut pit = make_pit();
        pit.write(0x43, 0x10);
        assert_eq!(pit.channels[0].access_mode, AccessMode::LowByteOnly);
        pit.write(0x43, 0x20);
        assert_eq!(pit.channels[0].access_mode, AccessMode::HighByteOnly);
        pit.write(0x43, 0x30);
        assert_eq!(pit.channels[0].access_mode, AccessMode::LowHighByte);
    }

    #[test]
    fn test_command_operating_modes() {
        let mut pit = make_pit();
        let cases = [
            (0x30u8, 0),
            (0x32, 1),
            (0x34, 2),
            (0x36, 3),
            (0x38, 4),
            (0x3A, 5),
            (0x3C, 2), // mode 6 -> 2
            (0x3E, 3), // mode 7 -> 3
        ];
        for (cmd, expected) in cases {
            pit.write(0x43, cmd);
            assert_eq!(
                pit.channels[0].operating_mode.mode_bits(),
                expected,
                "cmd {cmd:#x}"
            );
        }
    }

    #[test]
    fn test_bcd_bit_decoded() {
        let mut pit = make_pit();
        // Mode 3, lo/hi, BCD set.
        pit.write(0x43, 0x37);
        assert!(pit.channels[0].bcd);
        // Mode 3, lo/hi, binary.
        pit.write(0x43, 0x36);
        assert!(!pit.channels[0].bcd);
    }

    // ========== Counter Latch Command ==========

    #[test]
    fn test_counter_latch_command() {
        let mut pit = make_pit();
        pit.channels[0].count = 0x1234;
        pit.channels[0].reload_value = 0x1234;
        pit.channels[0].access_mode = AccessMode::LowHighByte;
        pit.channels[0].operating_mode = OperatingMode::InterruptOnTerminalCount;
        pit.channels[0].gate = false; // freeze so compute() returns count
        pit.write(0x43, 0x00);
        assert_eq!(pit.channels[0].read_latch.count, Some(0x1234));
    }

    #[test]
    fn test_counter_latch_preserves_until_read() {
        let mut pit = make_pit();
        pit.channels[0].count = 0xABCD;
        pit.channels[0].reload_value = 0xABCD;
        pit.channels[0].access_mode = AccessMode::LowHighByte;
        pit.channels[0].gate = false;

        pit.write(0x43, 0x00);
        assert_eq!(pit.channels[0].read_latch.count, Some(0xABCD));

        // Change actual count; latched value must persist.
        pit.channels[0].count = 0x1234;

        let low = pit.read(0x40);
        assert_eq!(low, 0xCD);
        let high = pit.read(0x40);
        assert_eq!(high, 0xAB);
        assert!(pit.channels[0].read_latch.count.is_none());
    }

    #[test]
    fn test_multiple_latch_commands_ignored() {
        let mut pit = make_pit();
        pit.channels[0].count = 0x1111;
        pit.channels[0].reload_value = 0x1111;
        pit.channels[0].access_mode = AccessMode::LowHighByte;
        pit.channels[0].gate = false;
        pit.write(0x43, 0x00); // latch

        pit.channels[0].count = 0x2222;
        pit.write(0x43, 0x00); // ignored

        let low = pit.read(0x40);
        let high = pit.read(0x40);
        assert_eq!((high as u16) << 8 | low as u16, 0x1111);
    }

    #[test]
    fn test_latch_does_not_change_mode() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36); // mode 3
        pit.write(0x43, 0x00); // latch command on channel 0
        assert_eq!(pit.channels[0].operating_mode.mode_bits(), 3);
    }

    // ========== Access Modes / flip-flop ==========

    #[test]
    fn test_low_byte_only_write() {
        let mut pit = make_pit();
        pit.write(0x43, 0x10);
        pit.write(0x40, 0x42);
        assert_eq!(pit.channels[0].reload_value, 0x0042);
    }

    #[test]
    fn test_high_byte_only_write() {
        let mut pit = make_pit();
        pit.write(0x43, 0x20);
        pit.write(0x40, 0x42);
        assert_eq!(pit.channels[0].reload_value & 0xFF00, 0x4200);
    }

    #[test]
    fn test_lobyte_hibyte_write_sequence() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        pit.write(0x40, 0x34);
        assert_eq!(pit.channels[0].write_latch, Some(0x34));
        // The control word set NULL COUNT. The first byte leaves it set.
        assert!(pit.channels[0].null_count);
        pit.write(0x40, 0x12);
        assert!(pit.channels[0].write_latch.is_none());
        assert_eq!(pit.channels[0].reload_value, 0x1234);
        // Nothing has sampled the transfer edge yet.
        assert!(pit.channels[0].null_count);
    }

    #[test]
    fn test_read_flip_flop_unlatched_lohi() {
        let mut pit = make_pit();
        pit.channels[0].reload_value = 0xBEEF;
        pit.channels[0].count = 0xBEEF;
        pit.channels[0].access_mode = AccessMode::LowHighByte;
        pit.channels[0].gate = false; // freeze count at 0xBEEF
        // Two consecutive unlatched reads return low then high byte.
        let lo = pit.read(0x40);
        let hi = pit.read(0x40);
        assert_eq!(lo, 0xEF);
        assert_eq!(hi, 0xBE);
        // Flip-flop reset back to low for the next pair.
        let lo2 = pit.read(0x40);
        assert_eq!(lo2, 0xEF);
    }

    #[test]
    fn test_low_byte_only_read() {
        let mut pit = make_pit();
        pit.channels[0].reload_value = 0xABCD;
        pit.channels[0].count = 0xABCD;
        pit.channels[0].access_mode = AccessMode::LowByteOnly;
        pit.channels[0].gate = false;
        assert_eq!(pit.read(0x40), 0xCD);
    }

    #[test]
    fn test_high_byte_only_read() {
        let mut pit = make_pit();
        pit.channels[0].reload_value = 0xABCD;
        pit.channels[0].count = 0xABCD;
        pit.channels[0].access_mode = AccessMode::HighByteOnly;
        pit.channels[0].gate = false;
        assert_eq!(pit.read(0x40), 0xAB);
    }

    // ========== Reload Value of 0 = 65536 ==========

    #[test]
    fn test_reload_value_zero_means_65536() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        pit.write(0x40, 0x00);
        pit.write(0x40, 0x00);
        assert_eq!(pit.channels[0].reload_value, 0);
        assert_eq!(pit.channels[0].period(), 0x10000);
    }

    // ========== Channel 2 Data Port ==========

    #[test]
    fn test_channel_2_read_write() {
        let mut pit = make_pit();
        pit.write(0x43, 0xB6);
        pit.write(0x42, 0xEF);
        pit.write(0x42, 0xBE);
        assert_eq!(pit.channels[2].reload_value, 0xBEEF);
    }

    // ========== Read-Back Command ==========

    #[test]
    fn test_readback_latch_count() {
        let mut pit = make_pit();
        pit.write(0x43, 0x30); // ch0 mode 0, lo/hi
        pit.channels[0].reload_value = 0x1234;
        pit.channels[0].count = 0x1234;
        pit.channels[0].gate = false; // freeze count

        // Read-back: latch count for channel 0.
        // 0b11 channel, bit5=0 latch-count, bit4=1 no status, bit1=1 select ch0.
        // = 1101_0010 = 0xD2
        pit.write(0x43, 0xD2);
        let lo = pit.read(0x40);
        let hi = pit.read(0x40);
        assert_eq!((hi as u16) << 8 | lo as u16, 0x1234);
    }

    #[test]
    fn test_readback_latch_status() {
        let mut pit = make_pit();
        // Configure channel 0: mode 3 (square wave), lo/hi, binary.
        pit.write(0x43, 0x36);
        pit.channels[0].gate = false; // forces OUT high for mode 3
        pit.channels[0].null_count = false;

        // Read-back status only for channel 0:
        // 0b11 channel, bit5=1 no count, bit4=0 latch-status, bit1=1 select ch0.
        // = 1110_0010 = 0xE2
        pit.write(0x43, 0xE2);
        let status = pit.read(0x40);

        // OUT high (gate low forces square-wave OUT high) -> bit7 set.
        assert_eq!(status & 0x80, 0x80, "OUT bit");
        // RW = lo/hi = 11 in bits 5:4.
        assert_eq!((status >> 4) & 0x03, 0x03, "RW bits");
        // Mode = 3 in bits 3:1.
        assert_eq!((status >> 1) & 0x07, 3, "mode bits");
        // BCD clear.
        assert_eq!(status & 0x01, 0, "BCD bit");
    }

    #[test]
    fn test_readback_status_null_count_bit() {
        let mut pit = make_pit();
        // Program control word but do not write a reload value: null count set.
        pit.write(0x43, 0x34); // ch0 mode 2 lo/hi
        assert!(pit.channels[0].null_count);

        pit.write(0x43, 0xE2); // status only, ch0
        let status = pit.read(0x40);
        assert_eq!(status & 0x40, 0x40, "null-count bit should be set");
    }

    #[test]
    fn test_readback_multiple_channels_count() {
        let mut pit = make_pit();
        for (cmd, ch) in [(0x30u8, 0usize), (0x70, 1), (0xB0, 2)] {
            pit.write(0x43, cmd); // mode 0 lo/hi per channel
            pit.channels[ch].reload_value = 0x1000 + ch as u16;
            pit.channels[ch].count = 0x1000 + ch as u16;
            pit.channels[ch].gate = false;
        }
        // Latch count for all three channels at once.
        // bits: 0b11, bit5=0 count, bit4=1 no status, select ch0|ch1|ch2 = bits1,2,3
        // = 1101_1110 = 0xDE
        pit.write(0x43, 0xDE);
        for (port, ch) in [(0x40u16, 0usize), (0x41, 1), (0x42, 2)] {
            let lo = pit.read(port);
            let hi = pit.read(port);
            assert_eq!((hi as u16) << 8 | lo as u16, 0x1000 + ch as u16);
        }
    }

    #[test]
    fn readback_status_and_count_remain_independent_across_restore() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        for (format, status, count) in [
            (0x10, 0x10, &[0x34][..]),
            (0x20, 0x20, &[0x12][..]),
            (0x30, 0x30, &[0x34, 0x12][..]),
        ] {
            at_tick(0);
            let mut source = Pit::new();
            source.write(0x43, 0x80 | format);
            for value in count {
                source.write(0x42, *value);
            }
            at_tick(1);
            source.write(0x43, 0xc8); // Channel 2, latch after the divisor transfers.
            // A second status request must keep the first sampled OUT bit.
            source.set_channel2_gate(true);
            at_tick(65_537);
            assert!(source.channel2_out());
            source.write(0x43, 0xe8);
            for read_status_before_save in [false, true] {
                let mut source = source.clone();
                if read_status_before_save {
                    assert_eq!(source.read(0x42), status);
                }
                let wire = crate::codec::serialize(&source).unwrap();
                let mut restored: Pit = crate::codec::deserialize_strict(&wire).unwrap();
                if !read_status_before_save {
                    assert_eq!(restored.read(0x42), status);
                }
                for value in count {
                    assert_eq!(restored.read(0x42), *value);
                }
                assert!(restored.channels[2].read_latch.count.is_none());
                assert!(restored.channels[2].read_latch.status.is_none());
            }
        }
    }

    #[test]
    fn status_only_leaves_the_live_byte_phase_intact() {
        let mut pit = make_pit();
        let [low, high] = DEFAULT_RELOAD.to_le_bytes();
        assert_eq!(pit.read(0x42), low);
        pit.write(0x43, 0xe8);
        let wire = crate::codec::serialize(&pit).unwrap();
        let mut pit: Pit = crate::codec::deserialize_strict(&wire).unwrap();
        assert_eq!(pit.read(0x42), 0xb4);
        assert_eq!(pit.read(0x42), high);
        assert_eq!(pit.read(0x42), low);
    }

    #[test]
    fn legacy_count_latch_wire_is_unchanged() {
        for count in [None, Some(0), Some(0xffff), Some(0x100ffu32)] {
            let old_bytes = crate::codec::serialize(&count).unwrap();
            let latch: ReadBackLatch = crate::codec::deserialize_strict(&old_bytes).unwrap();
            assert_eq!(latch.count, count);
            assert_eq!(latch.status, None);
            assert_eq!(crate::codec::serialize(&latch).unwrap(), old_bytes);
        }
    }

    #[test]
    fn count_and_status_latches_preserve_a_preexisting_live_high_byte() {
        let mut pit = make_pit();
        let [low, high] = DEFAULT_RELOAD.to_le_bytes();
        assert_eq!(pit.read(0x42), low);
        pit.write(0x43, 0xc8);
        let values = [0xb4, low, high, high, low];
        for consumed in 0..=3 {
            let mut source = pit.clone();
            for &value in &values[..consumed] {
                assert_eq!(source.read(0x42), value);
            }
            let wire = crate::codec::serialize(&source).unwrap();
            let mut restored: Pit = crate::codec::deserialize_strict(&wire).unwrap();
            let observed = values[consumed..]
                .iter()
                .map(|_| restored.read(0x42))
                .collect::<Vec<_>>();
            assert_eq!(
                observed,
                values[consumed..],
                "save after {consumed} latch byte reads"
            );
        }
    }

    #[test]
    fn invalid_readback_latch_words_are_rejected() {
        for word in [
            ReadBackLatch::MAX_COUNT + 1,
            ReadBackLatch::STATUS_PENDING | (ReadBackLatch::MAX_COUNT + 1),
            ReadBackLatch::STATUS_PENDING | (1 << 27),
            ReadBackLatch::LIVE_HIGH | ReadBackLatch::NO_COUNT,
            ReadBackLatch::LIVE_HIGH | (1 << ReadBackLatch::STATUS_SHIFT),
        ] {
            let wire = crate::codec::serialize(&Some(word)).unwrap();
            assert!(crate::codec::deserialize_strict::<ReadBackLatch>(&wire).is_err());
        }
    }

    // ========== Status byte construction ==========

    #[test]
    fn test_status_byte_fields() {
        let mut pit = make_pit();
        pit.write(0x43, 0x77); // ch1, lo/hi, mode 3, BCD
        pit.channels[1].null_count = false;
        pit.channels[1].gate = false; // mode 3 OUT high when gate low
        let s = pit.status_byte(1, pit.compute(1).1);
        assert_eq!(s & 0x80, 0x80); // OUT high
        assert_eq!((s >> 4) & 0x03, 3); // lo/hi
        assert_eq!((s >> 1) & 0x07, 3); // mode 3
        assert_eq!(s & 1, 1); // BCD
    }

    // ========== Interrupt Generation ==========

    #[test]
    fn test_has_pending_interrupt() {
        let mut pit = make_pit();
        assert!(!pit.has_pending_interrupt());
        pit.irq_pending = true;
        assert!(pit.has_pending_interrupt());
    }

    #[test]
    fn test_clear_interrupt() {
        let mut pit = make_pit();
        pit.irq_pending = true;
        pit.clear_interrupt();
        assert!(!pit.irq_pending);
    }

    // ========== Mode OUT-pin behavior ==========

    #[test]
    fn test_mode0_out_low_then_high() {
        let mut pit = make_pit();
        // Mode 0: OUT starts low, goes high at terminal count and holds.
        pit.channels[0].operating_mode = OperatingMode::InterruptOnTerminalCount;
        pit.channels[0].gate = true;
        let period: u16 = 100;
        pit.channels[0].reload_value = period;
        pit.channels[0].count = period;

        // Just loaded (0 ticks elapsed) -> OUT low, count == reload.
        let (c0, out0) = pit.compute_from_ticks(0, 0);
        assert!(!out0, "mode 0 OUT starts low");
        assert_eq!(c0, period);

        // Half way -> still low, count decreased.
        let (c1, out1) = pit.compute_from_ticks(0, 50);
        assert!(!out1);
        assert_eq!(c1, 50);

        // At/after terminal count -> OUT high, count 0.
        let (c2, out2) = pit.compute_from_ticks(0, period as u64);
        assert!(out2, "mode 0 OUT high at terminal count");
        assert_eq!(c2, 0);
        // Stays high afterwards.
        assert!(pit.compute_from_ticks(0, period as u64 + 500).1);
    }

    #[test]
    fn test_mode3_square_wave_out_toggles() {
        let mut pit = make_pit();
        pit.channels[0].operating_mode = OperatingMode::SquareWaveGenerator;
        pit.channels[0].gate = true;
        let period: u64 = 1000; // half = 500
        pit.channels[0].reload_value = period as u16;
        pit.channels[0].count = period as u16;

        // First half (0..500) -> OUT high.
        assert!(
            pit.compute_from_ticks(0, 0).1,
            "start of first half OUT high"
        );
        assert!(
            pit.compute_from_ticks(0, 250).1,
            "middle of first half OUT high"
        );
        assert!(
            pit.compute_from_ticks(0, 499).1,
            "end of first half OUT high"
        );

        // Second half (500..1000) -> OUT low.
        assert!(
            !pit.compute_from_ticks(0, 500).1,
            "start of second half OUT low"
        );
        assert!(
            !pit.compute_from_ticks(0, 750).1,
            "middle of second half OUT low"
        );
        assert!(
            !pit.compute_from_ticks(0, 999).1,
            "end of second half OUT low"
        );

        // Next cycle wraps back to high.
        assert!(
            pit.compute_from_ticks(0, 1000).1,
            "next cycle first half OUT high"
        );
        assert!(
            pit.compute_from_ticks(0, 1250).1,
            "next cycle first half OUT high"
        );
        assert!(
            !pit.compute_from_ticks(0, 1500).1,
            "next cycle second half OUT low"
        );
    }

    #[test]
    fn test_mode2_rate_generator_out_pulse() {
        let mut pit = make_pit();
        pit.channels[0].operating_mode = OperatingMode::RateGenerator;
        pit.channels[0].gate = true;
        let period: u64 = 1000;
        pit.channels[0].reload_value = period as u16;
        pit.channels[0].count = period as u16;

        // OUT is high for almost the whole period.
        let (count, out) = pit.compute_from_ticks(0, 0);
        assert!(out, "rate generator OUT high at start");
        assert_eq!(count, period as u16);

        // OUT high in the middle.
        assert!(pit.compute_from_ticks(0, 500).1);

        // OUT drops low for exactly the single tick where the count would reach 1.
        // remaining == 1 occurs at pos == period - 1.
        let (count_lo, out_lo) = pit.compute_from_ticks(0, period - 1);
        assert!(!out_lo, "rate generator OUT low at terminal count");
        assert_eq!(count_lo, 1);

        // Then reloads and OUT is high again next cycle.
        assert!(
            pit.compute_from_ticks(0, period).1,
            "OUT high again after reload"
        );
    }

    #[test]
    fn test_mode4_strobe_out_high_then_one_tick_low() {
        let mut pit = make_pit();
        pit.channels[0].operating_mode = OperatingMode::SoftwareTriggeredStrobe;
        pit.channels[0].gate = true;
        let period: u64 = 100;
        pit.channels[0].reload_value = period as u16;
        pit.channels[0].count = period as u16;

        // OUT high while counting down.
        assert!(pit.compute_from_ticks(0, 0).1, "mode 4 OUT high at start");
        assert!(pit.compute_from_ticks(0, 50).1, "mode 4 OUT high mid-count");

        // Strobes low for exactly the terminal-count tick.
        assert!(
            !pit.compute_from_ticks(0, period).1,
            "mode 4 strobes low at TC"
        );

        // Returns high on the following tick.
        assert!(
            pit.compute_from_ticks(0, period + 1).1,
            "mode 4 OUT high after strobe"
        );
    }

    #[test]
    fn mode4_has_one_strobe_and_counter_wraps_in_counter_radix() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let mut pit = Pit::new();
        pit.write(0x43, 0x18); // Channel 0, low byte only, mode 4.
        pit.write(0x40, 10);
        assert_eq!(pit.compute_from_ticks(0, 10), (1, true));
        assert_eq!(pit.compute_from_ticks(0, 11), (0, false));
        assert_eq!(pit.compute_from_ticks(0, 12), (0xffff, true));
        assert_eq!(pit.compute_from_ticks(0, 21), (0xfff6, true));
        assert_eq!(pit.compute_from_ticks(0, 11 + (1 << 16)), (0, true));
    }

    #[test]
    fn mode4_bcd_zero_load_wraps_at_four_decimal_digits() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let mut pit = Pit::new();
        pit.write(0x43, 0x19); // Channel 0, low byte only, mode 4, BCD.
        pit.write(0x40, 0);
        assert_eq!(pit.compute_from_ticks(0, 1), (0, true));
        assert_eq!(pit.compute_from_ticks(0, 10_000), (1, true));
        assert_eq!(pit.compute_from_ticks(0, 10_001), (0, false));
        assert_eq!(pit.compute_from_ticks(0, 10_002), (0x9999, true));
        assert_eq!(pit.compute_from_ticks(0, 20_001), (0, true));
    }

    #[test]
    fn mode4_irq_marks_strobe_rising_edge_once_per_load() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let mut pit = Pit::new();
        clock.set_resume_base(0);
        pit.write(0x43, 0x18);
        pit.write(0x40, 10);
        let at_tick = |ticks: u64| {
            clock.set_resume_base((ticks * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        let edges = [11, 12, 20].map(|tick| {
            at_tick(tick);
            let edge = pit.tick();
            pit.clear_interrupt();
            edge
        });
        assert_eq!(edges, [false, true, false]);
    }

    // ========== Channel 2 gate / OUT wiring ==========

    #[test]
    fn mode0_loads_on_the_next_clock_and_preserves_the_count_across_gate_changes() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        at_tick(0);
        let mut pit = Pit::new();
        pit.write(0x43, 0xb0);
        pit.write(0x42, 4);
        pit.write(0x42, 0);
        pit.set_channel2_gate(true);

        at_tick(1);
        assert_eq!(pit.compute(2), (4, false));
        at_tick(3);
        assert_eq!(pit.compute(2), (2, false));
        pit.set_channel2_gate(false);
        at_tick(100);
        assert_eq!(pit.compute(2), (2, false));
        pit.set_channel2_gate(true);
        at_tick(102);
        assert_eq!(pit.compute(2), (0, true));
        at_tick(103);
        assert_eq!(pit.compute(2), (0xffff, true));
    }

    #[test]
    fn mode4_partial_write_leaves_the_current_strobe_armed() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        at_tick(0);
        let mut pit = Pit::new();
        pit.write(0x43, 0x38);
        pit.write(0x40, 4);
        pit.write(0x40, 0);
        at_tick(2);
        pit.write(0x40, 3);
        pit.write(0x43, 0xe2);
        assert_eq!(pit.read(0x40), 0xb8);
        at_tick(5);
        assert_eq!(pit.compute(0), (0, false));
        at_tick(6);
        assert!(pit.tick());
        assert_eq!(pit.compute(0), (0xffff, true));
        pit.write(0x40, 0);
        at_tick(7);
        assert_eq!(pit.compute(0), (3, true));
    }

    #[test]
    fn mode4_strobe_ends_after_one_clock_with_gate_low() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        let mut pit = Pit::new();
        pit.write(0x43, 0x98);
        pit.write(0x42, 2);
        pit.set_channel2_gate(true);
        at_tick(3);
        pit.set_channel2_gate(false);
        assert_eq!(pit.compute(2), (0, false));
        at_tick(4);
        assert_eq!(pit.compute(2), (0, true));
        at_tick(100);
        pit.set_channel2_gate(true);
        at_tick(101);
        assert_eq!(pit.compute(2), (0xffff, true));
    }

    #[test]
    fn replacement_count_keeps_an_unpolled_mode4_irq0_edge() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let mut pit = Pit::new();
        pit.write(0x43, 0x18);
        pit.write(0x40, 2);
        clock.set_resume_base((4u64 * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        pit.write(0x40, 2); // OUT rose on this tick before the write.
        assert!(pit.has_pending_interrupt());
        assert!(!pit.tick());
        pit.clear_interrupt();
        clock.set_resume_base((8u64 * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        assert!(pit.tick());
    }

    #[test]
    fn triggered_one_shot_latches_gate_edges_and_keeps_the_active_divisor() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        let mut pit = Pit::new();
        at_tick(0);
        pit.set_channel2_gate(true);
        pit.write(0x43, 0x92);
        pit.write(0x42, 4);
        let status = |pit: &mut Pit| {
            pit.write(0x43, 0xe8);
            pit.read(0x42)
        };
        at_tick(1);
        assert_eq!(status(&mut pit), 0xd2);
        pit.set_channel2_gate(false);
        pit.set_channel2_gate(true);
        pit.set_channel2_gate(false);
        assert!(pit.channel2_out());
        at_tick(2);
        assert_eq!(status(&mut pit), 0x12);
        assert_eq!(pit.read(0x42), 4);
        at_tick(3);
        pit.write(0x42, 2);
        assert_eq!(status(&mut pit), 0x52);
        assert_eq!(pit.read(0x42), 3);
        at_tick(6);
        assert_eq!(status(&mut pit), 0xd2);
        assert_eq!(pit.read(0x42), 0);
        at_tick(7);
        assert_eq!(pit.read(0x42), 0xff);
        pit.set_channel2_gate(true);
        at_tick(8);
        assert_eq!(status(&mut pit), 0x12);
        assert_eq!(pit.read(0x42), 2);
        at_tick(10);
        assert!(pit.channel2_out());
    }

    #[test]
    fn triggered_strobe_pulses_once_and_the_count_wraps_in_bcd() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        let at_tick = |tick: u64| {
            clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
        };
        let mut pit = Pit::new();
        at_tick(0);
        pit.write(0x43, 0xbb);
        pit.write(0x42, 0);
        pit.write(0x42, 0);
        pit.set_channel2_gate(true);
        at_tick(9_999);
        pit.set_channel2_gate(false);
        for (tick, out, count) in [
            (10_000, true, 0x0001),
            (10_001, false, 0x0000),
            (10_002, true, 0x9999),
            (20_001, true, 0x0000),
        ] {
            at_tick(tick);
            pit.tick();
            pit.write(0x43, 0x80);
            let count_bytes = [pit.read(0x42), pit.read(0x42)];
            assert_eq!(
                (pit.channel2_out(), u16::from_le_bytes(count_bytes)),
                (out, count)
            );
        }
    }

    #[test]
    fn triggered_pc_irq0_requires_an_edge_on_its_hardwired_gate() {
        let clock =
            std::sync::Arc::new(timing::TimingContext::with_mode(timing::ClockMode::Retired));
        let _scope = clock.enter();
        for command in [0x12, 0x1a] {
            clock.set_resume_base(0);
            let mut pit = Pit::new();
            pit.write(0x43, command);
            pit.write(0x40, 3);
            clock.set_resume_base(50_000);
            assert!(!pit.tick(), "mode command {command:#x}");
            assert!(!pit.has_pending_interrupt());
        }
    }

    #[test]
    fn test_channel2_gate_getter_setter() {
        let mut pit = make_pit();
        assert!(!pit.channel2_gate());
        pit.set_channel2_gate(true);
        assert!(pit.channel2_gate());
        pit.set_channel2_gate(false);
        assert!(!pit.channel2_gate());
    }

    #[test]
    fn test_channel2_out_readable() {
        let mut pit = make_pit();
        // Configure channel 2 as a square wave generator with a known period.
        pit.write(0x43, 0xB6); // ch2, lo/hi, mode 3
        pit.write(0x42, 0x00);
        pit.write(0x42, 0x10); // reload 0x1000
        // With the gate enabled, OUT is computed live; with gate disabled the
        // square-wave OUT is forced high.
        pit.set_channel2_gate(false);
        assert!(pit.channel2_out(), "square-wave OUT high while gated off");
        // Re-enabling the gate restarts counting; OUT begins in the high half.
        pit.set_channel2_gate(true);
        assert!(pit.channel2_out(), "first half of square wave OUT high");
    }

    // ========== Standard Timer Configuration (like BIOS) ==========

    #[test]
    fn test_standard_100hz_configuration() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        pit.write(0x40, 0x9C);
        pit.write(0x40, 0x2E);
        assert_eq!(pit.channels[0].reload_value, 0x2E9C);
        assert_eq!(pit.channels[0].operating_mode.mode_bits(), 3);
    }

    #[test]
    fn test_bios_default_18hz_configuration() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        pit.write(0x40, 0x00);
        pit.write(0x40, 0x00);
        assert_eq!(pit.channels[0].reload_value, 0);
    }

    // ========== All Three Channels Independent ==========

    #[test]
    fn test_channels_independent() {
        let mut pit = make_pit();
        pit.write(0x43, 0x30); // Ch 0: mode 0
        pit.write(0x43, 0x76); // Ch 1: mode 3
        pit.write(0x43, 0xB4); // Ch 2: mode 2

        pit.write(0x40, 0x11);
        pit.write(0x40, 0x11);
        pit.write(0x41, 0x22);
        pit.write(0x41, 0x22);
        pit.write(0x42, 0x33);
        pit.write(0x42, 0x33);

        assert_eq!(pit.channels[0].operating_mode.mode_bits(), 0);
        assert_eq!(pit.channels[1].operating_mode.mode_bits(), 3);
        assert_eq!(pit.channels[2].operating_mode.mode_bits(), 2);

        assert_eq!(pit.channels[0].reload_value, 0x1111);
        assert_eq!(pit.channels[1].reload_value, 0x2222);
        assert_eq!(pit.channels[2].reload_value, 0x3333);
    }

    // ========== Write Latch Reset on Mode Change ==========

    #[test]
    fn test_write_latch_cleared_on_mode_change() {
        let mut pit = make_pit();
        pit.write(0x43, 0x36);
        pit.write(0x40, 0x12);
        assert!(pit.channels[0].write_latch.is_some());
        pit.write(0x43, 0x34);
        assert!(pit.channels[0].write_latch.is_none());
    }

    // ========== PIT Frequency Constant ==========

    #[test]
    fn test_pit_frequency_constant() {
        assert_eq!(PIT_FREQUENCY, 1193182);
    }

    // ========== BCD reload decode ==========

    #[test]
    fn test_bcd_reload_decode() {
        let mut pit = make_pit();
        // Mode 0, lo/hi, BCD. Write BCD value 0x1234 -> decimal 1234.
        pit.write(0x43, 0x31);
        pit.write(0x40, 0x34);
        pit.write(0x40, 0x12);
        assert_eq!(pit.channels[0].reload_value, 1234);
        assert!(pit.channels[0].bcd);
    }

    #[test]
    fn test_bcd_roundtrip_helpers() {
        assert_eq!(Pit::bin_to_bcd(1234), 0x1234);
        assert_eq!(Pit::bcd_to_bin(0x1234), 1234);
        assert_eq!(Pit::bcd_to_bin(0x9999), 9999);
        assert_eq!(Pit::bin_to_bcd(9999), 0x9999);
    }

    // ========== tick() drives IRQ on channel 0 ==========

    #[test]
    fn test_tick_fires_after_terminal_count_mode0() {
        let mut pit = make_pit();
        pit.channels[0].operating_mode = OperatingMode::InterruptOnTerminalCount;
        pit.channels[0].gate = true;
        pit.channels[0].reload_value = 100;
        pit.channels[0].count = 100;
        let now = timing::elapsed_nanos();
        pit.channels[0].loaded_at_nanos = now;
        pit.last_tick_nanos = now;

        // Back-date the load so the 100-tick period has fully elapsed by "now".
        let span = (200u128 * 1_000_000_000u128 / PIT_FREQUENCY as u128) as u64;
        pit.channels[0].loaded_at_nanos = now.saturating_sub(span);
        pit.last_tick_nanos = now.saturating_sub(span);

        assert!(pit.tick(), "mode 0 should fire once after terminal count");
        assert!(pit.has_pending_interrupt());
    }
}
