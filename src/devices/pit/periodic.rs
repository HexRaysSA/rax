//! Intel 8254 modes 2 and 3, sampled at PIT oscillator boundaries.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum PeriodicMode {
    Rate,
    Square,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
struct ActiveCycle {
    period: u32,
    tick: u64,
    phase: u32,
    // A rate generator has one phase and obtains OUT from its remaining count.
    high: bool,
}

impl ActiveCycle {
    fn phase_len(self, mode: PeriodicMode) -> u32 {
        match mode {
            PeriodicMode::Rate => self.period,
            PeriodicMode::Square if self.high => self.period.div_ceil(2),
            PeriodicMode::Square => self.period / 2,
        }
    }

    /// The first boundary can transfer a replacement divisor. All later
    /// cycles use that divisor and can be folded with a single division.
    fn advance(
        &mut self,
        tick: u64,
        mode: PeriodicMode,
        gate: bool,
        replacement: Option<u32>,
    ) -> (u64, bool) {
        if tick <= self.tick {
            return (0, false);
        }
        let elapsed = tick - self.tick;
        self.tick = tick;
        if !gate {
            return (0, false);
        }
        let first_boundary = u64::from(self.phase_len(mode) - self.phase);
        if elapsed < first_boundary {
            self.phase += elapsed as u32;
            return (0, false);
        }

        self.high = mode == PeriodicMode::Rate || !self.high;
        let first_rise = u64::from(self.high);
        if let Some(period) = replacement {
            self.period = period;
        }
        let high_len = match mode {
            PeriodicMode::Rate => self.period,
            PeriodicMode::Square => self.period.div_ceil(2),
        };
        let start = if self.high { 0 } else { u64::from(high_len) };
        let position = start + elapsed - first_boundary;
        let rises = first_rise + position / u64::from(self.period);
        let position = (position % u64::from(self.period)) as u32;
        self.high = position < high_len;
        self.phase = if self.high {
            position
        } else {
            position - high_len
        };
        (rises, replacement.is_some())
    }

    fn sample(self, mode: PeriodicMode) -> (u32, bool) {
        match mode {
            PeriodicMode::Rate => {
                let count = self.period - self.phase;
                (count, count != 1)
            }
            PeriodicMode::Square => ((self.period & !1) - self.phase * 2, self.high),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct PeriodicCounter {
    mode: PeriodicMode,
    active: Option<ActiveCycle>,
    next_load_tick: Option<u64>,
}

impl PeriodicCounter {
    pub(super) fn new(mode: PeriodicMode) -> Self {
        Self {
            mode,
            active: None,
            next_load_tick: None,
        }
    }

    pub(super) fn mode_bits(self) -> u8 {
        match self.mode {
            PeriodicMode::Rate => 2,
            PeriodicMode::Square => 3,
        }
    }

    pub(super) fn write_count(&mut self, tick: u64) {
        if self.active.is_none() {
            self.next_load_tick.get_or_insert(tick + 1);
        }
    }

    pub(super) fn trigger(&mut self, tick: u64) {
        if self.active.is_some() || self.next_load_tick.is_some() {
            self.next_load_tick = Some(tick + 1);
        }
    }

    pub(super) fn advance(
        &mut self,
        tick: u64,
        period: u32,
        gate: bool,
        null_count: bool,
    ) -> (u64, bool) {
        // The 8254 specifies 2 as the minimum divisor for both modes.
        let period = period.max(2);
        let load = self.next_load_tick.filter(|&load| load <= tick);
        if let Some(load) = load {
            // A gate trigger restarts the waveform high and takes precedence
            // over the periodic transfer. The old phase was stopped by GATE.
            let mut active = ActiveCycle {
                period,
                tick: load,
                phase: 0,
                high: true,
            };
            let (edges, _) = active.advance(tick, self.mode, gate, None);
            self.active = Some(active);
            self.next_load_tick = None;
            return (edges, true);
        }
        self.active.as_mut().map_or((0, false), |active| {
            active.advance(
                tick,
                self.mode,
                gate && self.next_load_tick.is_none(),
                null_count.then_some(period),
            )
        })
    }

    pub(super) fn sample(self, fallback: u16, gate: bool, bcd: bool) -> (u16, bool) {
        let Some(active) = self.active else {
            return (fallback, true);
        };
        let (count, output) = active.sample(self.mode);
        let count = if bcd {
            super::Pit::bin_to_bcd(count as u16)
        } else {
            count as u16
        };
        (count, output || !gate || self.next_load_tick.is_some())
    }

    pub(super) fn valid(self, null_count: bool, bcd: bool) -> bool {
        let max_tick = super::timing::nanos_to_pit_ticks(u64::MAX);
        let max_period = if bcd { 16_665 } else { 65_536 };
        let active_tick = self.active.map_or(0, |active| active.tick);
        (self.active.is_some() || null_count)
            && self.active.is_none_or(|active| {
                (1..=max_tick).contains(&active.tick)
                    && (2..=max_period).contains(&active.period)
                    && (self.mode == PeriodicMode::Square || active.high)
                    && active.phase < active.phase_len(self.mode)
                    && u64::from(active.phase) < active.tick
            })
            && self
                .next_load_tick
                .is_none_or(|next| active_tick < next && next <= max_tick + 1)
    }
}
