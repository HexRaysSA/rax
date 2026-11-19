//! Intel 8254 modes 1 and 5, sampled at PIT oscillator boundaries.

use serde::{Deserialize, Serialize};

/// Count transferred into the counting element on an earlier oscillator edge.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
struct ActiveCount {
    load_tick: u64,
    divisor: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum TriggeredMode {
    OneShot,
    Strobe,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct TriggeredCounter {
    mode: TriggeredMode,
    ready: bool,
    active: Option<ActiveCount>,
    next_load_tick: Option<u64>,
}

impl TriggeredCounter {
    pub(super) fn new(mode: TriggeredMode) -> Self {
        Self {
            mode,
            ready: false,
            active: None,
            next_load_tick: None,
        }
    }

    pub(super) fn mode_bits(self) -> u8 {
        match self.mode {
            TriggeredMode::OneShot => 1,
            TriggeredMode::Strobe => 5,
        }
    }

    pub(super) fn write_count(&mut self) {
        self.ready = true;
    }

    pub(super) fn trigger(&mut self, tick: u64) {
        if self.ready {
            self.next_load_tick = Some(tick + 1);
        }
    }

    fn pending_at(self, tick: u64, divisor: u16) -> Option<ActiveCount> {
        self.next_load_tick
            .filter(|&load_tick| load_tick <= tick)
            .map(|load_tick| ActiveCount { load_tick, divisor })
    }

    /// Materialize an earlier trigger before a write can change its divisor.
    pub(super) fn transfer(&mut self, tick: u64, divisor: u16) -> bool {
        let Some(active) = self.pending_at(tick, divisor) else {
            return false;
        };
        self.active = Some(active);
        self.next_load_tick = None;
        true
    }

    pub(super) fn sample(self, tick: u64, divisor: u16, bcd: bool) -> Option<(u16, bool)> {
        let active = self.pending_at(tick, divisor).or(self.active)?;
        let elapsed = tick.saturating_sub(active.load_tick);
        let modulus = if bcd { 10_000 } else { 65_536 };
        let divisor = u64::from(active.divisor);
        let terminal = if divisor == 0 { modulus } else { divisor };
        let remaining = ((terminal + modulus - elapsed % modulus) % modulus) as u16;
        let count = if bcd {
            super::Pit::bin_to_bcd(remaining)
        } else {
            remaining
        };
        let out = match self.mode {
            TriggeredMode::OneShot => elapsed >= terminal,
            TriggeredMode::Strobe => elapsed != terminal,
        };
        Some((count, out))
    }

    pub(super) fn valid(self, gate_can_trigger: bool, null_count: bool) -> bool {
        let has_phase = self.active.is_some() || self.next_load_tick.is_some();
        let active_tick = self.active.map_or(0, |active| active.load_tick);
        (!has_phase || (gate_can_trigger && self.ready))
            && (self.active.is_some() || null_count)
            && self.active.is_none_or(|_| active_tick != 0)
            && self.next_load_tick.is_none_or(|next| next > active_tick)
    }
}
