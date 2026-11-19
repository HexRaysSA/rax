//! Intel 8254 modes 0 and 4, sampled at PIT oscillator boundaries.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum SoftwareMode {
    TerminalCount,
    Strobe,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
struct ActiveCount {
    period: u32,
    tick: u64,
    enabled_ticks: u64,
    strobe_low: bool,
}

impl ActiveCount {
    fn advance(&mut self, tick: u64, mode: SoftwareMode, enabled: bool) -> bool {
        if tick <= self.tick {
            return false;
        }
        let terminal = u64::from(self.period);
        let was_before_terminal = self.enabled_ticks < terminal;
        if enabled {
            self.enabled_ticks += tick - self.tick;
        }
        self.tick = tick;
        let reached_terminal = was_before_terminal && self.enabled_ticks >= terminal;
        match mode {
            SoftwareMode::TerminalCount => reached_terminal,
            SoftwareMode::Strobe => {
                let rose = self.strobe_low || (reached_terminal && self.enabled_ticks > terminal);
                self.strobe_low = reached_terminal && self.enabled_ticks == terminal;
                rose
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SoftwareCounter {
    mode: SoftwareMode,
    active: Option<ActiveCount>,
    next_load_tick: Option<u64>,
}

impl SoftwareCounter {
    pub(super) fn new(mode: SoftwareMode) -> Self {
        Self {
            mode,
            active: None,
            next_load_tick: None,
        }
    }

    pub(super) fn mode_bits(self) -> u8 {
        match self.mode {
            SoftwareMode::TerminalCount => 0,
            SoftwareMode::Strobe => 4,
        }
    }

    pub(super) fn begin_write(&mut self) {
        if self.mode == SoftwareMode::TerminalCount {
            self.next_load_tick = None;
        }
    }

    pub(super) fn write_count(&mut self, tick: u64) {
        self.next_load_tick = Some(tick + 1);
    }

    pub(super) fn next_rise(self, period: u32, gate: bool, partial: bool) -> Option<u64> {
        let strobe = self.mode == SoftwareMode::Strobe;
        let enabled = gate && (strobe || !partial);
        let active = self.active.and_then(|active| {
            if active.strobe_low {
                return Some(active.tick + 1);
            }
            let remaining = u64::from(active.period).checked_sub(active.enabled_ticks)?;
            (enabled && remaining != 0).then(|| active.tick + remaining + u64::from(strobe))
        });
        match self.next_load_tick {
            Some(load) => active
                .filter(|&edge| edge < load || (strobe && edge == load))
                .or_else(|| enabled.then(|| load + u64::from(period) + u64::from(strobe))),
            None => active,
        }
    }

    /// Advance the counting element, returning rising OUT edges and whether
    /// the count register transferred. A load edge takes precedence over counting.
    pub(super) fn advance(
        &mut self,
        tick: u64,
        period: u32,
        gate: bool,
        partial_write: bool,
    ) -> (u64, bool) {
        let enabled = gate && (self.mode == SoftwareMode::Strobe || !partial_write);
        let load = self.next_load_tick.filter(|&load| load <= tick);
        let stop = load.map_or(tick, |load| load - 1);
        let mut edges = u64::from(
            self.active
                .as_mut()
                .is_some_and(|active| active.advance(stop, self.mode, enabled)),
        );
        if let Some(load) = load {
            edges += u64::from(self.active.is_some_and(|active| active.strobe_low));
            let mut active = ActiveCount {
                period,
                tick: load,
                enabled_ticks: 0,
                strobe_low: false,
            };
            edges += u64::from(active.advance(tick, self.mode, enabled));
            self.active = Some(active);
            self.next_load_tick = None;
        }
        (edges, load.is_some())
    }

    pub(super) fn sample(self, count: u16, bcd: bool, partial_write: bool) -> (u16, bool) {
        let output = match self.mode {
            SoftwareMode::TerminalCount => {
                !partial_write
                    && self.next_load_tick.is_none()
                    && self
                        .active
                        .is_some_and(|active| active.enabled_ticks >= u64::from(active.period))
            }
            SoftwareMode::Strobe => !self.active.is_some_and(|active| active.strobe_low),
        };
        let count = self.active.map_or(count, |active| {
            super::wrapped_count(u64::from(active.period), active.enabled_ticks, bcd)
        });
        (count, output)
    }

    pub(super) fn valid(self, null_count: bool, partial_write: bool, bcd: bool) -> bool {
        let max_tick = super::timing::nanos_to_pit_ticks(u64::MAX);
        let max_period = if bcd { 16_665 } else { 65_536 };
        let active_tick = self.active.map_or(0, |active| active.tick);
        let stopped_during_load = self.mode == SoftwareMode::TerminalCount
            && partial_write
            && self.next_load_tick.is_none();
        self.active.is_none_or(|active| {
            (1..=max_tick).contains(&active.tick)
                && active.enabled_ticks < active.tick
                && (1..=max_period).contains(&active.period)
                && (!active.strobe_low
                    || (self.mode == SoftwareMode::Strobe
                        && active.enabled_ticks == u64::from(active.period)))
        }) && self
            .next_load_tick
            .is_none_or(|next| active_tick < next && next <= max_tick + 1)
            && !(self.mode == SoftwareMode::TerminalCount
                && partial_write
                && self.next_load_tick.is_some())
            && (null_count == (self.active.is_none() || self.next_load_tick.is_some())
                || (null_count && stopped_during_load))
    }
}
