//! SPI state-register aliases and active-state programming (IHI0069H12.9).
use super::{Gic, InterruptState, SPI_END, SPI_START};

impl Gic {
    pub(super) fn read_dist_state(&self, offset: u64) -> Option<u32> {
        if offset & 3 != 0 {
            return None;
        }
        let bank = offset & !0x7f;
        let kind = match bank {
            0x100 | 0x180 => 0,
            0x200 | 0x280 => 1,
            0x300 | 0x380 => 2,
            _ => return None,
        };
        let first = ((offset - bank) / 4) as u32 * 32;
        let mut value = 0;
        for bit in 0..32 {
            let intid = first + bit;
            if !(SPI_START..=SPI_END).contains(&intid) {
                continue;
            }
            let Some(config) = self.spis.get((intid - SPI_START) as usize) else {
                continue;
            };
            let set = match kind {
                0 => config.enabled,
                1 => config.state.is_pending(),
                _ => config.state.is_active(),
            };
            if set {
                value |= 1 << bit;
            }
        }
        Some(value)
    }

    pub(super) fn write_dist_active(&mut self, offset: u64, value: u32) -> bool {
        if offset & 3 != 0 {
            return false;
        }
        let bank = offset & !0x7f;
        if !matches!(bank, 0x300 | 0x380) {
            return false;
        }
        if value == 0 {
            return true;
        }
        let first = ((offset - bank) / 4) as u32 * 32;
        for bit in 0..32 {
            let intid = first + bit;
            if value & (1 << bit) == 0 || !(SPI_START..=SPI_END).contains(&intid) {
                continue;
            }
            let Some(config) = self.spis.get_mut((intid - SPI_START) as usize) else {
                continue;
            };
            // These registers affect active state, not the PE's active-priority
            // stack or independently conserved physical/software pending sources.
            if bank == 0x300 {
                config.state = if config.state.is_pending() {
                    InterruptState::ActivePending
                } else {
                    InterruptState::Active
                };
            } else {
                config.state.clear_active();
            }
        }
        self.update_all_cpus();
        true
    }
}
