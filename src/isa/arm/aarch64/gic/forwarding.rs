//! Group forwarding before interrupt prioritization (Arm IHI0069H4.7.2).
use super::{CpuInterface, INTID_SPURIOUS, InterruptConfig, RoutingMode, SPI_END, SPI_START};

impl CpuInterface {
    fn group_forwarded(&self, group: u8, distributor: u8) -> bool {
        let cpu_enabled = match group {
            0 => self.enable_grp0,
            1 => self.enable_grp1 || self.enable_grp1_ns,
            _ => return false,
        };
        cpu_enabled && distributor & (1 << group) != 0
    }

    /// Update highest pending interrupt.
    pub fn update_pending(&mut self, spis: &[InterruptConfig]) {
        self.update_pending_for_groups(spis, 3);
    }

    pub(super) fn update_pending_for_groups(&mut self, spis: &[InterruptConfig], groups: u8) {
        let mut best_priority = 0xFF;
        let mut best_intid = INTID_SPURIOUS;

        // Check private interrupts (SGI/PPI)
        for (i, config) in self.private_interrupts.iter().enumerate() {
            if self.group_forwarded(config.group, groups)
                && config.enabled
                && config.state.is_pending()
                && !config.state.is_active()
                && config.priority < best_priority
            {
                // Check if unmasked
                if config.priority < self.priority_mask {
                    best_priority = config.priority;
                    best_intid = i as u32;
                }
            }
        }

        // Check SPIs
        for (i, config) in spis.iter().enumerate() {
            let intid = SPI_START + i as u32;
            if intid > SPI_END {
                break;
            }
            if self.group_forwarded(config.group, groups)
                && config.enabled
                && config.state.is_pending()
                && !config.state.is_active()
                && config.priority < best_priority
            {
                // Check routing
                let routed = match config.routing {
                    RoutingMode::Any => true,
                    RoutingMode::Affinity(aff) => aff == self.affinity,
                };

                if routed && config.priority < self.priority_mask {
                    best_priority = config.priority;
                    best_intid = intid;
                }
            }
        }

        self.highest_pending_priority = best_priority;
        self.highest_pending_intid = best_intid;
    }
}
