//! Classic SPI routing word accesses (Arm IHI0069H 12.9.22).
use super::{Gic, GicVersion, RoutingMode, SPI_START};

impl Gic {
    fn route_word(&self, offset: u64) -> Option<(usize, bool)> {
        // Include the upper word of IROUTER1019. Special and unallocated
        // INTIDs remain RAZ/WI, including historical extra storage slots.
        if !(0x6100..=0x7fdc).contains(&offset) || offset & 3 != 0 {
            return None;
        }
        let index = ((offset - 0x6000) / 8 - u64::from(SPI_START)) as usize;
        self.spis.get(index)?;
        Some((index, offset & 4 != 0))
    }

    pub(super) fn read_dist_route(&self, offset: u64) -> Option<u32> {
        let (index, upper) = self.route_word(offset)?;
        if self.config.version == GicVersion::V2 {
            return Some(0); // Affinity routing is disabled.
        }
        Some(match self.spis[index].routing {
            RoutingMode::Any => {
                // Affinity fields are architecturally UNKNOWN when IRM=1.
                if upper { 0 } else { 1 << 31 }
            }
            RoutingMode::Affinity(affinity) => {
                if upper {
                    ((affinity >> 24) & 0xff) as u32
                } else {
                    (affinity & 0x00ff_ffff) as u32
                }
            }
        })
    }

    pub(super) fn write_dist_route(&mut self, offset: u64, value: u32) -> bool {
        let Some((index, upper)) = self.route_word(offset) else {
            return false;
        };
        if self.config.version == GicVersion::V2 {
            return true;
        }
        let routing = &mut self.spis[index].routing;
        if upper {
            if let RoutingMode::Affinity(affinity) = routing {
                *affinity = (*affinity & 0x00ff_ffff) | (u64::from(value & 0xff) << 24);
            }
        } else {
            let aff3 = match *routing {
                RoutingMode::Affinity(affinity) => affinity & 0xff00_0000,
                RoutingMode::Any => 0,
            };
            *routing = if value & (1 << 31) != 0 {
                RoutingMode::Any
            } else {
                RoutingMode::Affinity(aff3 | u64::from(value & 0x00ff_ffff))
            };
        }
        self.update_all_cpus();
        true
    }
}
