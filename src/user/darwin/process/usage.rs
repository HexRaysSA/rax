//! BSD resource usage for closed guest processes.

use super::{Proc, Thread};
use crate::user::darwin::abi::types::{RUSAGE_SIZE, Timeval};
use crate::user::mm::PAGE_SIZE;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Usage {
    user_us: u64,
    system_us: u64,
    peak_rss: u64,
    faults: u64,
}

impl Usage {
    pub(crate) fn add(&mut self, other: Self) {
        self.user_us = self.user_us.saturating_add(other.user_us);
        self.system_us = self.system_us.saturating_add(other.system_us);
        self.peak_rss = self.peak_rss.max(other.peak_rss);
        self.faults = self.faults.saturating_add(other.faults);
    }

    pub(crate) fn bytes(self) -> [u8; RUSAGE_SIZE] {
        let timeval = |micros: u64| {
            Timeval {
                sec: (micros / 1_000_000) as i64,
                usec: (micros % 1_000_000) as i32,
            }
            .bytes()
        };
        let mut bytes = [0; RUSAGE_SIZE];
        bytes[..16].copy_from_slice(&timeval(self.user_us));
        bytes[16..32].copy_from_slice(&timeval(self.system_us));
        bytes[32..40].copy_from_slice(&self.peak_rss.to_le_bytes());
        // Guest demand and copy-on-write faults have no guest swap or page-in I/O.
        bytes[64..72].copy_from_slice(&self.faults.min(i64::MAX as u64).to_le_bytes());
        bytes
    }
}

impl Proc {
    pub(super) fn usage_cpu_ns(&self, current: Option<&Thread>) -> (u64, u64) {
        let (dead_user, dead_system) = self.task.dead_times;
        let initial = (
            self.exec_cpu_ns.0.saturating_add(dead_user),
            self.exec_cpu_ns.1.saturating_add(dead_system),
        );
        self.threads
            .values()
            .chain(current)
            .fold(initial, |(user, system), thread| {
                (
                    user.saturating_add(thread.mach.user_ns),
                    system.saturating_add(thread.mach.system_ns),
                )
            })
    }

    pub(crate) fn own_usage(&self, current: Option<&Thread>) -> Usage {
        let (user, system) = self.usage_cpu_ns(current);
        let (resident, peak, faults) = self.space.residency();
        Usage {
            user_us: user / 1_000,
            system_us: system / 1_000,
            peak_rss: resident.max(peak).saturating_mul(PAGE_SIZE),
            faults: u64::from(faults),
        }
    }
}
