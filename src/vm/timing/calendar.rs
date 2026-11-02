//! Guest calendar source; retired time is UTC2000 plus the retained VM counter.
use super::{ClockMode, TimingContext};
use crate::host::time::{Duration, UNIX_EPOCH};
use std::sync::Arc;
/// Unix seconds at 2000-01-01T00:00:00Z. This is a model origin,not a host sample.
pub(crate) const RETIRED_CALENDAR_ORIGIN: u64 = 946_684_800;
#[derive(Clone)]
pub(crate) struct CalendarClock {
    retired: Option<Arc<TimingContext>>,
}
impl Default for CalendarClock {
    fn default() -> Self {
        Self::selected()
    }
}
impl CalendarClock {
    pub(crate) fn selected() -> Self {
        Self {
            retired: TimingContext::current().filter(|c| c.mode() == ClockMode::Retired),
        }
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.retired.is_some()
    }
    pub(crate) fn timestamp(&self) -> Duration {
        match &self.retired {
            Some(owner) => {
                Duration::from_secs(RETIRED_CALENDAR_ORIGIN)
                    + Duration::from_nanos(owner.elapsed_nanos())
            }
            None => crate::host::time::system_now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO),
        }
    }
    pub(crate) fn date(&self) -> DateTime {
        from_unix_seconds(self.timestamp().as_secs())
    }
}
/// A broken-down wall-clock time in UTC, as fed to the RTC registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DateTime {
    pub(crate) second: u8,
    pub(crate) minute: u8,
    pub(crate) hour: u8,
    /// Day of week, 1 = Sunday .. 7 = Saturday (MC146818 convention).
    pub(crate) day_of_week: u8,
    pub(crate) day_of_month: u8,
    pub(crate) month: u8,
    /// Full four-digit year (e.g. 2026).
    pub(crate) year: u16,
}

// Gregorian conversion retained from the existing PC RTC civil_from_days path.
// O(1) time/storage; retired input spans years2000..2584 before nanosecond wrap.
pub(crate) fn from_unix_seconds(secs: u64) -> DateTime {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;

    let hour = (secs_of_day / 3_600) as u8;
    let minute = ((secs_of_day % 3_600) / 60) as u8;
    let second = (secs_of_day % 60) as u8;

    // Day of week: 1970-01-01 was a Thursday. MC146818 uses 1 = Sunday.
    // (days + 4) mod 7 gives 0 = Sunday .. 6 = Saturday; +1 to map to 1..7.
    let dow = (((days % 7) + 4) % 7 + 7) % 7; // 0 = Sunday
    let day_of_week = (dow as u8) + 1;

    // civil_from_days: shift epoch so the year starts on March 1.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as u16;

    DateTime {
        second,
        minute,
        hour,
        day_of_week,
        day_of_month: d as u8,
        month: m as u8,
        year,
    }
}
#[cfg(test)]
#[path = "calendar_tests.rs"]
mod tests;
