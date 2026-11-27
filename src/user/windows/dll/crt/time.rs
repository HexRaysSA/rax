//! UCRT epoch time on the same host clock as the built-in Win32 services.

use crate::user::clock::{HostClock, read};
use crate::user::windows::hle::{ApiResult, Archs, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::memory::Mem;

pub(crate) static UCRT_TIME_EXPORTS: &[Export] = &[Export::func("_time64", Cdecl, &[Ptr], time64)];

pub(crate) static KERNELBASE_TIME_FORWARDS: &[Export] = &[
    Export::forward("_time64", "ucrtbase._time64"),
    Export::forward("time", "ucrtbase._time64").only(Archs::X64),
];

fn time64(c: &mut Ctx) -> ApiResult {
    let output = c.ptr(0)?;
    let seconds =
        read(HostClock::Realtime).map_or(-1, |(seconds, nanos)| time64_seconds(seconds, nanos));
    if output != 0 {
        c.mem().w64(output, seconds as u64)?;
    }
    Flow::ret64(seconds as u64)
}

fn time64_seconds(seconds: i64, nanos: i64) -> i64 {
    // The retained GameOS UCRT compares the UTC delta against
    // 0x0483_f078_dd47_8000 100-nanosecond ticks.
    const LIMIT: i64 = 32_536_800_000; // 3001-01-19 08:00:00 UTC, exclusive.
    if seconds >= LIMIT {
        -1
    } else {
        // Its signed FILETIME division truncates pre-epoch fractions toward zero.
        seconds + i64::from(seconds < 0 && nanos >= 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::dll::crt::{
        RuntimeKind,
        tests::{area, invoke, run},
    };
    use crate::user::windows::hle::Value;
    use crate::user::windows::loader::{self, SymRef};

    #[test]
    fn time64_reads_epoch_seconds_and_stores_optional_output() {
        run(|c| {
            let output = area(c);
            for dest in [0, output] {
                let before = read(HostClock::Realtime).unwrap().0;
                let Flow::Ret(Value::I64(actual)) =
                    invoke(c, RuntimeKind::Ucrt, "_time64", &[dest]).unwrap()
                else {
                    panic!("64-bit time return");
                };
                let after = read(HostClock::Realtime).unwrap().0;
                assert!((before..=after).contains(&(actual as i64)));
                if dest != 0 {
                    assert_eq!(c.mem().u64(dest).unwrap(), actual);
                }
            }
        });
    }

    #[test]
    fn time64_enforces_retained_bounds_and_signed_truncation() {
        assert_eq!(time64_seconds(-1, 100), 0);
        assert_eq!(time64_seconds(-1, 99), -1);
        assert_eq!(time64_seconds(32_536_799_999, 999_999_999), 32_536_799_999);
        assert_eq!(time64_seconds(32_536_800_000, 0), -1);
    }

    #[test]
    fn gameos_x64_kernelbase_time_resolves_to_the_ucrt_implementation() {
        run(|c| {
            let kernelbase = loader::load_dll(c.p, "kernelbase.dll").unwrap();
            let name = SymRef::Name(b"time".to_vec(), None);
            let address = loader::lookup(c.p, kernelbase, &name).unwrap();
            if c.arch() == crate::user::windows::arch::WinArch::X64 {
                invoke(c, RuntimeKind::Ucrt, "_time64", &[0]).unwrap();
                assert_eq!(address, Some(c.entry_pc));
            } else {
                assert_eq!(address, None);
            }
        });
    }
}
