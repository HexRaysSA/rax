//! The clock subsystem (`clock.defs`, `osfmk/kern/clock_oldops.c`):
//! `SYSTEM_CLOCK` reads the uptime, `CALENDAR_CLOCK` the wall clock.

use super::{Buf, MigResult, Out, Req, ids};
use crate::user::darwin::mach::ipc::KObject;
use crate::user::darwin::mach::kr;
use crate::user::darwin::syscall::Ctx;

/// `CLOCK_GET_TIME_RES` and the alarm resolutions.
const CLOCK_GET_TIME_RES: i32 = 1;
const CLOCK_ALARM_CURRES: i32 = 3;
const CLOCK_ALARM_MAXRES: i32 = 5;

/// Nanoseconds since boot (`clock_get_system_nanotime`).
pub fn system_nanotime() -> u64 {
    crate::vm::timing::elapsed_nanos()
}

/// Nanoseconds since the epoch (`clock_get_calendar_nanotime`).
pub fn calendar_nanotime() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Serves the clock subsystem.
pub fn serve(_ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    let KObject::Clock(id) = req.port.kobject else {
        return match req.id {
            ids::clock::CLOCK_GET_TIME
            | ids::clock::CLOCK_GET_ATTRIBUTES
            | ids::clock::CLOCK_ALARM => Err(kr::KERN_INVALID_ARGUMENT),
            _ => Err(kr::MIG_BAD_ID),
        };
    };
    match req.id {
        ids::clock::CLOCK_GET_TIME => {
            req.simple(24)?;
            let ns = if id == 0 {
                system_nanotime()
            } else {
                calendar_nanotime()
            };
            // mach_timespec_t: unsigned seconds, signed nanoseconds.
            Ok(Out::Simple(
                Buf::new()
                    .u32((ns / 1_000_000_000) as u32)
                    .i32((ns % 1_000_000_000) as i32)
                    .done(),
            ))
        }
        ids::clock::CLOCK_GET_ATTRIBUTES => {
            req.simple(40)?;
            let flavor = req.i32(32);
            // The MIG array bound is 1.
            let count = req.u32(36).min(1);
            if count != 1 {
                return Err(kr::KERN_FAILURE);
            }
            // Both clocks resolve to NSEC_PER_SEC / 100; the calendar clock
            // has no alarms.
            let res = match flavor {
                CLOCK_GET_TIME_RES => 10_000_000,
                CLOCK_ALARM_CURRES..=CLOCK_ALARM_MAXRES => {
                    if id == 0 {
                        10_000_000
                    } else {
                        0
                    }
                }
                _ => return Err(kr::KERN_INVALID_VALUE),
            };
            Ok(Out::Simple(Buf::new().u32(1).i32(res).done()))
        }
        ids::clock::CLOCK_ALARM => {
            // Alarms deliver clock_alarm_reply messages; the calendar clock
            // refuses them, and the system clock's are not modelled.
            Err(if id == 0 {
                kr::KERN_NOT_SUPPORTED
            } else {
                kr::KERN_FAILURE
            })
        }
        _ => Err(kr::MIG_BAD_ID),
    }
}
