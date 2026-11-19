//! Replays the fixed installed desktop settings into guest-owned memory.

use super::{
    Availability, Mem, Outcome, Proc, Thread, check_guest_alignment, failure, guest_memory_status,
    probe_guest_write, query_error, write_guest,
};
use crate::user::windows::gui::system_parameters::{
    GET_HIGH_CONTRAST, GET_MOUSE_HOVER_TIME, GET_NONCLIENT_METRICS, GET_WHEEL_SCROLL_LINES,
    HIGH_CONTRAST_SCHEME_UNITS, NONCLIENT_METRICS_SIZE, Snapshot,
};
use crate::user::windows::nt::error::ERROR_INVALID_PARAMETER;
use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;
use crate::user::windows::nt::status_to_error;

fn put_metrics(p: &mut Proc, output: u64, settings: &Snapshot) -> Result<(), u32> {
    check_guest_alignment(output, 4)?;
    if output == 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    probe_guest_write(p, output, NONCLIENT_METRICS_SIZE)?;
    let body = output.checked_add(4).ok_or(STATUS_ACCESS_VIOLATION)?;
    write_guest(p, body, &settings.nonclient_metrics)
}

fn put_contrast(p: &mut Proc, output: u64, settings: &Snapshot) -> Result<(), u32> {
    let width = p.arch.ptr_size();
    check_guest_alignment(output, 4)?;
    let descriptor = p
        .space
        .bytes(output, 8 + width as usize)
        .map_err(|fault| guest_memory_status(p, fault.addr))?;
    let mut pointer = [0; 8];
    pointer[..width as usize].copy_from_slice(&descriptor[8..]);
    let scheme = u64::from_le_bytes(pointer);
    check_guest_alignment(scheme, 2)?;
    let flags = output.checked_add(4).ok_or(STATUS_ACCESS_VIOLATION)?;
    probe_guest_write(p, flags, 4)?;
    probe_guest_write(p, scheme, HIGH_CONTRAST_SCHEME_UNITS * 2)?;
    p.space
        .put_wunits(scheme, &settings.high_contrast_scheme)
        .map_err(|fault| guest_memory_status(p, fault.addr))?;
    write_guest(p, flags, &settings.high_contrast_flags.to_le_bytes())
}

pub(super) fn complete(
    p: &mut Proc,
    t: &Thread,
    action: u32,
    parameter: u32,
    output: u64,
) -> Result<u64, Outcome> {
    let Some(Availability::Available(inputs)) = p.native.as_ref().map(|runtime| &runtime.gui)
    else {
        return Err(failure(
            "system parameters require selected native GUI inputs",
        ));
    };
    let inputs = inputs.clone();
    let settings = inputs.system_parameters.as_ref().map_err(|reason| {
        failure(format!(
            "selected GUI system parameters are unavailable: {reason}"
        ))
    })?;
    let result = match action {
        GET_WHEEL_SCROLL_LINES => {
            write_guest(p, output, &settings.wheel_scroll_lines.to_le_bytes())
        }
        GET_MOUSE_HOVER_TIME => write_guest(p, output, &settings.mouse_hover_time.to_le_bytes()),
        GET_NONCLIENT_METRICS if parameter == NONCLIENT_METRICS_SIZE as u32 => {
            put_metrics(p, output, settings)
        }
        GET_NONCLIENT_METRICS => return query_error(p, t, ERROR_INVALID_PARAMETER, None),
        GET_HIGH_CONTRAST => put_contrast(p, output, settings),
        _ => {
            return Err(failure(format!(
                "system parameter action {action:#x} is not modeled"
            )));
        }
    };
    match result {
        Ok(()) => Ok(1),
        Err(status) => query_error(p, t, status_to_error(status), Some(status)),
    }
}
