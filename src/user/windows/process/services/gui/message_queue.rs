//! Installed Win32u thread-message services.

use super::{Availability, Mem, Outcome, Proc, Thread, failure, guest_memory_status, query_error};
use crate::user::windows::gui::message_queue::{Message, WM_QUIT};
use crate::user::windows::nt::error::{ERROR_INVALID_THREAD_ID, ERROR_NOACCESS};
use crate::user::windows::process::ThreadState;
use crate::user::windows::sync::{self, Wait};

const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_NOT_ENOUGH_QUOTA: u32 = 1816;
const PM_REMOVE: u32 = 1;
const PM_NOYIELD: u32 = 2;
const QS_POSTED: u32 = 0x0008 | 0x0100;
const HWND_THREAD_ONLY: u64 = u64::MAX;

fn cursor(p: &Proc) -> [i32; 2] {
    match p.native.as_ref().map(|runtime| &runtime.gui) {
        Some(Availability::Available(gui)) => gui.message_cursor,
        _ => [0; 2],
    }
}

pub(super) fn post(
    p: &mut Proc,
    t: &Thread,
    [tid, id, wparam, lparam]: [u64; 4],
) -> Result<u64, Outcome> {
    let message = Message {
        id: id as u32,
        wparam,
        lparam,
        time: p.uptime_ms() as u32,
        point: cursor(p),
    };
    let Some(target) = p.gui.threads.get_mut(&(tid as u32)) else {
        return query_error(p, t, ERROR_INVALID_THREAD_ID, None);
    };
    if !target.messages.post(message) {
        return query_error(p, t, ERROR_NOT_ENOUGH_QUOTA, None);
    }
    Ok(1)
}

pub(super) fn quit(p: &mut Proc, t: &Thread, [code]: [u64; 1]) -> Result<u64, Outcome> {
    let thread = p.gui.threads.get_mut(&t.tid).expect("converted GUI thread");
    thread.messages.quit(code as u32);
    Ok(0)
}

fn copy_fault(p: &mut Proc, t: &Thread, address: u64) -> Result<u64, Outcome> {
    let status = guest_memory_status(p, address);
    query_error(p, t, ERROR_NOACCESS, Some(status))
}

fn window_filter(p: &Proc, window: u64) -> Result<bool, Outcome> {
    if matches!(window, 0 | HWND_THREAD_ONLY) {
        return Ok(true);
    }
    if p.gui
        .window_accepting_wildcard_generation(&p.vm, window)
        .is_some()
    {
        return Err(failure("window-filtered message delivery is unavailable"));
    }
    Ok(false)
}

fn transfer(
    p: &mut Proc,
    t: &Thread,
    output: u64,
    minimum: u32,
    maximum: u32,
    remove: bool,
    get: bool,
) -> Result<Option<u64>, Outcome> {
    let time = p.uptime_ms() as u32;
    let point = cursor(p);
    let thread = p.gui.threads.get_mut(&t.tid).expect("converted GUI thread");
    let Some(message) = thread.messages.get(minimum, maximum, remove, time, point) else {
        return Ok(None);
    };
    // Native PM_REMOVE and GetMessage dequeue before probing the user output.
    if let Err(fault) = p.space.wr(output, &message.encode()) {
        return copy_fault(p, t, fault.addr).map(Some);
    }
    Ok(Some(u64::from(!get || message.id != WM_QUIT)))
}

pub(super) fn peek(
    p: &mut Proc,
    t: &Thread,
    [output, window, minimum, maximum, flags]: [u64; 5],
) -> Result<u64, Outcome> {
    let flags = flags as u32;
    if flags & 0xffff & !(PM_REMOVE | PM_NOYIELD) != 0 {
        return query_error(p, t, ERROR_INVALID_FLAGS, None);
    }
    if !window_filter(p, window)? {
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None);
    }
    let sources = flags >> 16;
    if sources != 0 && sources & QS_POSTED == 0 {
        return Ok(0);
    }
    transfer(
        p,
        t,
        output,
        minimum as u32,
        maximum as u32,
        flags & PM_REMOVE != 0,
        false,
    )
    .map(|result| result.unwrap_or(0))
}

pub(super) fn get(
    p: &mut Proc,
    t: &mut Thread,
    [output, window, minimum, maximum]: [u64; 4],
) -> Result<u64, Outcome> {
    if !window_filter(p, window)? {
        if let Err(fault) = p.space.w32(output.wrapping_add(8), 0) {
            return copy_fault(p, t, fault.addr);
        }
        return query_error(p, t, ERROR_INVALID_WINDOW_HANDLE, None).map(|_| u64::from(u32::MAX));
    }
    take_or_wait(p, t, output, minimum as u32, maximum as u32)
}

pub(super) fn take_or_wait(
    p: &mut Proc,
    t: &mut Thread,
    output: u64,
    minimum: u32,
    maximum: u32,
) -> Result<u64, Outcome> {
    if let Some(result) = transfer(p, t, output, minimum, maximum, true, true)? {
        return Ok(result);
    }
    let wait = Wait::PostedMessage {
        output,
        minimum,
        maximum,
    };
    sync::on_block(p, t.tid, &wait).map_err(|error| {
        failure(format!(
            "posted message wait registration failed: {error:?}"
        ))
    })?;
    t.state = ThreadState::Waiting(wait);
    Err(Outcome::Park)
}
