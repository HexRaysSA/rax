//! Native USER services for the installed ARM64 default input context.
use super::{Outcome, Proc, Thread, WinArch, failure, query_error, selected_user_client_data};
use crate::user::windows::gui::input_contexts::Change;
use crate::user::windows::nt::error::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};

const ERROR_ALREADY_INITIALIZED: u32 = 1247;

pub(super) fn default(p: &mut Proc, t: &Thread) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "default input context requires the selected ARM64 USER profile",
        ));
    }
    let csr = selected_user_client_data(p)?;
    p.gui
        .default_input_context(&mut p.vm, &csr, t.tid)
        .map(u64::from)
        .map_err(|error| failure(format!("default input context data view: {error:?}")))
}

pub(super) fn query(p: &Proc, t: &Thread, [handle, selector]: [u64; 2]) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "input context query requires the selected ARM64 USER profile",
        ));
    }
    let Some((handle, owner)) = p.gui.input_context(&p.vm, handle) else {
        return query_error(p, t, ERROR_INVALID_HANDLE, None);
    };
    let thread = &p.gui.threads[&owner];
    let value = match selector as u32 {
        0 => p.pid,
        1 => owner,
        2 => thread.default_ime_window.unwrap_or_default(),
        3 => handle,
        _ => return query_error(p, t, ERROR_INVALID_PARAMETER, None),
    };
    Ok(u64::from(value))
}

pub(super) fn update(
    p: &mut Proc,
    t: &Thread,
    [handle, selector, value]: [u64; 3],
) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "input context update requires the selected ARM64 USER profile",
        ));
    }
    let Some((handle, _)) = p.gui.input_context(&p.vm, handle) else {
        return query_error(p, t, ERROR_INVALID_HANDLE, None);
    };
    let change = match selector as u32 {
        0 => Change::ClientContext(value),
        1 => Change::AssociatedWindow(value),
        _ => return Ok(0),
    };
    match p.gui.update_input_context(&mut p.vm, handle, change) {
        Ok(true) => Ok(1),
        Ok(false) => query_error(p, t, ERROR_ALREADY_INITIALIZED, None),
        Err(error) => Err(failure(format!("input context field write: {error:?}"))),
    }
}
