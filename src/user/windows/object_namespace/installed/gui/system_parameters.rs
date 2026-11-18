//! Read-only acquisition of the selected desktop settings on the native helper.

use super::{GetProcAddress, Module};
use crate::user::windows::gui::system_parameters::{
    GET_HIGH_CONTRAST, GET_MOUSE_HOVER_TIME, GET_NONCLIENT_METRICS, GET_WHEEL_SCROLL_LINES,
    HIGH_CONTRAST_SCHEME_UNITS, NONCLIENT_METRICS_SIZE, Snapshot,
};
use std::ffi::c_void;
use std::io;

type Query = unsafe extern "system" fn(u32, u32, *mut c_void, u32) -> i32;

#[repr(C)]
struct HighContrast {
    size: u32,
    flags: u32,
    scheme: *mut u16,
}

pub(super) fn capture(win32u: &Module) -> Result<Snapshot, String> {
    // SAFETY: the selected DLL stays live and the Win32u export uses the
    // measured 64-bit four-argument ABI. Calls use only fixed GET actions,
    // zero flags, and exclusive initialized host storage.
    let address = unsafe { GetProcAddress(win32u.0, c"NtUserSystemParametersInfo".as_ptr()) };
    if address.is_null() {
        return Err("selected Win32u has no system parameters query".into());
    }
    let query: Query = unsafe { std::mem::transmute(address) };

    let scalar = |action| {
        let mut value = 0u32;
        if unsafe { query(action, 0, (&raw mut value).cast(), 0) } == 0 {
            return Err(format!(
                "native GUI scalar query {action:#x}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(value)
    };
    let wheel_scroll_lines = scalar(GET_WHEEL_SCROLL_LINES)?;
    let mouse_hover_time = scalar(GET_MOUSE_HOVER_TIME)?;

    let mut metrics = [0u32; NONCLIENT_METRICS_SIZE / 4];
    metrics[0] = NONCLIENT_METRICS_SIZE as u32;
    if unsafe {
        query(
            GET_NONCLIENT_METRICS,
            metrics[0],
            metrics.as_mut_ptr().cast(),
            0,
        )
    } == 0
    {
        return Err(format!(
            "native GUI nonclient metrics: {}",
            io::Error::last_os_error()
        ));
    }
    let mut nonclient_metrics = [0; NONCLIENT_METRICS_SIZE - 4];
    for (bytes, word) in nonclient_metrics.chunks_exact_mut(4).zip(&metrics[1..]) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }

    let mut high_contrast_scheme = [0u16; HIGH_CONTRAST_SCHEME_UNITS];
    let scheme = high_contrast_scheme.as_mut_ptr();
    let mut contrast = HighContrast {
        size: std::mem::size_of::<HighContrast>() as u32,
        flags: 0,
        scheme,
    };
    if unsafe {
        query(
            GET_HIGH_CONTRAST,
            contrast.size,
            (&raw mut contrast).cast(),
            0,
        )
    } == 0
    {
        return Err(format!(
            "native GUI high contrast: {}",
            io::Error::last_os_error()
        ));
    }
    if contrast.scheme != scheme || !high_contrast_scheme.contains(&0) {
        return Err("native GUI high-contrast data changed its bounded output layout".into());
    }

    Ok(Snapshot {
        wheel_scroll_lines,
        mouse_hover_time,
        nonclient_metrics,
        high_contrast_flags: contrast.flags,
        high_contrast_scheme,
    })
}
