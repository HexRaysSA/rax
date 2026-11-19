//! Replays the selected overlapped window's non-client rendering attribute.

use super::{
    Availability, Mem, Outcome, Proc, Thread, WinArch, check_guest_alignment, failure,
    guest_memory_status, probe_guest_write, query_error, write_guest,
};
use crate::user::windows::gui::windows::{WCA_NCRENDERING_ENABLED, WindowKind};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
};
use crate::user::windows::nt::status_to_error;

struct Attribute {
    selector: u32,
    output: u64,
    size: usize,
}

impl Attribute {
    fn read(p: &mut Proc, address: u64) -> Result<Self, u32> {
        // The 64-bit service reads through cbData, excluding trailing padding.
        let mut bytes = [0; 20];
        p.space
            .rd(address, &mut bytes)
            .map_err(|fault| guest_memory_status(p, fault.addr))?;
        let selector = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let output = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[16..].try_into().unwrap()) as usize;

        // The native probe ignores zero-sized ranges, even at unaligned or
        // null addresses. Otherwise it checks the entire declared extent.
        if size != 0 {
            check_guest_alignment(output, 4)?;
            if output == 0 {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            probe_guest_write(p, output, size)?;
        }
        Ok(Self {
            selector,
            output,
            size,
        })
    }
}

pub(super) fn complete(
    p: &mut Proc,
    t: &Thread,
    [handle, descriptor]: [u64; 2],
) -> Result<u64, Outcome> {
    if p.arch != WinArch::Arm64 {
        return Err(failure(
            "window composition lacks a selected architecture profile",
        ));
    }
    let report = |p: &Proc, status| query_error(p, t, status_to_error(status), Some(status));
    let attribute = match Attribute::read(p, descriptor) {
        Ok(attribute) => attribute,
        Err(status) => return report(p, status),
    };
    match attribute.selector {
        0 | 99 => return report(p, STATUS_INVALID_PARAMETER),
        WCA_NCRENDERING_ENABLED | 2 | 3 | 4 | 7 => {}
        selector => {
            return Err(failure(format!(
                "unmeasured window composition attribute {selector}"
            )));
        }
    }
    if attribute.size < 4 {
        return report(p, STATUS_BUFFER_TOO_SMALL);
    }
    let Some(window) = p.gui.window_accepting_wildcard_generation(&p.vm, handle) else {
        return report(p, STATUS_INVALID_HANDLE);
    };
    if !matches!(window.creation.kind, WindowKind::Overlapped { .. }) {
        return report(p, STATUS_INVALID_HANDLE);
    }

    // These recognized attributes validate the native HWND before rejecting
    // this window profile. An unknown selector is rejected before the size.
    if attribute.selector != WCA_NCRENDERING_ENABLED {
        return report(p, STATUS_INVALID_PARAMETER);
    }
    let Some(Availability::Available(inputs)) = p.native.as_ref().map(|runtime| &runtime.gui)
    else {
        return Err(failure(
            "window composition requires selected native GUI inputs",
        ));
    };
    let rendering = inputs
        .overlapped_nonclient_rendering
        .as_ref()
        .map_err(failure)?;
    let result = u32::from(*rendering).to_le_bytes();
    match write_guest(p, attribute.output, &result) {
        Ok(()) => Ok(1),
        Err(status) => report(p, status),
    }
}
