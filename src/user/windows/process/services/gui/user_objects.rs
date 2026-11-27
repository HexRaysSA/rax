//! Guest-owned USER station identity and installed object information.
use super::{Mem, MemoryAccessKind, Outcome, Proc, Thread, failure, query_error};
use crate::user::windows::nt::error::{
    ERROR_BUSY, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION, ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER,
};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::nt::status_to_error;
use crate::user::windows::objects::Object;

const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;

pub(super) fn station(p: &Proc) -> Result<u32, Outcome> {
    let station = p
        .native
        .as_ref()
        .and_then(|native| native.gui.window_station())
        .ok_or_else(|| failure("process window station requires selected native GUI inputs"))?
        .as_ref()
        .map_err(|reason| failure(format!("selected window station unavailable: {reason}")))?;
    p.objects
        .window_station_handle(station)
        .ok_or_else(|| failure("selected assigned-window-station handle identity was lost"))
}

pub(super) fn close_station(p: &mut Proc, t: &Thread, [handle]: [u64; 1]) -> Result<u64, Outcome> {
    if p.objects.assigned_window_station_handle(handle) {
        return query_error(p, t, ERROR_BUSY, Some(STATUS_DEVICE_BUSY));
    }
    match p.objects.get(handle) {
        None => query_error(p, t, ERROR_INVALID_HANDLE, Some(STATUS_INVALID_HANDLE)),
        Some(Object::WindowStation(_)) => match p.objects.close(handle) {
            Ok(_) => Ok(1),
            Err(()) => query_error(p, t, ERROR_INVALID_HANDLE, Some(STATUS_INVALID_HANDLE)),
        },
        Some(_) => query_error(
            p,
            t,
            ERROR_INVALID_HANDLE,
            Some(STATUS_OBJECT_TYPE_MISMATCH),
        ),
    }
}

fn wide(name: impl IntoIterator<Item = u16>) -> Vec<u8> {
    name.into_iter()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub(super) fn information(
    p: &mut Proc,
    t: &Thread,
    [handle, class, output, capacity, needed]: [u64; 5],
) -> Result<u64, Outcome> {
    let class = class as u32;
    let capacity = capacity as u32;
    let alignment = if class == 1 { 4 } else { 2 };
    let probe = (|| -> Result<(), u32> {
        if capacity != 0 {
            if !output.is_multiple_of(alignment) {
                return Err(STATUS_DATATYPE_MISALIGNMENT);
            }
            p.space
                .probe(output, capacity as usize, MemoryAccessKind::Write)
                .map_err(|fault| memory_status(p, fault.address))?;
        }
        if needed != 0 {
            p.space
                .probe(needed, 4, MemoryAccessKind::Write)
                .map_err(|fault| memory_status(p, fault.address))?;
        }
        Ok(())
    })();
    if let Err(status) = probe {
        return query_error(p, t, status_to_error(status), Some(status));
    }
    let Some(object @ (Object::Desktop(_) | Object::WindowStation(_))) = p.objects.get(handle)
    else {
        return Ok(0);
    };
    let payload = match (class, object) {
        (1, _) => {
            let inherit = p.objects.flags(handle).unwrap_or(0) & 1;
            let flags = match object {
                Object::WindowStation(station) => station.user_flags,
                _ => 0,
            };
            Ok([inherit, 0, flags]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect())
        }
        (2, Object::WindowStation(station)) => Ok(wide(station.name.iter().copied())),
        (2, Object::Desktop(desktop)) => Ok(wide(desktop.name().iter().copied())),
        (3, _) => Ok(wide(object.type_name().encode_utf16())),
        (4, Object::WindowStation(station)) => Ok(station.sid.to_vec()),
        (5 | 6, Object::WindowStation(_)) => Err(ERROR_INVALID_FUNCTION),
        (4..=6, Object::Desktop(_)) => {
            return Err(failure(format!(
                "desktop object information class {class} is unavailable"
            )));
        }
        _ => Err(ERROR_INVALID_PARAMETER),
    };
    let (bytes, error) = match payload {
        Ok(bytes) => {
            let error = (capacity < bytes.len() as u32).then_some(ERROR_INSUFFICIENT_BUFFER);
            (bytes, error)
        }
        Err(error) => (Vec::new(), Some(error)),
    };
    let result = (|| -> Result<(), u32> {
        if error.is_none() && !bytes.is_empty() {
            p.space
                .wr(output, &bytes)
                .map_err(|fault| memory_status(p, fault.addr))?;
        }
        if needed != 0 {
            p.space
                .w32(needed, bytes.len() as u32)
                .map_err(|fault| memory_status(p, fault.addr))?;
        }
        Ok(())
    })();
    match (result, error) {
        (Err(status), _) => query_error(p, t, status_to_error(status), Some(status)),
        (Ok(()), Some(error)) => query_error(p, t, error, None),
        (Ok(()), None) => Ok(1),
    }
}

fn memory_status(p: &mut Proc, address: u64) -> u32 {
    if p.vm.take_guard(address) {
        STATUS_GUARD_PAGE_VIOLATION
    } else {
        STATUS_ACCESS_VIOLATION
    }
}
