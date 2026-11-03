//! Bounded owned copies of the optional LARGE_INTEGER and FILE_FULL_EA records.
use super::{Checked, Ctx, Mem, STATUS_DATATYPE_MISALIGNMENT, STATUS_INVALID_PARAMETER, status};

pub(super) fn allocation(c: &Ctx, address: u64) -> Checked<Option<i64>> {
    if address == 0 {
        return Ok(None);
    }
    // LARGE_INTEGER is captured with ULONG alignment, including native64.
    if address % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    let value = c.mem().u64(address)? as i64;
    if value < 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    Ok(Some(value))
}

pub(super) fn ea(c: &Ctx, address: u64, bytes: u32) -> Checked<Vec<u8>> {
    if address == 0 || bytes == 0 {
        return Ok(Vec::new());
    }
    if address % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    // The native EA list is at most 64 KiB. Reject unrepresentable requests
    // before allocation rather than allowing an unbounded caller-sized Vec.
    if bytes > 65536 {
        return status(0xc000_0050);
    }
    Ok(c.mem().bytes(address, bytes as usize)?)
}

pub(super) fn valid_ea(raw: &[u8]) -> bool {
    let mut at = 0;
    loop {
        let Some(header) = raw.get(at..at + 8) else {
            return false;
        };
        let next = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let name = usize::from(header[5]);
        let value = usize::from(u16::from_le_bytes(header[6..8].try_into().unwrap()));
        let size = 8 + name + 1 + value;
        if raw.get(at + 8 + name) != Some(&0) || raw.len() - at < size {
            return false;
        }
        if next == 0 {
            return true;
        }
        if next % 4 != 0 || next < size || next > raw.len() - at {
            return false;
        }
        at += next;
    }
}
