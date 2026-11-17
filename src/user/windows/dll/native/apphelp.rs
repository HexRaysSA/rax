//! Measured AppHelp CDB and executable process-cache queries.
use super::query::write_guard_result;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

mod executable_process;

fn number(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn pointer(bytes: &[u8], offset: usize, wow: bool) -> u64 {
    if wow {
        u64::from(number(bytes, offset))
    } else {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }
}

pub(super) fn control(c: &mut Ctx) -> ApiResult {
    let result = capture(c);
    write_guard_result(c, result)
}

fn capture(c: &mut Ctx) -> ApiResult {
    let operation = c.u32(0)?;
    if operation == 11 {
        return executable_process::lookup(c);
    }
    if operation != 6 {
        return Err(c.unsupported(format!("NtApphelpCacheControl operation {operation}")));
    }
    let input = c.ptr(1)?;
    let wow = c.arch() == WinArch::X86;
    let mut packet = [0; 392];
    let bytes = if wow { 204 } else { 392 };
    // Capture the entire fixed packet before validating any inner fields.
    c.mem().rd(input, &mut packet[..bytes])?;
    let result = lookup(c, &packet, wow).and_then(|status| Flow::ret(status.into()));
    let result = write_guard_result(c, result);
    let status = match result {
        Ok(Flow::Ret(Value::Int(status))) => status as u32,
        Err(ApiErr::Fault(_)) => STATUS_ACCESS_VIOLATION,
        Err(error) => return Err(error),
        Ok(_) => unreachable!(),
    };
    if wow {
        // Only DriverStatus and ParamsOutSize are projected, in that order,
        // even after a kernel failure. A copyback fault overrides its status
        // and retains a completed output write (including overlapping fields).
        c.mem().w32(input + 192, number(&packet, 192))?;
        c.mem().w32(input + 200, number(&packet, 200))?;
    }
    Flow::ret(status.into())
}

fn lookup(c: &mut Ctx, packet: &[u8], wow: bool) -> Result<u32, ApiErr> {
    let (name, output) = if wow { (132, 196) } else { (248, 376) };
    let length = u16::from_le_bytes(packet[name..name + 2].try_into().unwrap());
    let buffer = pointer(packet, name + if wow { 4 } else { 8 }, wow);
    let destination = pointer(packet, output, wow);
    let size = number(packet, output + if wow { 4 } else { 8 });
    if length == 0 || buffer == 0 || destination == 0 || size != 4 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if length >= 65_534 {
        return Ok(STATUS_INTEGER_OVERFLOW);
    }
    let mut data = Vec::new();
    if data.try_reserve_exact(usize::from(length)).is_err() {
        return Ok(STATUS_NO_MEMORY);
    }
    data.resize(usize::from(length), 0);
    c.mem().rd(buffer, &mut data)?;
    if data[0] == 0 && data.get(1).copied().unwrap_or(0) == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // MaximumLength is ignored; odd Length captures all its bytes but only
    // complete UTF-16 code units participate in the counted name comparison.
    let units: Vec<_> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
        .collect();
    let value = c.p.appcompat.lookup(&units);
    if destination % 4 != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    super::query::probe_write(c, destination, 4)?;
    c.mem().w32(destination, value)?;
    Ok(STATUS_SUCCESS)
}
