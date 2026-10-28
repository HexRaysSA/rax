//! Build29683 native/WoW64 capture and selected-namespace connection failures.
//! No guest pointer, handle, message or connection request reaches a host port.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::LookupError;

/// Bound transient caller-data probing separately from any server capacity.
const MAX_INFORMATION_BYTES: u64 = 1 << 20;
mod csr;

struct Capture {
    secure: bool,
    out: u64,
    qos: u64,
    name: Option<(u16, u64)>,
    client: u64,
    client_length: Option<u32>,
    server: u64,
    server_length: Option<u32>,
    sid: u64,
    maximum: u64,
    information: u64,
    length: u64,
}

impl Capture {
    fn service(&self) -> &'static str {
        if self.secure {
            "NtSecureConnectPort"
        } else {
            "NtConnectPort"
        }
    }
}

fn capture(c: &mut Ctx, secure: bool) -> Result<Capture, ApiErr> {
    let (out, name, qos, client, sid, server, maximum, information, length) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        if secure { c.ptr(4)? } else { 0 },
        c.ptr(if secure { 5 } else { 4 })?,
        c.ptr(if secure { 6 } else { 5 })?,
        c.ptr(if secure { 7 } else { 6 })?,
        c.ptr(if secure { 8 } else { 7 })?,
    );
    // These wrapper captures precede the WoW64 failure HANDLE copyback.
    probe_write(c, out, c.psize() as usize)?;
    let name = if name == 0 {
        None
    } else {
        let mut header = [0u8; 16];
        let bytes = if c.arch().is64() { 16 } else { 8 };
        c.mem().rd(name, &mut header[..bytes])?;
        let length = u16::from_le_bytes([header[0], header[1]]);
        let buffer = if c.arch().is64() {
            u64::from_le_bytes(header[8..16].try_into().expect("fixed header span"))
        } else {
            u32::from_le_bytes(header[4..8].try_into().expect("fixed header span")).into()
        };
        Some((length, buffer))
    };
    if qos != 0 {
        c.mem().rd(qos, &mut [0; 12])?;
    }
    let client_length = if client == 0 {
        None
    } else {
        let length = c.mem().u32(client)?;
        let bytes = if c.arch() == WinArch::X86 && length == 24 {
            24
        } else {
            48
        };
        c.mem().rd(client, &mut [0; 48][..bytes])?;
        Some(length)
    };
    let server_length = if server == 0 {
        None
    } else {
        let mut view = [0; 24];
        c.mem().rd(server, &mut view)?;
        Some(u32::from_le_bytes(
            view[..4].try_into().expect("fixed view span"),
        ))
    };
    Ok(Capture {
        secure,
        out,
        qos,
        name,
        client,
        client_length,
        server,
        server_length,
        sid,
        maximum,
        information,
        length,
    })
}

pub(super) fn connect(c: &mut Ctx) -> ApiResult {
    let result = checked(c, true);
    guard_result(c, result)
}

pub(super) fn connect_plain(c: &mut Ctx) -> ApiResult {
    let result = checked(c, false);
    guard_result(c, result)
}

fn checked(c: &mut Ctx, secure: bool) -> ApiResult {
    let request = capture(c, secure)?;
    let result = resolve(c, &request);
    // The measured WoW64 adapter stores a zero 32-bit HANDLE after a reached
    // native failure, including SID/data faults. Early wrapper faults above
    // leave the caller's bytes unchanged. Unsupported paths publish no output.
    if c.arch() == WinArch::X86
        && !matches!(&result, Err(ApiErr::Unimplemented(_)))
        && !matches!(
            &result,
            Ok(Flow::Ret(crate::user::windows::hle::Value::Int(0)))
        )
    {
        c.mem().w32(request.out, 0)?;
    }
    result
}

fn resolve(c: &mut Ctx, request: &Capture) -> ApiResult {
    if request
        .client_length
        .is_some_and(|length| length != 48 && !(c.arch() == WinArch::X86 && length == 24))
        || request.server_length.is_some_and(|length| length != 24)
    {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Native and WoW64 both require writable views even on a missing port.
    // These probes follow the wrapper's read capture: a WoW64 write fault
    // therefore still reaches its zero-HANDLE failure copyback.
    if let Some(length) = request.client_length {
        let bytes = if c.arch() == WinArch::X86 && length == 24 {
            24
        } else {
            48
        };
        probe_write(c, request.client, bytes)?;
    }
    if request.server_length.is_some() {
        probe_write(c, request.server, 24)?;
    }
    if request.sid != 0 {
        let mut header = [0; 8];
        c.mem().rd(request.sid, &mut header)?;
        if header[0] != 1 || header[1] > 15 {
            return Flow::ret(STATUS_INVALID_SID.into());
        }
        let bytes = 8 + usize::from(header[1]) * 4;
        c.mem().rd(request.sid, &mut [0; 68][..bytes])?;
    }
    if request.maximum != 0 {
        probe_write(c, request.maximum, 4)?;
    }
    if request.length != 0 {
        // The missing-port path reads this counter without requiring write
        // access. Native read-only controls preserve it and return NAME_NOT_FOUND.
        let length = u64::from(c.mem().u32(request.length)?);
        if length > MAX_INFORMATION_BYTES {
            return Err(c.unsupported(&format!(
                "{} information exceeds the 1 MiB capture bound",
                request.service()
            )));
        }
        // Probe in fixed chunks: O(B) checking time and O(1) scratch storage
        // for B caller bytes. No message is sent and no caller data retained.
        let mut captured = 0;
        let mut scratch = [0; 4096];
        while captured < length {
            let bytes = (length - captured).min(scratch.len() as u64) as usize;
            let Some(address) = request.information.checked_add(captured) else {
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            };
            probe_write(c, address, bytes)?;
            c.mem().rd(address, &mut scratch[..bytes])?;
            captured += bytes as u64;
        }
    }
    let Some((length, buffer)) = request.name else {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    };
    if length == 0 || length % 2 != 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    if buffer % 2 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let mut bytes = vec![0; usize::from(length)];
    c.mem().rd(buffer, &mut bytes)?;
    let name: Vec<_> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    match c.p.object_namespace.lookup_port(&name) {
        Err(LookupError::Status(status)) => Flow::ret(status.into()),
        Err(LookupError::Unselected) => Err(c.unsupported(&format!(
            "{} namespace or intermediate target is unselected",
            request.service()
        ))),
        Ok(()) => match c.p.object_namespace.csr_server(&name) {
            Ok(server) => csr::connect(c, request, server),
            Err(_) => Err(c.unsupported(&format!(
                "{} requires a matched selected guest server and owned shared views",
                request.service()
            ))),
        },
    }
}
