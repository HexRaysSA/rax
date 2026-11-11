//! Kernel argument capture precedes dispatch to an owned, typed peer endpoint.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

mod cache;
mod csr;

pub(super) fn send_wait_receive(c: &mut Ctx) -> ApiResult {
    let result = capture(c);
    guard_result(c, result)
}

fn capture(c: &mut Ctx) -> ApiResult {
    let (port, flags, send, send_attributes, receive, length, receive_attributes, timeout) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
        c.ptr(6)?,
        c.ptr(7)?,
    );
    // The WoW64 thunk captures caller SIZE_T before entering the native kernel.
    // Native64 checks the handle first. This is a width adapter, not peer policy.
    let wow_capacity = if c.arch() == WinArch::X86 && length != 0 {
        Some(c.read_ptr(length)?)
    } else {
        None
    };
    if port == c.arch().ptr(u64::MAX) || port == c.arch().ptr(u64::MAX - 1) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    match c.p.objects.get(port) {
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
        Some(Object::LpcPort(_)) => {}
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
    }
    // PORT_CONNECT is checked on the concrete handle before flags or native
    // pointer capture. WoW64's caller-length capture remains above this check.
    if c.p.objects.access(port).unwrap_or(0) & 1 == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    let cache_peer = matches!(c.p.objects.get(port), Some(Object::LpcPort(endpoint)) if endpoint.cache_peer().is_some());
    if flags == 0x10000 && cache_peer {
        return cache::release_reply(
            c,
            port,
            send,
            [
                send_attributes,
                receive,
                length,
                receive_attributes,
                timeout,
            ],
        );
    }
    if flags == u32::MAX || send == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_2.into());
    }
    if flags != 0x20000 {
        return Err(c.unsupported(format!("NtAlpcSendWaitReceivePort flags {flags:#x}")));
    }
    if receive == 0 {
        // STATUS_LPC_INVALID_CONNECTION_USAGE, independently observed for this
        // synchronous request on a legacy-compatible connected endpoint.
        return Flow::ret(0xC000_0705);
    }
    if timeout != 0 {
        c.mem().u64(timeout)?;
    }
    // Independent +2/+4/+8 native controls establish ULONG alignment on all
    // three guest ABIs, including64-bit entries.
    if receive % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let capacity = match wow_capacity {
        Some(capacity) => capacity,
        None if length != 0 => c.read_ptr(length)?,
        None => 952,
    };
    let header = if c.arch().is64() { 40 } else { 24 };
    probe_write(c, receive, header)?;
    if receive_attributes != 0 {
        c.mem().bytes(receive_attributes, 8)?;
    }
    let mut prefix = vec![0; header];
    c.mem().rd(send, &mut prefix)?;
    let data_bytes = u16::from_le_bytes(prefix[..2].try_into().expect("message data length"));
    let supplied_total = u16::from_le_bytes(prefix[2..4].try_into().expect("message total length"));
    let wire_total = if c.arch() == WinArch::X86 {
        // The thunk constructs a64-bit PORT_MESSAGE with16-bit length words.
        // Its TotalLength ignores the caller's word and wraps in that width.
        usize::from(data_bytes.wrapping_add(40))
    } else {
        usize::from(supplied_total)
    };
    if wire_total < 40 || usize::from(data_bytes) > wire_total - 40 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if wire_total > 952 {
        // The selected CSR connection advertised its measured952B maximum.
        return Flow::ret(0xC000_002F); // STATUS_PORT_MESSAGE_TOO_LONG
    }
    let total = if c.arch() == WinArch::X86 {
        usize::from(data_bytes) + header
    } else {
        wire_total
    };
    let message = c.mem().bytes(send, total)?;
    if cache_peer {
        return cache::lookup(
            c,
            port,
            [
                send_attributes,
                receive,
                length,
                receive_attributes,
                timeout,
            ],
            capacity,
            &message,
        );
    }
    csr::client_connect(
        c,
        port,
        send_attributes,
        receive,
        length,
        receive_attributes,
        timeout,
        capacity,
        &message,
    )
}
