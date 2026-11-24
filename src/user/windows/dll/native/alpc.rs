//! Kernel argument capture precedes dispatch to an owned, typed peer endpoint.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{LsarpcInterface, Object};

mod activation;
mod cache;
mod child_start;
mod csr;
mod information;
pub(super) mod lsarpc;
mod theme;

const SYNCHRONOUS: u32 = 0x0002_0000;

struct Connection {
    out: u64,
    attributes: u64,
    port_attributes: u64,
    flags: u32,
    sid: u64,
    message: u64,
    length: u64,
    send: u64,
    receive: u64,
    wait: u64,
}

pub(super) use child_start::application_manifest_name;

pub(super) fn query_information(c: &mut Ctx) -> ApiResult {
    information::query(c)
}

pub(super) fn connect(c: &mut Ctx) -> ApiResult {
    let result = connect_checked(c);
    guard_result(c, result)
}

fn connect_checked(c: &mut Ctx) -> ApiResult {
    let out = c.ptr(0)?;
    let name = c.ptr(1)?;
    let connection = Connection {
        out,
        attributes: c.ptr(2)?,
        port_attributes: c.ptr(3)?,
        flags: c.u32(4)?,
        sid: c.ptr(5)?,
        message: c.ptr(6)?,
        length: c.ptr(7)?,
        send: c.ptr(8)?,
        receive: c.ptr(9)?,
        wait: c.ptr(10)?,
    };
    let build = c.p.native.as_ref().map(|runtime| runtime.version.build);
    if build != Some(29708) {
        return Err(c.unsupported(format!(
            "native ALPC connection profile is unavailable on {} build {build:?}",
            c.arch()
        )));
    }

    let width = c.psize() as usize;
    let descriptor = c.mem().bytes(name, 2 * width)?;
    let bytes = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let maximum = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    if bytes % 2 != 0 || maximum < bytes {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Neither selected endpoint admits an arbitrary-sized object name.
    let (path, connect): (&str, fn(&mut Ctx, Connection) -> ApiResult) = match bytes {
        count if count == theme::PORT_NAME.len() * 2 => (theme::PORT_NAME, theme::connect),
        count if count == lsarpc::PORT_NAME.len() * 2 => (lsarpc::PORT_NAME, lsarpc::connect),
        _ => return Err(c.unsupported("ALPC connection is outside the selected local endpoints")),
    };
    let buffer = u64::from_le_bytes({
        let mut pointer = [0; 8];
        pointer[..width].copy_from_slice(&descriptor[width..]);
        pointer
    });
    let units = c.mem().wunits(buffer, bytes / 2)?;
    if !units.into_iter().eq(path.encode_utf16()) {
        return Err(c.unsupported("ALPC connection is outside the selected local endpoints"));
    }
    connect(c, connection)
}

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
    let lsarpc_peer = match c.p.objects.get(port) {
        Some(Object::LpcPort(endpoint)) => endpoint.lsarpc_peer().map(|peer| peer.interface),
        _ => None,
    };
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
    let wide_wow64 = c.arch() == WinArch::X86
        && lsarpc_peer == Some(LsarpcInterface::Policy)
        && flags == lsarpc::WOW64_SYNCHRONOUS;
    if flags != SYNCHRONOUS && !wide_wow64 {
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
        None if lsarpc_peer.is_some() => lsarpc::MAX_MESSAGE as u64,
        None => 952,
    };
    // The installed WoW64 RPC client can supply native messages and
    // attributes while the thunk still accepts a 32-bit receive length.
    let converted_message = c.arch() == WinArch::X86 && !wide_wow64;
    let header = if converted_message { 24 } else { 40 };
    if wide_wow64 && (send_attributes % 8 != 0 || receive_attributes % 8 != 0) {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    probe_write(c, receive, header)?;
    if receive_attributes != 0 {
        c.mem().bytes(receive_attributes, 8)?;
    }
    let mut prefix = vec![0; header];
    c.mem().rd(send, &mut prefix)?;
    let data_bytes = u16::from_le_bytes(prefix[..2].try_into().expect("message data length"));
    let supplied_total = u16::from_le_bytes(prefix[2..4].try_into().expect("message total length"));
    let wire_total = if converted_message {
        // The thunk constructs a64-bit PORT_MESSAGE with16-bit length words.
        // Its TotalLength ignores the caller's word and wraps in that width.
        usize::from(data_bytes.wrapping_add(40))
    } else {
        usize::from(supplied_total)
    };
    if wire_total < 40 || usize::from(data_bytes) > wire_total - 40 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let limit = if lsarpc_peer.is_some() {
        lsarpc::MAX_MESSAGE
    } else {
        952
    };
    if wire_total > limit {
        return Flow::ret(0xC000_002F); // STATUS_PORT_MESSAGE_TOO_LONG
    }
    let total = if converted_message {
        usize::from(data_bytes) + header
    } else {
        wire_total
    };
    let message = c.mem().bytes(send, total)?;
    if lsarpc_peer.is_some() {
        return lsarpc::exchange(
            c,
            port,
            [send_attributes, receive, length, receive_attributes],
            capacity,
            if converted_message { 4 } else { 8 },
            &message,
        );
    }
    if matches!(c.p.objects.get(port), Some(Object::LpcPort(endpoint)) if endpoint.theme_message().is_some())
    {
        return theme::reply(
            c,
            port,
            [
                send,
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
    if child_start::is_request(&message) {
        return child_start::register(
            c,
            port,
            [
                receive,
                length,
                send_attributes,
                receive_attributes,
                timeout,
            ],
            capacity,
            &message,
        );
    }
    if activation::is_request(&message) {
        return activation::reply(
            c,
            port,
            [
                receive,
                length,
                send_attributes,
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
