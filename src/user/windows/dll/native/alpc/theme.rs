//! Process-local endpoint for the installed USER theme bootstrap exchange.
//! The two measured commands publish no host handle or shared memory section.
use super::{Connection, Ctx, Flow, Mem, Object, SYNCHRONOUS, WinArch, probe_write};
use crate::user::windows::hle::ApiResult;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LpcPort;

const HEADER: usize = 40;
const CONNECTION_BYTES: usize = 104;
const MESSAGE_BYTES: usize = 112;
pub(super) const PORT_NAME: &str = "\\ThemeApiPort";
const HELLO: &str = "ThemeApiConnectionRequest";
// These identifiers belong to the virtual service and are never used to open
// a host process or thread. They are multiples of four like native CIDs.
const SERVER_PROCESS: u64 = 0x4000_0000;
const SERVER_THREAD: u64 = SERVER_PROCESS + 4;

fn packet<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    bytes[0..2].copy_from_slice(&((N - HEADER) as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(N as u16).to_le_bytes());
    bytes
}

fn response(bytes: &mut [u8], kind: u16, sequence: u32) {
    bytes[4..6].copy_from_slice(&kind.to_le_bytes());
    bytes[8..16].copy_from_slice(&SERVER_PROCESS.to_le_bytes());
    bytes[16..24].copy_from_slice(&SERVER_THREAD.to_le_bytes());
    bytes[24..28].copy_from_slice(&sequence.to_le_bytes());
    bytes[32..40].copy_from_slice(&u64::from(sequence).to_le_bytes());
}

fn disjoint(a: u64, size_a: usize, b: u64, size_b: usize) -> bool {
    a.checked_add(size_a as u64)
        .zip(b.checked_add(size_b as u64))
        .is_some_and(|(end_a, end_b)| end_a <= b || end_b <= a)
}

pub(super) fn connect(c: &mut Ctx, connection: Connection) -> ApiResult {
    let Connection {
        out,
        attributes,
        port_attributes,
        flags,
        sid,
        message,
        length,
        send,
        receive,
        wait,
    } = connection;
    if c.arch() != WinArch::Arm64 {
        return Err(c.unsupported("native theme connection profile requires ARM64"));
    }
    if attributes != 0 || flags != SYNCHRONOUS || sid != 0 || send != 0 || receive != 0 || wait != 0
    {
        return Err(c.unsupported(format!("theme connection options flags={flags:#x}, object={} SID={} send={} receive={} timeout={}",
            attributes != 0, sid != 0, send != 0, receive != 0, wait != 0)));
    }
    let mut expected_attributes = [0; 72];
    for (index, value) in [0u32, 12, 2, 0x0101, 112].into_iter().enumerate() {
        expected_attributes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let requested_attributes = c.mem().bytes(port_attributes, expected_attributes.len())?;
    if let Some(index) = requested_attributes
        .iter()
        .zip(expected_attributes)
        .position(|(given, expected)| *given != expected)
    {
        return Err(c.unsupported(format!(
            "theme connection port attribute byte {index} differs"
        )));
    }
    let requested_length = c.mem().u32(length)?;
    if requested_length != CONNECTION_BYTES as u32 {
        return Err(c.unsupported(format!(
            "theme connection message length {requested_length} differs"
        )));
    }
    let mut reply = packet::<CONNECTION_BYTES>();
    for (index, unit) in HELLO.encode_utf16().enumerate() {
        let at = HEADER + index * 2;
        reply[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let requested = c.mem().bytes(message, reply.len())?;
    if let Some(index) = requested
        .iter()
        .zip(reply)
        .position(|(given, expected)| *given != expected)
    {
        return Err(c.unsupported(format!("theme connection request byte {index} differs")));
    }
    if !disjoint(out, 8, message, reply.len())
        || !disjoint(out, 8, length, 4)
        || !disjoint(message, reply.len(), length, 4)
    {
        return Err(c.unsupported("theme connection output spans overlap or wrap"));
    }
    probe_write(c, out, 8)?;
    probe_write(c, message, reply.len())?;
    probe_write(c, length, 4)?;
    response(&mut reply, 11, 1);
    let Some(id) = c.p.objects.try_create(Object::LpcPort(LpcPort::theme())) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, false, 0x001f_0001) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let publication = c
        .mem()
        .wr(message, &reply)
        .and_then(|_| c.mem().w64(out, handle.into()));
    if let Err(fault) = publication {
        let _ = c.p.objects.close(handle.into());
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}

pub(super) fn reply(
    c: &mut Ctx,
    handle: u64,
    [
        send,
        send_attributes,
        receive,
        length,
        receive_attributes,
        timeout,
    ]: [u64; 6],
    capacity: u64,
    request: &[u8],
) -> ApiResult {
    if c.arch() != WinArch::Arm64
        || send != receive
        || send_attributes != 0
        || receive_attributes != 0
        || timeout != 0
        || request.len() != MESSAGE_BYTES
        || length == 0
        || !disjoint(receive, MESSAGE_BYTES, length, 8)
    {
        return Err(c.unsupported("theme service request layout is not selected"));
    }
    let mut expected = packet::<MESSAGE_BYTES>();
    let command = u32::from_le_bytes(
        request[HEADER..HEADER + 4]
            .try_into()
            .expect("theme command"),
    );
    expected[HEADER..HEADER + 4].copy_from_slice(&command.to_le_bytes());
    if !matches!(command, 2 | 0x3ef) || request != expected {
        return Err(c.unsupported("theme service command is not selected"));
    }
    if capacity < MESSAGE_BYTES as u64 {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    let Some(Object::LpcPort(port)) = c.p.objects.get(handle) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let Some(sequence) = port.theme_message() else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let Some(next) = sequence.checked_add(1) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    probe_write(c, receive, MESSAGE_BYTES)?;
    probe_write(c, length, 8)?;
    let mut reply = packet::<MESSAGE_BYTES>();
    response(&mut reply, 2, sequence);
    if command == 2 {
        reply[HEADER + 8..HEADER + 12].copy_from_slice(&0x0004_0002u32.to_le_bytes());
    }
    c.mem().wr(receive, &reply)?;
    c.write_ptr(length, MESSAGE_BYTES as u64)?;
    let Some(Object::LpcPort(port)) = c.p.objects.get_mut(handle) else {
        unreachable!("checked local endpoint");
    };
    port.advance_theme(next);
    Flow::ret(STATUS_SUCCESS.into())
}
