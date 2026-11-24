//! Bounded connection capture and transactional guest-owned handle transfer.
use super::alpc::{SYNCHRONOUS, WOW64_SYNCHRONOUS};
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::cache::{PORT_NAME, SECTION_BYTES, server_security};
use crate::user::windows::objects::{LpcPort, Object};

mod policy_lookup;

const HANDLE_ATTRIBUTE: u32 = 0x1000_0000;

pub(super) fn connect(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

struct Connection {
    out: u64,
    server: u64,
    client: u64,
    port: u64,
    flags: u32,
    security: u64,
    message: u64,
    length: u64,
    output: u64,
    input: u64,
    timeout: u64,
}

fn checked(c: &mut Ctx) -> ApiResult {
    let arguments = Connection {
        out: c.ptr(0)?,
        server: c.ptr(1)?,
        client: c.ptr(2)?,
        port: c.ptr(3)?,
        flags: c.u32(4)?,
        security: c.ptr(5)?,
        message: c.ptr(6)?,
        length: c.ptr(7)?,
        output: c.ptr(8)?,
        input: c.ptr(9)?,
        timeout: c.ptr(10)?,
    };
    // The installed WoW64 RPC client sets the native message-width flag on
    // Policy Lookup connections even when there is no connection message.
    let wow64_policy_lookup =
        c.arch() == WinArch::X86 && arguments.client != 0 && arguments.flags == WOW64_SYNCHRONOUS;
    if (arguments.flags != SYNCHRONOUS && !wow64_policy_lookup)
        || arguments.output != 0
        || arguments.timeout != 0
    {
        return Err(c.unsupported("NtAlpcConnectPortEx connection options are not selected"));
    }
    if arguments.client != 0 {
        return policy_lookup::connect(c, arguments);
    }
    cache(c, arguments)
}

fn pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}

fn cache(c: &mut Ctx, arguments: Connection) -> ApiResult {
    let Connection {
        out,
        server: connection,
        port,
        security,
        message,
        length,
        input,
        ..
    } = arguments;
    let width = c.psize() as usize;
    let wow = c.arch() == WinArch::X86;
    let attributes_bytes = if wow { 24 } else { 48 };
    let attributes = c.mem().bytes(connection, attributes_bytes)?;
    if attributes[..4] != (attributes_bytes as u32).to_le_bytes()
        || pointer(&attributes, width, width) != 0
        || attributes[3 * width..3 * width + 4] != [0; 4]
        || pointer(&attributes, if wow { 16 } else { 32 }, width) != 0
        || pointer(&attributes, if wow { 20 } else { 40 }, width) != 0
    {
        return Err(
            c.unsupported("NtAlpcConnectPortEx connection object attributes are not selected")
        );
    }
    let name_at = pointer(&attributes, 2 * width, width);
    let name_header = c.mem().bytes(name_at, if wow { 8 } else { 16 })?;
    let name_length = usize::from(u16::from_le_bytes(
        name_header[..2].try_into().expect("name length"),
    ));
    let expected_name: Vec<u16> = PORT_NAME.encode_utf16().collect();
    if name_length != expected_name.len() * 2 {
        return Err(c.unsupported("NtAlpcConnectPortEx port name is not selected"));
    }
    let name = c
        .mem()
        .bytes(pointer(&name_header, width, width), name_length)?;
    if !name
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .eq(expected_name.iter().copied())
    {
        return Err(c.unsupported("NtAlpcConnectPortEx port name is not selected"));
    }
    let server =
        c.p.object_namespace
            .cache_server(&expected_name)
            .map_err(|error| {
                c.unsupported(format!(
                    "NtAlpcConnectPortEx cache service selection: {error:?}"
                ))
            })?;
    if server.metadata.server_pid == c.p.pid {
        return Err(c.unsupported("NtAlpcConnectPortEx cache server identity aliases caller"));
    }
    let port_bytes = if wow { 44 } else { 72 };
    let mut expected_port = vec![0; port_bytes];
    expected_port[..4].copy_from_slice(&0x80000u32.to_le_bytes());
    expected_port[4..8].copy_from_slice(&12u32.to_le_bytes());
    expected_port[12..14].copy_from_slice(&[1, 1]);
    for (index, value) in [
        80u64,
        0,
        u32::MAX.into(),
        u32::MAX.into(),
        u32::MAX.into(),
        u32::MAX.into(),
    ]
    .into_iter()
    .enumerate()
    {
        expected_port[16 + index * width..16 + (index + 1) * width]
            .copy_from_slice(&value.to_le_bytes()[..width]);
    }
    expected_port[16 + 6 * width..20 + 6 * width].copy_from_slice(&0x80u32.to_le_bytes());
    if c.mem().bytes(port, port_bytes)? != expected_port {
        return Err(c.unsupported(
            "NtAlpcConnectPortEx cache port attributes differ from selected profile",
        ));
    }
    let expected_security = server_security();
    if c.mem().bytes(security, 100)? != expected_security {
        return Err(c.unsupported("NtAlpcConnectPortEx server security descriptor is not selected"));
    }
    let header = if wow { 24 } else { 40 };
    let total = header + 40;
    if c.read_ptr(length)? != total as u64 {
        return Err(c.unsupported("NtAlpcConnectPortEx connection buffer extent is not selected"));
    }
    let mut expected_message = vec![0; total];
    expected_message[..2].copy_from_slice(&40u16.to_le_bytes());
    expected_message[2..4].copy_from_slice(&(total as u16).to_le_bytes());
    expected_message[header + 8..header + 12].copy_from_slice(&7u32.to_le_bytes());
    if c.mem().bytes(message, total)? != expected_message
        || c.mem().u32(input)? != HANDLE_ATTRIBUTE
        || c.mem().u32(input + 4)? != 0
    {
        return Err(c.unsupported(
            "NtAlpcConnectPortEx cache connection packet or handle attribute is not selected",
        ));
    }
    let attribute_bytes = if wow { 24 } else { 32 };
    let spans = [
        (out, width),
        (message, total),
        (length, width),
        (input, attribute_bytes),
    ];
    let mut originals = Vec::with_capacity(spans.len());
    // O(1) disjoint-span checks, at most128 bytes of output undo state.
    for (index, &(base, bytes)) in spans.iter().enumerate() {
        let end = base
            .checked_add(bytes as u64)
            .ok_or_else(|| c.unsupported("NtAlpcConnectPortEx output span wraps"))?;
        for &(other, size) in &spans[..index] {
            if other
                .checked_add(size as u64)
                .is_none_or(|other_end| base < other_end && other < end)
            {
                return Err(
                    c.unsupported("NtAlpcConnectPortEx overlapping output spans are not measured")
                );
            }
        }
        probe_write(c, base, bytes)?;
        let mut bytes = vec![0; bytes];
        c.p.space.read_raw(base, &mut bytes).map_err(|error| {
            ApiErr::Internal(format!("ALPC prepared-output snapshot: {error:?}"))
        })?;
        originals.push((base, bytes));
    }
    let mut peer = match server.peer() {
        Ok(peer) => peer,
        Err(error) => return Flow::ret(error.status().into()),
    };
    let mut reply = expected_message;
    reply[4..6].copy_from_slice(&(if wow { 0x300bu16 } else { 0x200bu16 }).to_le_bytes());
    reply[8..8 + width].copy_from_slice(&u64::from(peer.server_pid).to_le_bytes()[..width]);
    reply[8 + width..8 + 2 * width]
        .copy_from_slice(&u64::from(peer.server_thread).to_le_bytes()[..width]);
    // Transport identifiers belong to this private peer, independent of the
    // captured host's changing message/callback identifiers and server thread.
    reply[8 + 2 * width..12 + 2 * width].copy_from_slice(&peer.connection_message.to_le_bytes());
    reply[header - width..header]
        .copy_from_slice(&u64::from(peer.connection_message).to_le_bytes()[..width]);
    reply[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
    peer.pending_reply = Some(reply.clone());
    let section = Object::Mapping {
        file: None,
        size: SECTION_BYTES,
        protect: prot::READWRITE,
        attributes: 0x0800_0000,
        shared: Some(peer.backing.clone()),
    };
    let Some(section_id) = c.p.objects.try_create(section) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(section_handle) = c.p.objects.open_access(section_id, false, 6) else {
        c.p.objects.release(section_id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(port_id) =
        c.p.objects
            .try_create(Object::LpcPort(LpcPort::cache(peer)))
    else {
        c.p.objects.close(section_handle.into());
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(port_handle) = c.p.objects.open_access(port_id, false, 0x001F_0001) else {
        c.p.objects.release(port_id);
        c.p.objects.close(section_handle.into());
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let mut attributes = originals[3].1.clone();
    attributes[4..8].copy_from_slice(&HANDLE_ATTRIBUTE.to_le_bytes());
    attributes[8..12].fill(0);
    if !wow {
        // Native64 copies the complete24-byte caller attribute, including
        // zero padding after Flags, rather than preserving caller canaries.
        attributes[12..16].fill(0);
    }
    let handle_at = if wow { 12 } else { 16 };
    attributes[handle_at..handle_at + width]
        .copy_from_slice(&u64::from(section_handle).to_le_bytes()[..width]);
    attributes[handle_at + width..handle_at + width + 4].copy_from_slice(&0x80u32.to_le_bytes());
    attributes[handle_at + width + 4..handle_at + width + 8].copy_from_slice(&6u32.to_le_bytes());
    let publication = (|| -> Result<(), ApiErr> {
        c.mem().wr(message, &reply)?;
        c.mem().wr(input, &attributes)?;
        c.write_ptr(length, total as u64)?;
        c.write_ptr(out, port_handle.into())?;
        Ok(())
    })();
    if let Err(error) = publication {
        c.p.objects.close(port_handle.into());
        c.p.objects.close(section_handle.into());
        for (address, bytes) in originals {
            c.p.space
                .write_raw(address, &bytes)
                .map_err(|fault| ApiErr::Internal(format!("ALPC output rollback: {fault:?}")))?;
        }
        return Err(error);
    }
    Flow::ret(STATUS_SUCCESS.into())
}
