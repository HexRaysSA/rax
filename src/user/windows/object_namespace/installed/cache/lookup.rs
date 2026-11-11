//! Acquire Sections through the selected host service with adapter-owned
//! packets and a retained file. Guest ALPC packets never cross this boundary.
use super::*;
use crate::user::windows::object_namespace::FileSection;
use crate::user::windows::object_namespace::cache::{
    LOOKUP_ACCESS, lookup_request, server_security,
};
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

const HANDLE_ATTRIBUTE: u32 = 0x1000_0000;
const LOOKUP_ATTRIBUTES: u32 = 0x3000_0000;
const RELEASE_MESSAGE: u32 = 0x10000;
const SYNC_REQUEST: u32 = 0x20000;

#[repr(C)]
struct PortAttributes {
    flags: u32,
    qos: [u32; 3],
    limits: [usize; 6],
    duplicate_object_types: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation_base: usize,
    allocation_protection: u32,
    partition: u16,
    bytes: usize,
    state: u32,
    protection: u32,
    kind: u32,
}
const _: [(); 72] = [(); std::mem::size_of::<PortAttributes>()];
const _: [(); 48] = [(); std::mem::size_of::<Region>()];

#[repr(align(8))]
struct Packet([u8; 80]);
#[repr(align(8))]
struct MessageAttributes([u8; 64]);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtAlpcConnectPortEx(
        output: *mut Handle,
        name: *mut Attributes,
        client: Handle,
        port: *mut PortAttributes,
        flags: u32,
        security: *const u8,
        message: *mut u8,
        length: *mut usize,
        send: *mut u8,
        receive: *mut u8,
        timeout: *const i64,
    ) -> i32;
    fn AlpcInitializeMessageAttribute(
        mask: u32,
        attributes: *mut u8,
        size: usize,
        required: *mut usize,
    ) -> i32;
    fn NtAlpcSendWaitReceivePort(
        port: Handle,
        flags: u32,
        send: *mut u8,
        send_attrs: *mut u8,
        receive: *mut u8,
        length: *mut usize,
        receive_attrs: *mut u8,
        timeout: *const i64,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MapViewOfFile(section: Handle, access: u32, high: u32, low: u32, count: usize) -> Handle;
    fn UnmapViewOfFile(base: Handle) -> i32;
    fn VirtualQuery(base: Handle, region: *mut Region, size: usize) -> usize;
    fn ReadProcessMemory(
        process: Handle,
        from: Handle,
        to: Handle,
        bytes: usize,
        copied: *mut usize,
    ) -> i32;
}

fn require_zero(status: i32, operation: &str) -> io::Result<()> {
    if status != 0 {
        return Err(invalid(&format!("{operation}: {:#010x}", status as u32)));
    }
    Ok(())
}

fn attributes(mask: u32, expected: usize) -> io::Result<MessageAttributes> {
    let mut buffer = MessageAttributes([0; 64]);
    let mut required = 0;
    // SAFETY: local fixed mask and an initialized, aligned buffer and size.
    let status = unsafe {
        AlpcInitializeMessageAttribute(mask, buffer.0.as_mut_ptr(), buffer.0.len(), &mut required)
    };
    require_zero(status, "AlpcInitializeMessageAttribute")?;
    if required != expected {
        return Err(invalid("native translation-cache attribute layout changed"));
    }
    Ok(buffer)
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed packet word"))
}

fn take_handle(bytes: &[u8], at: usize) -> io::Result<OwnedHandle> {
    let value = usize::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed handle field"));
    if value == 0 || value == usize::MAX {
        return Err(invalid("native translation-cache transfer has no handle"));
    }
    // SAFETY: called only on a successful transfer with the handle attribute
    // present. These kernel-provided handle values are uniquely owned locally.
    Ok(unsafe { OwnedHandle::from_raw_handle(value as Handle) })
}

fn release(port: &OwnedHandle, message: &mut Packet) -> io::Result<()> {
    // SAFETY: the live host port owns this native reply. All optional arguments
    // are null and neither the packet nor the port came from guest memory.
    let status = unsafe {
        NtAlpcSendWaitReceivePort(
            port.as_raw_handle(),
            RELEASE_MESSAGE,
            message.0.as_mut_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            std::ptr::null(),
        )
    };
    require_zero(status, "release native translation-cache message")
}

fn connect() -> io::Result<OwnedHandle> {
    let mut name_buf: Vec<u16> = PORT_NAME.encode_utf16().collect();
    let length = (name_buf.len() * 2) as u16;
    let mut name = Unicode {
        length,
        maximum: length,
        buffer: name_buf.as_mut_ptr(),
    };
    let mut object = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &mut name,
        flags: 0,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut attrs = PortAttributes {
        flags: 0x80000,
        qos: [12, 0, 0x101],
        limits: [
            80,
            0,
            u32::MAX as usize,
            u32::MAX as usize,
            u32::MAX as usize,
            u32::MAX as usize,
        ],
        duplicate_object_types: 0x80,
        reserved: 0,
    };
    let security = server_security();
    let mut message = Packet([0; 80]);
    message.0[..4].copy_from_slice(&[40, 0, 80, 0]);
    message.0[48] = 7;
    let mut size = message.0.len();
    let mut receive = attributes(HANDLE_ATTRIBUTE, 32)?;
    let mut port = null_mut();
    // SAFETY: fixed selected service name/security and live, aligned host
    // buffers with measured extents. The API retains none of these pointers.
    let status = unsafe {
        NtAlpcConnectPortEx(
            &mut port,
            &mut object,
            null_mut(),
            &mut attrs,
            SYNC_REQUEST,
            security.as_ptr(),
            message.0.as_mut_ptr(),
            &mut size,
            null_mut(),
            receive.0.as_mut_ptr(),
            std::ptr::null(),
        )
    };
    require_zero(status, "connect to selected native translation cache")?;
    if port.is_null() {
        return Err(invalid("native translation-cache connection returned NULL"));
    }
    // SAFETY: unique port received from the successful connect.
    let port = unsafe { OwnedHandle::from_raw_handle(port) };
    let valid = word(&receive.0, 4);
    let section = (valid & HANDLE_ATTRIBUTE != 0)
        .then(|| take_handle(&receive.0, 16))
        .transpose()?;
    if size != 80 || valid != HANDLE_ATTRIBUTE || section.is_none() {
        return Err(invalid(
            "native translation-cache connection reply layout changed",
        ));
    }
    release(&port, &mut message)?;
    drop(section);
    Ok(port)
}

struct View(Handle);
impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: unique successful MapViewOfFile, unmapped once.
        unsafe { UnmapViewOfFile(self.0) };
    }
}

fn section_extent(section: &OwnedHandle) -> io::Result<u64> {
    let mut basic = [0u64; 7];
    let mut returned = 0;
    // SAFETY: owned native transferred handle and initialized aligned 56-byte
    // ObjectBasicInformation buffer. This query requests no additional rights.
    let status = unsafe {
        NtQueryObject(
            section.as_raw_handle(),
            0,
            basic.as_mut_ptr().cast(),
            56,
            &mut returned,
        )
    };
    require_zero(status, "query native translation-cache section grant")?;
    if (basic[0] >> 32) as u32 != 0xc {
        return Err(invalid("native translation-cache section grant changed"));
    }
    // SAFETY: live section handle from the selected peer, fixed FILE_MAP_READ
    // request. A complete native view supplies the kernel-rounded extent.
    let address = unsafe { MapViewOfFile(section.as_raw_handle(), 4, 0, 0, 0) };
    if address.is_null() {
        return Err(io::Error::last_os_error());
    }
    let view = View(address);
    let mut region = Region::default();
    // SAFETY: live view address and exclusive initialized native region output.
    let bytes = unsafe { VirtualQuery(view.0, &mut region, std::mem::size_of::<Region>()) };
    if bytes != std::mem::size_of::<Region>()
        || region.base != address as usize
        || region.allocation_base != address as usize
        || region.kind != 0x40000
        || region.state != 0x1000
        || region.protection != 2
        || !(4096..=64 << 20).contains(&region.bytes)
    {
        return Err(invalid("native translation-cache view geometry changed"));
    }
    let mut magic = [0u8; 4];
    let mut copied = 0;
    // SAFETY: the first four bytes belong to the live read-only view. Reading
    // through the kernel converts a backing I/O fault into a regular error.
    let read = unsafe {
        ReadProcessMemory(
            (-1isize) as Handle,
            view.0,
            magic.as_mut_ptr().cast(),
            magic.len(),
            &mut copied,
        )
    };
    if read == 0 || copied != magic.len() || &magic != b"XTAC" {
        return Err(invalid("native translation-cache view signature changed"));
    }
    drop(view);
    let fits = |bytes| -> io::Result<bool> {
        // SAFETY: fixed read-only view of the same retained native Section.
        let address = unsafe { MapViewOfFile(section.as_raw_handle(), 4, 0, 0, bytes) };
        if !address.is_null() {
            drop(View(address));
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::PermissionDenied {
            return Ok(false);
        }
        Err(error)
    };
    let mut lower = region.bytes - 4096 + 1;
    let mut upper = region.bytes;
    if !fits(lower)? || fits(upper + 1)? {
        return Err(invalid(
            "native translation-cache logical extent is outside the last mapped page",
        ));
    }
    // SECTION_QUERY is absent. The fixed read-only view count exposes the
    // native byte bound, with at most 12 probes over one 4 KiB page.
    while lower < upper {
        let middle = lower + (upper - lower).div_ceil(2);
        if fits(middle)? {
            lower = middle;
        } else {
            upper = middle - 1;
        }
    }
    Ok(lower as u64)
}

pub(super) fn file(file: &File) -> io::Result<Option<Arc<FileSection>>> {
    let port = connect()?;
    let mut message = Packet(lookup_request());
    let mut send = attributes(LOOKUP_ATTRIBUTES, 64)?;
    let mut receive = attributes(LOOKUP_ATTRIBUTES, 64)?;
    send.0[4..8].copy_from_slice(&HANDLE_ATTRIBUTE.to_le_bytes());
    send.0[48..56].copy_from_slice(&(file.as_raw_handle() as usize).to_le_bytes());
    send.0[60..64].copy_from_slice(&LOOKUP_ACCESS.to_le_bytes());
    let mut reply = Packet([0; 80]);
    let mut length = reply.0.len();
    // SAFETY: fixed normal operation on the private selected host connection.
    // The only resource transferred is the already admitted, live host file at
    // the fixed read/execute/attribute grant. All pointers refer to local buffers.
    let status = unsafe {
        NtAlpcSendWaitReceivePort(
            port.as_raw_handle(),
            SYNC_REQUEST,
            message.0.as_mut_ptr(),
            send.0.as_mut_ptr(),
            reply.0.as_mut_ptr(),
            &mut length,
            receive.0.as_mut_ptr(),
            std::ptr::null(),
        )
    };
    require_zero(status, "lookup native translation-cache section")?;
    let valid = word(&receive.0, 4);
    let section = (valid & HANDLE_ATTRIBUTE != 0)
        .then(|| take_handle(&receive.0, 48))
        .transpose()?;
    if length != 80 || word(&reply.0, 0) != 0x0050_0028 || word(&reply.0, 40) != 3 {
        return Err(invalid(
            "native translation-cache lookup reply layout changed",
        ));
    }
    match section {
        None if valid == 0x2000_0000 && word(&reply.0, 4) == 2 => Ok(None),
        Some(section)
            if valid == LOOKUP_ATTRIBUTES
                && word(&reply.0, 4) == 0x2002
                && word(&receive.0, 56) == 0x80
                && word(&receive.0, 60) == 0xc =>
        {
            release(&port, &mut reply)?;
            let size = section_extent(&section)?;
            FileSection::from_cache(section, size).map(Some)
        }
        _ => Err(invalid(
            "native translation-cache lookup attributes changed",
        )),
    }
}
