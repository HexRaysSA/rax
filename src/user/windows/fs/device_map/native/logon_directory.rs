//! The current subject's logon DOS directory also works through WoW64.
//! API declarations: retained Microsoft NtOpen/QueryDirectoryObject references.
use std::ffi::{c_char, c_void};
use std::io;

type Handle = *mut c_void;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: Handle,
    name: *const UnicodeString,
    attributes: u32,
    security: *const c_void,
    quality: *const c_void,
}

type Open = unsafe extern "system" fn(*mut Handle, u32, *const ObjectAttributes) -> i32;
type Query = unsafe extern "system" fn(Handle, *mut c_void, u32, u8, u8, *mut u32, *mut u32) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn CloseHandle(handle: Handle) -> i32;
}

struct Directory(Handle);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: exactly one owned directory handle, never exposed elsewhere.
        unsafe { CloseHandle(self.0) };
    }
}

fn api() -> io::Result<(Open, Query)> {
    let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: terminated fixed names; the process's mandatory NTDLL remains
    // loaded throughout this synchronous capture. No module handle is owned.
    let (open, query) = unsafe {
        let module = GetModuleHandleW(name.as_ptr());
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        (
            GetProcAddress(module, c"NtOpenDirectoryObject".as_ptr()),
            GetProcAddress(module, c"NtQueryDirectoryObject".as_ptr()),
        )
    };
    if open.is_null() || query.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fixed exports and their documented NTAPI prototypes. The pointer
    // sizes agree; neither function retains any input or output pointer.
    Ok(unsafe {
        (
            std::mem::transmute::<*mut c_void, Open>(open),
            std::mem::transmute::<*mut c_void, Query>(query),
        )
    })
}

/// O(n) queries, at most 4096 entries, with 64 KiB of owned query storage.
pub(super) fn capture(all: &[u8; 36]) -> io::Result<[u8; 36]> {
    let (open, query) = api()?;
    let path = [u16::from(b'\\'), u16::from(b'?'), u16::from(b'?'), 0];
    let name = UnicodeString {
        length: 6,
        maximum_length: 8,
        buffer: path.as_ptr(),
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root: std::ptr::null_mut(),
        name: &name,
        attributes: 0x40,
        security: std::ptr::null(),
        quality: std::ptr::null(),
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: live native-layout headers and three UTF-16 code units (6 bytes),
    // plus the NUL (8-byte capacity). DIRECTORY_QUERY only; exclusive output.
    let status = unsafe { open(&mut handle, 1, &attributes) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "native logon directory open: {:#010x}",
            status as u32
        )));
    }
    let directory = Directory(handle);
    const BYTES: usize = 65_536;
    let mut buffer = vec![0usize; BYTES / std::mem::size_of::<usize>()];
    let mut context = 0;
    let mut mask = 0u32;
    for index in 0..4096 {
        let mut returned = 0;
        // SAFETY: owned aligned 64 KiB buffer, exclusive DWORD outputs, valid
        // retained handle, native one-byte BOOLEAN arguments. Synchronous call.
        let status = unsafe {
            query(
                directory.0,
                buffer.as_mut_ptr().cast(),
                BYTES as u32,
                1,
                u8::from(index == 0),
                &mut context,
                &mut returned,
            )
        };
        if status as u32 == 0x8000_001a {
            let all_mask = u32::from_le_bytes(all[..4].try_into().unwrap());
            if mask & !all_mask != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "logon drives changed during native selection",
                ));
            }
            let mut record = [0; 36];
            record[..4].copy_from_slice(&mask.to_le_bytes());
            for drive in 0..26 {
                if mask & (1 << drive) != 0 {
                    record[4 + drive] = all[4 + drive];
                }
            }
            return Ok(record);
        }
        if status < 0 || returned as usize > BYTES {
            return Err(io::Error::other(format!(
                "native logon directory query: {:#010x}",
                status as u32
            )));
        }
        // SAFETY: initialized owned storage covers a native UNICODE_STRING;
        // integers and raw pointers admit every bit pattern. No foreign pointer
        // is dereferenced; the name's range is checked against this allocation.
        let entry = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<UnicodeString>()) };
        if entry.length != 4 {
            continue;
        }
        let Some(offset) = (entry.buffer as usize)
            .checked_sub(buffer.as_ptr() as usize)
            .filter(|offset| *offset <= BYTES - 4)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native logon name lies outside its owned buffer",
            ));
        };
        // SAFETY: offset..offset+4 lies within the live initialized allocation;
        // this pointer derives from the owned buffer, not the returned pointer.
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(offset), 4) };
        let letter = u16::from_le_bytes([bytes[0], bytes[1]]);
        let colon = u16::from_le_bytes([bytes[2], bytes[3]]);
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&letter) && colon == u16::from(b':') {
            mask |= 1 << (letter - u16::from(b'A'));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "native logon directory exceeds 4096 entries",
    ))
}
