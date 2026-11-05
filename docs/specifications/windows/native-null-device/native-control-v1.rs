use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: *mut c_void,
    name: *const Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        out: *mut *mut c_void,
        access: u32,
        attrs: *const Attributes,
        io: *mut Io,
        allocation: *const i64,
        attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn NtOpenFile(
        out: *mut *mut c_void,
        access: u32,
        attrs: *const Attributes,
        io: *mut Io,
        share: u32,
        options: u32,
    ) -> i32;
    fn NtQueryInformationFile(
        file: *mut c_void,
        io: *mut Io,
        data: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtQueryVolumeInformationFile(
        file: *mut c_void,
        io: *mut Io,
        data: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtReadFile(
        file: *mut c_void,
        event: *mut c_void,
        apc: *const c_void,
        context: *const c_void,
        io: *mut Io,
        data: *mut c_void,
        length: u32,
        offset: *const i64,
        key: *const u32,
    ) -> i32;
    fn NtWaitForSingleObject(handle: *mut c_void, alertable: u8, timeout: *const i64) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileType(file: *mut c_void) -> u32;
}

fn fresh_io() -> Io {
    Io {
        status: usize::MAX,
        information: usize::MAX,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn complete(status: i32, file: &OwnedHandle) -> i32 {
    if status as u32 != 0x103 {
        return status;
    }
    // SAFETY: all callers admit SYNCHRONIZE and keep this handle plus all private
    // query/read outputs live until the original operation completes. No timeout
    // converts a pending request into a terminal result or releases its buffers.
    loop {
        let waited = unsafe { NtWaitForSingleObject(file.as_raw_handle(), 0, std::ptr::null()) };
        if waited == 0 {
            return status;
        }
        println!("WAIT status={:#010x}", waited as u32);
    }
}

fn inspect(id: usize, file: &OwnedHandle, access: u32, options: u32) {
    // SAFETY: query only on this live owned handle; no retained output pointer.
    println!("TYPE id={id} value={}", unsafe {
        GetFileType(file.as_raw_handle())
    });
    if access & 0x100000 == 0 || options & 0x30 == 0 {
        return;
    }
    for (class, length) in [(4u32, 40u32), (5, 24), (14, 8), (16, 4), (17, 4), (35, 8)] {
        let mut io = fresh_io();
        let mut bytes = [0xa5u8; 64];
        // SAFETY: live synchronized handle and disjoint initialized private
        // bounded output/IOSB storage; completion is drained before reuse.
        let status = unsafe {
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut io,
                bytes.as_mut_ptr().cast(),
                length,
                class,
            )
        };
        let status = complete(status, file);
        println!(
            "QUERY id={id} class={class} status={:#010x} io={:#x}/{:#x} bytes={}",
            status as u32,
            io.status,
            io.information,
            hex(&bytes[..length as usize])
        );
    }
    for class in [4u32, 5] {
        let mut io = fresh_io();
        let mut bytes = [0xa5u8; 64];
        // SAFETY: same ownership/lifetime argument as the information query.
        let status = unsafe {
            NtQueryVolumeInformationFile(
                file.as_raw_handle(),
                &mut io,
                bytes.as_mut_ptr().cast(),
                64,
                class,
            )
        };
        let status = complete(status, file);
        println!(
            "VOLUME id={id} class={class} status={:#010x} io={:#x}/{:#x} bytes={}",
            status as u32,
            io.status,
            io.information,
            hex(&bytes)
        );
    }
    for length in [0u32, 1, 4] {
        let mut io = fresh_io();
        let mut bytes = [0xa5u8; 4];
        // SAFETY: bounded initialized private buffer, no APC or guest address.
        // The synchronized owned file drains any original pending operation.
        let status = unsafe {
            NtReadFile(
                file.as_raw_handle(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                &mut io,
                bytes.as_mut_ptr().cast(),
                length,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        let status = complete(status, file);
        println!(
            "READ id={id} length={length} status={:#010x} io={:#x}/{:#x} bytes={}",
            status as u32,
            io.status,
            io.information,
            hex(&bytes)
        );
    }
}

fn open(
    id: usize,
    create: bool,
    text: &str,
    flags: u32,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    inspect_file: bool,
) -> Option<OwnedHandle> {
    let words: Vec<u16> = text.encode_utf16().collect();
    let name = Unicode {
        length: (words.len() * 2) as u16,
        maximum: (words.len() * 2) as u16,
        buffer: words.as_ptr(),
    };
    let attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: std::ptr::null_mut(),
        name: &name,
        flags,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let mut raw = std::ptr::null_mut();
    let mut io = fresh_io();
    // SAFETY: counted host UTF-16 name and aligned native records remain live;
    // only the fixed null-device namespace is selected, with no filesystem
    // creation target. Each successful fresh handle transfers ownership once.
    let status = unsafe {
        if create {
            NtCreateFile(
                &mut raw,
                access,
                &attrs,
                &mut io,
                std::ptr::null(),
                0x80,
                share,
                disposition,
                options,
                std::ptr::null(),
                0,
            )
        } else {
            NtOpenFile(&mut raw, access, &attrs, &mut io, share, options)
        }
    };
    println!(
        "OPEN id={id} create={} name={text:?} flags={flags:#x} access={access:#010x} share={share} disposition={disposition} options={options:#x} status={:#010x} io={:#x}/{:#x} handle={}",
        u8::from(create),
        status as u32,
        io.status,
        io.information,
        u8::from(!raw.is_null())
    );
    if status != 0 {
        assert!(raw.is_null());
        return None;
    }
    assert!(!raw.is_null());
    // SAFETY: successful native open transferred one fresh host handle.
    let file = unsafe { OwnedHandle::from_raw_handle(raw) };
    if inspect_file {
        inspect(id, &file, access, options);
    }
    Some(file)
}

fn main() {
    let mut id = 0;
    let mut opened = 0;
    for text in [
        r"\??\NUL",
        r"\??\nul",
        r"\Device\Null",
        r"\device\null",
        r"\DosDevices\NUL",
        r"\??\NUL.",
        r"\??\NUL\child",
    ] {
        for flags in [0u32, 0x40] {
            for create in [false, true] {
                let file = open(id, create, text, flags, 0x80100080, 3, 1, 0x20060, true);
                opened += usize::from(file.is_some());
                drop(file);
                id += 1;
            }
        }
    }
    for disposition in 0..=5 {
        let file = open(
            id,
            true,
            r"\??\NUL",
            0x40,
            0xc0100080,
            0,
            disposition,
            0x60,
            false,
        );
        opened += usize::from(file.is_some());
        drop(file);
        id += 1;
    }
    for (access, options) in [
        (1u32, 0x40u32),
        (0x100001, 0x60),
        (0x100002, 0x60),
        (0x100003, 0x60),
        (0, 0x40),
        (0x100000, 0x60),
        (0x100003, 0x21),
        (0x100003, 0x41),
        (0x100003, 0x30),
        (0x100003, 0x1000),
    ] {
        let file = open(id, true, r"\??\NUL", 0x40, access, 0, 1, options, true);
        opened += usize::from(file.is_some());
        drop(file);
        id += 1;
    }
    let a = open(id, true, r"\??\NUL", 0x40, 0x100003, 0, 1, 0x60, false);
    id += 1;
    let b = open(id, true, r"\Device\Null", 0x40, 0x100003, 0, 1, 0x60, false);
    id += 1;
    opened += usize::from(a.is_some()) + usize::from(b.is_some());
    drop(a);
    drop(b);
    println!(
        "COMPLETE cases={id} opened={opened} all_successful_handles_closed=true pointer_bytes={}",
        std::mem::size_of::<usize>()
    );
}
