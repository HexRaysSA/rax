use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
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

#[repr(C, align(8))]
struct Standard([u8; 24]);

#[link(name = "ntdll")]
unsafe extern "system" {
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
        output: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtCreateSection(
        out: *mut *mut c_void,
        access: u32,
        attrs: *const c_void,
        maximum: *const i64,
        protection: u32,
        allocation: u32,
        file: *mut c_void,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: u32,
        output: *mut c_void,
        bytes: u32,
    ) -> i32;
}

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .expect("explicit read-only file target");
    let text = path.to_str().expect("Unicode target");
    assert!(text.starts_with("C:\\Windows\\System32\\en-US\\") && text.ends_with(".mui"));
    let mut units: Vec<u16> = "\\??\\".encode_utf16().collect();
    units.extend(path.encode_wide());
    assert!(units.len() <= 32766 && !units.contains(&0));
    let name = Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    };
    let attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: std::ptr::null_mut(),
        name: &name,
        flags: 0x40,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let mut opened = 0;
    let mut sections = 0;
    for (access, options) in [
        (0x0010_0001u32, 0x60),
        (1, 0x40),
        (0x0010_0081, 0x60),
        (0x81, 0x40),
        (0x0012_0089, 0x60),
    ] {
        let mut raw = std::ptr::null_mut();
        let mut io = Io {
            status: usize::MAX,
            information: usize::MAX,
        };
        // SAFETY: local aligned host objects and bounded UTF-16 name are live
        // for the synchronous read-only call; output has one ownership transfer.
        let status = unsafe { NtOpenFile(&mut raw, access, &attrs, &mut io, 5, options) };
        println!(
            "OPEN access={access:#010x} options={options:#x} status={:#010x} io={:#x}/{}",
            status as u32, io.status, io.information
        );
        assert_eq!(status, 0);
        assert!(!raw.is_null());
        // SAFETY: successful NtOpenFile transferred this fresh handle once.
        let file = unsafe { File::from_raw_handle(raw) };
        opened += 1;
        match file.metadata() {
            Ok(metadata) => println!(
                "STD_METADATA access={access:#010x} status=ok bytes={}",
                metadata.len()
            ),
            Err(error) => println!(
                "STD_METADATA access={access:#010x} status=error code={:?} kind={:?}",
                error.raw_os_error(),
                error.kind()
            ),
        }
        assert_eq!(std::mem::size_of::<Standard>(), 24);
        let mut win32 = Standard([0xa5; 24]);
        // SAFETY: the documented synchronous Win32 call borrows the existing
        // handle and an aligned, initialized private FILE_STANDARD_INFO buffer.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                1,
                (&mut win32 as *mut Standard).cast(),
                24,
            )
        };
        let error = if ok == 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let eof = i64::from_le_bytes(win32.0[8..16].try_into().unwrap());
        println!(
            "STANDARD_WIN32 access={access:#010x} options={options:#x} ok={ok} error={error:?} eof={eof} data={:02x?}",
            win32.0
        );
        assert_ne!(ok, 0);
        assert!(eof >= 0);
        if options & 0x20 != 0 {
            let mut standard = Standard([0xa5; 24]);
            // SAFETY: owned handle and private aligned 24-byte destination/IOSB.
            let status = unsafe {
                NtQueryInformationFile(
                    file.as_raw_handle(),
                    &mut io,
                    (&mut standard as *mut Standard).cast(),
                    24,
                    5,
                )
            };
            println!(
                "STANDARD_INFORMATION access={access:#010x} status={:#010x} io={:#x}/{} eof={} data={:02x?}",
                status as u32,
                io.status,
                io.information,
                u64::from_le_bytes(standard.0[8..16].try_into().unwrap()),
                standard.0
            );
            assert_eq!(status, 0);
            assert_eq!(io.status, 0);
            assert_eq!(io.information, 24);
            assert_eq!(
                i64::from_le_bytes(standard.0[8..16].try_into().unwrap()),
                eof
            );
        }
        let mut section = std::ptr::null_mut();
        // SAFETY: borrowed read-only file, fixed scalar policy, private output;
        // NULL maximum selects the file's length and no name/security is used.
        let status = unsafe {
            NtCreateSection(
                &mut section,
                5,
                std::ptr::null(),
                std::ptr::null(),
                2,
                0x0800_0000,
                file.as_raw_handle(),
            )
        };
        println!(
            "READONLY_SECTION access={access:#010x} status={:#010x}",
            status as u32
        );
        assert_eq!(status, 0);
        assert!(!section.is_null());
        // SAFETY: successful creation transferred this fresh section handle.
        drop(unsafe { OwnedHandle::from_raw_handle(section) });
        sections += 1;
        drop(file);
    }
    println!("CLEANUP closed_files={opened} closed_sections={sections}");
}
