//! Query fixed startup policy names on the installed 64-bit Windows kernel.

use std::ffi::c_void;
use std::io::{self, Write};
use std::ptr::null_mut;

const AMD64: u16 = 0x8664;
const ARM64: u16 = 0xaa64;
const INITIAL_KIND: u32 = 0xa5a5_a5a5;
const INITIAL_LENGTH: u32 = 0x5a5a_5a5a;
const INITIAL_BYTES: [u8; 24] = *b"ABCDEFGHIJKLMNOPQRSTUVWX";
const NAMES: [&str; 2] = [
    "Kernel-OneCore-DeviceFamilyID",
    "TerminalServices-RemoteConnectionManager-AllowAppServerMode",
];

#[repr(C)]
struct OsVersion {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(align(8))]
struct GuardedBytes([u8; 24]);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OsVersion) -> i32;
    fn NtQueryLicenseValue(
        name: *const UnicodeString,
        kind: *mut u32,
        data: *mut c_void,
        capacity: u32,
        required: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn IsWow64Process2(process: *mut c_void, guest: *mut u16, native: *mut u16) -> i32;
}

fn host() -> (OsVersion, u16) {
    let mut version = OsVersion {
        size: size_of::<OsVersion>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    let mut guest = 0u16;
    let mut native = 0u16;
    // SAFETY: the version record has its native size and both machine
    // outputs are exclusive and live. GetCurrentProcess is a pseudo-handle.
    unsafe {
        assert_eq!(RtlGetVersion(&mut version), 0);
        assert_ne!(
            IsWow64Process2(GetCurrentProcess(), &mut guest, &mut native),
            0
        );
    }
    let expected = match std::env::consts::ARCH {
        "x86_64" => AMD64,
        "aarch64" => ARM64,
        _ => panic!("the startup query producer requires a native 64-bit process"),
    };
    assert_eq!((guest, native), (0, expected));
    assert_eq!(size_of::<UnicodeString>(), 16);
    (version, native)
}

fn main() -> io::Result<()> {
    let (version, machine) = host();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(
        out,
        "{{\"kernel\":[{},{},{}],\"machine\":{},\"rows\":[",
        version.major, version.minor, version.build, machine,
    )?;
    let mut first = true;
    for name in NAMES {
        let lowercase = name.to_ascii_lowercase();
        for spelling in [name, lowercase.as_str()] {
            let units: Vec<_> = spelling.encode_utf16().chain(Some(0)).collect();
            let length = u16::try_from((units.len() - 1) * 2).unwrap();
            for maximum in [length, length + 2] {
                let descriptor = UnicodeString {
                    length,
                    maximum_length: maximum,
                    buffer: units.as_ptr(),
                };
                for (capacity, null_data) in
                    [(0, true), (0, false), (3, false), (4, false), (16, false)]
                {
                    for has_type in [false, true] {
                        let mut kind = INITIAL_KIND;
                        let mut required = INITIAL_LENGTH;
                        let mut storage = GuardedBytes(INITIAL_BYTES);
                        let data = storage.0[4..20].as_mut_ptr();
                        // SAFETY: the fixed descriptor and its UTF-16 source are live.
                        // Optional outputs are null or refer to exclusive initialized data.
                        // The data pointer has the full declared capacity and adjacent guards.
                        let status = unsafe {
                            NtQueryLicenseValue(
                                &descriptor,
                                if has_type { &mut kind } else { null_mut() },
                                if null_data { null_mut() } else { data.cast() },
                                capacity,
                                &mut required,
                            )
                        } as u32;
                        if !first {
                            writeln!(out, ",")?;
                        }
                        first = false;
                        write!(
                            out,
                            "{{\"name\":{spelling:?},\"length\":{length},\"maximum\":{maximum},\"capacity\":{capacity},\"null_data\":{null_data},\"has_type\":{has_type},\"status\":{status},\"kind\":{kind},\"required\":{required},\"storage\":\""
                        )?;
                        for byte in storage.0 {
                            write!(out, "{byte:02x}")?;
                        }
                        write!(out, "\"}}")?;
                    }
                }
            }
        }
    }
    writeln!(out, "\n]}}")
}
