//! Query the two installed UI-language services through the selected NTDLL ABI.

use std::ffi::c_void;
use std::io::Write;
use std::ptr::null_mut;

const READONLY: u32 = 0x02;
const READWRITE: u32 = 0x04;
const NOACCESS: u32 = 0x01;
const GUARD: u32 = 0x100;
const LAST_ERROR: u32 = 0x1234;

#[repr(C)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum: usize,
    maximum: usize,
    processor_mask: usize,
    processor_count: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn IsWow64Process2(process: *mut c_void, guest: *mut u16, native: *mut u16) -> i32;
    fn GetSystemInfo(info: *mut SystemInfo);
    fn GetSystemDefaultUILanguage() -> u16;
    fn SetLastError(value: u32);
    fn GetLastError() -> u32;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, symbol: *const u8) -> *mut c_void;
    fn K32GetMappedFileNameW(
        process: *mut c_void,
        address: *const c_void,
        name: *mut u16,
        max: u32,
    ) -> u32;
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocations: u32,
        protection: u32,
    ) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, bytes: usize, protection: u32, old: *mut u32) -> i32;
    fn VirtualFree(address: *mut c_void, bytes: usize, operation: u32) -> i32;
}

fn protect(address: *mut u8, size: usize, mode: u32) -> u32 {
    let mut old = 0;
    // SAFETY: Every address describes a whole live page in the private allocation.
    assert_ne!(
        unsafe { VirtualProtect(address.cast(), size, mode, &mut old) },
        0
    );
    old
}

#[repr(C, align(2))]
struct CachedWord([u8; 4]);

fn main() {
    let mut out: Box<dyn Write> = match std::env::args_os().nth(1) {
        Some(path) => Box::new(std::fs::File::create(path).unwrap()),
        None => Box::new(std::io::stdout().lock()),
    };
    // SAFETY: the buffer records and Windows module/allocator lifetimes are
    // local to this synchronous control. Only fixed NTDLL services are called.
    unsafe {
        let process = GetCurrentProcess();
        let mut guest = 0u16;
        let mut native = 0u16;
        assert_ne!(IsWow64Process2(process, &mut guest, &mut native), 0);
        let compiled = match std::env::consts::ARCH {
            "x86" => 0x14c,
            "x86_64" => 0x8664,
            "aarch64" => 0xaa64,
            arch => panic!("unexpected architecture {arch}"),
        };
        if compiled == 0x14c {
            assert_eq!(guest, compiled);
            assert!(matches!(native, 0x8664 | 0xaa64));
        } else {
            assert_eq!((guest, native), (0, compiled));
        }

        let name: Vec<_> = "ntdll.dll\0".encode_utf16().collect();
        let module = GetModuleHandleW(name.as_ptr());
        assert!(!module.is_null());
        let mut provider = [0u16; 512];
        let length = K32GetMappedFileNameW(
            process,
            module,
            provider.as_mut_ptr(),
            provider.len() as u32,
        );
        assert!((1..provider.len() as u32).contains(&length));
        writeln!(
            out,
            "profile guest={guest} native={native} provider={}",
            String::from_utf16(&provider[..length as usize]).unwrap()
        )
        .unwrap();
        let commitment = GetProcAddress(module, c"NtIsUILanguageComitted".as_ptr().cast());
        let query = GetProcAddress(module, c"NtQueryInstallUILanguage".as_ptr().cast());
        assert!(!commitment.is_null() && !query.is_null());
        let commitment: unsafe extern "system" fn() -> u32 = std::mem::transmute(commitment);
        let query: unsafe extern "system" fn(*mut u16) -> u32 = std::mem::transmute(query);
        for iteration in 0..3 {
            SetLastError(LAST_ERROR);
            let status = commitment();
            let error = GetLastError();
            writeln!(
                out,
                "commit index={iteration} status={status:08x} error={error:08x}"
            )
            .unwrap();
        }
        let expected = GetSystemDefaultUILanguage();
        writeln!(out, "public langid={expected:04x}").unwrap();

        let mut info = std::mem::MaybeUninit::uninit();
        GetSystemInfo(info.as_mut_ptr());
        let page = info.assume_init().page_size as usize;
        assert!(page.is_power_of_two() && (4096..=65536).contains(&page));
        let base: *mut u8 = VirtualAlloc(null_mut(), 2 * page, 0x3000, READWRITE).cast();
        assert!(!base.is_null());
        let edge = base.add(page - 1);
        let upper = base.add(page);
        let interior = base.add(16);
        protect(upper, page, NOACCESS);
        let mut destinations = CachedWord([0xa5; 4]);
        for (case, address, inspect, mode) in [
            ("aligned", interior, interior, READWRITE),
            ("unaligned", interior.add(1), interior, READWRITE),
            ("null", null_mut(), destinations.0.as_mut_ptr(), READWRITE),
            ("readonly", interior, interior, READONLY),
            ("cross-page", edge, edge.sub(3), READWRITE),
            ("write-guard", interior, interior, READWRITE | GUARD),
            ("write-guard-retry", interior, interior, READWRITE),
            ("readonly-guard", interior, interior, READONLY | GUARD),
        ] {
            if case != "write-guard-retry" {
                std::ptr::write_bytes(inspect, 0xa5, 4);
                protect(base, page, mode);
            }
            SetLastError(LAST_ERROR);
            let status = query(address.cast());
            let error = GetLastError();
            let remaining = protect(base, page, READWRITE);
            let bytes = std::ptr::read_unaligned(inspect.cast::<[u8; 4]>());
            writeln!(out,
                "query case={case} status={status:08x} error={error:08x} protection={remaining:03x} bytes={:02x}{:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3],
            ).unwrap();
        }
        assert_ne!(VirtualFree(base.cast(), 0, 0x8000), 0);
        out.flush().unwrap();
    }
}
