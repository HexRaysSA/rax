#![no_std]
#![no_main]

use core::ffi::{c_char, c_void};
use core::panic::PanicInfo;

type Module = *mut c_void;
type SetLocale = unsafe extern "C" fn(i32, *const c_char) -> *const c_char;
type Collate = unsafe extern "C" fn(*const u16, *const u16) -> i32;

const ALPHA: &[u16] = &wide_ascii(b"alpha\0");
const CHARLIE: &[u16] = &wide_ascii(b"charlie\0");

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> Module;
    fn GetProcAddress(module: Module, name: *const c_char) -> *const c_void;
    fn GetStdHandle(kind: u32) -> *mut c_void;
    fn WriteFile(
        handle: *mut c_void,
        bytes: *const u8,
        length: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn ExitProcess(status: u32) -> !;
    fn CompareStringEx(
        name: *const u16,
        flags: u32,
        left: *const u16,
        left_len: i32,
        right: *const u16,
        right_len: i32,
        version: *mut c_void,
        reserved: *mut c_void,
        sort_handle: isize,
    ) -> i32;
    fn GetLastError() -> u32;
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    unsafe { ExitProcess(125) }
}

const fn wide_ascii<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut wide = [0; N];
    let mut index = 0;
    while index < N {
        wide[index] = bytes[index] as u16;
        index += 1;
    }
    wide
}

fn sample(dll: &[u16], output: &mut [u8; 10]) {
    const LC_COLLATE: i32 = 1;
    const E_ACUTE: &[u16] = &[0x00e9, 0];
    const Z: &[u16] = &wide_ascii(b"z\0");

    // These names and signatures are the installed CRT's public exports.
    let module = unsafe { LoadLibraryW(dll.as_ptr()) };
    if module.is_null() {
        return;
    }
    let set = unsafe { GetProcAddress(module, c"setlocale".as_ptr()) };
    let coll = unsafe { GetProcAddress(module, c"wcscoll".as_ptr()) };
    let icoll = unsafe { GetProcAddress(module, c"_wcsicoll".as_ptr()) };
    if set.is_null() || coll.is_null() || icoll.is_null() {
        return;
    }
    let set = unsafe { core::mem::transmute::<*const c_void, SetLocale>(set) };
    let coll = unsafe { core::mem::transmute::<*const c_void, Collate>(coll) };
    let icoll = unsafe { core::mem::transmute::<*const c_void, Collate>(icoll) };
    for (index, name) in [c"C", c""].into_iter().enumerate() {
        let row = &mut output[index * 5..][..5];
        let locale = unsafe { set(LC_COLLATE, name.as_ptr()) };
        if locale.is_null() {
            continue;
        }
        row[0] = 1;
        for (index, (left, right)) in [(ALPHA, CHARLIE), (E_ACUTE, Z)].into_iter().enumerate() {
            row[index * 2 + 1] = collation_result(unsafe { coll(left.as_ptr(), right.as_ptr()) });
            row[index * 2 + 2] = collation_result(unsafe { icoll(left.as_ptr(), right.as_ptr()) });
        }
    }
}

fn collation_result(result: i32) -> u8 {
    // Preserve the CRT error sentinel separately from a comparison result.
    if result == i32::MAX {
        3
    } else {
        (result.signum() + 1) as u8
    }
}

fn compare_locale(name: *const u16) -> [u8; 8] {
    let null = core::ptr::null_mut();
    let result = unsafe {
        CompareStringEx(
            name,
            0,
            ALPHA.as_ptr(),
            -1,
            CHARLIE.as_ptr(),
            -1,
            null,
            null,
            0,
        )
    };
    let error = if result == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let mut output = [0; 8];
    output[..4].copy_from_slice(&result.to_le_bytes());
    output[4..].copy_from_slice(&error.to_le_bytes());
    output
}

#[unsafe(no_mangle)]
extern "system" fn entry() -> ! {
    const MSVCRT: &[u16] = &wide_ascii(b"msvcrt.dll\0");
    const UCRT: &[u16] = &wide_ascii(b"ucrtbase.dll\0");
    let (mut msvcrt, mut ucrt) = ([0; 10], [0; 10]);
    sample(MSVCRT, &mut msvcrt);
    sample(UCRT, &mut ucrt);
    let default = compare_locale(core::ptr::null());
    let explicit = compare_locale(wide_ascii(b"en-US\0").as_ptr());
    let invariant = compare_locale(wide_ascii(b"\0").as_ptr());
    let out = unsafe { GetStdHandle((-11i32) as u32) };
    for row in [msvcrt.as_slice(), &ucrt, &default, &explicit, &invariant] {
        let mut written = 0;
        let length = row.len() as u32;
        let ok = unsafe {
            WriteFile(
                out,
                row.as_ptr(),
                length,
                &mut written,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 || written != length {
            unsafe { ExitProcess(74) };
        }
    }
    unsafe { ExitProcess(0) }
}
