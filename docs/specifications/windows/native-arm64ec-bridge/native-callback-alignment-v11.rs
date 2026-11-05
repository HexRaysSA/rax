//! Native current-process callback alignment oracle; no RAX runtime linked.
#![allow(dead_code)]
#[path = "../../../../src/user/image/pe/mod.rs"]
mod pe;
use std::ffi::{c_char, c_void};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn VirtualAlloc(base: *mut c_void, size: usize, flags: u32, protection: u32) -> *mut c_void;
    fn VirtualProtect(base: *mut c_void, size: usize, protection: u32, old: *mut u32) -> i32;
    fn VirtualFree(base: *mut c_void, size: usize, flags: u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, base: *const c_void, size: usize) -> i32;
}
fn main() {
    let name = "ntdll.dll\0".encode_utf16().collect::<Vec<_>>();
    // SAFETY: NTDLL is loaded for this process lifetime; both symbol strings are terminated.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!module.is_null());
    let address = unsafe { GetProcAddress(module, c"RtlRunOnceExecuteOnce".as_ptr()) };
    assert!(!address.is_null());
    type Init = unsafe extern "system" fn(*mut usize, *mut c_void, *mut *mut c_void) -> u32;
    type Run = unsafe extern "system" fn(*mut usize, Init, *mut c_void, *mut *mut c_void) -> i32;
    // SAFETY: exact documented RTL_RUN_ONCE_INIT_FN and NTAPI signature, current-process export.
    let run: Run = unsafe { std::mem::transmute(address) };
    for offset in [0usize, 4, 5, 15] {
        // SAFETY: own private allocation; no other threads or external addresses are touched.
        let page = unsafe { VirtualAlloc(std::ptr::null_mut(), 4096, 0x3000, 4) };
        assert!(!page.is_null());
        let callback = unsafe { page.cast::<u8>().add(256 + offset) };
        let code = [
            0x49u8, 0xc7, 0x00, 0x00, 0x40, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
        ];
        // SAFETY: 13 initialized bytes fit within this exclusively-owned RW page.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), callback, code.len()) };
        let mut old = 0;
        assert_ne!(unsafe { VirtualProtect(page, 4096, 0x20, &mut old) }, 0);
        assert_ne!(
            unsafe { FlushInstructionCache((-1isize) as *mut c_void, page, 4096) },
            0
        );
        // SAFETY: exact AMD64 callback writes context through its third argument, returns1,
        // preserves nonvolatiles and stack, and has no pointers beyond the supplied output.
        let init: Init = unsafe { std::mem::transmute(callback) };
        let mut once = 0usize;
        let mut context = std::ptr::null_mut();
        println!(
            "CALLBACK_PENDING offset={offset} address={:x}",
            callback as usize
        );
        let status =
            unsafe { run(&mut once, init, 0x1234usize as *mut c_void, &mut context) } as u32;
        println!(
            "NATIVE_CALLBACK offset={offset} status={status:x} once={once:x} context={:x}",
            context as usize
        );
        assert_eq!((status, once, context as usize), (0, 0x4002, 0x4000));
        assert_ne!(unsafe { VirtualFree(page, 0, 0x8000) }, 0);
    }
    println!("NATIVE_CALLBACK_ALIGNMENT_PASSED=4");
}
