//! Native oracle: private allocations in this process only; no RAX linked.
use std::ffi::{c_char, c_void};
use std::mem::{size_of, transmute};
use std::ptr::{null, null_mut};

#[repr(C, align(8))]
struct Parameter { kind: u64, value: u64 }
#[repr(C)]
#[derive(Default, Debug)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protect: u32,
    #[cfg(target_pointer_width = "64")]
    partition: u16,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}
type Allocate = unsafe extern "system" fn(
    *mut c_void, *mut *mut c_void, *mut usize, u32, u32, *const Parameter, u32,
) -> i32;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn VirtualAlloc(address: *mut c_void, size: usize, flags: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, flags: u32) -> i32;
    fn VirtualQuery(address: *const c_void, out: *mut Region, size: usize) -> usize;
    fn ReadProcessMemory(process: *mut c_void, at: *const c_void, out: *mut c_void, size: usize, got: *mut usize) -> i32;
}
fn read(at: usize, out: &mut [u8]) -> bool {
    let mut got = 0;
    // The kernel checks the source address. The destination is initialized and live.
    unsafe { ReadProcessMemory((-1isize) as _, at as _, out.as_mut_ptr().cast(), out.len(), &mut got) != 0 && got == out.len() }
}
fn bitmap(ntdll: *mut c_void) -> Option<usize> {
    // PEB+0x368 is qualified for this x64-on-ARM64 process view only.
    if !cfg!(target_arch = "x86_64") { return None; }
    type Query = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
    let symbol = unsafe { GetProcAddress(ntdll, c"NtQueryInformationProcess".as_ptr()) };
    assert!(!symbol.is_null());
    let query: Query = unsafe { transmute(symbol) };
    let mut basic = [0usize; 6];
    let status = unsafe { query((-1isize) as _, 0, basic.as_mut_ptr().cast(), size_of::<[usize; 6]>() as u32, null_mut()) };
    assert_eq!(status, 0);
    let mut bytes = [0u8; size_of::<usize>()];
    assert!(read(basic[1] + 0x368, &mut bytes));
    let value = usize::from_le_bytes(bytes);
    (value != 0).then_some(value)
}
fn tags(bitmap: Option<usize>, address: usize) -> String {
    let Some(bitmap) = bitmap else { return "unavailable".into(); };
    [0usize, 4096, 61440].map(|offset| {
        let at = address + offset;
        let mut byte = [0];
        match bitmap.checked_add(at >> 15) {
            Some(source) if read(source, &mut byte) => format!("{}", (byte[0] >> ((at >> 12) & 7)) & 1),
            _ => "unreadable".into(),
        }
    }).join(",")
}
fn main() {
    let name = "ntdll.dll\0".encode_utf16().collect::<Vec<_>>();
    let ntdll = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!ntdll.is_null());
    let symbol = unsafe { GetProcAddress(ntdll, c"NtAllocateVirtualMemoryEx".as_ptr()) };
    assert!(!symbol.is_null());
    let allocate: Allocate = unsafe { transmute(symbol) };
    let bitmap = bitmap(ntdll);
    println!("PROFILE arch={} pointer_bytes={} page_bytes=4096 granularity_bytes=65536 bitmap={bitmap:x?}", std::env::consts::ARCH, size_of::<usize>());
    let mut owned = Vec::new();
    let mut index = 0;
    for attributes in [0u64, 0x40] {
        for (mode, flags) in [("reserve", 0x2000), ("commit", 0x1000), ("both", 0x3000), ("existing", 0x1000)] {
            for protect in [0u32, 1, 4, 0x10, 0x20, 0x40, 0x80, 0x50, 0x110, 0x140, 0x210, 0x410, 0x40000040] {
                index += 1;
                let original = if mode == "existing" {
                    let p = unsafe { VirtualAlloc(null_mut(), 65536, 0x2000, 4) };
                    assert!(!p.is_null());
                    p
                } else { null_mut() };
                let before = if original.is_null() { "not-selected".into() } else { tags(bitmap, original as usize) };
                let mut base = original;
                let requested = if mode == "reserve" || mode == "both" { 65536usize } else { 4096 };
                let mut size = requested;
                let parameter = Parameter { kind: 5, value: attributes };
                let status = unsafe { allocate((-1isize) as _, &mut base, &mut size, flags, protect, &parameter, 1) };
                let mut region = Region::default();
                let queried = if status >= 0 { unsafe { VirtualQuery(base, &mut region, size_of::<Region>()) } } else { 0 };
                println!("CASE index={index} attributes={attributes:016x} mode={mode} flags={flags:08x} protect={protect:08x} requested={requested:x} original={:x} before={before} status={:08x} base={:x} size={size:x} queried={queried} region={region:x?} tags={}", original as usize, status as u32, base as usize, if status >= 0 { tags(bitmap, base as usize) } else { "failure".into() });
                if !original.is_null() { owned.push((index, original)); }
                else if status >= 0 { assert!(!base.is_null()); owned.push((index, base)); }
            }
        }
    }
    // Validation/publication controls: the caller owns every pointer; no fault injection.
    for (label, handle, size_in, flags, protect, kind, value, shift, count) in [
        ("invalid-handle-ec", -42isize, 4096usize, 0x3000u32, 0x40u32, 5u64, 0x40u64, 0usize, 1u32),
        ("invalid-handle-unknown", -42, 4096, 0x3000, 0x40, 5, 0x80, 0, 1),
        ("zero-size-ec", -1, 0, 0x3000, 0x40, 5, 0x40, 0, 1),
        ("invalid-flags-ec", -1, 4096, 0, 0x40, 5, 0x40, 0, 1),
        ("unknown-allocation-bit-ec", -1, 4096, 0x13000, 0x40, 5, 0x40, 0, 1),
        ("misaligned-ec", -1, 4096, 0x3000, 0x40, 5, 0x40, 1, 1),
        ("reserved-type-ec", -1, 4096, 0x3000, 0x40, 0x105, 0x40, 0, 1),
        ("duplicate-ec", -1, 4096, 0x3000, 0x40, 5, 0x40, 0, 2),
    ] {
        let mut bytes = [0u64; 6];
        let raw = unsafe { std::slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u8>(), size_of::<[u64; 6]>()) };
        for n in 0..2 { raw[shift+n*16..shift+n*16+8].copy_from_slice(&kind.to_le_bytes()); raw[shift+n*16+8..shift+n*16+16].copy_from_slice(&value.to_le_bytes()); }
        let mut base = null_mut();
        let mut size = size_in;
        let status = unsafe { allocate(handle as _, &mut base, &mut size, flags, protect, raw.as_ptr().add(shift).cast(), count) };
        println!("CONTROL name={label} status={:08x} base={:x} size={size:x}", status as u32, base as usize);
        if status >= 0 { owned.push((0, base)); }
    }
    for (index, base) in owned {
        assert_ne!(unsafe { VirtualFree(base, 0, 0x8000) }, 0);
        println!("RELEASE index={index} base={:x} tags={}", base as usize, tags(bitmap, base as usize));
    }
    println!("COMPLETE cases={index} controls=8 all_owned_allocations_released=true");
    let _ = null::<u8>();
}
