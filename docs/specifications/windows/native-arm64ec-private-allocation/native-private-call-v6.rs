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
    fn SetErrorMode(mode: u32) -> u32;
    fn FlushInstructionCache(process: *mut c_void, at: *const c_void, size: usize) -> i32;
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

fn pointer(at: usize) -> usize {
    let mut bytes = [0; size_of::<usize>()];
    assert!(read(at, &mut bytes));
    usize::from_le_bytes(bytes)
}
fn word(at: usize) -> u32 {
    let mut bytes = [0; 4];
    assert!(read(at, &mut bytes));
    u32::from_le_bytes(bytes)
}
fn mov(register: u32, value: u64) -> [u32; 4] {
    std::array::from_fn(|n| {
        let opcode = if n == 0 {0xd2800000} else {0xf2800000};
        opcode | ((n as u32) << 21) | (((value >> (n * 16)) as u32 & 0xffff) << 5) | register
    })
}

fn main() {
    unsafe {SetErrorMode(2);}
    let name = "ntdll.dll\0".encode_utf16().collect::<Vec<_>>();
    let ntdll = unsafe {GetModuleHandleW(name.as_ptr())};
    assert!(!ntdll.is_null());
    let mut original = 0usize;
    for candidate in [c"RtlRunOnceExecuteOnce", c"RtlRandomEx", c"RtlCompareUnicodeString", c"RtlGetVersion", c"RtlGetNtGlobalFlags"] {
        let mut address = unsafe {GetProcAddress(ntdll, candidate.as_ptr())} as usize;
        let mut stub = [0u8; 14];
        if address != 0 && read(address, &mut stub) {
            println!("EXPORT name={candidate:?} address={address:x} bytes={stub:02x?}");
            if stub[..10] == [0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9] {
                let displacement = i32::from_le_bytes(stub[10..14].try_into().unwrap());
                address=usize::try_from(address as i64 + 14 + i64::from(displacement)).unwrap();
            }
        }
        let classification = tags(bitmap(ntdll), address);
        println!("CANDIDATE name={candidate:?} address={address:x} tags={classification}");
        if address != 0 && classification.starts_with('1') {original=address; break;}
    }
    assert_ne!(original, 0);
    let original_prefix = word(original-4);
    let delta = (original_prefix & !3) as i32;
    let thunk = usize::try_from(original as i64 + i64::from(delta)).unwrap();
    let mut thunk_bytes = [0u8; 32];
    println!("ORIGINAL target={original:x} prefix={original_prefix:08x} thunk={thunk:x} tags={}", tags(bitmap(ntdll), original));
    assert!(read(thunk, &mut thunk_bytes));
    println!("ORIGINAL_THUNK bytes={thunk_bytes:02x?}");
    let symbol = unsafe {GetProcAddress(ntdll, c"NtAllocateVirtualMemoryEx".as_ptr())};
    assert!(!symbol.is_null());
    let allocate: Allocate = unsafe {transmute(symbol)};
    for above in [false, true] {
        let lower = if above { (thunk + 65536) & !65535 } else { (thunk - (1 << 29)) & !65535 };
        let upper = if above { ((thunk + (1 << 29)) & !65535) - 1 } else { (thunk & !65535) - 1 };
        let requirements = [lower, upper, 65536usize];
        let params = [Parameter {kind:1, value:requirements.as_ptr() as usize as u64}, Parameter {kind:5, value:0x40}];
        let mut owner = null_mut();
        let mut size = 65536;
        let status = unsafe {allocate((-1isize) as _, &mut owner, &mut size, 0x3000, 0x40, params.as_ptr(), 2)};
        println!("ALLOC above={above} status={:08x} owner={:x} size={size:x}", status as u32, owner as usize);
        assert_eq!(status, 0);
        let target = owner as usize + 0x200;
        let displacement = i32::try_from(thunk as i64 - target as i64).unwrap();
        let expected = if above {0x1234u64} else {0x4321u64};
        unsafe {
            ((target-4) as *mut u32).write_unaligned((displacement as u32 & !3) | (original_prefix & 3));
            (target as *mut u32).write_unaligned(0xd2800000 | (expected as u32) << 5);
            ((target+4) as *mut u32).write_unaligned(0xd65f03c0);
        }
        assert_ne!(unsafe {FlushInstructionCache((-1isize) as _, (target-4) as _, 12)}, 0);
        println!("CALL stage=before above={above} target={target:x} thunk={thunk:x} displacement={displacement} tags={}", tags(bitmap(ntdll), target));
        let call: unsafe extern "system" fn() -> u64 = unsafe {transmute(target)};
        let returned = unsafe {call()};
        println!("CALL stage=after above={above} returned={returned:x}");
        assert_eq!(returned, expected);
        assert_ne!(unsafe {VirtualFree(owner, 0, 0x8000)}, 0);
    }
    println!("COMPLETE private_calls=2 installed_thunk=true signed_displacements=true all_owned_allocations_released=true");
}
