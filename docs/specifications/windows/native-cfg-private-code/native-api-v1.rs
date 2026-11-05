//! Independent API observations in this process; no RAX or external process writes.
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

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
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Target { offset: usize, flags: usize }
#[repr(C)]
struct Range { address: *mut c_void, size: usize }
#[repr(C)]
struct List {
    count: u32,
    reserved: u32,
    processed: *mut u32,
    targets: *mut Target,
    section: *mut c_void,
    file_offset: u64,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessMitigationPolicy(process: *mut c_void, policy: u32, output: *mut c_void, length: usize) -> i32;
    fn GetLastError() -> u32;
    fn SetLastError(value: u32);
    fn VirtualAlloc(address: *mut c_void, size: usize, flags: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, flags: u32) -> i32;
    fn VirtualQuery(address: *const c_void, output: *mut Region, size: usize) -> usize;
}
#[link(name = "windowsapp")]
unsafe extern "system" {
    fn SetProcessValidCallTargets(process: *mut c_void, address: *mut c_void, size: usize, count: u32, targets: *mut Target) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtAllocateVirtualMemory(process: *mut c_void, base: *mut *mut c_void, zero_bits: usize, size: *mut usize, flags: u32, protection: u32) -> i32;
    fn NtProtectVirtualMemory(process: *mut c_void, base: *mut *mut c_void, size: *mut usize, protection: u32, previous: *mut u32) -> i32;
    fn NtSetInformationVirtualMemory(process: *mut c_void, class: u32, count: usize, ranges: *mut Range, information: *mut c_void, length: u32) -> i32;
}

struct Owned(*mut c_void);
impl Owned {
    fn allocate(flags: u32, protection: u32) -> Self {
        let p = unsafe { VirtualAlloc(null_mut(), 65536, flags, protection) };
        assert!(!p.is_null(), "initial allocation failed: {}", unsafe { GetLastError() });
        Self(p)
    }
}
impl Drop for Owned {
    fn drop(&mut self) { assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0); }
}
fn query(base: *mut c_void) -> String {
    let mut region = Region::default();
    let length = unsafe { VirtualQuery(base, &mut region, size_of::<Region>()) };
    format!("length={length} region={region:x?}")
}
fn main() {
    let process = unsafe { GetCurrentProcess() };
    let mut policy = 0u32;
    let queried = unsafe { GetProcessMitigationPolicy(process, 7, (&raw mut policy).cast(), size_of::<u32>()) };
    println!("PROFILE arch={} pointer_bytes={} cfg_policy_query={queried} cfg_policy={policy:08x} list_bytes={}", std::env::consts::ARCH, size_of::<usize>(), size_of::<List>());
    assert_ne!(queried, 0);
    assert_ne!(policy & 1, 0, "CFG must be enabled before qualifying target updates");
    let mut allocation_cases = 0;
    for mode in ["reserve", "commit", "both", "existing"] {
        for protection in [1u32, 2, 4, 0x10, 0x20, 0x40, 0x80, 0x50, 0x140, 0x240, 0x440] {
            for modifier in [0, 0x40000000] {
                let existing = (mode == "existing").then(|| Owned::allocate(0x2000, 4));
                let original = existing.as_ref().map_or(null_mut(), |owned| owned.0);
                let mut base = original;
                let mut size = 4096;
                let flags = if mode == "reserve" { 0x2000 } else if mode == "both" { 0x3000 } else { 0x1000 };
                let status = unsafe { NtAllocateVirtualMemory(process, &raw mut base, 0, &raw mut size, flags, protection | modifier) };
                let successful = (status >= 0 && existing.is_none()).then(|| Owned(base));
                allocation_cases += 1;
                println!("ALLOC index={allocation_cases} mode={mode} flags={flags:08x} protect={:08x} status={:08x} base={:x} size={size:x} {}", protection | modifier, status as u32, base as usize, if status >= 0 { query(base) } else { "unqueried".into() });
                drop(successful);
            }
        }
    }
    let mut protection_cases = 0;
    for initial in [4u32, 0x40, 0x40000040] {
        for protection in [1u32, 2, 4, 0x10, 0x20, 0x40, 0x80, 0x50, 0x140, 0x240, 0x440] {
            for modifier in [0, 0x40000000] {
                let owned = Owned::allocate(0x3000, initial);
                let mut base = owned.0;
                let mut size = 4096;
                let mut previous = 0xababababu32;
                let status = unsafe { NtProtectVirtualMemory(process, &raw mut base, &raw mut size, protection | modifier, &raw mut previous) };
                protection_cases += 1;
                println!("PROTECT index={protection_cases} initial={initial:08x} protect={:08x} status={:08x} base={:x} size={size:x} previous={previous:08x} {}", protection | modifier, status as u32, base as usize, query(owned.0));
            }
        }
    }
    let mut target_cases = 0;
    for protection in [4u32, 0x40, 0x40000040] {
        for (label, offset, flags) in [("valid", 0usize, 1usize), ("invalid", 16, 0), ("unaligned", 1, 1), ("unaligned-end", 15, 1), ("boundary", 4096, 1), ("last-slot", 4080, 1), ("unknown-flags", 0, 0x80000000), ("processed-input", 0, 3)] {
            let owned = Owned::allocate(0x3000, protection);
            let mut target = Target { offset, flags };
            unsafe { SetLastError(0xabababab) };
            let result = unsafe { SetProcessValidCallTargets(process, owned.0, 4096, 1, &raw mut target) };
            let error = unsafe { GetLastError() };
            target_cases += 1;
            println!("TARGET index={target_cases} api=win32 protect={protection:08x} case={label} offset_in={offset:x} flags_in={flags:x} result={result} error={error:08x} offset_out={:x} flags_out={:x}", target.offset, target.flags);
        }
    }
    let mut native_cases = 0;
    for protection in [4u32, 0x40, 0x40000040] {
        for length in [0u32, 16, 24, 32, 40, 48] {
            let owned = Owned::allocate(0x3000, protection);
            let mut target = Target { offset: 16, flags: 1 };
            let mut processed = 0xababababu32;
            let mut information = List { count: 1, reserved: 0, processed: &raw mut processed, targets: &raw mut target, section: null_mut(), file_offset: 0 };
            let mut range = Range { address: owned.0, size: 4096 };
            // The full backing buffer is initialized even for oversized lengths.
            let mut backing = [0u64; 8];
            unsafe { std::ptr::copy_nonoverlapping((&raw mut information).cast::<u8>(), backing.as_mut_ptr().cast::<u8>(), size_of::<List>()) };
            let status = unsafe { NtSetInformationVirtualMemory(process, 2, 1, &raw mut range, backing.as_mut_ptr().cast(), length) };
            native_cases += 1;
            println!("TARGET index={native_cases} api=nt protect={protection:08x} length={length} status={:08x} processed={processed:08x} offset_out={:x} flags_out={:x}", status as u32, target.offset, target.flags);
        }
    }
    let _ = null::<u8>();
    println!("COMPLETE allocation_cases={allocation_cases} protection_cases={protection_cases} win32_target_cases={target_cases} native_target_cases={native_cases} all_owned_allocations_released=true");
}
