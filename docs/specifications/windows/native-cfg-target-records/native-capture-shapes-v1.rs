//! Independent current-process NT CFG record-capture observations.
//!
//! Every pointer that the observer dereferences belongs to its own allocations.
//! Deliberately invalid syscall arguments are passed only to the NT service.
//! One child per case preserves evidence if an ABI thunk raises an exception.
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null_mut, read_unaligned, write_unaligned};

const RW: u32 = 4;
const PAGE: usize = 4096;
const SENTINEL: u32 = 0xabab_abab;

#[repr(C)]
#[derive(Clone, Copy)]
struct Range {
    address: usize,
    bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Target {
    offset: usize,
    flags: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct List {
    count: u32,
    reserved: u32,
    processed: usize,
    targets: usize,
    section: usize,
    file_offset: u64,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentProcessId() -> u32;
    fn GetLastError() -> u32;
    fn SetLastError(value: u32);
    fn SetErrorMode(mode: u32) -> u32;
    fn GetProcessMitigationPolicy(
        process: *mut c_void,
        policy: u32,
        output: *mut c_void,
        length: usize,
    ) -> i32;
    fn VirtualAlloc(address: *mut c_void, size: usize, flags: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, flags: u32) -> i32;
    fn VirtualProtect(address: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationVirtualMemory(
        process: *mut c_void,
        class: u32,
        count: usize,
        ranges: *mut Range,
        information: *mut c_void,
        length: u32,
    ) -> i32;
}

struct Owned(*mut c_void, bool);

impl Owned {
    fn allocate(bytes: usize, flags: u32, protection: u32) -> Self {
        let address = unsafe { VirtualAlloc(null_mut(), bytes, flags, protection) };
        assert!(!address.is_null(), "owned allocation: {}", unsafe {
            GetLastError()
        });
        Self(address, true)
    }

    fn address(&self) -> usize {
        self.0 as usize
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.1 {
            return;
        }
        assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
    }
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        assert_ne!(unsafe { CloseHandle(self.0) }, 0);
    }
}

struct Buffer {
    allocation: Owned,
    offset: usize,
}

impl Buffer {
    fn new() -> Self {
        let allocation = Owned::allocate(2 * PAGE, 0x3000, RW);
        unsafe { std::ptr::write_bytes(allocation.0.cast::<u8>(), 0xa5, 2 * PAGE) };
        Self {
            allocation,
            offset: 128,
        }
    }

    fn at(&self) -> usize {
        self.allocation.address() + self.offset
    }

    fn put<T: Copy>(&self, offset: usize, value: T) {
        assert!(self.offset + offset + size_of::<T>() <= 2 * PAGE);
        unsafe { write_unaligned((self.at() + offset) as *mut T, value) };
    }

    fn protect(&self, second_page_only: bool, protection: u32) -> u32 {
        let mut old = 0;
        let first = self.allocation.address() + if second_page_only { PAGE } else { 0 };
        let bytes = if second_page_only { PAGE } else { 2 * PAGE };
        assert_ne!(
            unsafe { VirtualProtect(first as *mut c_void, bytes, protection, &raw mut old) },
            0
        );
        old
    }

    fn snapshot(&self) -> String {
        assert!(self.offset + 64 <= 2 * PAGE);
        let bytes = unsafe { std::slice::from_raw_parts(self.at() as *const u8, 64) };
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

const CASES: &[&str] = &[
    "valid",
    "range-plus2",
    "range-plus4",
    "information-plus2",
    "information-plus4",
    "targets-plus2",
    "targets-plus4",
    "processed-plus4",
    "handle-vm-operation",
    "handle-vm-write",
    "handle-vm-both",
    "processed-writable-guard",
    "processed-readonly-guard",
];

fn observe(case: &str) {
    assert!(CASES.contains(&case));
    unsafe { SetErrorMode(0x8003) };
    let protection = match case {
        "rw-target"
        | "noaccess-target"
        | "uncommitted-target"
        | "badrecord-nostorage"
        | "uncommitted-rw-nearby-exec"
        | "readonly-rw-nearby-exec"
        | "noaccess-rw-nearby-exec" => RW,
        "rx-target" => 0x20,
        _ => 0x4000_0040,
    };
    // Keep the target and its complete 256 KiB bitmap-storage unit away from
    // caller buffers. The reservation remains alive until after every snapshot.
    let mut arena = Owned::allocate(0x80000, 0x2000, protection);
    let target = (arena.address() + 0x3ffff) & !0x3ffff;
    assert!(target + 0x4000 <= arena.address() + 0x80000);
    if !matches!(case, "uncommitted-target" | "uncommitted-exec-target") {
        assert_eq!(
            unsafe { VirtualAlloc(target as *mut c_void, 0x4000, 0x1000, protection) } as usize,
            target
        );
    }
    if case == "noaccess-target" {
        let mut old = 0;
        assert_ne!(
            unsafe { VirtualProtect(target as *mut c_void, PAGE, 1, &raw mut old) },
            0
        );
    }
    if case.ends_with("-rw-nearby-exec") {
        let mut old = 0;
        assert_ne!(
            unsafe { VirtualProtect((target + PAGE) as *mut c_void, PAGE, 0x40, &raw mut old) },
            0
        );
        match case {
            "uncommitted-rw-nearby-exec" => {
                assert_ne!(
                    unsafe { VirtualFree(target as *mut c_void, PAGE, 0x4000) },
                    0
                );
            }
            "readonly-rw-nearby-exec" | "noaccess-rw-nearby-exec" => {
                let protection = if case.starts_with("readonly") { 2 } else { 1 };
                assert_ne!(
                    unsafe {
                        VirtualProtect(target as *mut c_void, PAGE, protection, &raw mut old)
                    },
                    0
                );
            }
            _ => unreachable!(),
        }
    }
    if case == "decommitted-exec-target" {
        assert_ne!(
            unsafe { VirtualFree(target as *mut c_void, 0x4000, 0x4000) },
            0
        );
    }
    let mut ranges = Buffer::new();
    let mut information = Buffer::new();
    let mut targets = Buffer::new();
    let mut processed = Buffer::new();
    for (label, buffer) in [
        ("range-misaligned", &mut ranges),
        ("information-misaligned", &mut information),
        ("targets-misaligned", &mut targets),
        ("processed-misaligned", &mut processed),
    ] {
        if case == label {
            buffer.offset += 1;
        }
    }
    for (label, buffer) in [("range", &mut ranges), ("information", &mut information), ("targets", &mut targets), ("processed", &mut processed)] {
        if case == format!("{label}-plus2") { buffer.offset += 2; }
        if case == format!("{label}-plus4") { buffer.offset += 4; }
    }
    for (label, buffer) in [
        ("range-cross-page", &mut ranges),
        ("information-cross-page", &mut information),
        ("targets-cross-page", &mut targets),
        ("processed-cross-page", &mut processed),
    ] {
        if case == label {
            buffer.offset = PAGE
                - match label {
                    "information-cross-page" => size_of::<List>() / 2,
                    "processed-cross-page" => 2,
                    _ => size_of::<usize>(),
                };
        }
    }
    let mut range = Range {
        address: target,
        bytes: PAGE,
    };
    let mut list = List {
        count: 1,
        reserved: 0,
        processed: processed.at(),
        targets: targets.at(),
        section: 0,
        file_offset: 0,
    };
    let mut entries = [Target {
        offset: 0,
        flags: 1,
    }; 4];
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.offset = index * 16;
    }
    let mut process = unsafe { GetCurrentProcess() };
    let mut count = 1;
    let mut range_pointer = ranges.at();
    let mut information_pointer = information.at();
    let mut length = size_of::<List>() as u32;
    let mut handle = None;
    match case {
        "invalidate" => entries[0].flags = 0,
        "length-0" => length = 0,
        "length-16" => length = 16,
        "length-24" => length = 24,
        "length-32" => length = 32,
        "length-40" => length = 40,
        "length-48" => length = 48,
        "range-count-0" => count = 0,
        "range-count-2" => count = 2,
        "range-null" => range_pointer = 0,
        "range-bad" => range_pointer = 1,
        "range-size-0" => range.bytes = 0,
        "range-size-1" => range.bytes = 1,
        "range-base-unaligned" => range.address += 1,
        "range-spans-uncommitted" => range.bytes = 0x5000,
        "information-null" => information_pointer = 0,
        "information-bad" => information_pointer = 1,
        "reserved-1" => list.reserved = 1,
        "section-process" => list.section = process as usize,
        "file-offset-1" => list.file_offset = 1,
        "handle-null" => process = null_mut(),
        "handle-bad" => process = 0x1234usize as *mut c_void,
        "handle-thread" => process = (usize::MAX - 1) as *mut c_void,
        "handle-query-only" | "handle-vm-operation" | "handle-vm-write" | "handle-vm-both" => {
            let opened = unsafe { OpenProcess(match case { "handle-vm-operation" => 8, "handle-vm-write" => 32, "handle-vm-both" => 40, _ => 0x1000 }, 0, GetCurrentProcessId()) };
            assert!(!opened.is_null());
            process = opened;
            handle = Some(Handle(opened));
        }
        "entries-0" => list.count = 0,
        "entries-2" => list.count = 2,
        "entries-3" => list.count = 3,
        "targets-null" => list.targets = 0,
        "targets-bad" => list.targets = 1,
        "processed-null" => list.processed = 0,
        "processed-bad" => list.processed = 1,
        "offset-1" => entries[0].offset = 1,
        "offset-15" => entries[0].offset = 15,
        "offset-16" => entries[0].offset = 16,
        "offset-last-slot" => entries[0].offset = PAGE - 16,
        "offset-end" => entries[0].offset = PAGE,
        "offset-max" => entries[0].offset = usize::MAX,
        "flags-2" => entries[0].flags = 2,
        "flags-3" => entries[0].flags = 3,
        "flags-4" => entries[0].flags = 4,
        "flags-5" => entries[0].flags = 5,
        "flags-8" => entries[0].flags = 8,
        "flags-16" => entries[0].flags = 16,
        "flags-high" => entries[0].flags = 0x8000_0000,
        "flags-max" => entries[0].flags = usize::MAX,
        "duplicate" => {
            list.count = 2;
            entries[1].offset = 0;
        }
        "descending" => {
            list.count = 2;
            entries[0].offset = 16;
            entries[1].offset = 0;
        }
        "second-unaligned" => {
            list.count = 2;
            entries[1].offset = 17;
        }
        "second-bad-flags" => {
            list.count = 2;
            entries[1].flags = 0x8000_0000;
        }
        "first-unaligned" => {
            list.count = 2;
            entries[0].offset = 1;
        }
        "alias-info-count" => list.processed = information.at(),
        "alias-info-reserved" => list.processed = information.at() + 4,
        "alias-target-offset" => list.processed = targets.at(),
        "alias-target-flags" => list.processed = targets.at() + size_of::<usize>(),
        "alias-second-offset" => {
            list.count = 2;
            list.processed = targets.at() + size_of::<Target>();
        }
        "alias-range-address" => list.processed = ranges.at(),
        _ => {}
    }
    match case {
        "badlength-badrange" => {
            length = 0;
            range_pointer = 1;
        }
        "badlength-badinfo" => {
            length = 0;
            information_pointer = 1;
        }
        "badlength-count0" => {
            length = 0;
            count = 0;
        }
        "count0-badinfo" => {
            count = 0;
            information_pointer = 1;
        }
        "count2-badinfo" => {
            count = 2;
            information_pointer = 1;
        }
        "badinfo-badrange" => {
            information_pointer = 1;
            range_pointer = 1;
        }
        "badhandle-badinfo" => {
            process = null_mut();
            information_pointer = 1;
        }
        "badhandle-badrange" => {
            process = null_mut();
            range_pointer = 1;
        }
        "reserved-badrange" => {
            list.reserved = 1;
            range_pointer = 1;
        }
        "reserved-badtargets" => {
            list.reserved = 1;
            list.targets = 1;
        }
        "badhandle-badtargets" => {
            process = null_mut();
            list.targets = 1;
        }
        "badprocessed-badtargets" => {
            list.processed = 1;
            list.targets = 1;
        }
        "badrecord-badprocessed" => {
            entries[0].offset = 1;
            list.processed = 1;
        }
        "badrecord-nostorage" => entries[0].offset = 1,
        "badflags-badhandle" => {
            entries[0].flags = usize::MAX;
            process = null_mut();
        }
        "badflags-badprocessed" => {
            entries[0].flags = usize::MAX;
            list.processed = 1;
        }
        "entries0-badprocessed" => {
            list.count = 0;
            list.processed = 1;
        }
        "entries0-badtargets" => {
            list.count = 0;
            list.targets = 1;
        }
        "badhandle-badprocessed" => {
            process = null_mut();
            list.processed = 1;
        }
        "badlength-badhandle" => {
            length = 0;
            process = null_mut();
        }
        _ => {}
    }
    ranges.put(0, range);
    ranges.put(size_of::<Range>(), range);
    // Write fields separately: repr(C) has four padding bytes on x86. Leaving
    // the initialized backing pattern there avoids reading Rust padding bytes.
    information.put(std::mem::offset_of!(List, count), list.count);
    information.put(std::mem::offset_of!(List, reserved), list.reserved);
    information.put(std::mem::offset_of!(List, processed), list.processed);
    information.put(std::mem::offset_of!(List, targets), list.targets);
    information.put(std::mem::offset_of!(List, section), list.section);
    information.put(std::mem::offset_of!(List, file_offset), list.file_offset);
    targets.put(0, entries);
    processed.put(0, SENTINEL);
    let before = [
        ranges.snapshot(),
        information.snapshot(),
        targets.snapshot(),
        processed.snapshot(),
    ];
    for (label, buffer, protection, second) in [
        ("range-unreadable", &ranges, 1, false),
        ("range-cross-page", &ranges, 1, true),
        ("information-unreadable", &information, 1, false),
        ("information-readonly", &information, 2, false),
        ("information-cross-page", &information, 1, true),
        ("targets-unreadable", &targets, 1, false),
        ("targets-readonly", &targets, 2, false),
        ("targets-cross-page", &targets, 1, true),
        ("processed-readonly", &processed, 2, false),
        ("processed-writable-guard", &processed, 0x104, false),
        ("processed-readonly-guard", &processed, 0x102, false),
        ("processed-unwritable", &processed, 1, false),
        ("processed-cross-page", &processed, 1, true),
    ] {
        if case == label {
            buffer.protect(second, protection);
        }
    }
    println!(
        "ENTER case={case} range_count={count} information_bytes={length} list_bytes={} pointer_bytes={} target={target:x} range_pointer={range_pointer:x} information_pointer={information_pointer:x}",
        size_of::<List>(),
        size_of::<usize>()
    );
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    if case == "released-exec-target" {
        // Release after allocating caller buffers so they cannot reuse the
        // target reservation before the service observes the stale address.
        assert_ne!(unsafe { VirtualFree(arena.0, 0, 0x8000) }, 0);
        arena.1 = false;
    }
    unsafe { SetLastError(SENTINEL) };
    let status = unsafe {
        NtSetInformationVirtualMemory(
            process,
            2,
            count,
            range_pointer as *mut Range,
            information_pointer as *mut c_void,
            length,
        )
    };
    let last_error = unsafe { GetLastError() };
    for (index, buffer) in [&ranges, &information, &targets, &processed].into_iter().enumerate() {
        let old = buffer.protect(false, RW);
        println!("RESTORE case={case} index={index} previous={old:08x}");
    }
    let after = [
        ranges.snapshot(),
        information.snapshot(),
        targets.snapshot(),
        processed.snapshot(),
    ];
    let processed_value = unsafe { read_unaligned(processed.at() as *const u32) };
    println!(
        "RESULT case={case} status={:08x} last_error={last_error:08x} processed={processed_value:08x}",
        status as u32
    );
    for (index, name) in ["ranges", "information", "targets", "processed"]
        .into_iter()
        .enumerate()
    {
        println!(
            "BUFFER case={case} name={name} address={:x} before={} after={}",
            [&ranges, &information, &targets, &processed][index].at(),
            before[index],
            after[index]
        );
    }
    drop(handle);
    drop((ranges, information, targets, processed, arena));
    println!("COMPLETE case={case} all_owned_allocations_released=true");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--case" {
        observe(&args[2]);
        return;
    }
    assert!(args.len() == 1 || args.len() == 2 && args[1] == "--all");
    let mut policy = 0u32;
    assert_ne!(
        unsafe { GetProcessMitigationPolicy(GetCurrentProcess(), 7, (&raw mut policy).cast(), 4) },
        0
    );
    assert_ne!(
        policy & 1,
        0,
        "CFG must be enabled for native qualification"
    );
    println!(
        "PROFILE arch={} pointer_bytes={} list_bytes={} cfg_policy={policy:08x} cases={}",
        std::env::consts::ARCH,
        size_of::<usize>(),
        size_of::<List>(),
        CASES.len()
    );
    let exe = std::env::current_exe().unwrap();
    for case in CASES {
        let child = std::process::Command::new(&exe)
            .args(["--case", case])
            .output()
            .unwrap();
        println!("BEGIN_CASE case={case}");
        print!("{}", String::from_utf8(child.stdout).unwrap());
        let stderr = String::from_utf8(child.stderr).unwrap();
        // A native exception is an observation, never rewritten as NT success.
        // The validator decides whether the case supplied a usable NT result.
        println!(
            "END_CASE case={case} exit={:08x} stderr_hex={}",
            child.status.code().expect("Windows exit code") as u32,
            stderr
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
    }
    println!(
        "COMPLETE controls={} all_children_terminal=true",
        CASES.len()
    );
}
