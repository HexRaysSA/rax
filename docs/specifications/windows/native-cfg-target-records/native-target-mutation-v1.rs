//! Observe NT target publication by calling only a child-owned constant leaf.
//! Every case has a fresh process; CFG rejection terminates that child only.
use std::ffi::c_void;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::ptr::null_mut;

const CASES: &[&str] = &[
    "valid",
    "no-registration",
    "second-unaligned",
    "second-bad-flags",
    "descending",
    "partial-storage",
    "second-export-flag",
    "second-xfg-flag",
    "duplicate-invalidate",
    "duplicate-revalidate",
];

#[repr(C)]
struct Range {
    address: usize,
    bytes: usize,
}

#[repr(C)]
struct Target {
    offset: usize,
    flags: usize,
}

#[repr(C)]
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
    fn GetProcessMitigationPolicy(
        process: *mut c_void,
        policy: u32,
        output: *mut c_void,
        bytes: usize,
    ) -> i32;
    fn SetErrorMode(mode: u32) -> u32;
    fn VirtualAlloc(address: *mut c_void, bytes: usize, flags: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, bytes: usize, flags: u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, bytes: usize) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationVirtualMemory(
        process: *mut c_void,
        class: u32,
        count: usize,
        ranges: *mut Range,
        information: *mut c_void,
        bytes: u32,
    ) -> i32;
}

struct Owned(*mut c_void);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: This process owns the still-live reservation from VirtualAlloc.
        assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
    }
}

#[inline(never)]
fn call_owned_leaf(target: *mut u8) -> u32 {
    // SAFETY: The caller supplies this process's executable allocation, with a
    // complete constant-return instruction sequence and synchronized I-cache.
    // CFG instrumentation remains enabled on this typed indirect call. Rejected
    // admission is an intended terminal child result, not a host policy change.
    let function: unsafe extern "C" fn() -> u32 = unsafe { transmute(target) };
    unsafe { function() }
}

fn run(case: &str) {
    assert!(CASES.contains(&case));
    // SAFETY: Both calls affect or query only the current observer process.
    let process = unsafe { GetCurrentProcess() };
    let mut policy = 0u32;
    assert_ne!(
        unsafe {
            GetProcessMitigationPolicy(process, 7, (&raw mut policy).cast(), size_of::<u32>())
        },
        0
    );
    assert_ne!(policy & 1, 0);
    // Reserve enough private space to isolate two complete 256 KiB bitmap
    // coverage units from executable allocations outside this reservation.
    // SAFETY: Null selects a new current-process private reservation.
    let owned = Owned(unsafe { VirtualAlloc(null_mut(), 0xc0000, 0x2000, 4) });
    assert!(!owned.0.is_null());
    let first = ((owned.0 as usize + 0x3ffff) & !0x3ffff) as *mut c_void;
    // SAFETY: The aligned first page is wholly inside the owned reservation.
    assert_eq!(
        unsafe { VirtualAlloc(first, 4096, 0x1000, 0x40000040) },
        first
    );
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let code = [0xb8u8, 0x34, 0x12, 0, 0, 0xc3];
    #[cfg(target_arch = "aarch64")]
    let code = [0x80u8, 0x46, 0x82, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
    // SAFETY: The six/eight initialized bytes fit in the committed writable
    // page. The sequence returns 0x1234 without touching data or other code.
    unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), first.cast::<u8>(), code.len()) };
    assert_ne!(
        unsafe { FlushInstructionCache(process, first, code.len()) },
        0
    );

    let mut targets = [
        Target {
            offset: 0,
            flags: 1,
        },
        Target {
            offset: 16,
            flags: 1,
        },
    ];
    let count = match case {
        "second-unaligned" => {
            targets[1].offset = 17;
            2
        }
        "second-bad-flags" => {
            targets[1].flags = 0x80000000;
            2
        }
        "descending" => {
            targets[0].offset = 16;
            targets[1].offset = 0;
            2
        }
        "partial-storage" => {
            targets[1].offset = 0x40000;
            2
        }
        "second-export-flag" | "second-xfg-flag" => {
            targets[1].flags = if case == "second-export-flag" { 4 } else { 8 };
            2
        }
        "duplicate-invalidate" => {
            targets[1] = Target {
                offset: 0,
                flags: 0,
            };
            2
        }
        "duplicate-revalidate" => {
            targets[0].flags = 0;
            targets[1].offset = 0;
            2
        }
        _ => 1,
    };
    let mut range = Range {
        address: first as usize,
        bytes: if case == "partial-storage" {
            0x80000
        } else {
            4096
        },
    };
    let mut processed = 0xabab_ababu32;
    let mut list = List {
        count,
        reserved: 0,
        processed: (&raw mut processed) as usize,
        targets: targets.as_mut_ptr() as usize,
        section: 0,
        file_offset: 0,
    };
    // SAFETY: All input/output records are initialized live stack objects;
    // their addresses and pointed-to target range belong to this process.
    let status = unsafe {
        NtSetInformationVirtualMemory(
            process,
            2,
            1,
            &raw mut range,
            (&raw mut list).cast(),
            if case == "no-registration" {
                0
            } else {
                size_of::<List>() as u32
            },
        )
    } as u32;
    println!(
        "NT case={case} arch={} cfg_policy={policy:08x} status={status:08x} processed={processed:08x}",
        std::env::consts::ARCH
    );
    std::io::stdout().flush().unwrap();
    let result = call_owned_leaf(std::hint::black_box(first.cast()));
    println!("RETURN case={case} result={result:08x}");
    assert_eq!(result, 0x1234);
    drop(owned);
    println!("COMPLETE case={case} all_owned_allocations_released=true");
}

fn main() {
    // SAFETY: This observer's children suppress only their own fault dialogs.
    unsafe { SetErrorMode(2) };
    let case = std::env::args().nth(1).expect("named control or --all");
    if case != "--all" {
        run(&case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    for case in CASES {
        let child = std::process::Command::new(&executable)
            .arg(case)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        println!("BEGIN_CASE case={case} pid={}", child.id());
        std::io::stdout().flush().unwrap();
        let result = child.wait_with_output().unwrap();
        print!("{}", String::from_utf8(result.stdout).unwrap());
        assert!(
            result.stderr.is_empty(),
            "unexpected child stderr for {case}"
        );
        println!(
            "END_CASE case={case} exit={:08x}",
            result.status.code().unwrap_or(-1) as u32
        );
        std::io::stdout().flush().unwrap();
    }
    println!(
        "COMPLETE controls={} all_children_terminal=true",
        CASES.len()
    );
}
