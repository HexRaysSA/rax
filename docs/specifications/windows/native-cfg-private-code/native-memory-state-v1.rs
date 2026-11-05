//! One CFG lifecycle control in a fresh process, using its own private code only.
use std::ffi::c_void;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::ptr::null_mut;

#[repr(C)]
struct Target { offset: usize, flags: usize }
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetUnhandledExceptionFilter(handler: unsafe extern "system" fn(*const ExceptionPointers) -> i32) -> usize;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessMitigationPolicy(process: *mut c_void, policy: u32, output: *mut c_void, length: usize) -> i32;
    fn GetLastError() -> u32;
    fn SetErrorMode(mode: u32) -> u32;
    fn VirtualAlloc(address: *mut c_void, size: usize, flags: u32, protection: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, flags: u32) -> i32;
    fn VirtualProtect(address: *mut c_void, size: usize, protection: u32, previous: *mut u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}
#[link(name = "windowsapp")]
unsafe extern "system" {
    fn SetProcessValidCallTargets(process: *mut c_void, address: *mut c_void, size: usize, count: u32, targets: *mut Target) -> i32;
}
#[repr(C)]
struct ExceptionRecord { code: u32, flags: u32, nested: usize, address: usize, count: u32, padding: u32, information: [usize; 15] }
#[repr(C)]
struct ExceptionPointers { record: *const ExceptionRecord, context: usize }
unsafe extern "system" fn exception_report(p: *const ExceptionPointers) -> i32 {
    // SAFETY: Windows supplies a live EXCEPTION_POINTERS and its exception record
    // for this synchronous callback; neither is retained or mutated.
    // SAFETY: Windows supplies this callback's live exception-pointer and exception-record objects; neither reference escapes the callback.
    let record = unsafe { &*(*p).record };
    println!("EXCEPTION code={:08x} pc={:x} count={} kind={} address={:x}", record.code, record.address, record.count, record.information[0], record.information[1]);
    std::io::stdout().flush().unwrap();
    0 // Continue the ordinary unhandled-exception disposition.
}
struct Owned(*mut c_void);
impl Owned {
    fn allocate(address: *mut c_void, flags: u32, protection: u32) -> Self {
        // SAFETY: The kernel validates the requested range; returned allocations remain owned by this observer until release.
        let pointer = unsafe { VirtualAlloc(address, 65536, flags, protection) };
        // SAFETY: GetLastError has no pointer preconditions and reads this thread only.
        assert!(!pointer.is_null(), "allocation error {}", unsafe { GetLastError() });
        Self(pointer)
    }
    fn release(&mut self) {
        // SAFETY: The original live reservation base is released once, or its owned first page is decommitted.
        assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0);
        self.0 = null_mut();
    }
    fn protect(&self, protection: u32) {
        let mut previous = 0;
        // SAFETY: The pointer and 4 KiB interval lie in this observer's live reservation; old protection points to a live u32.
        assert_ne!(unsafe { VirtualProtect(self.0, 4096, protection, &raw mut previous) }, 0);
    }
    fn commit(&self, protection: u32) {
        // SAFETY: The kernel validates the requested range; returned allocations remain owned by this observer until release.
        assert_eq!(unsafe { VirtualAlloc(self.0, 4096, 0x1000, protection) }, self.0);
    }
    fn target(&self, offset: usize, flags: usize) {
        let mut target = Target { offset, flags };
        println!("UPDATE_BEFORE base={:x} offset={offset:x} flags={flags:x}", self.0 as usize);
        std::io::stdout().flush().unwrap();
        // SAFETY: The pseudo process handle and target descriptor are live; the target interval belongs to this observer.
        let result = unsafe { SetProcessValidCallTargets(GetCurrentProcess(), self.0, 4096, 1, &raw mut target) };
        // SAFETY: GetLastError has no pointer preconditions and reads this thread only.
        let error = unsafe { GetLastError() };
        println!("UPDATE_AFTER result={result} error={error:x} offset={:x} flags={:x}", target.offset, target.flags);
        std::io::stdout().flush().unwrap();
        assert_ne!(result, 0, "target error {error}");
        assert_ne!(target.flags & 2, 0);
    }
}
impl Drop for Owned {
    fn drop(&mut self) { if !self.0.is_null() { self.release(); } }
}
fn main() {
    // Suppress fault UI for this observer only. No host policy is changed.
    // SAFETY: Only this observer's error disposition changes; the callback has the Windows ABI and static code lifetime.
    unsafe { SetErrorMode(2); SetUnhandledExceptionFilter(exception_report); };
    let case = std::env::args().nth(1).expect("one named lifecycle control is required");
    if case == "--all" {
        storage_controls();
        let executable = std::env::current_exe().unwrap();
        let cases = [
            "default", "invalid", "invalid-mark-valid", "default-mark-invalid",
            "invalid-protect-no-update", "invalid-protect-default",
            "invalid-recommit-default", "default-recommit-invalid",
            "invalid-decommit-recommit", "invalid-mark-invalid-then-valid",
            "default-unaligned", "invalid-mark-valid-unaligned",
            "default-mark-invalid-other-slot", "invalid-mark-valid-other-slot",
            "invalid-mark-valid-wrong-slot", "reserve-invalid-commit-default",
            "reserve-invalid-commit-invalid", "invalid-release-reuse",
            "rw-mark-valid-no-update", "rw-mark-invalid-no-update", "rw-mark-invalid-default",
            "initial-rw-call", "initial-rw-exec-default", "initial-rw-exec-no-update",
            "initial-rw-valid-exec-no-update", "initial-rw-invalid-exec-default",
            "reserve-default-call", "default-decommit-call", "default-release-call",
            "initial-rw-neighbor-exec-valid", "initial-rw-neighbor-exec-invalid",
            "default-release-rw-register", "reserve-invalid-call", "invalid-decommit-call", "invalid-release-call",
            "initial-rw-no-update-then-default", "initial-rw-neighbor-default",
            "default-release-rw-call", "invalid-release-rw-call", "invalid-release-rw-exec",
            "default-mark-valid-unaligned", "default-mark-invalid-then-valid-unaligned",
            "initial-rw-neighbor-invalid-default", "initial-rw-neighbor-valid-default",
        ];
        for case in cases {
            let child = std::process::Command::new(&executable)
                .arg(case)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn().unwrap();
            println!("BEGIN_CASE case={case} pid={}", child.id());
            std::io::stdout().flush().unwrap();
            let result = child.wait_with_output().unwrap();
            println!("CHILD_STDOUT case={case}\n{}", String::from_utf8(result.stdout).unwrap());
            println!("CHILD_STDERR case={case}\n{}", String::from_utf8(result.stderr).unwrap());
            println!("END_CASE case={case} exit={:08x}", result.status.code().unwrap_or(-1) as u32);
            std::io::stdout().flush().unwrap();
        }
        println!("COMPLETE controls={} all_children_terminal=true", cases.len());
        return;
    }
    // SAFETY: GetCurrentProcess has no arguments and returns this process's documented pseudo handle.
    let process = unsafe { GetCurrentProcess() };
    let mut policy = 0u32;
    // SAFETY: The pseudo process handle is valid; policy is a live u32 of the supplied size.
    assert_ne!(unsafe { GetProcessMitigationPolicy(process, 7, (&raw mut policy).cast(), size_of::<u32>()) }, 0);
    assert_ne!(policy & 1, 0);
    let initial = if case.starts_with("initial-rw") { 4 } else if case.starts_with("default") || case.starts_with("rw") || case == "reserve-default-call" { 0x40 } else { 0x40000040 };
    let reserved = case.starts_with("reserve");
    let mut owned = Owned::allocate(null_mut(), if reserved { 0x2000 } else { 0x3000 }, initial);
    let mut offset = 0usize;
    match case.as_str() {
        "default" | "invalid" | "initial-rw-call" | "reserve-default-call" | "default-decommit-call" | "default-release-call" => {}
        "default-mark-valid-unaligned" => { owned.target(0, 1); offset = if cfg!(target_arch = "aarch64") { 4 } else { 1 }; }
        "default-mark-invalid-then-valid-unaligned" => { owned.target(0, 0); owned.target(0, 1); offset = if cfg!(target_arch = "aarch64") { 4 } else { 1 }; }
        "initial-rw-neighbor-invalid-default" | "initial-rw-neighbor-valid-default" => {
            let mut old = 0;
            // SAFETY: this page belongs to the live 64 KiB reservation, and old is a live u32.
            assert_ne!(unsafe { VirtualProtect(owned.0.cast::<u8>().add(4096).cast(), 4096, 0x40, &raw mut old) }, 0);
            owned.target(0, usize::from(case == "initial-rw-neighbor-valid-default"));
            owned.protect(0x40);
            offset = if cfg!(target_arch = "aarch64") { 4 } else { 1 };
        }
        "initial-rw-no-update-then-default" => { owned.protect(0x40000040); owned.protect(4); owned.protect(0x40); }
        "initial-rw-neighbor-default" => {
            let mut old = 0;
            // SAFETY: the second page belongs to this live 64 KiB allocation.
            // SAFETY: The pointer and 4 KiB interval lie in this observer's live reservation; old protection points to a live u32.
            assert_ne!(unsafe { VirtualProtect(owned.0.cast::<u8>().add(4096).cast(), 4096, 0x40, &raw mut old) }, 0);
            owned.protect(0x40);
        }
        "default-release-rw-call" | "invalid-release-rw-call" | "invalid-release-rw-exec" => {
            let address = owned.0;
            owned.release();
            owned = Owned::allocate(address, 0x3000, 4);
            assert_eq!(owned.0, address);
            if case.ends_with("exec") { owned.protect(0x40); }
        }
        "initial-rw-neighbor-exec-valid" | "initial-rw-neighbor-exec-invalid" => {
            let mut old = 0;
            // SAFETY: the second page belongs to this live 64 KiB allocation.
            // SAFETY: The pointer and 4 KiB interval lie in this observer's live reservation; old protection points to a live u32.
            assert_ne!(unsafe { VirtualProtect(owned.0.cast::<u8>().add(4096).cast(), 4096, 0x40, &raw mut old) }, 0);
            owned.target(0, usize::from(case.ends_with("valid") && !case.ends_with("invalid")));
            owned.protect(0x40000040);
        }
        "default-release-rw-register" => {
            let address = owned.0;
            owned.release();
            owned = Owned::allocate(address, 0x3000, 4);
            assert_eq!(owned.0, address);
            owned.target(0, 1);
            owned.protect(0x40000040);
        }
        "reserve-invalid-call" | "invalid-decommit-call" | "invalid-release-call" => {}
        "initial-rw-exec-default" => owned.protect(0x40),
        "initial-rw-exec-no-update" => owned.protect(0x40000040),
        "initial-rw-valid-exec-no-update" => { owned.target(0, 1); owned.protect(0x40000040); }
        "initial-rw-invalid-exec-default" => { owned.target(0, 0); owned.protect(0x40); }
        "invalid-mark-valid" => owned.target(0, 1),
        "default-mark-invalid" => owned.target(0, 0),
        "invalid-protect-no-update" => { owned.protect(4); owned.protect(0x40000040); }
        "invalid-protect-default" => { owned.protect(4); owned.protect(0x40); }
        "invalid-recommit-default" => owned.commit(0x40),
        "default-recommit-invalid" => owned.commit(0x40000040),
        "invalid-decommit-recommit" => {
            // SAFETY: The original live reservation base is released once, or its owned first page is decommitted.
            assert_ne!(unsafe { VirtualFree(owned.0, 4096, 0x4000) }, 0);
            owned.commit(0x40);
        }
        "invalid-mark-invalid-then-valid" => { owned.target(0, 0); owned.target(0, 1); }
        "default-unaligned" => offset = if cfg!(target_arch = "aarch64") { 4 } else { 1 },
        "invalid-mark-valid-unaligned" => { owned.target(0, 1); offset = if cfg!(target_arch = "aarch64") { 4 } else { 1 }; }
        "default-mark-invalid-other-slot" => { owned.target(0, 0); offset = 16; }
        "invalid-mark-valid-other-slot" => { owned.target(16, 1); offset = 16; }
        "invalid-mark-valid-wrong-slot" => { owned.target(0, 1); offset = 16; }
        "reserve-invalid-commit-default" => owned.commit(0x40),
        "reserve-invalid-commit-invalid" => owned.commit(0x40000040),
        "invalid-release-reuse" => {
            let address = owned.0;
            drop(owned);
            owned = Owned::allocate(address, 0x3000, 0x40);
            assert_eq!(owned.0, address);
        }
        "rw-mark-valid-no-update" => { owned.protect(4); owned.target(0, 1); owned.protect(0x40000040); }
        "rw-mark-invalid-no-update" => { owned.protect(4); owned.target(0, 0); owned.protect(0x40000040); }
        "rw-mark-invalid-default" => { owned.protect(4); owned.target(0, 0); owned.protect(0x40); }
        _ => panic!("unknown lifecycle control: {case}"),
    }
    #[cfg(target_arch = "x86_64")]
    let code = [0xb8u8, 0x34, 0x12, 0, 0, 0xc3];
    #[cfg(target_arch = "aarch64")]
    let code = [0x80u8, 0x46, 0x82, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
    // SAFETY: Every offset is within this live 64 KiB reservation, including the intentionally uncommitted controls.
    let target = unsafe { owned.0.cast::<u8>().add(offset) };
    println!("TARGET_STATE case={case} base={:x} initial={initial:08x} reserved={reserved}", owned.0 as usize);
    std::io::stdout().flush().unwrap();
    if !matches!(case.as_str(), "reserve-default-call" | "reserve-invalid-call") {
        // SAFETY: These disjoint buffers contain the leaf bytes and an owned writable interval with sufficient space.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), target, code.len()) };
        // SAFETY: The pseudo handle and owned code interval are valid; this operation does not dereference a host foreign pointer.
        assert_ne!(unsafe { FlushInstructionCache(process, target.cast(), code.len()) }, 0);
    }
    // SAFETY: The original live reservation base is released once, or its owned first page is decommitted.
    if matches!(case.as_str(), "default-decommit-call" | "invalid-decommit-call") { assert_ne!(unsafe { VirtualFree(owned.0, 4096, 0x4000) }, 0); }
    if matches!(case.as_str(), "default-release-call" | "invalid-release-call") { owned.release(); }
    println!("CALL case={case} arch={} cfg_policy={policy:08x} offset={offset} expected_leaf=1234", std::env::consts::ARCH);
    std::io::stdout().flush().unwrap();
    let pointer = std::hint::black_box(target);
    // SAFETY: Positive controls contain the exact leaf bytes with this ABI. Negative controls deliberately test an OS-terminated call in a fresh child.
    let function: unsafe extern "C" fn() -> u32 = unsafe { transmute(pointer) };
    // SAFETY: The admitted leaf has the declared ABI. Inaccessible or denied negative targets intentionally terminate this isolated child before return.
    let result = unsafe { function() };
    println!("RETURN case={case} result={result:x}");
    assert_eq!(result, 0x1234);
    drop(owned);
    println!("COMPLETE case={case} all_owned_allocations_released=true");
}

fn storage_controls() {
    // SAFETY: GetCurrentProcess has no arguments and returns this process's documented pseudo handle.
    let process = unsafe { GetCurrentProcess() };
    let mut allocations = Vec::new();
    for distance in [0x1000usize, 0x10000, 0x20000, 0x3f000, 0x40000, 0x80000, 0x100000] {
        // SAFETY: this process owns the complete allocation until its release.
        // SAFETY: The kernel validates the requested range; returned allocations remain owned by this observer until release.
        let base = unsafe { VirtualAlloc(null_mut(), 4 << 20, 0x3000, 4) };
        assert!(!base.is_null());
        let address = ((base as usize + 0x3ffff) & !0x3ffff) as *mut c_void;
        let mut before = Target { offset: 0, flags: 1 };
        // SAFETY: The pseudo process handle and target descriptor are live; the target interval belongs to this observer.
        let pre = unsafe { SetProcessValidCallTargets(process, address, 4096, 1, &raw mut before) };
        // SAFETY: GetLastError has no pointer preconditions and reads this thread only.
        let pre_error = unsafe { GetLastError() };
        let neighbor = (address as usize + distance) as *mut c_void;
        let mut old = 0;
        // SAFETY: The pointer and 4 KiB interval lie in this observer's live reservation; old protection points to a live u32.
        assert_ne!(unsafe { VirtualProtect(neighbor, 4096, 0x40, &raw mut old) }, 0);
        let mut after = Target { offset: 0, flags: 1 };
        // SAFETY: The pseudo process handle and target descriptor are live; the target interval belongs to this observer.
        let post = unsafe { SetProcessValidCallTargets(process, address, 4096, 1, &raw mut after) };
        // SAFETY: GetLastError has no pointer preconditions and reads this thread only.
        let post_error = unsafe { GetLastError() };
        println!("STORAGE base={:x} target={:x} distance={distance:x} pre={pre} pre_error={pre_error:x} post={post} post_error={post_error:x} flags={:x}", base as usize, address as usize, after.flags);
        allocations.push(Owned(base));
    }
    drop(allocations);
    println!("COMPLETE storage_controls=7 all_owned_allocations_released=true");
}
