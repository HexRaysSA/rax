//! One CFG lifecycle control in a fresh process, using its own private code only.
use std::ffi::c_void;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::ptr::null_mut;

#[repr(C)]
struct Target { offset: usize, flags: usize }
#[link(name = "kernel32")]
unsafe extern "system" {
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
struct Owned(*mut c_void);
impl Owned {
    fn allocate(address: *mut c_void, flags: u32, protection: u32) -> Self {
        let pointer = unsafe { VirtualAlloc(address, 65536, flags, protection) };
        assert!(!pointer.is_null(), "allocation error {}", unsafe { GetLastError() });
        Self(pointer)
    }
    fn protect(&self, protection: u32) {
        let mut previous = 0;
        assert_ne!(unsafe { VirtualProtect(self.0, 4096, protection, &raw mut previous) }, 0);
    }
    fn commit(&self, protection: u32) {
        assert_eq!(unsafe { VirtualAlloc(self.0, 4096, 0x1000, protection) }, self.0);
    }
    fn target(&self, offset: usize, flags: usize) {
        let mut target = Target { offset, flags };
        assert_ne!(unsafe { SetProcessValidCallTargets(GetCurrentProcess(), self.0, 4096, 1, &raw mut target) }, 0, "target error {}", unsafe { GetLastError() });
        assert_ne!(target.flags & 2, 0);
    }
}
impl Drop for Owned {
    fn drop(&mut self) { assert_ne!(unsafe { VirtualFree(self.0, 0, 0x8000) }, 0); }
}
fn main() {
    // Suppress fault UI for this observer only. No host policy is changed.
    unsafe { SetErrorMode(2) };
    let case = std::env::args().nth(1).expect("one named lifecycle control is required");
    if case == "--all" {
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
    let process = unsafe { GetCurrentProcess() };
    let mut policy = 0u32;
    assert_ne!(unsafe { GetProcessMitigationPolicy(process, 7, (&raw mut policy).cast(), size_of::<u32>()) }, 0);
    assert_ne!(policy & 1, 0);
    let initial = if case.starts_with("default") || case.starts_with("rw") { 0x40 } else { 0x40000040 };
    let reserved = case.starts_with("reserve");
    let mut owned = Owned::allocate(null_mut(), if reserved { 0x2000 } else { 0x3000 }, initial);
    let mut offset = 0usize;
    match case.as_str() {
        "default" | "invalid" => {}
        "invalid-mark-valid" => owned.target(0, 1),
        "default-mark-invalid" => owned.target(0, 0),
        "invalid-protect-no-update" => { owned.protect(4); owned.protect(0x40000040); }
        "invalid-protect-default" => { owned.protect(4); owned.protect(0x40); }
        "invalid-recommit-default" => owned.commit(0x40),
        "default-recommit-invalid" => owned.commit(0x40000040),
        "invalid-decommit-recommit" => {
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
    let target = unsafe { owned.0.cast::<u8>().add(offset) };
    unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), target, code.len()) };
    assert_ne!(unsafe { FlushInstructionCache(process, target.cast(), code.len()) }, 0);
    println!("CALL case={case} arch={} cfg_policy={policy:08x} offset={offset} expected_leaf=1234", std::env::consts::ARCH);
    std::io::stdout().flush().unwrap();
    let pointer = std::hint::black_box(target);
    let function: unsafe extern "C" fn() -> u32 = unsafe { transmute(pointer) };
    let result = unsafe { function() };
    println!("RETURN case={case} result={result:x}");
    assert_eq!(result, 0x1234);
    drop(owned);
    println!("COMPLETE case={case} all_owned_allocations_released=true");
}
