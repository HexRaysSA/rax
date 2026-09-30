//! Native primitives used by the closed Linux personality on Windows.
//!
//! External Unix host services are not part of the closed embedding profile.
//! Process creation validates that boundary before allocating guest state.

use super::abi::errno::Errno;
pub use crate::user::clock::HostClock;
pub use crate::user::mm::SharedWords;
pub use crate::user::readiness::{Descriptor, Readiness};

pub fn clock_gettime(clock: HostClock) -> (i64, i64) {
    crate::user::clock::read(clock).expect("required host clock unavailable")
}

pub fn pid() -> i32 {
    std::process::id() as i32
}

/// Closed descriptors are readiness levels. Read/write directions of guest
/// eventfd/timerfd objects are represented by separate readable native events.
pub fn poll(fds: &[(Descriptor, bool, bool)], timeout_ms: i32) -> Result<Vec<Readiness>, Errno> {
    if fds.iter().any(|&(_, read, write)| !read || write) {
        return Err(Errno(super::abi::errno_table::EINVAL));
    }
    let descriptors: Vec<_> = fds.iter().map(|&(fd, _, _)| fd).collect();
    Ok(
        crate::user::readiness::wait_readable(&descriptors, timeout_ms)?
            .into_iter()
            .map(|readable| Readiness {
                readable,
                ..Readiness::default()
            })
            .collect(),
    )
}

/// The emulator's process accounting, in the same units as the Unix adapter:
/// `(user microseconds, kernel microseconds, peak resident KiB)`.
pub fn rusage_self() -> (u64, u64, u64) {
    usage::read().expect("required host process accounting unavailable")
}

/// Whether a host process remains alive. Access denial is not evidence
/// of death, and only a signaled process handle proves an observed exit.
pub fn process_alive(pid: i32) -> bool {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    if pid <= 0 {
        return false;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const ERROR_INVALID_PARAMETER: i32 = 87;
    // SAFETY: valid access mask, no inheritance, integer process ID. No
    // caller memory or callback is supplied. Success returns a new handle.
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid as u32) };
    if handle.is_null() {
        // Preserve records on access denial or an indeterminate OS error.
        return std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: this is the fresh process handle returned by OpenProcess.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // SAFETY: the SYNCHRONIZE handle stays owned for this nonblocking call.
    // Waiting on a process observes its state without consuming it.
    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) != 0 }
}

/// Allocated file storage in bytes, not logical length or resident RAM.
pub fn allocated_bytes(file: &std::fs::File) -> std::io::Result<u64> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct StandardInfo {
        allocation_size: i64,
        end_of_file: i64,
        links: u32,
        delete_pending: u8,
        directory: u8,
    }
    const _: () = assert!(std::mem::size_of::<StandardInfo>() == 24);
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            class: i32,
            data: *mut c_void,
            size: u32,
        ) -> i32;
    }
    let mut info = StandardInfo::default();
    // SAFETY: live borrowed file, initialized exclusive FILE_STANDARD_INFO
    // buffer of the exact 24-byte native layout, class FileStandardInfo=1.
    // The API retains no pointer and cannot unwind through Rust.
    let ok = unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 1, (&raw mut info).cast(), 24)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    u64::try_from(info.allocation_size).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

mod usage {
    use std::{ffi::c_void, io};

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    impl FileTime {
        fn microseconds(&self) -> u64 {
            // FILETIME counts 100 ns units. Division truncates by < 1 us.
            ((u64::from(self.high) << 32) | u64::from(self.low)) / 10
        }
    }

    // PROCESS_MEMORY_COUNTERS (psapi.h). SIZE_T follows native pointer width;
    // all fields must be present even though only PeakWorkingSetSize is read.
    #[repr(C)]
    #[derive(Default)]
    struct MemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        peak_paged_pool: usize,
        paged_pool: usize,
        peak_nonpaged_pool: usize,
        nonpaged_pool: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessTimes(
            process: *mut c_void,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut MemoryCounters,
            bytes: u32,
        ) -> i32;
    }

    pub(super) fn read() -> io::Result<(u64, u64, u64)> {
        let mut created = FileTime::default();
        let mut exited = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        let bytes = std::mem::size_of::<MemoryCounters>() as u32;
        let mut memory = MemoryCounters {
            cb: bytes,
            ..MemoryCounters::default()
        };
        // SAFETY: the current-process pseudo-handle is always valid and is not
        // closed. Each out-pointer addresses distinct, initialized, correctly
        // aligned native-layout storage that outlives its synchronous call.
        unsafe {
            let process = GetCurrentProcess();
            if GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
                return Err(io::Error::last_os_error());
            }
            if K32GetProcessMemoryInfo(process, &mut memory, bytes) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // PeakWorkingSetSize is bytes, while the guest Linux ABI uses KiB.
        Ok((
            user.microseconds(),
            kernel.microseconds(),
            memory.peak_working_set as u64 / 1024,
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accounting_layout_units_and_native_samples() {
            assert_eq!(std::mem::size_of::<FileTime>(), 8);
            assert_eq!(
                std::mem::size_of::<MemoryCounters>(),
                8 + 8 * std::mem::size_of::<usize>()
            );
            assert_eq!(FileTime { low: 9, high: 0 }.microseconds(), 0);
            assert_eq!(FileTime { low: 10, high: 0 }.microseconds(), 1);
            assert_eq!(
                FileTime {
                    low: u32::MAX,
                    high: u32::MAX
                }
                .microseconds(),
                u64::MAX / 10
            );
            let before = read().unwrap();
            let after = read().unwrap();
            assert!(after.0 >= before.0 && after.1 >= before.1);
            assert!(after.2 >= before.2 && after.2 > 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn process_liveness_distinguishes_exit_code_259_from_a_running_process() {
        const CHILD: &str = "RAX_TEST_WINDOWS_LIVENESS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // Parent owns our input pipe. Wait until it has observed this
            // process alive, then exit with Windows' STILL_ACTIVE value.
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            std::process::exit(259);
        }
        assert!(!process_alive(0));
        assert!(!process_alive(-1));
        assert!(process_alive(pid()));
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "user::linux::host::tests::process_liveness_distinguishes_exit_code_259_from_a_running_process",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let child_pid = i32::try_from(child.0.id()).unwrap();
        assert!(process_alive(child_pid));
        child.0.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert_eq!(child.0.wait().unwrap().code(), Some(259));
        // Child keeps its native process handle alive, preventing PID reuse
        // while the adapter independently opens and observes that same PID.
        assert!(!process_alive(child_pid));
    }

    #[test]
    fn allocated_storage_tracks_written_file_and_duplicate_handle() {
        let mut file = crate::user::mm::anonymous_file().unwrap();
        assert_eq!(allocated_bytes(&file).unwrap(), 0);
        file.write_all(&vec![0xa5; 128 * 1024 + 7]).unwrap();
        file.sync_all().unwrap();
        let allocated = allocated_bytes(&file).unwrap();
        assert!(allocated > 0);
        assert_eq!(
            allocated_bytes(&file.try_clone().unwrap()).unwrap(),
            allocated
        );
        // Allocation is a filesystem quantity. Do not equate it with logical
        // length: sparse/compressed volumes can allocate fewer physical bytes.
        file.set_len(0).unwrap();
        file.sync_all().unwrap();
        assert_eq!(allocated_bytes(&file).unwrap(), 0);
    }
}
