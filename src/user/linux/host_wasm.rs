//! Linux personality host services on hosts that are neither Unix nor Windows.
//!
//! This covers wasm32-unknown-unknown and WASI. Neither has processes, signals,
//! or file-descriptor poll, and `std::process::id` panics on both. Spawning a
//! Linux process is refused earlier (`FrameArena::supports_shared_mappings` is
//! false), so these are fallbacks for shared code: the host process identity is
//! the virtual embedding PID, a host file or wait gets `ENOSYS`, and clocks and
//! resource accounting read as zero. `std::time` panics on
//! wasm32-unknown-unknown, so timestamps stay zero rather than being sampled.

use super::abi::errno::Errno;
use super::abi::errno_table::ENOSYS;
pub use crate::user::clock::HostClock;
pub use crate::user::mm::SharedWords;
pub use crate::user::readiness::{Descriptor, Readiness};

pub fn clock_gettime(_clock: HostClock) -> (i64, i64) {
    (0, 0)
}

/// The only host process is the emulator itself, identified as in a closed
/// embedding.
pub fn pid() -> i32 {
    super::embedding::PID
}

pub fn poll(_fds: &[(Descriptor, bool, bool)], _timeout_ms: i32) -> Result<Vec<Readiness>, Errno> {
    Err(Errno(ENOSYS))
}

/// `(user microseconds, kernel microseconds, peak resident KiB)`.
pub fn rusage_self() -> (u64, u64, u64) {
    (0, 0, 0)
}

pub fn process_alive(pid: i32) -> bool {
    pid == self::pid()
}

pub fn allocated_bytes(file: &std::fs::File) -> std::io::Result<u64> {
    file.metadata().map(|metadata| metadata.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_identity_is_the_embedding_pid_and_never_panics() {
        assert_eq!(pid(), super::super::embedding::PID);
        assert!(process_alive(pid()));
        assert!(!process_alive(pid() + 1));
        assert!(!process_alive(0));
        assert!(!process_alive(-1));
        assert!(super::super::ipc::alive(pid()));
        assert!(!super::super::ipc::alive(pid() + 1));
    }

    #[test]
    fn host_waits_report_enosys() {
        assert_eq!(poll(&[], 0).unwrap_err(), Errno(ENOSYS));
    }
}
