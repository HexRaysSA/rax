//! Per-operation nonblocking FIFO reads through a private pipe. splice's
//! nonblocking flag leaves the caller's shared open-file status flags intact.
use std::io::{self, Read};
use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(test)]
#[path = "fifo_linux_tests.rs"]
mod tests;

pub(super) fn read(fd: i32, capacity: usize) -> io::Result<Vec<u8>> {
    // SAFETY: F_GETFL takes no pointer. A zero-byte read must still reject a
    // write-only descriptor, whereas splice(len=0) would otherwise succeed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE == libc::O_WRONLY || flags & libc::O_PATH != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    if capacity == 0 {
        return Ok(Vec::new());
    }
    let mut descriptors = [-1; 2];
    // SAFETY: the array has room for the two newly owned private descriptors.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded and each new descriptor has one owner.
    let (reader, _writer) = unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    };
    let mut reader = std::fs::File::from(reader);
    let mut bytes = Vec::new();
    while bytes.len() < capacity {
        let want = (capacity - bytes.len()).min(1 << 20);
        if bytes.try_reserve(want).is_err() {
            if bytes.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ENOMEM));
            }
            break;
        }
        // SAFETY: both pipe endpoints and the entered source stay live. No
        // offsets are used. NONBLOCK covers the actual transfer, not a prior
        // readiness observation. The empty private pipe has its reader alive.
        let count = unsafe {
            libc::splice(
                fd,
                std::ptr::null_mut(),
                descriptors[1],
                std::ptr::null_mut(),
                want,
                libc::SPLICE_F_NONBLOCK,
            )
        };
        if count < 0 {
            if bytes.is_empty() {
                return Err(io::Error::last_os_error());
            }
            break;
        }
        if count == 0 {
            break;
        }
        let previous = bytes.len();
        bytes.resize(previous + count as usize, 0);
        // Exactly count bytes are privately queued. Retrying EINTR cannot
        // discard bytes already consumed by splice. Looping preserves reads
        // larger than the private pipe's capacity without shared flag changes.
        reader.read_exact(&mut bytes[previous..])?;
    }
    Ok(bytes)
}
