use super::{DARWIN_BLOCK_BYTES, MAX_BYTES};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

pub(super) struct Request {
    native: libc::fstore_t,
    available: usize,
}

impl Request {
    pub(super) fn new(flags: u32, length: u64, occupied: usize) -> io::Result<Self> {
        let available = (MAX_BYTES - occupied) / DARWIN_BLOCK_BYTES * DARWIN_BLOCK_BYTES;
        if length > available as u64 && (flags & libc::F_ALLOCATEALL != 0 || available == 0) {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        Ok(Self {
            native: libc::fstore_t {
                fst_flags: flags,
                fst_posmode: libc::F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: length.min(available as u64) as i64,
                fst_bytesalloc: 0,
            },
            available,
        })
    }

    pub(super) fn reserve(mut self, file: &File) -> (io::Result<()>, i64, usize) {
        // SAFETY: the descriptor belongs to the guest workspace and the
        // native request is a live, exclusive fstore_t.
        let result =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut self.native) };
        let result = if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        let allocated = self.native.fst_bytesalloc.max(0);
        let credit = (allocated.min(self.available as i64) as usize).div_ceil(DARWIN_BLOCK_BYTES)
            * DARWIN_BLOCK_BYTES;
        (result, allocated, credit)
    }
}
