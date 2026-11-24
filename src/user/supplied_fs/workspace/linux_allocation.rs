use super::MAX_BYTES;
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// Pages reserved beyond the logical length. Bytes inside the logical file
/// already count toward the workspace quota, even if they are sparse.
#[derive(Clone, Debug, Default)]
pub(super) struct Tail(BTreeSet<u64>);

impl Tail {
    pub(super) fn reserve(&mut self, offset: u64, end: u64, length: usize) -> io::Result<()> {
        let page = crate::user::mm::native_page_size();
        let first = (offset / page).max((length as u64).div_ceil(page));
        let last = end.div_ceil(page);
        if last.saturating_sub(first) > MAX_BYTES as u64 / page {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        self.0.extend(first..last);
        Ok(())
    }

    pub(super) fn charge_after_resize(&self, old: usize, new: usize) -> usize {
        let page = crate::user::mm::native_page_size();
        if new < old {
            0
        } else {
            let first = (new as u64).div_ceil(page);
            self.0.range(first..).count() * page as usize
        }
    }

    pub(super) fn resize(&mut self, old: usize, new: usize) {
        if new < old {
            self.0.clear();
        } else {
            let first = (new as u64).div_ceil(crate::user::mm::native_page_size());
            self.0.retain(|&index| index >= first);
        }
    }
}

pub(super) fn allocate(file: &File, mode: i32, offset: i64, length: i64) -> io::Result<()> {
    // SAFETY: the file is the workspace's private backing descriptor.
    let result = unsafe { libc::fallocate64(file.as_raw_fd(), mode, offset, length) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
