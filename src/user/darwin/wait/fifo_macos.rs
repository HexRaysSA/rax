//! Darwin FIFO EOF is visible to select even when poll and kqueue stay quiet.
use super::{Duration, Instant};

/// Only named FIFO readers need the additional readiness source. Anonymous
/// pipes and every other descriptor retain the ordinary native poll path.
struct FifoReads {
    entries: Vec<(usize, usize, u32)>,
    bits: Vec<libc::c_int>,
    nfds: libc::c_int,
}

unsafe extern "C" {
    // Apple's unlimited-select entry accepts an fd bitmap sized by nfds.
    // libc::select uses select$1050 on x86-64, whose nfds limit is FD_SETSIZE.
    // SAFETY: this declaration matches the retained Apple SDK prototype and
    // its documented unlimited-select symbol.
    #[link_name = "select$DARWIN_EXTSN"]
    fn select_unlimited(
        nfds: libc::c_int,
        read: *mut libc::fd_set,
        write: *mut libc::fd_set,
        error: *mut libc::fd_set,
        timeout: *mut libc::timeval,
    ) -> libc::c_int;
}

impl FifoReads {
    fn new(descriptors: &[libc::pollfd]) -> Self {
        let mut entries = Vec::new();
        let mut nfds = 0;
        for (index, descriptor) in descriptors.iter().enumerate() {
            if descriptor.events & libc::POLLIN == 0
                || !crate::user::darwin::host::fstat(descriptor.fd)
                    .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFIFO)
                || crate::user::darwin::host::anonymous_pipe(descriptor.fd)
            {
                continue;
            }
            let Some(end) = descriptor.fd.checked_add(1) else {
                continue;
            };
            nfds = nfds.max(end);
            let fd = descriptor.fd as usize;
            entries.push((index, fd / 32, 1u32 << (fd % 32)));
        }
        let words = (nfds as usize)
            .div_ceil(32)
            .max(std::mem::size_of::<libc::fd_set>().div_ceil(std::mem::size_of::<libc::c_int>()));
        let mut bits = vec![0; words];
        for &(_, word, mask) in &entries {
            bits[word] |= mask as libc::c_int;
        }
        Self {
            entries,
            bits,
            nfds,
        }
    }

    /// Merge FIFO readability; false means the native probe was interrupted.
    fn mark_ready(&self, descriptors: &mut [libc::pollfd]) -> bool {
        let mut bits = self.bits.clone();
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: the initialized c_int bitmap has fd_set alignment and at
        // least its complete size, plus every bit below nfds. The unlimited
        // entry reads/writes exactly the nfds-selected bitmap. Other sets are
        // null; timeout is a live initialized timeval. All fd numbers passed
        // the native fstat check when this bounded wait began.
        let count = unsafe {
            select_unlimited(
                self.nfds,
                bits.as_mut_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        if count < 0 {
            return std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR);
        }
        for &(index, word, mask) in &self.entries {
            if bits[word] as u32 & mask != 0 {
                descriptors[index].revents |= libc::POLLIN;
            }
        }
        true
    }
}

/// Preserve the original deadline and native EINTR behavior while sampling
/// the FIFO EOF source during an otherwise indefinite host poll. Work is
/// O(n + highest_fifo_fd/32) per sample, with the same storage bound.
pub(super) fn poll(descriptors: &mut [libc::pollfd], timeout: Option<Duration>) -> libc::c_int {
    let fifo = FifoReads::new(descriptors);
    if fifo.entries.is_empty() {
        return super::poll_once(descriptors, super::timeout_ms(timeout));
    }
    let started = Instant::now();
    loop {
        if !fifo.mark_ready(descriptors) {
            return -1;
        }
        let ready = descriptors.iter().any(|descriptor| descriptor.revents != 0);
        let remaining = timeout.map(|duration| duration.saturating_sub(started.elapsed()));
        // poll/kqueue do not wake for named FIFO EOF on the measured kernel.
        // Bound only the host sample interval; never shorten the guest wait.
        let milliseconds = if ready {
            0
        } else {
            remaining.map_or(10, |duration| super::timeout_ms(Some(duration)).min(10))
        };
        let count = super::poll_once(descriptors, milliseconds);
        if count < 0 || !fifo.mark_ready(descriptors) {
            return -1;
        }
        if descriptors.iter().any(|descriptor| descriptor.revents != 0) {
            return descriptors
                .iter()
                .filter(|descriptor| descriptor.revents != 0)
                .count() as libc::c_int;
        }
        if timeout.is_some_and(|duration| started.elapsed() >= duration) {
            return 0;
        }
    }
}
