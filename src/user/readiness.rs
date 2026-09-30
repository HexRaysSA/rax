//! Two independent readable levels for emulated anonymous objects.
//!
//! Unix levels use the two directions of a nonblocking socket pair and remain
//! shared across fork. Windows levels use two unnamed manual-reset events. A
//! caller owns the level state (typically in shared atomic words) and serializes
//! transitions with that state. Raw descriptors are borrowed from the pair.

use std::io;

/// Native readiness identifier; never a guest descriptor number.
#[cfg(unix)]
pub type Descriptor = std::os::fd::RawFd;
/// Native readiness identifier; never a guest descriptor number.
#[cfg(windows)]
pub type Descriptor = isize;

/// Native descriptor readiness. Error and hangup are reported independently
/// of the requested readable/writable directions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    pub error: bool,
}

impl Readiness {
    pub fn any(&self) -> bool {
        self.readable || self.writable || self.hangup || self.error
    }
}

/// POSIX descriptor polling with duplicate requests coalesced. Darwin's poll
/// implementation can populate only the last repeated descriptor. Union the
/// interests for each unique descriptor, then project back to every original
/// request, preserving each request's directions and unconditional error bits.
#[cfg(unix)]
pub(crate) fn poll_descriptors(
    requests: &[(Descriptor, bool, bool)],
    timeout_ms: i32,
) -> io::Result<Vec<Readiness>> {
    use std::collections::BTreeMap;
    let mut interests = BTreeMap::<Descriptor, (bool, bool)>::new();
    for &(fd, read, write) in requests {
        let entry = interests.entry(fd).or_default();
        entry.0 |= read;
        entry.1 |= write;
    }
    let mut fds: Vec<_> = interests
        .iter()
        .map(|(&fd, &(read, write))| libc::pollfd {
            fd,
            events: (if read { libc::POLLIN } else { 0 }) | (if write { libc::POLLOUT } else { 0 }),
            revents: 0,
        })
        .collect();
    let count = fds
        .len()
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: initialized writable pollfd array. Native descriptors are owned
    // by the caller throughout; poll does not retain the buffer.
    if unsafe { libc::poll(fds.as_mut_ptr(), count, timeout_ms) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(requests
        .iter()
        .map(|&(fd, read, write)| {
            // BTreeMap iteration keeps fds sorted, and every requested fd was inserted.
            let result = fds[fds.binary_search_by_key(&fd, |p| p.fd).unwrap()].revents;
            Readiness {
                readable: read && result & libc::POLLIN != 0,
                writable: write && result & libc::POLLOUT != 0,
                hangup: result & libc::POLLHUP != 0,
                error: result & (libc::POLLERR | libc::POLLNVAL) != 0,
            }
        })
        .collect())
}

/// Kernel-backed levels used by `eventfd` and timer objects.
#[derive(Debug)]
pub(crate) struct LevelPair(platform::Pair);

impl LevelPair {
    pub(crate) fn new() -> io::Result<Self> {
        platform::Pair::new().map(Self)
    }

    /// Borrow the native descriptor for level 0 or 1. Keep the pair alive while
    /// using it. The descriptor is readable exactly while the level is set.
    pub(crate) fn descriptor(&self, which: usize) -> Descriptor {
        self.0.descriptor(which)
    }

    /// Change a level. The caller must serialize with its state and call this
    /// only when `on` differs from the previous state, including across fork.
    /// The state must be committed only after this operation succeeds.
    pub(crate) fn transition(&self, which: usize, on: bool) -> io::Result<()> {
        self.0.transition(which, on)
    }
}

/// Wait for readable level descriptors. Positive timeout is in milliseconds;
/// zero probes once and a negative timeout waits indefinitely. Repeated
/// descriptors retain repeated result entries. An empty indefinite wait is an
/// input error. This is a level-event wait, not a Windows file/socket poll API.
/// Owners must keep all descriptors alive for the duration of the call.
pub(crate) fn wait_readable(descriptors: &[Descriptor], timeout_ms: i32) -> io::Result<Vec<bool>> {
    if descriptors.is_empty() {
        if timeout_ms < 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
        return Ok(Vec::new());
    }
    platform::wait_readable(descriptors, timeout_ms)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[derive(Debug)]
    pub struct Pair {
        ends: [UnixStream; 2],
    }
    impl Pair {
        pub fn new() -> io::Result<Self> {
            let (a, b) = UnixStream::pair()?;
            a.set_nonblocking(true)?;
            b.set_nonblocking(true)?;
            Ok(Self { ends: [a, b] })
        }
        pub fn descriptor(&self, which: usize) -> Descriptor {
            self.ends[which].as_raw_fd()
        }
        pub fn transition(&self, which: usize, on: bool) -> io::Result<()> {
            let mut reader = &self.ends[which];
            let mut writer = &self.ends[1 - which];
            loop {
                let result = if on {
                    writer.write(&[1])
                } else {
                    reader.read(&mut [0])
                };
                match result {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(1) => return Ok(()),
                    Ok(_) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Err(e) => return Err(e),
                }
            }
        }
    }

    pub fn wait_readable(descriptors: &[Descriptor], timeout_ms: i32) -> io::Result<Vec<bool>> {
        let requests: Vec<_> = descriptors.iter().map(|&fd| (fd, true, false)).collect();
        let ready = poll_descriptors(&requests, timeout_ms)?;
        if ready.iter().any(|r| r.error || r.hangup) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid level descriptor",
            ));
        }
        Ok(ready.iter().map(|r| r.readable).collect())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::time::{Duration, Instant};
    type Handle = *mut c_void;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;
    const INFINITE: u32 = u32::MAX;
    const MAXIMUM_WAIT_OBJECTS: usize = 64;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(
            attributes: *const c_void,
            manual_reset: i32,
            initial: i32,
            name: *const u16,
        ) -> Handle;
        fn SetEvent(event: Handle) -> i32;
        fn ResetEvent(event: Handle) -> i32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn WaitForMultipleObjects(
            count: u32,
            handles: *const Handle,
            wait_all: i32,
            milliseconds: u32,
        ) -> u32;
    }

    #[derive(Debug)]
    pub struct Pair {
        events: [OwnedHandle; 2],
    }
    impl Pair {
        pub fn new() -> io::Result<Self> {
            fn event() -> io::Result<OwnedHandle> {
                // SAFETY: null attributes/name create an unnamed,
                // non-inheritable manual-reset event, initially unsignalled.
                let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
                if handle.is_null() {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: valid newly-owned event handle, closed once by RAII.
                Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
            }
            Ok(Self {
                events: [event()?, event()?],
            })
        }
        pub fn descriptor(&self, which: usize) -> Descriptor {
            self.events[which].as_raw_handle() as isize
        }
        pub fn transition(&self, which: usize, on: bool) -> io::Result<()> {
            let handle = self.events[which].as_raw_handle();
            // SAFETY: live event owned by this pair; neither API retains memory.
            let ok = unsafe {
                if on {
                    SetEvent(handle)
                } else {
                    ResetEvent(handle)
                }
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn wait_readable(descriptors: &[Descriptor], timeout_ms: i32) -> io::Result<Vec<bool>> {
        let deadline =
            (timeout_ms >= 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        // WaitForMultipleObjects rejects duplicate handles. The result scan
        // still follows the original list, retaining duplicate entries.
        let mut unique = descriptors.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let handles: Vec<Handle> = unique.iter().map(|&d| d as Handle).collect();
        loop {
            let mut ready = Vec::with_capacity(descriptors.len());
            for &descriptor in descriptors {
                // SAFETY: borrowed live level-event handle, immediate probe.
                match unsafe { WaitForSingleObject(descriptor as Handle, 0) } {
                    WAIT_OBJECT_0 => ready.push(true),
                    WAIT_TIMEOUT => ready.push(false),
                    WAIT_FAILED => return Err(io::Error::last_os_error()),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected event wait result",
                        ));
                    }
                }
            }
            if ready.iter().any(|&r| r) || deadline.is_some_and(|end| Instant::now() >= end) {
                return Ok(ready);
            }
            let timeout = deadline.map_or(INFINITE, |end| {
                end.saturating_duration_since(Instant::now())
                    .as_nanos()
                    .div_ceil(1_000_000)
                    .min(u128::from(u32::MAX - 1)) as u32
            });
            if handles.len() > MAXIMUM_WAIT_OBJECTS {
                // Windows caps a native wait at 64 handles. Scan all levels at
                // 1 ms intervals for larger sets, rather than omitting handles
                // or waiting only on the first chunk. Signals are level-triggered.
                std::thread::sleep(Duration::from_millis(u64::from(timeout.min(1))));
                continue;
            }
            // SAFETY: nonempty, deduplicated array of <=64 live event handles;
            // count matches the array, wait-any is selected, no pointers retained.
            let result = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout)
            };
            if result == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            if result != WAIT_TIMEOUT && result >= WAIT_OBJECT_0 + handles.len() as u32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected event wait result",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn levels_are_independent_persistent_and_clearable() {
        let pair = LevelPair::new().unwrap();
        let fds = [pair.descriptor(0), pair.descriptor(1), pair.descriptor(0)];
        assert_eq!(wait_readable(&fds, 0).unwrap(), [false, false, false]);
        pair.transition(0, true).unwrap();
        for _ in 0..3 {
            assert_eq!(wait_readable(&fds, 0).unwrap(), [true, false, true]);
        }
        pair.transition(1, true).unwrap();
        assert_eq!(wait_readable(&fds, 0).unwrap(), [true, true, true]);
        pair.transition(0, false).unwrap();
        assert_eq!(wait_readable(&fds, 0).unwrap(), [false, true, false]);
        pair.transition(1, false).unwrap();
        assert_eq!(wait_readable(&fds, 0).unwrap(), [false, false, false]);
    }

    #[test]
    fn delayed_wake_including_more_than_64_levels_and_duplicates() {
        for count in [1, 65] {
            let pairs: Vec<_> = (0..count).map(|_| LevelPair::new().unwrap()).collect();
            let mut fds: Vec<_> = pairs.iter().map(|p| p.descriptor(0)).collect();
            fds.push(pairs.last().unwrap().descriptor(0));
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let last = pairs.last().unwrap();
                scope.spawn(|| {
                    barrier.wait();
                    std::thread::sleep(Duration::from_millis(10));
                    last.transition(0, true).unwrap();
                });
                barrier.wait();
                let ready = wait_readable(&fds, 2000).unwrap();
                assert!(ready[..count - 1].iter().all(|&r| !r));
                assert!(ready[count - 1] && ready[count]);
                last.transition(0, false).unwrap();
            });
        }
    }

    #[test]
    fn finite_empty_and_expired_waits() {
        assert!(wait_readable(&[], 0).unwrap().is_empty());
        assert_eq!(
            wait_readable(&[], -1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let pair = LevelPair::new().unwrap();
        let start = Instant::now();
        assert_eq!(wait_readable(&[pair.descriptor(0)], 10).unwrap(), [false]);
        assert!(start.elapsed() >= Duration::from_millis(10));
    }

    #[cfg(unix)]
    #[test]
    fn unix_duplicate_poll_interests_preserve_each_requests_mask() {
        let pair = LevelPair::new().unwrap();
        pair.transition(0, true).unwrap();
        let fd = pair.descriptor(0);
        let requests = [
            (fd, true, false),
            (fd, false, true),
            (fd, false, false),
            (fd, true, true),
        ];
        let ready = poll_descriptors(&requests, 0).unwrap();
        for (r, &(_, read, write)) in ready.iter().zip(&requests) {
            assert_eq!((r.readable, r.writable), (read, write));
            assert!(!r.error && !r.hangup);
        }
        for which in [0, 1] {
            let descriptor = pair.descriptor(which);
            // SAFETY: live descriptors and integer-only fcntl queries.
            let fd_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
            assert!(fd_flags >= 0 && fd_flags & libc::FD_CLOEXEC != 0);
            assert!(status_flags >= 0 && status_flags & libc::O_NONBLOCK != 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_levels_survive_fork() {
        let pair = LevelPair::new().unwrap();
        let reader = pair.descriptor(0);
        let writer = pair.descriptor(1);
        // SAFETY: child performs only async-signal-safe write and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let result = unsafe { libc::write(writer, [1u8].as_ptr().cast(), 1) };
            unsafe { libc::_exit(if result == 1 { 0 } else { 1 }) }
        }
        let mut status = 0;
        loop {
            // SAFETY: wait for the exact child with writable status storage.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(wait_readable(&[reader], 0).unwrap(), [true]);
        pair.transition(0, false).unwrap();
        assert_eq!(wait_readable(&[reader], 0).unwrap(), [false]);
    }
}
