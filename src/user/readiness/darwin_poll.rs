//! Darwin poll registers no filter for events=0. Its POLLHUP read filter is
//! one-shot, so queued data can consume it before a later peer exit. Socket
//! watches use a kqueue read filter whose low-water mark suppresses data;
//! EV_EOF still wakes it, including when unread bytes remain.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

struct Watch {
    index: usize,
    original: libc::pollfd,
    queue: OwnedFd,
    result: libc::c_short,
}

fn stream_socket(fd: i32) -> bool {
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: both output pointers refer to initialized, correctly sized values.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    result == 0 && kind == libc::SOCK_STREAM
}

pub(super) fn poll(
    fds: &mut [libc::pollfd],
    count: libc::nfds_t,
    timeout_ms: i32,
) -> io::Result<()> {
    let mut watches = Vec::new();
    for (index, entry) in fds.iter_mut().enumerate() {
        if entry.events != (libc::POLLHUP | libc::POLLERR) || !stream_socket(entry.fd) {
            continue;
        }
        // SAFETY: kqueue takes no pointers and returns a new owned descriptor.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ownership of the successful kqueue result is transferred once.
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        let change = libc::kevent {
            ident: entry.fd as libc::uintptr_t,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_LOWAT,
            data: libc::c_int::MAX as libc::intptr_t,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one initialized change, no event output. The caller keeps
        // the watched socket alive until this function returns.
        if unsafe { libc::kevent(raw, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        watches.push(Watch {
            index,
            original: *entry,
            queue,
            result: 0,
        });
        entry.fd = raw;
        entry.events = libc::POLLIN;
    }
    let deadline = (timeout_ms >= 0).then(|| {
        crate::host::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64)
    });
    let mut remaining = timeout_ms;
    loop {
        // SAFETY: initialized array of the stated length; descriptors remain owned.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, remaining) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        for watch in &mut watches {
            let entry = &fds[watch.index];
            watch.result = entry.revents & (libc::POLLERR | libc::POLLNVAL);
            if entry.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut event = libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: one writable event, no changes, initialized zero timeout.
            let received = unsafe {
                libc::kevent(
                    watch.queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    &zero,
                )
            };
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            if received != 0 {
                if event.flags & libc::EV_EOF != 0 {
                    watch.result |= libc::POLLHUP;
                }
                if event.flags & libc::EV_ERROR != 0 {
                    watch.result |= libc::POLLERR;
                }
            }
        }
        let observable = watches.iter().any(|watch| watch.result != 0)
            || fds.iter().enumerate().any(|(index, entry)| {
                entry.revents != 0
                    && watches
                        .binary_search_by_key(&index, |watch| watch.index)
                        .is_err()
            });
        if ready == 0 || observable {
            break;
        }
        // NOTE_LOWAT is clamped to the socket buffer capacity. A completely
        // full buffer can therefore produce one data event. EV_CLEAR keeps
        // the filter installed for a later EOF; consume data-only events and
        // preserve the caller's remaining timeout instead of returning early.
        if let Some(deadline) = deadline {
            let now = crate::host::time::Instant::now();
            if now >= deadline {
                break;
            }
            remaining = (deadline - now)
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
        }
    }
    for watch in watches {
        fds[watch.index] = watch.original;
        fds[watch.index].revents = watch.result;
    }
    Ok(())
}
