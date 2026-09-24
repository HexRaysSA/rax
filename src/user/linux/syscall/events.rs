//! Event, timer, and signal descriptors: `eventfd`/`eventfd2`
//! (`fs/eventfd.c`), `timerfd_create`/`timerfd_settime`/`timerfd_gettime`
//! (`fs/timerfd.c`), and `signalfd`/`signalfd4` (`fs/signalfd.c`), with
//! their `read`, `write`, `poll`, and `ioctl` behavior. The objects are in
//! [`anon`](crate::user::linux::fs::anon).
//!
//! As in the kernel, the file operations see the whole transfer: a read
//! shorter than one record is `EINVAL` even with a zero count, and a
//! destination that faults after the record was taken loses it.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_CLOEXEC, O_NONBLOCK, O_RDWR};
use super::super::fs::anon::{
    Anon, EFD_SEMAPHORE, EventFd, SignalFd, TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET, TimerFd,
};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::posix_timers::{Setting, clock_now};
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::signal::info::Layout;
use super::super::signal::{KERNEL_ONLY_MASK, SigInfo, deliver};
use super::super::wait::{Resume, Wait};
use super::io::install;
use super::ready::Polled;
use super::timer::{read_itimerspec, timespec_ns, timespec_valid, write_itimerspec};
use super::{Ctx, SysResult};

/// `sizeof(struct signalfd_siginfo)`.
pub const SIGNALFD_SIZE: u64 = 128;
/// `TFD_IOC_SET_TICKS`: `_IOW('T', 0, __u64)`.
pub const TFD_IOC_SET_TICKS: u32 = 0x4008_5400;

/// Clock IDs a `timerfd` may use.
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_BOOTTIME: i32 = 7;
const CLOCK_REALTIME_ALARM: i32 = 8;
const CLOCK_BOOTTIME_ALARM: i32 = 9;

/// Wraps `anon` in an open file description, as `anon_inode_getfile`
/// does: read-write, with `O_NONBLOCK` from `flags`.
fn anon_file(anon: Anon, flags: u32) -> Arc<OpenFile> {
    let name = format!("anon_inode:{}", anon.name());
    OpenFile::new(
        FileObject::Anon(anon),
        FileType::Anon,
        name,
        None,
        O_RDWR | (flags & O_NONBLOCK),
    )
}

/// `eventfd2`.
pub fn eventfd2(c: &mut Ctx<'_>, count: u32, flags: u32) -> SysResult {
    if flags & !(O_CLOEXEC | O_NONBLOCK | EFD_SEMAPHORE) != 0 {
        return Err(Errno(EINVAL));
    }
    let ev = EventFd::new(count, flags & EFD_SEMAPHORE != 0)?;
    install(c, anon_file(Anon::Event(ev), flags), flags & O_CLOEXEC != 0)
}

/// Whether the caller may use an alarm clock (`CAP_WAKE_ALARM`, which
/// only root holds here).
fn wake_alarm(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

/// `timerfd_create`.
pub fn timerfd_create(c: &mut Ctx<'_>, clockid: i32, flags: u32) -> SysResult {
    let known = matches!(
        clockid,
        CLOCK_MONOTONIC
            | CLOCK_REALTIME
            | CLOCK_REALTIME_ALARM
            | CLOCK_BOOTTIME
            | CLOCK_BOOTTIME_ALARM
    );
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 || !known {
        return Err(Errno(EINVAL));
    }
    let alarm = matches!(clockid, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM);
    if alarm && !wake_alarm(c) {
        return Err(Errno(EPERM));
    }
    let t = TimerFd::new(clockid)?;
    install(c, anon_file(Anon::Timer(t), flags), flags & O_CLOEXEC != 0)
}

/// The `timerfd` behind descriptor `fd` (`EBADF`; `EINVAL` for another
/// file).
fn timerfd(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    match &file.object {
        FileObject::Anon(Anon::Timer(_)) => Ok(file),
        _ => Err(Errno(EINVAL)),
    }
}

fn as_timer(file: &OpenFile) -> &TimerFd {
    match &file.object {
        FileObject::Anon(Anon::Timer(t)) => t,
        _ => unreachable!("checked by timerfd()"),
    }
}

/// `timerfd_settime`.
pub fn timerfd_settime(c: &mut Ctx<'_>, fd: i32, flags: u32, new: u64, old: u64) -> SysResult {
    let (interval, value) = read_itimerspec(c, new)?;
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0
        || !timespec_valid(interval)
        || !timespec_valid(value)
    {
        return Err(Errno(EINVAL));
    }
    let file = timerfd(c, fd)?;
    let t = as_timer(&file);
    if matches!(t.clockid, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM) && !wake_alarm(c) {
        return Err(Errno(EPERM));
    }
    let setting = Setting {
        value: timespec_ns(value),
        interval: timespec_ns(interval),
    };
    let prev = t.settime(flags, setting, &clock_now);
    if old != 0 {
        write_itimerspec(c, old, prev)?;
    }
    Ok(0)
}

/// `timerfd_gettime`.
pub fn timerfd_gettime(c: &mut Ctx<'_>, fd: i32, cur: u64) -> SysResult {
    let file = timerfd(c, fd)?;
    let now = as_timer(&file).gettime(&clock_now);
    write_itimerspec(c, cur, now)?;
    Ok(0)
}

/// `signalfd4` (and `signalfd` with no flags): a new descriptor for the
/// signals in the mask at `mask`, or a new mask for descriptor `fd`.
pub fn signalfd4(c: &mut Ctx<'_>, fd: i32, mask: u64, size: u64, flags: u32) -> SysResult {
    if size != 8 {
        return Err(Errno(EINVAL));
    }
    let set = c.read_u64(mask)?;
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    // SIGKILL and SIGSTOP cannot be read.
    let set = set & !KERNEL_ONLY_MASK;
    if fd == -1 {
        let s = SignalFd::new(set)?;
        return install(c, anon_file(Anon::Signal(s), flags), flags & O_CLOEXEC != 0);
    }
    let file = c.p.fds.file(fd)?;
    let FileObject::Anon(Anon::Signal(s)) = &file.object else {
        return Err(Errno(EINVAL));
    };
    s.set_mask(set);
    // Readers and pollers look again with the new mask.
    let (_, mut th) = c.split();
    for t in th.iter_mut() {
        if let Some(b) = t.blocked.as_mut()
            && b.wait.signals != 0
        {
            b.woken = true;
        }
    }
    Ok(fd as u64)
}

/// `access_ok`: the range lies in user space.
fn access_ok(c: &Ctx<'_>, addr: u64, len: u64) -> bool {
    addr.checked_add(len)
        .is_some_and(|end| end <= c.p.abi.task_size())
}

/// Copies `data` to the destination vectors from byte `at` on
/// (`copy_to_iter`), stopping at the first fault; returns the bytes
/// copied.
fn copy_out(c: &Ctx<'_>, vecs: &[(u64, u64)], mut at: u64, data: &[u8]) -> u64 {
    let mut done = 0u64;
    for &(base, len) in vecs {
        if at >= len {
            at -= len;
            continue;
        }
        let room = len - at;
        let take = room.min(data.len() as u64 - done);
        let dst = base + at;
        at = 0;
        let chunk = &data[done as usize..(done + take) as usize];
        if c.write_mem(dst, chunk).is_ok() {
            done += take;
        } else {
            // The bytes before the fault still arrive.
            for (i, b) in chunk.iter().enumerate() {
                if c.write_mem(dst + i as u64, std::slice::from_ref(b))
                    .is_err()
                {
                    return done + i as u64;
                }
            }
            done += take;
        }
        if done == data.len() as u64 {
            break;
        }
    }
    done
}

/// Whether a descriptor's reads and writes do not block.
fn nonblocking(file: &OpenFile) -> bool {
    file.flags() & O_NONBLOCK != 0
}

/// Sleeps in a read or write that must wait, or ends it: `EAGAIN` without
/// blocking, `-ERESTARTSYS` with a signal pending.
fn wait_or(c: &mut Ctx<'_>, file: &OpenFile, wait: Wait) -> Errno {
    if nonblocking(file) {
        return Errno(EAGAIN);
    }
    if c.signal_pending() {
        return Errno(ERESTARTSYS);
    }
    c.block(wait, Resume::Retry)
}

/// The transfer vectors' total length.
fn total(vecs: &[(u64, u64)]) -> u64 {
    vecs.iter().map(|&(_, l)| l).sum()
}

/// `read`/`readv` of an anonymous-inode file into `vecs`.
pub fn read(c: &mut Ctx<'_>, file: &OpenFile, vecs: &[(u64, u64)]) -> SysResult {
    let FileObject::Anon(anon) = &file.object else {
        unreachable!("an anonymous-inode file");
    };
    let len = total(vecs);
    match anon {
        Anon::Event(ev) => {
            if len < 8 {
                return Err(Errno(EINVAL));
            }
            let Some(v) = ev.read() else {
                return Err(wait_or(c, file, Wait::fd(ev.readable_fd(), true, false)));
            };
            // Room for writers.
            file.woke(super::ready::ev::OUT | super::ready::ev::WRNORM);
            // The count is taken even if the copy then faults.
            if copy_out(c, vecs, 0, &v.to_le_bytes()) != 8 {
                return Err(Errno(EFAULT));
            }
            Ok(8)
        }
        Anon::Timer(t) => {
            if len < 8 {
                return Err(Errno(EINVAL));
            }
            let Some(ticks) = t.read(&clock_now) else {
                let wait = Wait::fds(vec![(t.readable_fd(), true, false)], t.deadline());
                return Err(wait_or(c, file, wait));
            };
            match copy_out(c, vecs, 0, &ticks.to_le_bytes()) {
                0 => Err(Errno(EFAULT)),
                n => Ok(n),
            }
        }
        Anon::Epoll(_) => Err(Errno(EINVAL)),
        Anon::Signal(s) => {
            let count = len / SIGNALFD_SIZE;
            if count == 0 {
                return Err(Errno(EINVAL));
            }
            let mask = s.mask();
            let mut done = 0u64;
            for _ in 0..count {
                let info = deliver::dequeue_signal(c.p, c.t, !mask);
                c.t.sigpending = deliver::recalc_sigpending(c.p, c.t);
                let Some(info) = info else {
                    if done > 0 {
                        break;
                    }
                    let mut wait = Wait::event();
                    wait.signals = mask;
                    return Err(wait_or(c, file, wait));
                };
                // copy_to_iter_full: the record arrives whole or not at
                // all (and is lost).
                let rec = signalfd_record(&info);
                let at = done;
                let fits = vecs_writable(c, vecs, at, SIGNALFD_SIZE);
                if !fits || copy_out(c, vecs, at, &rec) != SIGNALFD_SIZE {
                    return if done > 0 {
                        Ok(done)
                    } else {
                        Err(Errno(EFAULT))
                    };
                }
                done += SIGNALFD_SIZE;
            }
            Ok(done)
        }
    }
}

/// `read(2)` of an anonymous-inode file (`vfs_read`): the destination
/// range must lie in user space; the file operation sees even a zero
/// count.
pub fn read_call(c: &mut Ctx<'_>, file: &OpenFile, buf: u64, count: u64) -> SysResult {
    if !file.readable() {
        return Err(Errno(EBADF));
    }
    if !can_read(file) {
        return Err(Errno(EINVAL));
    }
    if !access_ok(c, buf, count) {
        return Err(Errno(EFAULT));
    }
    read(c, file, &[(buf, count.min(MAX_RW_COUNT))])
}

/// `write(2)` of an anonymous-inode file (`vfs_write`): only an `eventfd`
/// can be written (`FMODE_CAN_WRITE`), before the buffer is checked.
pub fn write_call(c: &mut Ctx<'_>, file: &OpenFile, buf: u64, count: u64) -> SysResult {
    if !file.writable() {
        return Err(Errno(EBADF));
    }
    if !can_write(file) {
        return Err(Errno(EINVAL));
    }
    if !access_ok(c, buf, count) {
        return Err(Errno(EFAULT));
    }
    write(c, file, &[(buf, count.min(MAX_RW_COUNT))])
}

/// Whether the file has a read operation (`FMODE_CAN_READ`).
pub fn can_read(file: &OpenFile) -> bool {
    !matches!(file.object, FileObject::Anon(Anon::Epoll(_)))
}

/// Whether the file has a write operation (`FMODE_CAN_WRITE`).
pub fn can_write(file: &OpenFile) -> bool {
    matches!(file.object, FileObject::Anon(Anon::Event(_)))
}

/// `MAX_RW_COUNT`.
const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// Whether `len` bytes from byte `at` of the vectors are writable.
fn vecs_writable(c: &Ctx<'_>, vecs: &[(u64, u64)], mut at: u64, mut len: u64) -> bool {
    use crate::error::MemoryAccessKind;
    for &(base, vlen) in vecs {
        if len == 0 {
            break;
        }
        if at >= vlen {
            at -= vlen;
            continue;
        }
        let take = (vlen - at).min(len);
        if c.p
            .space
            .probe(base + at, take as usize, MemoryAccessKind::Write)
            .is_err()
        {
            return false;
        }
        len -= take;
        at = 0;
    }
    len == 0
}

/// `signalfd_copyinfo`: the `struct signalfd_siginfo` of a dequeued
/// signal, with the fields of its `siginfo_t` layout and zeros elsewhere.
pub fn signalfd_record(info: &SigInfo) -> [u8; SIGNALFD_SIZE as usize] {
    let mut r = [0u8; SIGNALFD_SIZE as usize];
    let f = &info.fields;
    let put = |r: &mut [u8; 128], at: usize, b: &[u8]| r[at..at + b.len()].copy_from_slice(b);
    put(&mut r, 0, &info.signo.to_le_bytes());
    put(&mut r, 4, &info.errno.to_le_bytes());
    put(&mut r, 8, &info.code.to_le_bytes());
    // ssi_pid @12, ssi_uid @16, ssi_fd @20, ssi_tid @24, ssi_band @28,
    // ssi_overrun @32, ssi_status @40, ssi_int @44, ssi_ptr @48,
    // ssi_utime @56, ssi_stime @64, ssi_addr @72, ssi_addr_lsb @80,
    // ssi_syscall @84, ssi_call_addr @88, ssi_arch @96.
    match info.layout() {
        Layout::Kill => {
            put(&mut r, 12, &f[0..4]);
            put(&mut r, 16, &f[4..8]);
        }
        Layout::Timer => {
            put(&mut r, 24, &f[0..4]);
            put(&mut r, 32, &f[4..8]);
            put(&mut r, 48, &f[8..16]);
            put(&mut r, 44, &f[8..12]);
        }
        Layout::Poll => {
            // ssi_band is 32 bits wide; si_band a long.
            put(&mut r, 28, &f[0..4]);
            put(&mut r, 20, &f[8..12]);
        }
        Layout::Fault => put(&mut r, 72, &f[0..8]),
        Layout::FaultMceErr => {
            put(&mut r, 72, &f[0..8]);
            put(&mut r, 80, &f[8..10]);
        }
        Layout::Chld => {
            put(&mut r, 12, &f[0..4]);
            put(&mut r, 16, &f[4..8]);
            put(&mut r, 40, &f[8..12]);
            put(&mut r, 56, &f[16..24]);
            put(&mut r, 64, &f[24..32]);
        }
        Layout::Rt => {
            put(&mut r, 12, &f[0..4]);
            put(&mut r, 16, &f[4..8]);
            put(&mut r, 48, &f[8..16]);
            put(&mut r, 44, &f[8..12]);
        }
        Layout::Sys => {
            put(&mut r, 88, &f[0..8]);
            put(&mut r, 84, &f[8..12]);
            put(&mut r, 96, &f[12..16]);
        }
    }
    r
}

/// `write`/`writev` of an anonymous-inode file from `vecs`: an `eventfd`
/// takes each vector as one write (`do_loop_readv_writev`); the others
/// have no write operation (`EINVAL`).
pub fn write(c: &mut Ctx<'_>, file: &OpenFile, vecs: &[(u64, u64)]) -> SysResult {
    let FileObject::Anon(Anon::Event(ev)) = &file.object else {
        return Err(Errno(EINVAL));
    };
    let mut done = 0u64;
    let mut first = true;
    for &(base, len) in vecs {
        if len == 0 && !first {
            continue;
        }
        first = false;
        let r = eventfd_write(c, file, ev, base, len);
        match r {
            Ok(n) => done += n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `eventfd_write` of `len` bytes at `buf`.
fn eventfd_write(c: &mut Ctx<'_>, file: &OpenFile, ev: &EventFd, buf: u64, len: u64) -> SysResult {
    if len != 8 {
        return Err(Errno(EINVAL));
    }
    let v = c.read_u64(buf)?;
    if v == u64::MAX {
        return Err(Errno(EINVAL));
    }
    if ev.write(v) {
        file.woke(super::ready::ev::IN | super::ready::ev::RDNORM);
        return Ok(8);
    }
    Err(wait_or(c, file, Wait::fd(ev.writable_fd(), true, false)))
}

/// `poll` of an anonymous-inode file: its mask, its level (the counter,
/// pending ticks, or queued signals of its mask), and what a sleeper that
/// asks for `events` waits on.
pub fn poll(c: &Ctx<'_>, anon: &Anon, events: u32) -> (Polled, Wait) {
    use super::ready::ev::*;
    let want_r = events & (IN | RDNORM) != 0;
    let want_w = events & (OUT | WRNORM) != 0;
    let mut wait = Wait::event();
    let mut p = Polled::default();
    match anon {
        Anon::Epoll(ep) => return super::epoll::poll_instance(c, ep, events),
        Anon::Event(ev) => {
            let (r, w, err) = ev.poll();
            if r {
                p.mask |= IN | RDNORM;
            }
            if w {
                p.mask |= OUT | WRNORM;
            }
            if err {
                p.mask |= ERR;
            }
            p.level = ev.count();
            if want_r {
                wait.fds.push((ev.readable_fd(), true, false));
            }
            if want_w {
                wait.fds.push((ev.writable_fd(), true, false));
            }
        }
        Anon::Timer(t) => {
            p.level = t.pending_ticks(&clock_now);
            if p.level != 0 {
                p.mask |= IN | RDNORM;
            }
            if want_r {
                wait.fds.push((t.readable_fd(), true, false));
                wait.deadline = t.deadline();
            }
        }
        Anon::Signal(s) => {
            let mask = s.mask();
            p.level = (c.t.pending.queued_in(mask) + c.p.shared_pending.queued_in(mask)) as u64;
            if p.level != 0 {
                p.mask |= IN | RDNORM;
            }
            if want_r {
                wait.signals = mask;
            }
        }
    }
    (p, wait)
}

/// `TFD_IOC_SET_TICKS` on a `timerfd`.
pub fn set_ticks(c: &mut Ctx<'_>, file: &OpenFile, arg: u64) -> SysResult {
    let FileObject::Anon(Anon::Timer(t)) = &file.object else {
        return Err(Errno(ENOTTY));
    };
    let n = c.read_u64(arg)?;
    if n == 0 {
        return Err(Errno(EINVAL));
    }
    t.set_ticks(n, &clock_now);
    file.woke(super::ready::ev::IN | super::ready::ev::RDNORM);
    Ok(0)
}
