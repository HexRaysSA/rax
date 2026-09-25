//! inotify against `fs/notify/` (Linux 6.19), through the system calls on
//! every ABI: `inotify_init1`, `inotify_add_watch`, and `inotify_rm_watch`
//! (their checks in order, descriptors, masks), the events the file calls
//! report and their order (a directory before the file itself, names only
//! for entry changes, cookies, `IN_ISDIR`), the queue (merging, overflow,
//! `read`'s records and `EINVAL`, `FIONREAD`), waiting readers, one-shot
//! and `IN_EXCL_UNLINK` watches, closes at the last reference (a
//! duplicate, a mapping), `fdinfo`, and the instance limit.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::fsnotify::Backend;
use crate::user::linux::fsnotify::bits::*;
use crate::user::linux::signal::deliver::restart::ERESTARTSYS;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;

const AT_FDCWD: u64 = -100i64 as u64;
const AT_REMOVEDIR: u64 = 0x200;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const FIONREAD: u64 = 0x541B;
const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

/// A host directory for one test, removed when dropped.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rax-inotify-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        Dir(p)
    }

    fn at(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Guest memory for paths and buffers.
struct Mem {
    base: u64,
}

impl Mem {
    fn new(h: &mut Harness) -> Self {
        Mem {
            base: h.anon(64 * P, 3, false),
        }
    }

    /// A NUL-terminated string at slot `i` (256 bytes each, first page).
    fn s(&self, h: &Harness, i: u64, s: &str) -> u64 {
        let at = self.base + i * 256;
        h.proc
            .state
            .space
            .write_raw(at, &[s.as_bytes(), b"\0"].concat())
            .unwrap();
        at
    }

    /// The buffer (from the second page).
    fn buf(&self) -> u64 {
        self.base + P
    }
}

/// A read event.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ev {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

fn ev(wd: i32, mask: u32, name: &str) -> Ev {
    Ev {
        wd,
        mask,
        cookie: 0,
        name: name.into(),
    }
}

fn parse(b: &[u8]) -> Vec<Ev> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 16 <= b.len() {
        let w = |o: usize| u32::from_le_bytes(b[i + o..i + o + 4].try_into().unwrap());
        let len = w(12) as usize;
        let name = &b[i + 16..i + 16 + len];
        let name = name.split(|&c| c == 0).next().unwrap_or(&[]);
        out.push(Ev {
            wd: w(0) as i32,
            mask: w(4),
            cookie: w(8),
            name: String::from_utf8_lossy(name).into_owned(),
        });
        i += 16 + len;
    }
    out
}

/// Every queued event of non-blocking instance `fd`.
fn drain(h: &mut Harness, m: &Mem, fd: u64) -> Vec<Ev> {
    let r = h.call(Sysno::Read, &[fd, m.buf(), 60 * P]);
    if r == -(EAGAIN as i64) {
        return Vec::new();
    }
    assert!(r >= 0, "read: {r}");
    let mut b = vec![0u8; r as usize];
    h.proc.state.space.read(m.buf(), &mut b).unwrap();
    parse(&b)
}

/// Events without their cookies.
fn plain(v: Vec<Ev>) -> Vec<Ev> {
    v.into_iter().map(|e| Ev { cookie: 0, ..e }).collect()
}

fn open(h: &mut Harness, m: &Mem, path: &str, flags: u64) -> u64 {
    let p = m.s(h, 0, path);
    h.ok(Sysno::Openat, &[AT_FDCWD, p, flags, 0o644])
}

fn watch(h: &mut Harness, m: &Mem, fd: u64, path: &str, mask: u32) -> i64 {
    let p = m.s(h, 1, path);
    h.call(Sysno::InotifyAddWatch, &[fd, p, u64::from(mask)])
}

/// Runs `f` on every ABI with each backend this host has: the emulated
/// one, and on Linux hosts the host's inotify, whose kernel then checks
/// the expectations themselves.
fn each(f: impl Fn(Harness, bool)) {
    each_abi(|abi| {
        f(Harness::new(abi), false);
        if cfg!(target_os = "linux") {
            f(Harness::with_fsnotify(abi, Some(Backend::Host)), true);
        }
    });
}

#[test]
fn watches_follow_inotify_add_watch() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("watch");
        std::fs::write(d.at("f"), b"").unwrap();
        assert_eq!(h.err(Sysno::InotifyInit1, &[1]), EINVAL);
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK | O_CLOEXEC]);
        // The mask, the descriptor, the flag pair, the kind of file, then
        // the path.
        assert_eq!(watch(&mut h, &m, fd, &d.at(""), 0), -(EINVAL as i64));
        assert_eq!(
            watch(&mut h, &m, fd, &d.at(""), FS_EVENT_ON_CHILD),
            -(EINVAL as i64)
        );
        assert_eq!(
            watch(&mut h, &m, 99, "/nonexistent", IN_OPEN),
            -(EBADF as i64)
        );
        assert_eq!(
            watch(
                &mut h,
                &m,
                fd,
                "/nonexistent",
                IN_OPEN | IN_MASK_ADD | IN_MASK_CREATE
            ),
            -(EINVAL as i64)
        );
        let other = open(&mut h, &m, &d.at("f"), 0);
        assert_eq!(
            watch(&mut h, &m, other, "/nonexistent", IN_OPEN),
            -(EINVAL as i64)
        );
        assert_eq!(
            watch(&mut h, &m, fd, &d.at("none"), IN_OPEN),
            -(ENOENT as i64)
        );
        assert_eq!(
            watch(&mut h, &m, fd, &d.at("f"), IN_OPEN | IN_ONLYDIR),
            -(ENOTDIR as i64)
        );
        // A descriptor per inode, from 1, never reused.
        assert_eq!(watch(&mut h, &m, fd, &d.at(""), IN_ALL_EVENTS), 1);
        assert_eq!(watch(&mut h, &m, fd, &d.at(""), IN_ATTRIB), 1);
        assert_eq!(
            watch(&mut h, &m, fd, &d.at(""), IN_ATTRIB | IN_MASK_CREATE),
            -(EEXIST as i64)
        );
        assert_eq!(watch(&mut h, &m, fd, &d.at("f"), IN_ISDIR), 2);
        assert_eq!(h.call(Sysno::InotifyRmWatch, &[fd, 2]), 0);
        assert_eq!(h.err(Sysno::InotifyRmWatch, &[fd, 2]), EINVAL);
        assert_eq!(h.err(Sysno::InotifyRmWatch, &[other, 1]), EINVAL);
        assert_eq!(watch(&mut h, &m, fd, &d.at("f"), IN_OPEN), 3);
        assert_eq!(drain(&mut h, &m, fd), [ev(2, IN_IGNORED, "")]);
        // The directory watch now wants only attribute changes.
        assert_eq!(open(&mut h, &m, &d.at("f"), 0), other + 1);
        assert_eq!(drain(&mut h, &m, fd), [ev(3, IN_OPEN, "")]);
        // fdinfo: the newest watch first.
        let path = format!("/proc/self/fdinfo/{fd}");
        let info = open(&mut h, &m, &path, 0);
        let n = h.ok(Sysno::Read, &[info, m.buf(), P]) as usize;
        let mut b = vec![0u8; n];
        h.proc.state.space.read(m.buf(), &mut b).unwrap();
        let text = String::from_utf8(b).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("inotify ")).collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("inotify wd:3 ino:"), "{text}");
        assert!(lines[0].contains(" mask:20 ignored_mask:0"), "{text}");
        assert!(lines[1].starts_with("inotify wd:1 ino:"), "{text}");
        assert!(lines[1].contains(" mask:4 ignored_mask:0"), "{text}");
    });
}

#[test]
fn file_calls_report_events_in_order() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("calls");
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        assert_eq!(watch(&mut h, &m, fd, &d.at(""), IN_ALL_EVENTS), 1);
        // Creation, then the open; writes merge; the close.
        let f = open(&mut h, &m, &d.at("f"), O_CREAT | O_WRONLY);
        h.ok(Sysno::Write, &[f, m.buf(), 3]);
        h.ok(Sysno::Write, &[f, m.buf(), 3]);
        h.ok(Sysno::Close, &[f]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_CREATE, "f"),
                ev(1, IN_OPEN, "f"),
                ev(1, IN_MODIFY, "f"),
                ev(1, IN_CLOSE_WRITE, "f")
            ]
        );
        // A read of nothing is no access; a vectored one is.
        let f = open(&mut h, &m, &d.at("f"), 0);
        assert_eq!(h.ok(Sysno::Read, &[f, m.buf(), 64]), 6);
        assert_eq!(h.ok(Sysno::Read, &[f, m.buf(), 64]), 0);
        let fchmod = h.abi().number(Sysno::Fchmod).is_some();
        if fchmod {
            h.ok(Sysno::Fchmod, &[f, 0o600]);
        }
        let iov = m.buf() + 0x800;
        let v: Vec<u8> = [m.buf(), 64].iter().flat_map(|x| x.to_le_bytes()).collect();
        h.proc.state.space.write_raw(iov, &v).unwrap();
        assert_eq!(h.ok(Sysno::Readv, &[f, iov, 1]), 0);
        h.ok(Sysno::Close, &[f]);
        let mut want = vec![ev(1, IN_OPEN, "f"), ev(1, IN_ACCESS, "f")];
        if fchmod {
            want.push(ev(1, IN_ATTRIB, "f"));
            want.push(ev(1, IN_ACCESS, "f"));
        }
        want.push(ev(1, IN_CLOSE_NOWRITE, "f"));
        assert_eq!(drain(&mut h, &m, fd), want);
        // O_TRUNC of an existing file: the open, then the truncation.
        let f = open(&mut h, &m, &d.at("f"), O_WRONLY | O_TRUNC);
        h.ok(Sysno::Close, &[f]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_OPEN, "f"),
                ev(1, IN_MODIFY, "f"),
                ev(1, IN_CLOSE_WRITE, "f")
            ]
        );
        // Directories: IN_ISDIR, a listing an access.
        let s = m.s(&h, 5, &d.at("s"));
        h.ok(Sysno::Mkdirat, &[AT_FDCWD, s, 0o755]);
        let dirflag = u64::from(h.abi().open_flags().directory);
        let sd = open(&mut h, &m, &d.at("s"), dirflag);
        h.ok(Sysno::Getdents64, &[sd, m.buf(), 4096]);
        h.ok(Sysno::Close, &[sd]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_CREATE | IN_ISDIR, "s"),
                ev(1, IN_OPEN | IN_ISDIR, "s"),
                ev(1, IN_ACCESS | IN_ISDIR, "s"),
                ev(1, IN_CLOSE_NOWRITE | IN_ISDIR, "s")
            ]
        );
        // A rename: two events with one cookie.
        let (from, to) = (m.s(&h, 2, &d.at("f")), m.s(&h, 3, &d.at("g")));
        h.ok(Sysno::Renameat2, &[AT_FDCWD, from, AT_FDCWD, to, 0]);
        let moved = drain(&mut h, &m, fd);
        assert_eq!(
            plain(moved.clone()),
            [ev(1, IN_MOVED_FROM, "f"), ev(1, IN_MOVED_TO, "g")]
        );
        assert!(moved[0].cookie != 0 && moved[0].cookie == moved[1].cookie);
        // Links, attributes, times, removal.
        let (g, l) = (m.s(&h, 2, &d.at("g")), m.s(&h, 3, &d.at("l")));
        h.ok(Sysno::Linkat, &[AT_FDCWD, g, AT_FDCWD, l, 0]);
        h.ok(Sysno::Fchmodat, &[AT_FDCWD, g, 0o640, 0]);
        let times = m.buf() + 0x900;
        let omit = 0x3FFF_FFFEu64;
        let t: Vec<u8> = [0u64, omit, 0, 5]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        h.proc.state.space.write_raw(times, &t).unwrap();
        h.ok(Sysno::Utimensat, &[AT_FDCWD, g, times, 0]);
        h.ok(Sysno::Utimensat, &[AT_FDCWD, g, 0, 0]);
        h.ok(Sysno::Unlinkat, &[AT_FDCWD, l, 0]);
        h.ok(Sysno::Unlinkat, &[AT_FDCWD, s, AT_REMOVEDIR]);
        let dot = m.s(&h, 4, &d.at(""));
        h.ok(Sysno::Fchmodat, &[AT_FDCWD, dot, 0o700, 0]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_CREATE, "l"),
                ev(1, IN_ATTRIB, "g"),
                ev(1, IN_MODIFY, "g"),
                ev(1, IN_ATTRIB, "g"),
                ev(1, IN_DELETE, "l"),
                ev(1, IN_DELETE | IN_ISDIR, "s"),
                ev(1, IN_ATTRIB | IN_ISDIR, "")
            ]
        );
    });
}

#[test]
fn a_file_hears_of_itself_after_its_directory() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("self");
        std::fs::write(d.at("f"), b"").unwrap();
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        watch(&mut h, &m, fd, &d.at(""), IN_ALL_EVENTS);
        watch(&mut h, &m, fd, &d.at("f"), IN_ALL_EVENTS);
        let f = open(&mut h, &m, &d.at("f"), O_RDWR);
        h.ok(Sysno::Write, &[f, m.buf(), 1]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_OPEN, "f"),
                ev(2, IN_OPEN, ""),
                ev(1, IN_MODIFY, "f"),
                ev(2, IN_MODIFY, "")
            ]
        );
        // Removed while open: the inode goes at the last close.
        let p = m.s(&h, 2, &d.at("f"));
        h.ok(Sysno::Unlinkat, &[AT_FDCWD, p, 0]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [ev(2, IN_ATTRIB, ""), ev(1, IN_DELETE, "f")]
        );
        h.ok(Sysno::Close, &[f]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [
                ev(1, IN_CLOSE_WRITE, "f"),
                ev(2, IN_CLOSE_WRITE, ""),
                ev(2, IN_DELETE_SELF, ""),
                ev(2, IN_IGNORED, "")
            ]
        );
        // Removed while closed: at once, before the directory hears.
        let g = open(&mut h, &m, &d.at("g"), O_CREAT | O_WRONLY);
        h.ok(Sysno::Close, &[g]);
        drain(&mut h, &m, fd);
        assert_eq!(watch(&mut h, &m, fd, &d.at("g"), IN_ALL_EVENTS), 3);
        let (g, k) = (m.s(&h, 2, &d.at("g")), m.s(&h, 3, &d.at("k")));
        h.ok(Sysno::Renameat2, &[AT_FDCWD, g, AT_FDCWD, k, 0]);
        h.ok(Sysno::Unlinkat, &[AT_FDCWD, k, 0]);
        assert_eq!(
            plain(drain(&mut h, &m, fd)),
            [
                ev(1, IN_MOVED_FROM, "g"),
                ev(1, IN_MOVED_TO, "k"),
                ev(3, IN_MOVE_SELF, ""),
                ev(3, IN_ATTRIB, ""),
                ev(3, IN_DELETE_SELF, ""),
                ev(3, IN_IGNORED, ""),
                ev(1, IN_DELETE, "k")
            ]
        );
    });
}

#[test]
fn queues_merge_overflow_and_read_whole_records() {
    each(|mut h, host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("queue");
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        assert_eq!(h.err(Sysno::Read, &[fd, m.buf(), 64]), EAGAIN);
        watch(&mut h, &m, fd, &d.at(""), IN_ALL_EVENTS);
        let f = open(&mut h, &m, &d.at("name"), O_CREAT | O_RDWR);
        // FIONREAD: 32 bytes a named event; a read too small for the first
        // is EINVAL; one that fits some returns those.
        h.ok(Sysno::Ioctl, &[fd, FIONREAD, m.buf()]);
        let mut n = [0u8; 4];
        h.proc.state.space.read(m.buf(), &mut n).unwrap();
        assert_eq!(u32::from_le_bytes(n), 64);
        assert_eq!(h.err(Sysno::Read, &[fd, m.buf(), 31]), EINVAL);
        assert_eq!(h.ok(Sysno::Read, &[fd, m.buf(), 40]), 32);
        assert_eq!(drain(&mut h, &m, fd), [ev(1, IN_OPEN, "name")]);
        // An overflow: 16384 events, then IN_Q_OVERFLOW once (a host
        // kernel's max_queued_events is its own).
        if host {
            return;
        }
        assert_eq!(h.call(Sysno::InotifyRmWatch, &[fd, 1]), 0);
        drain(&mut h, &m, fd);
        watch(&mut h, &m, fd, &d.at("name"), IN_MODIFY | IN_ACCESS);
        for i in 0..8200u64 {
            h.ok(Sysno::Pwrite64, &[f, m.buf(), 1, i]);
            h.ok(Sysno::Pread64, &[f, m.buf(), 1, 0]);
        }
        h.ok(Sysno::Ioctl, &[fd, FIONREAD, m.buf()]);
        h.proc.state.space.read(m.buf(), &mut n).unwrap();
        assert_eq!(u32::from_le_bytes(n), 16385 * 16);
        let mut all = Vec::new();
        loop {
            let e = drain(&mut h, &m, fd);
            if e.is_empty() {
                break;
            }
            all.extend(e);
        }
        assert_eq!(all.len(), 16385);
        assert_eq!(all[16383], ev(2, IN_ACCESS, ""));
        assert_eq!(all[16384], ev(-1, IN_Q_OVERFLOW, ""));
    });
}

#[test]
fn readers_wait_for_events() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("wait");
        std::fs::write(d.at("f"), b"x").unwrap();
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        let fd = h.ok(Sysno::InotifyInit1, &[0]);
        watch(&mut h, &m, fd, &d.at("f"), IN_ACCESS);
        let f = open(&mut h, &m, &d.at("f"), 0);
        let buf = m.buf() + 0x1000;
        assert_eq!(h.start(w, Sysno::Read, &[fd, buf, 256]), None);
        h.ok(Sysno::Read, &[f, m.buf(), 1]);
        std::thread::sleep(std::time::Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 16);
        // A signal with a handler ends a wait with -ERESTARTSYS.
        assert_eq!(h.start(w, Sysno::Read, &[fd, buf, 256]), None);
        let act = m.buf() + 0x2000;
        let mut words = vec![0x40_1000u64];
        if h.abi().has_sa_restorer() {
            words.extend([sa::RESTORER, 0x40_1100]);
        } else {
            words.push(0);
        }
        words.push(0);
        let b: Vec<u8> = words.iter().flat_map(|x| x.to_le_bytes()).collect();
        h.proc.state.space.write_raw(act, &b).unwrap();
        h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]);
        let pid = h.proc.state.pid as u64;
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), -(ERESTARTSYS as i64));
    });
}

#[test]
fn one_shot_and_excl_unlink_watches() {
    each(|mut h, _host| {
        let abi = h.abi();
        let m = Mem::new(&mut h);
        let d = Dir::new("flags");
        std::fs::write(d.at("f"), b"").unwrap();
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        watch(&mut h, &m, fd, &d.at("f"), IN_OPEN | IN_ONESHOT);
        let a = open(&mut h, &m, &d.at("f"), 0);
        let b = open(&mut h, &m, &d.at("f"), 0);
        h.ok(Sysno::Close, &[a]);
        h.ok(Sysno::Close, &[b]);
        assert_eq!(
            drain(&mut h, &m, fd),
            [ev(1, IN_OPEN, ""), ev(1, IN_IGNORED, "")]
        );
        // A file whose name is gone: IN_EXCL_UNLINK hears no more of it.
        for (excl, want_modify) in [(IN_EXCL_UNLINK, false), (0, true)] {
            let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
            watch(&mut h, &m, fd, &d.at(""), IN_MODIFY | IN_DELETE | excl);
            let t = open(&mut h, &m, &d.at("t"), O_CREAT | O_RDWR);
            let p = m.s(&h, 2, &d.at("t"));
            h.ok(Sysno::Unlinkat, &[AT_FDCWD, p, 0]);
            h.ok(Sysno::Write, &[t, m.buf(), 1]);
            h.ok(Sysno::Close, &[t]);
            let mut want = vec![ev(1, IN_DELETE, "t")];
            if want_modify {
                want.push(ev(1, IN_MODIFY, "t"));
            }
            assert_eq!(drain(&mut h, &m, fd), want, "{abi:?} excl {excl:x}");
        }
    });
}

#[test]
fn closes_come_with_the_last_reference() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("close");
        std::fs::write(d.at("f"), vec![7u8; 8192]).unwrap();
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        watch(&mut h, &m, fd, &d.at("f"), IN_CLOSE);
        // A duplicate holds the description.
        let a = open(&mut h, &m, &d.at("f"), 0);
        let b = h.ok(Sysno::Dup, &[a]);
        h.ok(Sysno::Close, &[a]);
        assert!(drain(&mut h, &m, fd).is_empty());
        h.ok(Sysno::Close, &[b]);
        assert_eq!(drain(&mut h, &m, fd), [ev(1, IN_CLOSE_NOWRITE, "")]);
        // So does a mapping (vm_file).
        let a = open(&mut h, &m, &d.at("f"), 0);
        let map = h.ok(Sysno::Mmap, &[0, P, 1, 2, a, 0]);
        h.ok(Sysno::Close, &[a]);
        assert!(drain(&mut h, &m, fd).is_empty());
        h.ok(Sysno::Munmap, &[map, P]);
        assert_eq!(drain(&mut h, &m, fd), [ev(1, IN_CLOSE_NOWRITE, "")]);
    });
}

#[test]
fn instances_are_limited_per_user() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    // The limits of a fresh kernel, as /proc/sys shows them.
    let m = Mem::new(&mut h);
    for (name, want) in [
        ("max_user_instances", "128\n"),
        ("max_user_watches", "1048576\n"),
        ("max_queued_events", "16384\n"),
    ] {
        let f = open(&mut h, &m, &format!("/proc/sys/fs/inotify/{name}"), 0);
        let n = h.ok(Sysno::Read, &[f, m.buf(), 64]) as usize;
        let mut b = vec![0u8; n];
        h.proc.state.space.read(m.buf(), &mut b).unwrap();
        assert_eq!(b, want.as_bytes(), "{name}");
        h.ok(Sysno::Close, &[f]);
    }
    for _ in 0..128 {
        h.ok(Sysno::InotifyInit1, &[O_CLOEXEC]);
    }
    assert_eq!(h.err(Sysno::InotifyInit1, &[0]), EMFILE);
    h.ok(Sysno::Close, &[3]);
    h.ok(Sysno::InotifyInit1, &[0]);
}

#[test]
fn polls_see_queued_events() {
    each(|mut h, _host| {
        let m = Mem::new(&mut h);
        let d = Dir::new("poll");
        let fd = h.ok(Sysno::InotifyInit1, &[O_NONBLOCK]);
        watch(&mut h, &m, fd, &d.at(""), IN_CREATE);
        let pfd = m.buf();
        let rec: Vec<u8> = [(fd as u32).to_le_bytes(), 0x1u32.to_le_bytes()].concat();
        h.proc.state.space.write_raw(pfd, &rec).unwrap();
        let ts = m.buf() + 64;
        h.proc.state.space.write_raw(ts, &[0u8; 16]).unwrap();
        assert_eq!(h.call(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]), 0);
        open(&mut h, &m, &d.at("n"), O_CREAT | O_WRONLY);
        assert_eq!(h.call(Sysno::Ppoll, &[pfd, 1, ts, 0, 8]), 1);
        // POLLIN | POLLRDNORM, of which the caller asked for POLLIN.
        let mut re = [0u8; 2];
        h.proc.state.space.read(pfd + 6, &mut re).unwrap();
        assert_eq!(u16::from_le_bytes(re), 0x1);
    });
}
