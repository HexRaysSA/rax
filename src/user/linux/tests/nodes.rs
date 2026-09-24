//! `mknodat` (`fs/namei.c` `do_mknodat`) and file times (`fs/utimes.c`),
//! driven through the system calls (Linux 6.19).

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AT_FDCWD: u64 = -100i64 as u64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// A fresh host directory for one test, removed when dropped.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rax-nodes-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        Dir(d)
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.0.display())
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes `s` (NUL-terminated) to the scratch page at `off`; its address.
fn put(h: &Harness, off: u64, s: &str) -> u64 {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    h.proc.state.space.write_raw(h.scratch + off, &b).unwrap();
    h.scratch + off
}

fn put_words(h: &Harness, off: u64, w: &[i64]) -> u64 {
    let b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
    h.proc.state.space.write_raw(h.scratch + off, &b).unwrap();
    h.scratch + off
}

fn mknod(h: &mut Harness, path: &str, mode: u64, dev: u64) -> i64 {
    let p = put(h, 0x100, path);
    h.call(Sysno::Mknodat, &[AT_FDCWD, p, mode, dev])
}

#[test]
fn mknodat_checks_the_type_then_the_name_then_the_privilege() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let d = Dir::new(&format!("mk-{abi:?}"));
        let err = |e: i32| -(e as i64);
        assert_eq!(
            mknod(&mut h, &d.path("x"), 0o40755, 0),
            err(EPERM),
            "{abi:?}"
        );
        assert_eq!(mknod(&mut h, &d.path("x"), 0o170644, 0), err(EINVAL));
        // A type-less mode is a regular file; the umask (022) applies.
        assert_eq!(mknod(&mut h, &d.path("r"), 0o666, 0), 0);
        let m = std::fs::metadata(d.path("r")).unwrap();
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        assert!(m.is_file() && m.permissions().mode() & 0o7777 == 0o644);
        assert_eq!(mknod(&mut h, &d.path("r"), 0o10644, 0), err(EEXIST));
        assert_eq!(mknod(&mut h, &(d.path("r") + "/"), 0o10644, 0), err(EEXIST));
        assert_eq!(mknod(&mut h, &(d.path("n") + "/"), 0o10644, 0), err(ENOENT));
        assert_eq!(mknod(&mut h, &d.path("none/x"), 0o10644, 0), err(ENOENT));
        assert_eq!(mknod(&mut h, &d.path("f"), 0o10640, 0), 0);
        let m = std::fs::symlink_metadata(d.path("f")).unwrap();
        assert!(m.file_type().is_fifo() && m.permissions().mode() & 0o7777 == 0o640);
        assert_eq!(mknod(&mut h, &d.path("s"), 0o140600, 0), 0);
        let m = std::fs::symlink_metadata(d.path("s")).unwrap();
        assert!(m.file_type().is_socket() && m.permissions().mode() & 0o7777 == 0o600);
        // A device node needs CAP_MKNOD.
        h.proc.state.creds.1 = 1000;
        assert_eq!(mknod(&mut h, &d.path("c"), 0o20600, 0x103), err(EPERM));
        assert_eq!(
            mknod(&mut h, &d.path("none/c"), 0o20600, 0x103),
            err(ENOENT)
        );
        if abi == LinuxAbi::X86_64 {
            let p = put(&h, 0x100, &d.path("f2"));
            assert_eq!(h.call(Sysno::Mknod, &[p, 0o10600, 0]), 0);
        }
    });
}

/// `(atime, mtime)` of a host path as `(sec, nsec)` pairs, not following
/// a final link.
fn times(path: &str) -> ((i64, i64), (i64, i64)) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).unwrap();
    ((m.atime(), m.atime_nsec()), (m.mtime(), m.mtime_nsec()))
}

#[test]
fn utimensat_looks_up_the_path_before_checking_the_times() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let d = Dir::new(&format!("ut-{abi:?}"));
        let f = d.path("t");
        std::fs::write(&f, b"").unwrap();
        let fp = put(&h, 0x100, &f);
        let ts = put_words(&h, 0x300, &[100, 5, 200, 6]);
        assert_eq!(
            h.call(Sysno::Utimensat, &[AT_FDCWD, fp, ts, 0]),
            0,
            "{abi:?}"
        );
        assert_eq!(times(&f), ((100, 5), (200, 6)));
        // Both omitted: nothing is done, not even the lookup.
        let none = put(&h, 0x200, &d.path("none"));
        let omit = put_words(&h, 0x300, &[0, UTIME_OMIT, 0, UTIME_OMIT]);
        assert_eq!(h.call(Sysno::Utimensat, &[AT_FDCWD, none, omit, 0]), 0);
        // The path, then the times.
        let bad = put_words(&h, 0x300, &[0, 1_000_000_000, 0, 0]);
        assert_eq!(h.err(Sysno::Utimensat, &[AT_FDCWD, none, bad, 0]), ENOENT);
        assert_eq!(h.err(Sysno::Utimensat, &[AT_FDCWD, fp, bad, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Utimensat, &[AT_FDCWD, 0, 0, 0]), EFAULT);
        assert_eq!(h.err(Sysno::Utimensat, &[AT_FDCWD, fp, 0, 2]), EINVAL);
        // A descriptor takes no flags.
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, fp, 0, 0]);
        assert_eq!(
            h.err(Sysno::Utimensat, &[fd, 0, 0, AT_SYMLINK_NOFOLLOW]),
            EINVAL
        );
        let ts = put_words(&h, 0x300, &[7, 0, 0, UTIME_OMIT]);
        assert_eq!(h.call(Sysno::Utimensat, &[fd, 0, ts, 0]), 0);
        assert_eq!(times(&f), ((7, 0), (200, 6)), "mtime omitted");
        // An eventfd's inode refuses it.
        let ev = h.ok(Sysno::Eventfd2, &[0, 0]);
        assert_eq!(h.err(Sysno::Utimensat, &[ev, 0, 0, 0]), EOPNOTSUPP);
        // A link itself.
        let l = d.path("l");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        let lp = put(&h, 0x200, &l);
        let ts = put_words(&h, 0x300, &[50, 0, 60, 0]);
        assert_eq!(
            h.call(Sysno::Utimensat, &[AT_FDCWD, lp, ts, AT_SYMLINK_NOFOLLOW]),
            0
        );
        assert_eq!(times(&l), ((50, 0), (60, 0)));
        assert_eq!(times(&f), ((7, 0), (200, 6)));
    });
}

#[test]
fn the_older_time_calls_convert_to_utimensat() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let d = Dir::new("old");
    let f = d.path("t");
    std::fs::write(&f, b"").unwrap();
    let fp = put(&h, 0x100, &f);
    // utimes: microseconds within [0, 1000000).
    let tv = put_words(&h, 0x300, &[100, 5, 200, 1_000_000]);
    assert_eq!(h.err(Sysno::Utimes, &[fp, tv]), EINVAL);
    let tv = put_words(&h, 0x300, &[100, 5, 200, -1]);
    assert_eq!(h.err(Sysno::Utimes, &[fp, tv]), EINVAL);
    let tv = put_words(&h, 0x300, &[100, 5, 200, 7]);
    assert_eq!(h.call(Sysno::Utimes, &[fp, tv]), 0);
    assert_eq!(times(&f), ((100, 5000), (200, 7000)));
    // futimesat: relative to a directory, or on a descriptor.
    let dp = put(&h, 0x200, &d.0.display().to_string());
    let dir = h.ok(Sysno::Openat, &[AT_FDCWD, dp, 0o200000, 0]);
    let name = put(&h, 0x200, "t");
    let tv = put_words(&h, 0x300, &[11, 0, 12, 0]);
    assert_eq!(h.call(Sysno::Futimesat, &[dir, name, tv]), 0);
    assert_eq!(times(&f), ((11, 0), (12, 0)));
    let fd = h.ok(Sysno::Openat, &[AT_FDCWD, fp, 0, 0]);
    let tv = put_words(&h, 0x300, &[13, 0, 14, 0]);
    assert_eq!(h.call(Sysno::Futimesat, &[fd, 0, tv]), 0);
    assert_eq!(times(&f), ((13, 0), (14, 0)));
    // utime: whole seconds.
    let ub = put_words(&h, 0x300, &[300, 400]);
    assert_eq!(h.call(Sysno::Utime, &[fp, ub]), 0);
    assert_eq!(times(&f), ((300, 0), (400, 0)));
    assert_eq!(h.err(Sysno::Utime, &[fp, 8]), EFAULT);
    let none = put(&h, 0x200, &d.path("none"));
    assert_eq!(h.err(Sysno::Utime, &[none, ub]), ENOENT);
}
