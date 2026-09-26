//! A compatibility task's file calls against Linux 6.19: `compat_sys_open`
//! without forced `O_LARGEFILE` and `generic_file_open`'s `EOVERFLOW`
//! (`fs/open.c`), 64-bit offsets in register pairs
//! (`arch/x86/kernel/sys_ia32.c`, `fs/read_write.c`), `compat_off_t`
//! offsets, `_llseek`, `do_sys_ftruncate`'s `small` rule, `struct stat64`
//! (`cp_stat64`), `struct compat_stat`, `struct __old_kernel_stat`,
//! `struct compat_statfs{,64}` (`fs/statfs.c`), `struct
//! compat_linux_dirent` and `compat_old_linux_dirent` (`fs/readdir.c`),
//! `struct compat_flock{,64}` (`fs/fcntl.c`), `compat_sys_sendfile`, and
//! `execve`'s `compat_uptr_t` vectors (`fs/exec.c`).
//!
//! Arguments are what a 32-bit register holds: a negative number is its
//! two's complement in 32 bits.

use std::os::unix::fs::MetadataExt;

use super::super::harness::Harness;
use super::{cstr, put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::syscall::Outcome;

const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_TRUNC: u64 = 0o1000;
const O_LARGEFILE: u64 = 0o100000;
const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const F_GETFL: u64 = 3;
const GIB: u64 = 1 << 30;

/// A 32-bit register holding `v`.
fn reg(v: i32) -> u64 {
    u64::from(v as u32)
}

const AT_FDCWD: i32 = -100;

/// A temporary host directory, removed on drop.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("rax-i386-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        Dir(p)
    }

    /// A file of `len` bytes of `b'x'`, or sparse past 1 MiB.
    fn file(&self, name: &str, len: u64) -> String {
        let p = self.0.join(name);
        let f = std::fs::File::create(&p).unwrap();
        if len <= 1 << 20 {
            std::fs::write(&p, vec![b'x'; len as usize]).unwrap();
        } else {
            f.set_len(len).unwrap();
        }
        p.to_str().unwrap().to_owned()
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn put_str(h: &Harness, at: u64, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    put(h, at, &b);
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from(u32_at(h, at)) | u64::from(u32_at(h, at + 4)) << 32
}

fn u16_at(h: &Harness, at: u64) -> u16 {
    u32_at(h, at) as u16
}

/// `pages` fresh pages (`mmap2`).
fn pages(h: &mut Harness, pages: u64) -> u64 {
    h.ok(Sysno::Mmap2, &[0, pages * 4096, 3, 0x22, reg(-1), 0])
}

fn open(h: &mut Harness, at: u64, path: &str, flags: u64) -> i64 {
    put_str(h, at, path);
    h.call(Sysno::Open, &[at, flags, 0o644])
}

#[test]
fn a_compat_open_forces_no_o_largefile_and_refuses_large_files_without_it() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let d = Dir::new("open");
    let small = d.file("small", 10);
    let getfl = |h: &mut Harness, fd: i64| h.ok(Sysno::Fcntl64, &[fd as u64, F_GETFL, 0]);
    // compat_sys_open and compat_sys_openat keep the flags as passed.
    let fd = open(&mut h, m, &small, O_RDWR);
    assert_eq!(getfl(&mut h, fd), O_RDWR);
    let fd = open(&mut h, m, &small, O_RDWR | O_LARGEFILE);
    assert_eq!(getfl(&mut h, fd), O_RDWR | O_LARGEFILE);
    put_str(&h, m, &small);
    let fd = h.ok(Sysno::Openat, &[reg(AT_FDCWD), m, 0, 0]);
    assert_eq!(getfl(&mut h, fd as i64), 0);
    // sys_creat and sys_openat2 are native and force it.
    let fd = h.ok(Sysno::Creat, &[m, 0o644]);
    assert_eq!(getfl(&mut h, fd as i64), O_WRONLY | O_LARGEFILE);
    let how = m + 0x800;
    put(&h, how, &[0u8; 24]);
    let fd = h.ok(Sysno::Openat2, &[reg(AT_FDCWD), m, how, 24]);
    assert_eq!(getfl(&mut h, fd as i64), O_LARGEFILE);
    // generic_file_open: past MAX_NON_LFS, only with O_LARGEFILE; the
    // refused open truncates nothing.
    let big = d.file("big", 3 * GIB);
    assert_eq!(
        open(&mut h, m, &big, O_RDWR | O_TRUNC),
        -i64::from(EOVERFLOW)
    );
    assert_eq!(std::fs::metadata(&big).unwrap().len(), 3 * GIB);
    assert!(open(&mut h, m, &big, O_LARGEFILE) >= 0);
    assert!(open(&mut h, m, &big, O_PATH) >= 0, "O_PATH opens no file");
    // A small file is truncated after the check, O_RDONLY as well.
    assert!(open(&mut h, m, &small, O_TRUNC) >= 0);
    assert_eq!(std::fs::metadata(&small).unwrap().len(), 0);
}

#[test]
fn stat64_and_compat_stat_fill_the_i386_structures() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (path, buf) = (m, m + 0x400);
    let d = Dir::new("stat");
    let file = d.file("f", 5000);
    let link = d.path("l");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let meta = std::fs::metadata(&file).unwrap();
    let check64 = |h: &Harness, what: &str| {
        assert_eq!(u64_at(h, buf + 88), meta.ino(), "{what}: st_ino");
        assert_eq!(u32_at(h, buf + 12), meta.ino() as u32, "{what}: __st_ino");
        assert_eq!(u32_at(h, buf + 16), 0o100000 | (meta.mode() & 0o7777));
        assert_eq!(u64_at(h, buf + 44), 5000, "{what}: st_size");
        assert_eq!(
            u64_at(h, buf + 56),
            meta.blocks() as u64,
            "{what}: st_blocks"
        );
        assert_eq!(u32_at(h, buf + 72), meta.mtime() as u32, "{what}: st_mtime");
        // cp_stat64 leaves the pads alone.
        assert_eq!(u32_at(h, buf + 8), 0xAAAA_AAAA, "{what}: __pad0");
        assert_eq!(u32_at(h, buf + 40), 0xAAAA_AAAA, "{what}: __pad3");
    };
    put_str(&h, path, &file);
    put(&h, buf, &[0xAA; 96]);
    assert_eq!(h.call(Sysno::Stat64, &[path, buf]), 0);
    check64(&h, "stat64");
    put(&h, buf, &[0xAA; 96]);
    let fd = h.ok(Sysno::Open, &[path, 0, 0]);
    assert_eq!(h.call(Sysno::Fstat64, &[fd, buf]), 0);
    check64(&h, "fstat64");
    put(&h, buf, &[0xAA; 96]);
    assert_eq!(h.call(Sysno::Fstatat64, &[reg(AT_FDCWD), path, buf, 0]), 0);
    check64(&h, "fstatat64");
    // Not following the link: S_IFLNK.
    put_str(&h, path, &link);
    assert_eq!(h.call(Sysno::Lstat64, &[path, buf]), 0);
    assert_eq!(u32_at(&h, buf + 16) & 0o170000, 0o120000);
    assert_eq!(
        h.call(Sysno::Fstatat64, &[reg(AT_FDCWD), path, buf, 0x100]),
        0
    );
    assert_eq!(u32_at(&h, buf + 16) & 0o170000, 0o120000);
    assert_eq!(
        h.call(Sysno::Fstatat64, &[reg(AT_FDCWD), path, buf, 1]),
        -i64::from(EINVAL)
    );
    // struct compat_stat through the link: 32-bit fields, 16-bit IDs.
    assert_eq!(h.call(Sysno::Stat, &[path, buf]), 0);
    assert_eq!(u32_at(&h, buf + 4), meta.ino() as u32);
    assert_eq!(
        u16_at(&h, buf + 8),
        0o100000 | (meta.mode() & 0o7777) as u16
    );
    assert_eq!(u32_at(&h, buf + 20), 5000);
    assert_eq!(h.call(Sysno::Lstat, &[path, buf]), 0);
    assert_eq!(u16_at(&h, buf + 8) & 0o170000, 0o120000);
    assert_eq!(h.call(Sysno::Fstat, &[fd, buf]), 0);
    assert_eq!(u32_at(&h, buf + 20), 5000);
    // A size past MAX_NON_LFS: EOVERFLOW for compat_stat, not for stat64.
    let big = d.file("big", 3 * GIB);
    put_str(&h, path, &big);
    assert_eq!(h.call(Sysno::Stat, &[path, buf]), -i64::from(EOVERFLOW));
    assert_eq!(h.call(Sysno::Stat64, &[path, buf]), 0);
    assert_eq!(u64_at(&h, buf + 44), 3 * GIB);
    // The old stat: a pipe's inode 0 fits, /proc's does not.
    let fds = m + 0x800;
    h.ok(Sysno::Pipe, &[fds]);
    let rd = u64::from(u32_at(&h, fds));
    assert_eq!(h.call(Sysno::Oldfstat, &[rd, buf]), 0);
    assert_eq!(u16_at(&h, buf), 0xe, "old_encode_dev(0:0xe)");
    assert_eq!(u16_at(&h, buf + 2), 0);
    assert_eq!(u16_at(&h, buf + 4), 0o010600, "S_IFIFO | 0600");
    put_str(&h, path, "/proc/self/stat");
    assert_eq!(h.call(Sysno::Oldstat, &[path, buf]), -i64::from(EOVERFLOW));
    assert_eq!(h.call(Sysno::Oldlstat, &[path, buf]), -i64::from(EOVERFLOW));
}

#[test]
fn statfs_fills_compat_statfs_and_statfs64_checks_its_size() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (path, buf) = (m, m + 0x400);
    put_str(&h, path, "/proc/self");
    assert_eq!(h.call(Sysno::Statfs, &[path, buf]), 0);
    // PROC_SUPER_MAGIC, 4096-byte blocks, no blocks, 255-byte names,
    // ST_VALID.
    let words: Vec<u32> = (0..12).map(|i| u32_at(&h, buf + 4 * i)).collect();
    assert_eq!(words, [0x9fa0, 4096, 0, 0, 0, 0, 0, 0, 0, 255, 4096, 0x20]);
    // sizeof(struct compat_statfs64) is 84.
    assert_eq!(
        h.call(Sysno::Statfs64, &[path, 88, buf]),
        -i64::from(EINVAL)
    );
    put(&h, buf, &[0xAA; 88]);
    assert_eq!(h.call(Sysno::Statfs64, &[path, 84, buf]), 0);
    assert_eq!((u32_at(&h, buf), u32_at(&h, buf + 4)), (0x9fa0, 4096));
    assert_eq!(u64_at(&h, buf + 8), 0, "64-bit f_blocks");
    assert_eq!((u32_at(&h, buf + 56), u32_at(&h, buf + 64)), (255, 0x20));
    assert_eq!(u32_at(&h, buf + 84), 0xAAAA_AAAA, "84 bytes, packed");
    // By descriptor, and the size check before the descriptor's.
    let fd = h.ok(Sysno::Open, &[path, O_DIRECTORY, 0]);
    assert_eq!(h.call(Sysno::Fstatfs, &[fd, buf]), 0);
    assert_eq!(u32_at(&h, buf), 0x9fa0);
    assert_eq!(h.call(Sysno::Fstatfs64, &[fd, 84, buf]), 0);
    assert_eq!(h.call(Sysno::Fstatfs64, &[999, 1, buf]), -i64::from(EINVAL));
    assert_eq!(h.call(Sysno::Fstatfs64, &[999, 84, buf]), -i64::from(EBADF));
}

#[test]
fn getdents_fills_compat_linux_dirent_and_readdir_one_entry() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 2);
    let (path, buf) = (m, m + 0x1000);
    let d = Dir::new("dirents");
    d.file("a", 1);
    d.file("bb", 1);
    std::fs::create_dir(d.path("ccc")).unwrap();
    let fd = open(&mut h, path, d.0.to_str().unwrap(), O_DIRECTORY) as u64;
    // Room for none: EINVAL.
    assert_eq!(h.call(Sysno::Getdents, &[fd, buf, 8]), -i64::from(EINVAL));
    let n = h.ok(Sysno::Getdents, &[fd, buf, 0x1000]);
    let mut at = 0;
    let mut seen = Vec::new();
    while at < n {
        let rec = buf + at;
        let reclen = u64::from(u16_at(&h, rec + 8));
        // offsetof(d_name) 10, the name, its NUL, and d_type, aligned to 4.
        let name = cstr(&h, rec + 10);
        assert_eq!(
            reclen,
            (10 + name.len() as u64 + 2).div_ceil(4) * 4,
            "{name}"
        );
        let ino = u32_at(&h, rec);
        let host = std::fs::symlink_metadata(d.0.join(&name)).unwrap().ino();
        assert_eq!(u64::from(ino), host, "{name}: d_ino");
        assert_eq!(
            u32_at(&h, rec + 4),
            seen.len() as u32 + 1,
            "d_off: the next entry"
        );
        let dtype = u32_at(&h, rec + reclen - 4) >> 24;
        let want = if name.starts_with('c') || name.starts_with('.') {
            4
        } else {
            8
        };
        assert_eq!(dtype, want, "{name}: d_type in the last byte");
        seen.push(name);
        at += reclen;
    }
    seen.sort();
    assert_eq!(seen, [".", "..", "a", "bb", "ccc"]);
    assert_eq!(h.ok(Sysno::Getdents, &[fd, buf, 0x1000]), 0, "the end");
    // compat_sys_old_readdir: one entry a call, its own offset, then 0.
    let fd = open(&mut h, path, d.0.to_str().unwrap(), O_DIRECTORY) as u64;
    let mut names = Vec::new();
    for i in 0..5u32 {
        assert_eq!(h.call(Sysno::Readdir, &[fd, buf, 1]), 1);
        assert_eq!(u32_at(&h, buf + 4), i, "d_offset");
        let name = cstr(&h, buf + 10);
        assert_eq!(usize::from(u16_at(&h, buf + 8)), name.len(), "d_namlen");
        names.push(name);
    }
    assert_eq!(h.call(Sysno::Readdir, &[fd, buf, 1]), 0);
    names.sort();
    assert_eq!(names, [".", "..", "a", "bb", "ccc"]);
    assert_eq!(h.call(Sysno::Readdir, &[999, buf, 1]), -i64::from(EBADF));
    let file = open(&mut h, path, &d.path("a"), 0) as u64;
    assert_eq!(h.call(Sysno::Readdir, &[file, buf, 1]), -i64::from(ENOTDIR));
}

#[test]
fn offsets_come_in_register_pairs_or_as_compat_off_t() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (path, buf) = (m, m + 0x400);
    let d = Dir::new("offsets");
    let file = d.file("f", 100);
    let fd = open(&mut h, path, &file, O_RDWR) as u64;
    // compat_sys_lseek: -1 is -1.
    assert_eq!(h.call(Sysno::Lseek, &[fd, reg(-1), 2]), 99);
    assert_eq!(
        h.call(Sysno::Lseek, &[fd, reg(i32::MIN), 0]),
        -i64::from(EINVAL)
    );
    // _llseek: the offset from two registers, the result a loff_t.
    let result = buf + 0x100;
    assert_eq!(h.call(Sysno::Llseek, &[fd, 1, 0x10, result, 0]), 0);
    assert_eq!(u64_at(&h, result), 0x1_0000_0010);
    assert_eq!(
        h.call(Sysno::Llseek, &[fd, 0, 0, result, 5]),
        -i64::from(EINVAL)
    );
    assert_eq!(
        h.call(Sysno::Llseek, &[999, 0, 0, result, 5]),
        -i64::from(EBADF)
    );
    assert_eq!(
        h.call(Sysno::Llseek, &[fd, reg(-1), reg(-1), result, 0]),
        -i64::from(EINVAL)
    );
    // pread64 and pwrite64 past 4 GiB.
    put(&h, buf, b"wxyz");
    assert_eq!(h.call(Sysno::Pwrite64, &[fd, buf, 4, 0x10, 1]), 4);
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 0x1_0000_0014);
    put(&h, buf, b"....");
    assert_eq!(h.call(Sysno::Pread64, &[fd, buf + 8, 2, 0x11, 1]), 2);
    let mut got = [0u8; 2];
    h.proc.state.space.read_raw(buf + 8, &mut got).unwrap();
    assert_eq!(&got, b"xy");
    assert_eq!(
        h.call(Sysno::Pread64, &[fd, buf, 1, 0, 0x8000_0000]),
        -i64::from(EINVAL)
    );
    // preadv's position from two registers; preadv2's -1 is the current
    // position, which it advances.
    let iov = buf + 0x200;
    put(
        &h,
        iov,
        &[(buf as u32).to_le_bytes(), 2u32.to_le_bytes()].concat(),
    );
    assert_eq!(h.call(Sysno::Preadv, &[fd, iov, 1, 0x12, 1]), 2);
    h.proc.state.space.read_raw(buf, &mut got).unwrap();
    assert_eq!(&got, b"yz");
    assert_eq!(h.call(Sysno::Lseek, &[fd, 5, 0]), 5);
    assert_eq!(
        h.call(Sysno::Preadv2, &[fd, iov, 1, reg(-1), reg(-1), 0]),
        2
    );
    assert_eq!(h.call(Sysno::Lseek, &[fd, 0, 1]), 7);
    assert_eq!(
        h.call(Sysno::Preadv, &[fd, iov, 1, reg(-1), reg(-1)]),
        -i64::from(EINVAL)
    );
    assert_eq!(h.call(Sysno::Pwritev, &[fd, iov, 1, 0, 0]), 2);
    // truncate64 and ftruncate64; compat_sys_truncate's length is signed.
    put_str(&h, path, &file);
    assert_eq!(h.call(Sysno::Truncate64, &[path, 0x20, 1]), 0);
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 0x1_0000_0020);
    assert_eq!(
        h.call(Sysno::Truncate, &[path, reg(-1)]),
        -i64::from(EINVAL)
    );
    assert_eq!(h.call(Sysno::Truncate, &[path, 50]), 0);
    // do_sys_ftruncate(small): without O_LARGEFILE, not past MAX_NON_LFS.
    assert_eq!(h.call(Sysno::Ftruncate64, &[fd, 0, 1]), -i64::from(EINVAL));
    assert_eq!(h.call(Sysno::Ftruncate, &[fd, reg(-1)]), -i64::from(EINVAL));
    assert_eq!(h.call(Sysno::Ftruncate64, &[fd, 0x7FFF_FFFF, 0]), 0);
    let large = open(&mut h, path, &file, O_RDWR | O_LARGEFILE) as u64;
    assert_eq!(h.call(Sysno::Ftruncate64, &[large, 0, 1]), 0);
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 1 << 32);
    // fadvise64_64's length from two registers: negative is EINVAL;
    // fadvise64's is a size_t.
    assert_eq!(
        h.call(Sysno::Fadvise6464, &[fd, 0, 0, 0, 0x8000_0000, 0]),
        -i64::from(EINVAL)
    );
    assert_eq!(h.call(Sysno::Fadvise6464, &[fd, 0, 1, 10, 0, 0]), 0);
    assert_eq!(h.call(Sysno::Fadvise64, &[fd, 0, 0, reg(-1), 0]), 0);
    // sync_file_range and fallocate with register pairs.
    assert_eq!(
        h.call(Sysno::SyncFileRange, &[fd, 0, 0x8000_0000, 1, 0, 2]),
        -i64::from(EINVAL)
    );
    assert_eq!(h.call(Sysno::SyncFileRange, &[fd, 0, 1, 1, 0, 2]), 0);
    assert_eq!(h.call(Sysno::Ftruncate, &[large, 0]), 0);
    assert_eq!(h.call(Sysno::Fallocate, &[large, 0, 0, 1, 0x10, 0]), 0);
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 0x1_0000_0010);
    assert_eq!(h.call(Sysno::Readahead, &[fd, 0, 1, 10]), 0);
}

#[test]
fn compat_sendfile_takes_a_compat_off_t_and_stops_at_max_non_lfs() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (path, off) = (m, m + 0x400);
    let d = Dir::new("sendfile");
    let input = d.file("in", 100);
    let output = d.file("out", 0);
    let big = d.file("big", 3 * GIB);
    let fin = open(&mut h, path, &input, 0) as u64;
    let fout = open(&mut h, path, &output, O_WRONLY) as u64;
    // A 4-byte offset, the word after it untouched.
    put(&h, off, &[10, 0, 0, 0, 0xEE, 0xEE, 0xEE, 0xEE]);
    assert_eq!(h.call(Sysno::Sendfile, &[fout, fin, off, 20]), 20);
    assert_eq!((u32_at(&h, off), u32_at(&h, off + 4)), (30, 0xEEEE_EEEE));
    assert_eq!(std::fs::metadata(&output).unwrap().len(), 20);
    // A negative compat_off_t: EINVAL.
    put(&h, off, &reg(-1).to_le_bytes()[..4]);
    assert_eq!(
        h.call(Sysno::Sendfile, &[fout, fin, off, 1]),
        -i64::from(EINVAL)
    );
    // Past 2 GiB: at MAX_NON_LFS EOVERFLOW, below it the count shrinks.
    let fbig = open(&mut h, path, &big, O_LARGEFILE) as u64;
    put(&h, off, &0x7FFF_FFFFu32.to_le_bytes());
    assert_eq!(
        h.call(Sysno::Sendfile, &[fout, fbig, off, 1]),
        -i64::from(EOVERFLOW)
    );
    put(&h, off, &0x7FFF_FFF0u32.to_le_bytes());
    assert_eq!(h.call(Sysno::Sendfile, &[fout, fbig, off, 100]), 15);
    assert_eq!(u32_at(&h, off), 0x7FFF_FFFF);
    // sendfile64: a loff_t and no such limit.
    put(&h, off, &(2 * GIB + 5).to_le_bytes());
    assert_eq!(h.call(Sysno::Sendfile64, &[fout, fbig, off, 100]), 100);
    assert_eq!(u64_at(&h, off), 2 * GIB + 105);
}

#[test]
fn compat_fcntl_converts_the_lock_structures() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (path, fl) = (m, m + 0x400);
    let d = Dir::new("locks");
    let file = d.file("f", 100);
    let fd = open(&mut h, path, &file, O_RDWR) as u64;
    // struct compat_flock: F_WRLCK from SEEK_SET, start 10, length 20.
    let flock = |kind: i16, start: i32, len: i32, pid: i32| {
        [
            &kind.to_le_bytes()[..],
            &0i16.to_le_bytes(),
            &start.to_le_bytes(),
            &len.to_le_bytes(),
            &pid.to_le_bytes(),
        ]
        .concat()
    };
    put(&h, fl, &flock(1, 10, 20, 0));
    assert_eq!(h.call(Sysno::Fcntl, &[fd, 6, fl]), 0, "F_SETLK");
    // Our own lock does not conflict: F_UNLCK, the rest as it was.
    put(&h, fl, &flock(1, 0, 0, 77));
    assert_eq!(h.call(Sysno::Fcntl, &[fd, 5, fl]), 0, "F_GETLK");
    assert_eq!(u16_at(&h, fl), 2, "F_UNLCK");
    assert_eq!((u32_at(&h, fl + 4), u32_at(&h, fl + 12)), (0, 77));
    // A negative start from SEEK_SET: EINVAL (flock_to_posix_lock).
    put(&h, fl, &flock(1, -5, 1, 0));
    assert_eq!(h.call(Sysno::Fcntl, &[fd, 6, fl]), -i64::from(EINVAL));
    // struct compat_flock64: 64-bit start and length at 4 and 12.
    let flock64 = |kind: i16, start: i64, len: i64| {
        [
            &kind.to_le_bytes()[..],
            &0i16.to_le_bytes(),
            &start.to_le_bytes(),
            &len.to_le_bytes(),
            &0i32.to_le_bytes(),
        ]
        .concat()
    };
    put(&h, fl, &flock64(0, 1 << 33, 1));
    assert_eq!(h.call(Sysno::Fcntl64, &[fd, 13, fl]), 0, "F_SETLK64");
    put(&h, fl, &flock64(1, 1 << 33, 0));
    assert_eq!(h.call(Sysno::Fcntl64, &[fd, 12, fl]), 0, "F_GETLK64");
    assert_eq!(u16_at(&h, fl), 2);
    assert_eq!(u64_at(&h, fl + 4), 1 << 33);
    // compat_sys_fcntl refuses the 64-bit commands before the descriptor.
    for cmd in [12, 13, 14, 36, 37, 38] {
        assert_eq!(
            h.call(Sysno::Fcntl, &[999, cmd, fl]),
            -i64::from(EINVAL),
            "{cmd}"
        );
    }
    assert_eq!(h.call(Sysno::Fcntl64, &[999, 12, fl]), -i64::from(EBADF));
    // Other commands are the native ones.
    assert_eq!(h.call(Sysno::Fcntl, &[fd, F_GETFL, 0]), O_RDWR as i64);
}

#[test]
fn execve_reads_compat_vectors_and_an_i386_program_keeps_the_personality() {
    use crate::user::image::elf::{EM_386, EM_X86_64, ET_EXEC, PF_R, PF_W, PF_X};
    use crate::user::linux::tests::loader::{Seg, image, image32};
    let segs = [
        Seg::load(0x40_0000, 0, 0x2000, 0x2000, PF_R | PF_X),
        Seg::load(0x60_0000, 0x2000, 0x1000, 0x2000, PF_R | PF_W),
    ];
    let d = Dir::new("exec");
    let prog32 = d.path("prog32");
    let prog64 = d.path("prog64");
    std::fs::write(&prog32, image32(EM_386, ET_EXEC, 0x40_1000, &segs)).unwrap();
    std::fs::write(&prog64, image(EM_X86_64, ET_EXEC, 0x40_1000, &segs, None)).unwrap();
    for p in [&prog32, &prog64] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (prog, abi) in [(&prog32, LinuxAbi::I386), (&prog64, LinuxAbi::X86_64)] {
        let mut h = Harness::new(LinuxAbi::I386);
        let m = pages(&mut h, 1);
        let (path, argv, envp, strs) = (m, m + 0x200, m + 0x300, m + 0x400);
        put_str(&h, path, prog);
        put_str(&h, strs, "one");
        put_str(&h, strs + 4, "two");
        put_str(&h, strs + 8, "K=V");
        let words = |w: &[u32]| w.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
        put(&h, argv, &words(&[strs as u32, strs as u32 + 4, 0]));
        put(&h, envp, &words(&[strs as u32 + 8, 0]));
        // PER_LINUX32 | ADDR_NO_RANDOMIZE | READ_IMPLIES_EXEC.
        let persona = 0x0008 | 0x0004_0000 | 0x0040_0000;
        h.ok(Sysno::Personality, &[persona]);
        let out = h.dispatch(Sysno::Execve, &[path, argv, envp]);
        let Outcome::Exec(image) = out else {
            panic!("{abi:?}: {out:?}");
        };
        h.proc.commit_exec(0, *image.0);
        let p = &h.proc.state;
        assert_eq!(p.abi, abi);
        assert_eq!(p.cmdline, b"one\0two\0", "{abi:?}");
        assert_eq!(p.environ, b"K=V\0");
        // set_personality_ia32 keeps it; set_personality_64bit drops
        // READ_IMPLIES_EXEC.
        let want = if abi == LinuxAbi::I386 {
            persona as u32
        } else {
            (persona & !0x0040_0000) as u32
        };
        assert_eq!(p.persona, want, "{abi:?}");
    }
}

#[test]
fn epoll_events_are_packed_for_a_compatibility_task() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let (ev, fds, out) = (m, m + 0x100, m + 0x200);
    let ep = h.ok(Sysno::EpollCreate1, &[0]);
    h.ok(Sysno::Pipe2, &[fds, 0]);
    let wr = u64::from(u32_at(&h, fds + 4));
    // EPOLLOUT, data 0x1122334455667788 at offset 4: 12 bytes.
    put(
        &h,
        ev,
        &[
            &4u32.to_le_bytes()[..],
            &0x1122_3344_5566_7788u64.to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(h.call(Sysno::EpollCtl, &[ep, 1, wr, ev]), 0);
    put(&h, out, &[0xAA; 32]);
    assert_eq!(h.call(Sysno::EpollWait, &[ep, out, 2, 0]), 1);
    assert_eq!(u32_at(&h, out), 4);
    assert_eq!(u64_at(&h, out + 4), 0x1122_3344_5566_7788);
    assert_eq!(u32_at(&h, out + 12), 0xAAAA_AAAA, "one event is 12 bytes");
}

#[test]
fn prctl_is_native_but_for_the_seccomp_filter() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    // PR_GET_TSC is x86's, 32-bit tasks' too: PR_TSC_ENABLE.
    assert_eq!(h.call(Sysno::Prctl, &[25, m, 0, 0, 0]), 0);
    assert_eq!(u32_at(&h, m), 1);
    // PR_SET_NAME and PR_GET_NAME.
    put_str(&h, m, "compat");
    assert_eq!(h.call(Sysno::Prctl, &[15, m, 0, 0, 0]), 0);
    put(&h, m, &[0; 16]);
    assert_eq!(h.call(Sysno::Prctl, &[16, m, 0, 0, 0]), 0);
    assert_eq!(cstr(&h, m), "compat");
    // PR_SET_SECCOMP reads a struct compat_sock_fprog: not converted yet.
    assert_eq!(h.call(Sysno::Prctl, &[22, 2, m, 0, 0]), -i64::from(ENOSYS));
    // The 32-bit ID calls are the native ones.
    assert_eq!(
        h.call(Sysno::Getuid32, &[]),
        i64::from(h.proc.state.creds.0)
    );
}

/// `access_ok` on an x86-64 kernel checks a compatibility task's pointers
/// against the 64-bit `USER_PTR_MAX`: a vector running past 4 GiB is
/// accepted, and only the copy can fault.
#[test]
fn a_vector_past_4_gib_is_in_user_space_for_access_ok() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 1);
    let fds = m + 0x100;
    h.ok(Sysno::Pipe, &[fds]);
    let (rd, wr) = (u64::from(u32_at(&h, fds)), u64::from(u32_at(&h, fds + 4)));
    put(&h, m + 0x200, b"abc");
    assert_eq!(h.call(Sysno::Write, &[wr, m + 0x200, 3]), 3);
    // One struct compat_iovec: 1 GiB from a page near the top of the
    // 32-bit space, its end past 4 GiB.
    assert!(m > 0xC000_0000, "{m:#x}");
    let iov = m + 0x300;
    put(
        &h,
        iov,
        &[
            (m as u32 + 0x400).to_le_bytes(),
            0x4000_0000u32.to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(h.call(Sysno::Readv, &[rd, iov, 1]), 3);
    assert_eq!(cstr(&h, m + 0x400), "abc");
}

/// Pipe transfers that fault move whole pages, as for a 64-bit caller
/// (`anon_pipe_write`, `pipe_read`; recorded on Linux 6.19 for x86-64).
#[test]
fn a_compat_pipe_transfer_that_faults_moves_whole_pages() {
    let mut h = Harness::new(LinuxAbi::I386);
    let m = pages(&mut h, 3);
    h.ok(Sysno::Mprotect, &[m + 0x2000, 0x1000, 0]);
    let (bad, fds) = (m + 0x2000, m + 0x100);
    h.ok(Sysno::Pipe, &[fds]);
    let (rd, wr) = (u64::from(u32_at(&h, fds)), u64::from(u32_at(&h, fds + 4)));
    let iov = m + 0x200;
    put(
        &h,
        iov,
        &[
            (m as u32).to_le_bytes(),
            5u32.to_le_bytes(),
            (bad as u32).to_le_bytes(),
            5u32.to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(h.call(Sysno::Writev, &[wr, iov, 2]), -i64::from(EFAULT));
    assert_eq!(h.call(Sysno::Write, &[wr, bad - 0x1000, 0x2000]), 0x1000);
    put(&h, m + 0x300, &[0; 16]);
    assert_eq!(
        h.call(Sysno::Read, &[rd, bad - 5, 0x1000]),
        -i64::from(EFAULT)
    );
}
