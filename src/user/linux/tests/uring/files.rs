//! io_uring's opens, closes, pipes, installs, and path operations
//! (`io_uring/openclose.c`, `fs.c`, `statx.c`, Linux 6.19).

use super::*;

// Operations.
const OPENAT: u8 = 18;
const CLOSE: u8 = 19;
const STATX: u8 = 21;
const READ: u8 = 22;
const OPENAT2: u8 = 28;
const RENAMEAT: u8 = 35;
const UNLINKAT: u8 = 36;
const MKDIRAT: u8 = 37;
const SYMLINKAT: u8 = 38;
const LINKAT: u8 = 39;
const FIXED_FD_INSTALL: u8 = 54;
const PIPE: u8 = 62;
const FIXED_FILE: u8 = 1;
const REGISTER_FILES2: u64 = 13;
const SPARSE: u32 = 1;
const FILE_INDEX_ALLOC: u32 = u32::MAX;
// Open flags and fcntl (x86-64).
const O_WRONLY: u32 = 1;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_NONBLOCK: u32 = 0o4000;
const O_LARGEFILE: u64 = 0o100000;
const O_CLOEXEC: u32 = 0o2000000;
const F_GETFL: u64 = 3;
const AT_FDCWD: i32 = -100;
const AT_REMOVEDIR: u32 = 0x200;
const AT_EMPTY_PATH: u32 = 0x1000;
const RLIMIT_NOFILE: usize = 7;

fn run(h: &mut Harness, r: &Ring, sqes: &[Sqe]) -> Vec<(u64, i32, u32)> {
    for s in sqes {
        r.push(h, *s);
    }
    assert_eq!(r.enter(h, sqes.len() as u64, 0, 0), sqes.len() as i64);
    r.reap(h)
}

fn neg(e: i32) -> i32 {
    -e
}

/// A directory of its own for the test, and a guest string at `at` for
/// `name` in it.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("rax-uring-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }

    fn put(&self, h: &Harness, at: u64, name: &str) -> u64 {
        let s = format!("{}\0", self.path(name).display());
        put(h, at, s.as_bytes());
        at
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open_sqe(path: u64, flags: u32, mode: u32, ud: u64) -> Sqe {
    Sqe {
        opcode: OPENAT,
        fd: AT_FDCWD,
        addr: path,
        op_flags: flags,
        len: mode,
        user_data: ud,
        ..Sqe::default()
    }
}

fn sparse(h: &mut Harness, r: &Ring, n: u32, at: u64) {
    let mut rr = [0u8; 32];
    rr[0..4].copy_from_slice(&n.to_le_bytes());
    rr[4..8].copy_from_slice(&SPARSE.to_le_bytes());
    put(h, at, &rr);
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_FILES2, at, 32]),
        0
    );
}

#[test]
fn openat_opens_into_the_descriptor_table() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("open");
    std::fs::write(d.path("a"), b"hello").unwrap();
    let buf = h.anon(P, RW, false);
    let a = d.put(&h, buf, "a");
    // __get_unused_fd_flags, do_filp_open: the lowest free descriptor,
    // O_LARGEFILE added (force_o_largefile), O_NONBLOCK only as asked.
    let got = run(&mut h, &r, &[open_sqe(a, 0, 0, 1)]);
    let fd = got[0].1;
    assert!(fd > 0, "{got:?}");
    let fl = h.ok(Sysno::Fcntl, &[fd as u64, F_GETFL]);
    assert_eq!(fl & (O_LARGEFILE | u64::from(O_NONBLOCK)), O_LARGEFILE);
    assert!(!h.proc.state.fds.get(fd).unwrap().cloexec);
    let got = run(&mut h, &r, &[open_sqe(a, O_CLOEXEC, 0, 2)]);
    assert!(h.proc.state.fds.get(got[0].1).unwrap().cloexec);
    // A missing file fails the request and its link.
    let missing = d.put(&h, buf + 0x200, "missing");
    let head = Sqe {
        flags: LINK,
        ..open_sqe(missing, 0, 0, 3)
    };
    assert_eq!(
        run(&mut h, &r, &[head, Sqe::nop(4)]),
        [(3, neg(ENOENT), 0), (4, neg(ECANCELED), 0)]
    );
    // O_CREAT runs on the workers: after an inline request.
    let created = d.put(&h, buf + 0x400, "created");
    let got = run(
        &mut h,
        &r,
        &[open_sqe(created, O_CREAT, 0o600, 5), Sqe::nop(6)],
    );
    assert_eq!(got[0], (6, 0, 0));
    assert_eq!(got[1].0, 5);
    assert!(got[1].1 > 0);
    assert!(d.path("created").exists());
    // The limit is the one at preparation; the descriptor is taken before
    // the lookup (EMFILE, not ENOENT).
    let nofile = h.proc.state.rlimits[RLIMIT_NOFILE].0;
    h.proc.state.rlimits[RLIMIT_NOFILE].0 = 3;
    assert_eq!(
        run(&mut h, &r, &[open_sqe(missing, 0, 0, 7)]),
        [(7, neg(EMFILE), 0)]
    );
    h.proc.state.rlimits[RLIMIT_NOFILE].0 = nofile;
    // Tried with O_NONBLOCK: a FIFO for writing without a reader is ENXIO.
    let fifo = d.path("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let f = d.put(&h, buf + 0x600, "fifo");
    assert_eq!(
        run(&mut h, &r, &[open_sqe(f, O_WRONLY, 0, 8)]),
        [(8, neg(ENXIO), 0)]
    );
}

#[test]
fn open_preparation_takes_the_name_and_checks_the_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("openprep");
    std::fs::write(d.path("a"), b"A").unwrap();
    std::fs::write(d.path("b"), b"B").unwrap();
    let buf = h.anon(P, RW, false);
    let empty = buf + 0x800;
    put(&h, empty, &[0]);
    let bad = [
        (open_sqe(empty, 0, 0, 1), ENOENT),
        (open_sqe(0x10, 0, 0, 2), EFAULT),
        (
            Sqe {
                buf_index: 1,
                ..open_sqe(buf, 0, 0, 3)
            },
            EINVAL,
        ),
        (
            Sqe {
                flags: FIXED_FILE,
                ..open_sqe(buf, 0, 0, 4)
            },
            EBADF,
        ),
        (
            Sqe {
                file_index: 1,
                ..open_sqe(d.put(&h, buf, "a"), O_CLOEXEC, 0, 5)
            },
            EINVAL,
        ),
    ];
    for (s, e) in bad {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1, "{s:?}");
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    // IORING_FEAT_SUBMIT_STABLE: the name is the one at preparation. A
    // read linked ahead rewrites it before the open is issued.
    let name_b = d.path("b").display().to_string();
    let src = h.file("uring-name", 0, 0, 2);
    let data = buf + 0x400;
    put(&h, data, format!("{name_b}\0").as_bytes());
    h.ok(Sysno::Pwrite64, &[src, data, name_b.len() as u64 + 1, 0]);
    let a = d.put(&h, buf, "a");
    let rewrite = Sqe {
        opcode: READ,
        fd: src as i32,
        addr: a,
        len: name_b.len() as u32 + 1,
        flags: LINK,
        user_data: 6,
        ..Sqe::default()
    };
    let got = run(&mut h, &r, &[rewrite, open_sqe(a, 0, 0, 7)]);
    assert_eq!(got[0], (6, name_b.len() as i32 + 1, 0));
    let fd = got[1].1;
    assert!(fd > 0, "{got:?}");
    h.ok(Sysno::Read, &[fd as u64, buf + 0xa00, 1]);
    assert_eq!(bytes_at(&h, buf + 0xa00, 1), b"A");
}

fn bytes_at(h: &Harness, at: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    b
}

#[test]
fn openat2_follows_copy_struct_from_user_and_build_open_flags() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("openat2");
    std::fs::write(d.path("a"), b"A").unwrap();
    let buf = h.anon(P, RW, false);
    let a = d.put(&h, buf, "a");
    let how = buf + 0x400;
    let open2 = |len: u32, ud: u64| Sqe {
        opcode: OPENAT2,
        fd: AT_FDCWD,
        addr: a,
        off: how,
        len,
        user_data: ud,
        ..Sqe::default()
    };
    let put_how = |h: &Harness, flags: u64, mode: u64, resolve: u64, tail: u64| {
        let b: Vec<u8> = [flags, mode, resolve, tail]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        put(h, how, &b);
    };
    put_how(&h, 0, 0, 0, 0);
    // io_openat2_prep: at least OPEN_HOW_SIZE_VER0, anything past zero.
    r.push(&h, open2(16, 1));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(1, neg(EINVAL), 0)]);
    put_how(&h, 0, 0, 0, 1);
    r.push(&h, open2(32, 2));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(2, neg(E2BIG), 0)]);
    put_how(&h, 0, 0, 0, 0);
    let got = run(&mut h, &r, &[open2(32, 3)]);
    assert!(got[0].1 > 0, "{got:?}");
    // build_open_flags at issue: an unknown flag, a mode without O_CREAT.
    put_how(&h, 1 << 40, 0, 0, 0);
    assert_eq!(run(&mut h, &r, &[open2(24, 4)]), [(4, neg(EINVAL), 0)]);
    put_how(&h, 0, 0o600, 0, 0);
    assert_eq!(run(&mut h, &r, &[open2(24, 5)]), [(5, neg(EINVAL), 0)]);
}

#[test]
fn direct_descriptors_open_close_and_install() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("direct");
    std::fs::write(d.path("a"), b"direct").unwrap();
    let buf = h.anon(P, RW, false);
    let a = d.put(&h, buf, "a");
    let direct = |slot: u32, ud: u64| Sqe {
        file_index: slot,
        ..open_sqe(a, 0, 0, ud)
    };
    // io_fixed_fd_install: without a table ENXIO.
    assert_eq!(run(&mut h, &r, &[direct(1, 1)]), [(1, neg(ENXIO), 0)]);
    sparse(&mut h, &r, 4, buf + 0x800);
    // A named slot: 0; an allocated one: its index; past the table EINVAL.
    assert_eq!(run(&mut h, &r, &[direct(2, 2)]), [(2, 0, 0)]);
    assert_eq!(run(&mut h, &r, &[direct(FILE_INDEX_ALLOC, 3)]), [(3, 2, 0)]);
    assert_eq!(run(&mut h, &r, &[direct(5, 4)]), [(4, neg(EINVAL), 0)]);
    let read = Sqe {
        opcode: READ,
        flags: FIXED_FILE,
        fd: 1,
        addr: buf + 0x100,
        len: 6,
        user_data: 5,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[read]), [(5, 6, 0)]);
    assert_eq!(bytes_at(&h, buf + 0x100, 6), b"direct");
    // io_install_fixed_fd: close-on-exec unless asked not to.
    let install = |slot: i32, flags: u32, ud: u64| Sqe {
        opcode: FIXED_FD_INSTALL,
        flags: FIXED_FILE,
        fd: slot,
        op_flags: flags,
        user_data: ud,
        ..Sqe::default()
    };
    let got = run(&mut h, &r, &[install(1, 0, 6)]);
    assert!(h.proc.state.fds.get(got[0].1).unwrap().cloexec);
    let got = run(&mut h, &r, &[install(1, 1, 7)]);
    assert!(!h.proc.state.fds.get(got[0].1).unwrap().cloexec);
    for (s, e) in [
        (
            Sqe {
                flags: 0,
                ..install(1, 0, 8)
            },
            EBADF,
        ),
        (install(1, 2, 9), EINVAL),
        (
            Sqe {
                addr: 1,
                ..install(1, 0, 10)
            },
            EINVAL,
        ),
    ] {
        assert_eq!(run(&mut h, &r, &[s]), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    let pers = h.call(Sysno::IoUringRegister, &[r.fd, 9, 0, 0]) as u16;
    let with_creds = Sqe {
        personality: pers,
        ..install(1, 0, 11)
    };
    assert_eq!(run(&mut h, &r, &[with_creds]), [(11, neg(EPERM), 0)]);
    // io_close of a slot: emptied; empty EBADF.
    let close_slot = |slot: u32, ud: u64| Sqe {
        opcode: CLOSE,
        file_index: slot,
        user_data: ud,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[close_slot(2, 12)]), [(12, 0, 0)]);
    assert_eq!(run(&mut h, &r, &[close_slot(2, 13)]), [(13, neg(EBADF), 0)]);
}

#[test]
fn close_closes_descriptors_but_not_rings() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let fd = h.file("uring-close", 1, 0, 0);
    let close = |fd: i32, ud: u64| Sqe {
        opcode: CLOSE,
        fd,
        user_data: ud,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[close(fd as i32, 1)]), [(1, 0, 0)]);
    assert!(h.proc.state.fds.get(fd as i32).is_err());
    assert_eq!(
        run(&mut h, &r, &[close(fd as i32, 2)]),
        [(2, neg(EBADF), 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[close(r.fd as i32, 3)]),
        [(3, neg(EBADF), 0)]
    );
    // io_close_prep.
    for (s, e) in [
        (
            Sqe {
                file_index: 1,
                ..close(3, 4)
            },
            EINVAL,
        ),
        (
            Sqe {
                addr: 1,
                ..close(3, 5)
            },
            EINVAL,
        ),
        (
            Sqe {
                flags: FIXED_FILE,
                ..close(3, 6)
            },
            EBADF,
        ),
    ] {
        assert_eq!(run(&mut h, &r, &[s]), [(s.user_data, neg(e), 0)], "{s:?}");
    }
}

#[test]
fn pipe_makes_a_pipe() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let buf = h.anon(P, RW, false);
    let pipe = |flags: u32, slot: u32, at: u64, ud: u64| Sqe {
        opcode: PIPE,
        addr: at,
        op_flags: flags,
        file_index: slot,
        user_data: ud,
        ..Sqe::default()
    };
    assert_eq!(run(&mut h, &r, &[pipe(O_CLOEXEC, 0, buf, 1)]), [(1, 0, 0)]);
    let (rd, wr) = (u32_at(&h, buf), u32_at(&h, buf + 4));
    assert!(h.proc.state.fds.get(rd as i32).unwrap().cloexec);
    put(&h, buf + 0x100, b"xy");
    assert_eq!(h.ok(Sysno::Write, &[u64::from(wr), buf + 0x100, 2]), 2);
    assert_eq!(h.ok(Sysno::Read, &[u64::from(rd), buf + 0x200, 2]), 2);
    // io_pipe_prep and create_pipe_files: pipe2's flags; no notification
    // pipes without CONFIG_WATCH_QUEUE.
    assert_eq!(
        run(&mut h, &r, &[pipe(1, 0, buf, 2)]),
        [(2, neg(EINVAL), 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[pipe(O_EXCL, 0, buf, 3)]),
        [(3, neg(ENOPKG), 0)]
    );
    // The numbers cannot be written: no descriptor stays.
    let before = h.proc.state.fds.open_fds().len();
    assert_eq!(
        run(&mut h, &r, &[pipe(0, 0, 0x10, 4)]),
        [(4, neg(EFAULT), 0)]
    );
    assert_eq!(h.proc.state.fds.open_fds().len(), before);
    // Into slots: allocated ones give their indexes, a named one and the
    // next 0 each; not close-on-exec.
    sparse(&mut h, &r, 4, buf + 0x800);
    assert_eq!(
        run(&mut h, &r, &[pipe(0, FILE_INDEX_ALLOC, buf, 5)]),
        [(5, 0, 0)]
    );
    assert_eq!((u32_at(&h, buf), u32_at(&h, buf + 4)), (0, 1));
    assert_eq!(run(&mut h, &r, &[pipe(0, 3, buf, 6)]), [(6, 0, 0)]);
    assert_eq!((u32_at(&h, buf), u32_at(&h, buf + 4)), (0, 0));
    assert_eq!(
        run(&mut h, &r, &[pipe(O_CLOEXEC, 3, buf, 7)]),
        [(7, neg(EINVAL), 0)]
    );
}

#[test]
fn path_operations_run_on_the_workers_and_keep_their_links() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("paths");
    let buf = h.anon(2 * P, RW, false);
    let at = |i: u64| buf + 0x200 * i;
    let op = |opcode: u8, addr: u64, addr2: u64, len: u32, flags: u32, ud: u64| Sqe {
        opcode,
        fd: AT_FDCWD,
        addr,
        off: addr2,
        len,
        op_flags: flags,
        user_data: ud,
        ..Sqe::default()
    };
    let dir = d.put(&h, at(0), "dir");
    assert_eq!(
        run(&mut h, &r, &[op(MKDIRAT, dir, 0, 0o700, 0, 1)]),
        [(1, 0, 0)]
    );
    assert!(d.path("dir").is_dir());
    std::fs::write(d.path("f"), b"12345").unwrap();
    let f = d.put(&h, at(1), "f");
    let g = d.put(&h, at(2), "g");
    let linked = d.put(&h, at(3), "linked");
    let sym = d.put(&h, at(4), "sym");
    let rename = op(RENAMEAT, f, g, AT_FDCWD as u32, 0, 2);
    assert_eq!(run(&mut h, &r, &[rename]), [(2, 0, 0)]);
    assert!(d.path("g").exists() && !d.path("f").exists());
    assert_eq!(
        run(&mut h, &r, &[op(LINKAT, g, linked, AT_FDCWD as u32, 0, 3)]),
        [(3, 0, 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[op(SYMLINKAT, g, sym, 0, 0, 4)]),
        [(4, 0, 0)]
    );
    assert_eq!(std::fs::read_link(d.path("sym")).unwrap(), d.path("g"));
    // do_statx: stx_size (at 40) of the file.
    let stx = at(8);
    let statx = op(STATX, g, stx, 0x7ff, 0, 5);
    assert_eq!(run(&mut h, &r, &[statx]), [(5, 0, 0)]);
    assert_eq!(u64_at(&h, stx + 40), 5);
    // A failure keeps the link going (no req_set_fail).
    let gone = d.put(&h, at(5), "gone");
    let failing = Sqe {
        flags: LINK,
        ..op(UNLINKAT, gone, 0, 0, 0, 6)
    };
    assert_eq!(
        run(&mut h, &r, &[failing, Sqe::nop(7)]),
        [(6, neg(ENOENT), 0), (7, 0, 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[op(UNLINKAT, linked, 0, 0, 0, 8)]),
        [(8, 0, 0)]
    );
    assert_eq!(
        run(&mut h, &r, &[op(UNLINKAT, dir, 0, 0, AT_REMOVEDIR, 9)]),
        [(9, 0, 0)]
    );
    assert!(!d.path("dir").exists());
    // Preparation: flags, unused fields, registered files, empty names
    // (a statx's with AT_EMPTY_PATH names its descriptor).
    let empty = at(6);
    put(&h, empty, &[0]);
    for (s, e) in [
        (op(UNLINKAT, g, 0, 0, 0x100, 10), EINVAL),
        (op(UNLINKAT, g, 0, 1, 0, 11), EINVAL),
        (op(MKDIRAT, dir, 1, 0, 0, 12), EINVAL),
        (op(SYMLINKAT, g, sym, 1, 0, 13), EINVAL),
        (
            Sqe {
                flags: FIXED_FILE,
                ..op(RENAMEAT, g, f, 0, 0, 14)
            },
            EBADF,
        ),
        (op(UNLINKAT, empty, 0, 0, 0, 15), ENOENT),
        (op(STATX, empty, stx, 0x7ff, 0, 16), ENOENT),
    ] {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1, "{s:?}");
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    let fd = h.file("uring-statx", 3, 0, 0);
    let by_fd = Sqe {
        fd: fd as i32,
        ..op(STATX, empty, stx, 0x7ff, AT_EMPTY_PATH, 17)
    };
    assert_eq!(run(&mut h, &r, &[by_fd]), [(17, 0, 0)]);
    assert_eq!(u64_at(&h, stx + 40), 3);
}

// IORING_OP_FSETXATTR, _SETXATTR, _FGETXATTR, _GETXATTR.
const FSETXATTR: u8 = 41;
const SETXATTR: u8 = 42;
const FGETXATTR: u8 = 43;
const GETXATTR: u8 = 44;
const XATTR_CREATE: u32 = 1;

#[test]
fn xattrs_are_read_and_set() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    let d = Dir::new("xattr");
    std::fs::write(d.path("x"), b"x").unwrap();
    let buf = h.anon(P, RW, false);
    let path = d.put(&h, buf, "x");
    let name = buf + 0x200;
    put(&h, name, b"user.k\0");
    let value = buf + 0x300;
    let fd = open_via(&mut h, &d, buf + 0x800, "x");
    let set = |opcode: u8, fd: i32, v: &[u8], flags: u32, ud: u64| Sqe {
        opcode,
        fd,
        addr: name,
        off: value,
        len: v.len() as u32,
        addr3: path,
        op_flags: flags,
        user_data: ud,
        ..Sqe::default()
    };
    let get = |opcode: u8, fd: i32, size: u32, ud: u64| Sqe {
        opcode,
        fd,
        addr: name,
        off: value + 0x100,
        len: size,
        addr3: path,
        user_data: ud,
        ..Sqe::default()
    };
    put(&h, value, b"v1");
    assert_eq!(
        run(&mut h, &r, &[set(FSETXATTR, fd, b"v1", 0, 1)]),
        [(1, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[get(FGETXATTR, fd, 16, 2)]), [(2, 2, 0)]);
    assert_eq!(bytes_at(&h, value + 0x100, 2), b"v1");
    // By path, from the working directory; a size of 0 asks the length.
    assert_eq!(run(&mut h, &r, &[get(GETXATTR, 0, 0, 3)]), [(3, 2, 0)]);
    put(&h, value, b"v22");
    assert_eq!(
        run(&mut h, &r, &[set(SETXATTR, 0, b"v22", 0, 4)]),
        [(4, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[get(GETXATTR, 0, 16, 5)]), [(5, 3, 0)]);
    // vfs_setxattr's XATTR_CREATE; a failure keeps the link going.
    let exists = Sqe {
        flags: LINK,
        ..set(FSETXATTR, fd, b"v22", XATTR_CREATE, 6)
    };
    assert_eq!(
        run(&mut h, &r, &[exists, Sqe::nop(7)]),
        [(6, neg(EEXIST), 0), (7, 0, 0)]
    );
    // Preparation: a path form takes no registered file; a get no flags;
    // setxattr_copy's flags, name, and size.
    put(&h, buf + 0x280, b"\0");
    for (s, e) in [
        (
            Sqe {
                flags: FIXED_FILE,
                ..get(GETXATTR, 0, 16, 8)
            },
            EBADF,
        ),
        (
            Sqe {
                op_flags: 1,
                ..get(FGETXATTR, fd, 16, 9)
            },
            EINVAL,
        ),
        (set(FSETXATTR, fd, b"v", 4, 10), EINVAL),
        (
            Sqe {
                addr: buf + 0x280,
                ..get(FGETXATTR, fd, 16, 11)
            },
            ERANGE,
        ),
        (
            Sqe {
                len: 65537,
                ..set(FSETXATTR, fd, b"", 0, 12)
            },
            E2BIG,
        ),
    ] {
        r.push(&h, s);
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1, "{s:?}");
        assert_eq!(r.reap(&h), [(s.user_data, neg(e), 0)], "{s:?}");
    }
    // setxattr_copy: the value is the one at preparation; a read linked
    // ahead rewrites it before the set runs.
    let src = h.file("uring-xattr-src", 0, 0, 2);
    put(&h, buf + 0x900, b"new");
    h.ok(Sysno::Pwrite64, &[src, buf + 0x900, 3, 0]);
    put(&h, value, b"old");
    let rewrite = Sqe {
        opcode: READ,
        fd: src as i32,
        addr: value,
        len: 3,
        flags: LINK,
        user_data: 13,
        ..Sqe::default()
    };
    assert_eq!(
        run(&mut h, &r, &[rewrite, set(FSETXATTR, fd, b"old", 0, 14)]),
        [(13, 3, 0), (14, 0, 0)]
    );
    assert_eq!(run(&mut h, &r, &[get(FGETXATTR, fd, 16, 15)]), [(15, 3, 0)]);
    assert_eq!(bytes_at(&h, value + 0x100, 3), b"old");
}

/// Opens `name` in `d` through the guest.
fn open_via(h: &mut Harness, d: &Dir, at: u64, name: &str) -> i32 {
    let p = d.put(h, at, name);
    h.ok(Sysno::Openat, &[AT_FDCWD as u64, p, 2, 0]) as i32
}
