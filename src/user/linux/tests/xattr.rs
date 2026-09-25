//! Extended attributes (`fs/xattr.c`, Linux 6.19), driven through the
//! system calls on host files.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AT_FDCWD: u64 = -100i64 as u64;
const AT_EMPTY_PATH: u64 = 0x1000;
const XATTR_CREATE: u64 = 1;

/// A host file for one test, removed when dropped.
struct File(std::path::PathBuf);

impl File {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rax-xattr-t-{tag}-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        File(p)
    }

    fn path(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn put(h: &Harness, off: u64, b: &[u8]) -> u64 {
    h.proc.state.space.write_raw(h.scratch + off, b).unwrap();
    h.scratch + off
}

fn cstr(h: &Harness, off: u64, s: &[u8]) -> u64 {
    put(h, off, &[s, b"\0"].concat())
}

fn get(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

#[test]
fn setxattr_checks_flags_then_name_then_value_then_path() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = File::new(&format!("order-{abi:?}"));
        let path = cstr(&h, 0x100, f.path().as_bytes());
        let none = cstr(&h, 0x200, b"/rax-no-such-dir/x");
        let name = cstr(&h, 0x300, b"user.a");
        let val = put(&h, 0x340, b"v");
        let set = |h: &mut Harness, p, n, v, size, flags| {
            h.call(Sysno::Setxattr, &[p, n, v, size, flags])
        };
        let e = |x: i32| -(x as i64);
        assert_eq!(
            set(&mut h, none, name, val, 1, 4),
            e(EINVAL),
            "{abi:?}: flags first"
        );
        let empty = cstr(&h, 0x380, b"");
        assert_eq!(
            set(&mut h, none, empty, val, 1, 0),
            e(ERANGE),
            "then the name"
        );
        assert_eq!(set(&mut h, none, 8, val, 1, 0), e(EFAULT));
        assert_eq!(
            set(&mut h, none, name, val, 65537, 0),
            e(E2BIG),
            "then the size"
        );
        assert_eq!(
            set(&mut h, none, name, 8, 1, 0),
            e(EFAULT),
            "then the value"
        );
        assert_eq!(
            set(&mut h, none, name, val, 1, 0),
            e(ENOENT),
            "then the path"
        );
        assert_eq!(set(&mut h, path, name, val, 1, 0), 0);
        assert_eq!(set(&mut h, path, name, val, 1, XATTR_CREATE), e(EEXIST));
        // A name of 255 bytes is the longest.
        let long = [b"user.".to_vec(), vec![b'n'; 250]].concat();
        let ln = cstr(&h, 0x400, &long);
        assert_eq!(set(&mut h, path, ln, val, 1, 0), 0);
        let longer = [long.clone(), b"n".to_vec()].concat();
        let lr = cstr(&h, 0x400, &longer);
        assert_eq!(set(&mut h, path, lr, val, 1, 0), e(ERANGE));
        // Both names are listed (NUL-terminated), in any order.
        let buf = h.scratch + 0x600;
        let n = h.ok(Sysno::Listxattr, &[path, buf, 0x400]) as usize;
        let list = get(&h, buf, n);
        let mut names: Vec<&[u8]> = list.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
        names.sort();
        assert_eq!(names, [&b"user.a"[..], &long[..]], "{abi:?}");
        assert_eq!(h.call(Sysno::Listxattr, &[path, 0, 0]), n as i64);
        assert_eq!(h.err(Sysno::Listxattr, &[path, buf, 3]), ERANGE);
    });
}

#[test]
fn namespaces_follow_xattr_permission_and_the_handlers() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let f = File::new("spaces");
    let path = cstr(&h, 0x100, f.path().as_bytes());
    let val = put(&h, 0x340, b"v");
    let buf = h.scratch + 0x600;
    let set = |h: &mut Harness, n: &[u8]| {
        let name = cstr(h, 0x300, n);
        h.call(Sysno::Setxattr, &[path, name, val, 1, 0])
    };
    let getx = |h: &mut Harness, n: &[u8]| {
        let name = cstr(h, 0x300, n);
        h.call(Sysno::Getxattr, &[path, name, buf, 16])
    };
    let e = |x: i32| -(x as i64);
    h.proc.state.creds.1 = 1000;
    assert_eq!(set(&mut h, b"trusted.t"), e(EPERM));
    assert_eq!(getx(&mut h, b"trusted.t"), e(ENODATA));
    assert_eq!(set(&mut h, b"security.s"), e(EPERM));
    assert_eq!(getx(&mut h, b"security.s"), e(ENODATA));
    assert_eq!(set(&mut h, b"user."), e(EINVAL));
    assert_eq!(set(&mut h, b"foo.bar"), e(EOPNOTSUPP));
    assert_eq!(getx(&mut h, b"foo.bar"), e(EOPNOTSUPP));
    assert_eq!(set(&mut h, b"system.foo"), e(EOPNOTSUPP));
    // No POSIX ACLs.
    assert_eq!(set(&mut h, b"system.posix_acl_access"), e(EOPNOTSUPP));
    assert_eq!(getx(&mut h, b"system.posix_acl_default"), e(EOPNOTSUPP));
    // Root may use trusted.*, which only root sees listed.
    h.proc.state.creds.1 = 0;
    if cfg!(not(target_os = "linux")) {
        assert_eq!(set(&mut h, b"trusted.t"), 0);
        assert_eq!(getx(&mut h, b"trusted.t"), 1);
        let n = h.ok(Sysno::Listxattr, &[path, buf, 0x100]);
        assert_eq!(get(&h, buf, n as usize), b"trusted.t\0");
        h.proc.state.creds.1 = 1000;
        assert_eq!(h.call(Sysno::Listxattr, &[path, buf, 0x100]), 0);
    }
}

/// A macOS host keeps names of its own, which are not shown (a Linux host
/// has only Linux names).
#[cfg(not(target_os = "linux"))]
#[test]
fn only_linux_names_are_listed() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = File::new("host");
    use crate::user::linux::fs::xattr::{self, Obj};
    xattr::set(Obj::Path(&f.0, true), b"com.example.host", b"x", 0).unwrap();
    xattr::set(Obj::Path(&f.0, true), b"user.mine", b"y", 0).unwrap();
    let path = cstr(&h, 0x100, f.path().as_bytes());
    let buf = h.scratch + 0x600;
    let n = h.ok(Sysno::Listxattr, &[path, buf, 0x100]);
    assert_eq!(get(&h, buf, n as usize), b"user.mine\0");
    let name = cstr(&h, 0x300, b"com.example.host");
    assert_eq!(h.err(Sysno::Getxattr, &[path, name, buf, 16]), EOPNOTSUPP);
}

#[test]
fn descriptors_sockets_and_the_at_calls() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = File::new(&format!("fd-{abi:?}"));
        let path = cstr(&h, 0x100, f.path().as_bytes());
        let buf = h.scratch + 0x600;
        let name = cstr(&h, 0x300, b"user.x");
        let val = put(&h, 0x340, b"zz");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, path, 0, 0]);
        assert_eq!(h.call(Sysno::Fsetxattr, &[fd, name, val, 2, 0]), 0);
        assert_eq!(h.call(Sysno::Fgetxattr, &[fd, name, buf, 16]), 2);
        // O_PATH descriptors are refused (fdget).
        let op = h.ok(Sysno::Openat, &[AT_FDCWD, path, 0o10000000, 0]);
        assert_eq!(h.err(Sysno::Fgetxattr, &[op, name, buf, 16]), EBADF);
        // A pipe: user.* only for files and directories; nothing listed.
        let fds = h.scratch + 0x500;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let r = u64::from(u32::from_le_bytes(get(&h, fds, 4).try_into().unwrap()));
        assert_eq!(h.err(Sysno::Fsetxattr, &[r, name, val, 2, 0]), EPERM);
        assert_eq!(h.err(Sysno::Fgetxattr, &[r, name, buf, 16]), ENODATA);
        assert_eq!(h.call(Sysno::Flistxattr, &[r, buf, 16]), 0);
        // A Unix stream socket names its protocol.
        let s = h.ok(Sysno::Socket, &[1, 1, 0]);
        let proto = cstr(&h, 0x380, b"system.sockprotoname");
        assert_eq!(h.call(Sysno::Fgetxattr, &[s, proto, buf, 16]), 12);
        assert_eq!(get(&h, buf, 12), b"UNIX-STREAM\0");
        assert_eq!(h.call(Sysno::Flistxattr, &[s, buf, 64]), 21);
        // struct xattr_args: its size, trailing bytes, and flags.
        let args = |h: &Harness, v: u64, size: u32, flags: u32, extra: u64| {
            let mut b = v.to_le_bytes().to_vec();
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&flags.to_le_bytes());
            b.extend_from_slice(&extra.to_le_bytes());
            put(h, 0x700, &b)
        };
        let a = args(&h, buf, 16, 0, 0);
        assert_eq!(
            h.err(Sysno::Getxattrat, &[AT_FDCWD, path, 0, name, a, 8]),
            EINVAL
        );
        assert_eq!(
            h.err(Sysno::Getxattrat, &[AT_FDCWD, path, 0, name, a, 8192]),
            E2BIG
        );
        assert_eq!(
            h.call(Sysno::Getxattrat, &[AT_FDCWD, path, 0, name, a, 24]),
            2
        );
        let a = args(&h, buf, 16, 0, 1);
        assert_eq!(
            h.err(Sysno::Getxattrat, &[AT_FDCWD, path, 0, name, a, 24]),
            E2BIG
        );
        let a = args(&h, buf, 16, 1, 0);
        assert_eq!(
            h.err(Sysno::Getxattrat, &[AT_FDCWD, path, 0, name, a, 16]),
            EINVAL
        );
        let a = args(&h, buf, 16, 0, 0);
        assert_eq!(
            h.call(Sysno::Getxattrat, &[fd, 0, AT_EMPTY_PATH, name, a, 16]),
            2,
            "a null path with AT_EMPTY_PATH is the descriptor"
        );
        // A list or removal of nothing from AT_FDCWD has no descriptor.
        let empty = cstr(&h, 0x380, b"");
        assert_eq!(
            h.err(
                Sysno::Listxattrat,
                &[AT_FDCWD, empty, AT_EMPTY_PATH, buf, 16]
            ),
            EBADF
        );
        assert_eq!(
            h.call(Sysno::Removexattrat, &[fd, empty, AT_EMPTY_PATH, name]),
            0
        );
        assert_eq!(
            h.err(Sysno::Removexattrat, &[fd, empty, AT_EMPTY_PATH, name]),
            ENODATA
        );
    });
}
