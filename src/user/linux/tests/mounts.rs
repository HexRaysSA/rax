//! Mounts (`fs/namespace.c`, `fs/fsopen.c`, Linux 6.19): each call's
//! checks in the kernel's order, `EPERM` at `may_mount` for an
//! unprivileged caller, and for root the checks after it and then
//! `EOPNOTSUPP` for the change; `open_tree` without a clone as an `O_PATH`
//! open.

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::errno_table::*;

const NOBODY: u32 = 65534;
/// Never mapped (below `mmap_min_addr`).
const BAD: u64 = 0x10;
const AT_FDCWD: u64 = -100i64 as u64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_RECURSIVE: u64 = 0x8000;
const OPEN_TREE_CLONE: u64 = 1;
const O_CLOEXEC: u64 = 0o2000000;
const O_PATH: u64 = 0o10000000;
const F_GETFD: u64 = 1;
const F_GETFL: u64 = 3;
const MISSING: &str = "/nonexistent-rax-user-mount";

fn creds(h: &mut Harness, id: u32) {
    h.proc.state.creds = (id, id, id, id);
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn cstr(h: &Harness, at: u64, s: &str) -> u64 {
    put(h, at, &[s.as_bytes(), &[0]].concat());
    at
}

/// A host directory holding a file and a dangling symbolic link.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(h: &Harness, name: &str) -> Self {
        let d = std::env::temp_dir().join(format!(
            "rax-user-mounts-{}-{name}-{:?}",
            std::process::id(),
            h.abi()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("file"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("gone"), d.join("dangling")).unwrap();
        Dir(d)
    }

    fn at(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn mount_copies_its_arguments_and_looks_up_the_mount_point_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        h.ok(Sysno::Munmap, &[m + 3 * P, P]);
        let slash = cstr(&h, m, "/");
        let tmpfs = cstr(&h, m + 0x10, "tmpfs");
        let missing = cstr(&h, m + 0x20, MISSING);
        // A type of PATH_MAX bytes without its NUL.
        let long = m + 0x100;
        put(&h, long, &[b't'; 4096]);
        cstr(&h, long + 4095, "");
        let too_long = m + 2 * P;
        put(&h, too_long, &[b't'; 4096]);
        // Options at the very end of the mapping: one readable byte is
        // enough.
        let data = m + 3 * P - 1;
        for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
            creds(&mut h, id);
            let mount = |h: &mut Harness, dev, dir, ty, flags, data| {
                h.err(Sysno::Mount, &[dev, dir, ty, flags, data])
            };
            assert_eq!(mount(&mut h, BAD, BAD, BAD, u64::MAX, BAD), EFAULT);
            assert_eq!(mount(&mut h, BAD, BAD, too_long, u64::MAX, BAD), EINVAL);
            assert_eq!(mount(&mut h, BAD, BAD, long, u64::MAX, BAD), EFAULT);
            assert_eq!(mount(&mut h, BAD, BAD, 0, u64::MAX, BAD), EFAULT);
            assert_eq!(mount(&mut h, tmpfs, BAD, tmpfs, u64::MAX, BAD), EFAULT);
            assert_eq!(mount(&mut h, 0, BAD, 0, u64::MAX, data), EFAULT);
            assert_eq!(mount(&mut h, 0, missing, 0, u64::MAX, 0), ENOENT);
            // MS_NOUSER, unless it is part of the old 0xC0ED magic.
            assert_eq!(mount(&mut h, 0, slash, 0, 1 << 31, 0), EINVAL);
            assert_eq!(mount(&mut h, 0, slash, 0, u64::MAX, 0), EINVAL);
            assert_eq!(mount(&mut h, 0, slash, 0, 0xc0ed_0000, 0), last);
            assert_eq!(mount(&mut h, tmpfs, slash, tmpfs, 0, data), last);
            assert_eq!(mount(&mut h, 0, slash, long, 1 << 32, 0), last);
        }
    });
}

#[test]
fn umount2_checks_its_flags_and_path_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let d = Dir::new(&h, "umount");
        let m = h.anon(P, 3, false);
        let slash = cstr(&h, m, "/");
        let dangling = cstr(&h, m + 0x100, &d.at("dangling"));
        for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
            creds(&mut h, id);
            assert_eq!(h.err(Sysno::Umount2, &[slash, 16]), EINVAL);
            assert_eq!(h.err(Sysno::Umount2, &[BAD, u64::MAX]), EINVAL);
            assert_eq!(h.err(Sysno::Umount2, &[BAD, 1]), EFAULT);
            assert_eq!(h.err(Sysno::Umount2, &[dangling, 0]), ENOENT);
            // UMOUNT_NOFOLLOW finds the link itself.
            assert_eq!(h.err(Sysno::Umount2, &[dangling, 8]), last);
            assert_eq!(h.err(Sysno::Umount2, &[slash, 1 | 2 | 4]), last);
        }
    });
}

#[test]
fn the_new_mount_calls_check_may_mount_first() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let slash = cstr(&h, m, "/");
        let missing = cstr(&h, m + 0x20, MISSING);
        let empty = cstr(&h, m + 0x80, "");
        let tmpfs = cstr(&h, m + 0x90, "tmpfs");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, slash, 0, 0]);
        creds(&mut h, NOBODY);
        assert_eq!(h.err(Sysno::PivotRoot, &[BAD, BAD]), EPERM);
        assert_eq!(h.err(Sysno::MoveMount, &[0, BAD, 0, BAD, u64::MAX]), EPERM);
        assert_eq!(h.err(Sysno::Fsopen, &[BAD, u64::MAX]), EPERM);
        assert_eq!(h.err(Sysno::Fspick, &[0, BAD, u64::MAX]), EPERM);
        assert_eq!(
            h.err(Sysno::Fsmount, &[u64::MAX, u64::MAX, u64::MAX]),
            EPERM
        );
        creds(&mut h, 0);
        assert_eq!(h.err(Sysno::PivotRoot, &[BAD, BAD]), EOPNOTSUPP);
        // move_mount: its flags, MOVE_MOUNT_BENEATH excluding
        // MOVE_MOUNT_SET_GROUP.
        assert_eq!(h.err(Sysno::MoveMount, &[0, BAD, 0, BAD, 0x8]), EINVAL);
        assert_eq!(h.err(Sysno::MoveMount, &[0, BAD, 0, BAD, 0x300]), EINVAL);
        assert_eq!(
            h.err(Sysno::MoveMount, &[0, BAD, 0, BAD, 0x277]),
            EOPNOTSUPP
        );
        // fsopen: its flags, then the name.
        assert_eq!(h.err(Sysno::Fsopen, &[tmpfs, 2]), EINVAL);
        assert_eq!(h.err(Sysno::Fsopen, &[BAD, 1]), EFAULT);
        assert_eq!(h.err(Sysno::Fsopen, &[tmpfs, 1]), EOPNOTSUPP);
        // fspick: its flags, then the lookup.
        assert_eq!(h.err(Sysno::Fspick, &[AT_FDCWD, slash, 16]), EINVAL);
        assert_eq!(h.err(Sysno::Fspick, &[AT_FDCWD, missing, 0]), ENOENT);
        assert_eq!(h.err(Sysno::Fspick, &[AT_FDCWD, empty, 0]), ENOENT);
        assert_eq!(h.err(Sysno::Fspick, &[fd, empty, 8]), EOPNOTSUPP);
        assert_eq!(h.err(Sysno::Fspick, &[AT_FDCWD, slash, 0xf]), EOPNOTSUPP);
        // fsmount: its flags and attributes, then a context there never is.
        assert_eq!(h.err(Sysno::Fsmount, &[fd, 2, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Fsmount, &[fd, 0, 0x100]), EINVAL);
        for atime in [0x30, 0x40, 0x50, 0x60, 0x70] {
            assert_eq!(h.err(Sysno::Fsmount, &[fd, 0, atime]), EINVAL);
        }
        assert_eq!(h.err(Sysno::Fsmount, &[99, 1, 0x2000ff & !0x50]), EBADF);
        assert_eq!(h.err(Sysno::Fsmount, &[fd, 1, 0x20]), EINVAL);
    });
}

// `FSCONFIG_*`.
const SET_FLAG: u64 = 0;
const SET_STRING: u64 = 1;
const SET_BINARY: u64 = 2;
const SET_PATH: u64 = 3;
const SET_PATH_EMPTY: u64 = 4;
const SET_FD: u64 = 5;
const CMD_CREATE: u64 = 6;
const CMD_CREATE_EXCL: u64 = 8;

#[test]
fn fsconfig_finds_no_file_system_context() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let slash = cstr(&h, m, "/");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, slash, 0, 0]);
        let path_fd = h.ok(Sysno::Openat, &[AT_FDCWD, slash, O_PATH, 0]);
        let k = m + 0x10;
        let fsconfig = |h: &mut Harness, fd, cmd, key, value, aux: i64| {
            h.err(Sysno::Fsconfig, &[fd, cmd, key, value, aux as u64])
        };
        for id in [NOBODY, 0] {
            creds(&mut h, id);
            assert_eq!(fsconfig(&mut h, u64::MAX, SET_FLAG, k, 0, 0), EINVAL);
            assert_eq!(fsconfig(&mut h, 99, 9, k, 0, 0), EOPNOTSUPP);
            assert_eq!(fsconfig(&mut h, 99, u64::MAX, 0, 0, 0), EOPNOTSUPP);
            // Each command's arguments.
            for (cmd, key, value, aux) in [
                (SET_FLAG, 0, 0, 0),
                (SET_FLAG, k, k, 0),
                (SET_FLAG, k, 0, 1),
                (SET_STRING, k, 0, 0),
                (SET_STRING, k, k, 1),
                (SET_BINARY, k, k, 0),
                (SET_BINARY, k, k, (1 << 20) + 1),
                (SET_PATH, k, k, -1),
                (SET_PATH_EMPTY, 0, k, 0),
                (SET_FD, k, k, 0),
                (SET_FD, k, 0, -1),
                (CMD_CREATE, k, 0, 0),
                (CMD_CREATE_EXCL, 0, 0, 1),
            ] {
                assert_eq!(fsconfig(&mut h, 99, cmd, key, value, aux), EINVAL, "{cmd}");
            }
            for (cmd, key, value, aux) in [
                (SET_FLAG, k, 0, 0),
                (SET_BINARY, k, k, 1 << 20),
                (SET_PATH, k, k, -100),
                (SET_PATH_EMPTY, k, k, 3),
                (SET_FD, k, 0, 3),
                (7, 0, 0, 0),
            ] {
                assert_eq!(fsconfig(&mut h, 99, cmd, key, value, aux), EBADF, "{cmd}");
                assert_eq!(fsconfig(&mut h, path_fd, cmd, key, value, aux), EBADF);
                assert_eq!(fsconfig(&mut h, fd, cmd, key, value, aux), EINVAL);
            }
        }
    });
}

#[test]
fn open_tree_opens_a_path_without_privilege() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        creds(&mut h, NOBODY);
        let d = Dir::new(&h, "tree");
        let m = h.anon(P, 3, false);
        let file = cstr(&h, m, &d.at("file"));
        let dangling = cstr(&h, m + 0x200, &d.at("dangling"));
        let missing = cstr(&h, m + 0x400, MISSING);
        let empty = cstr(&h, m + 0x480, "");
        let stat = m + 0x800;
        let mode = |h: &Harness| {
            let at = stat
                + if h.abi() == crate::user::linux::abi::LinuxAbi::X86_64 {
                    24
                } else {
                    16
                };
            let mut b = [0u8; 4];
            h.proc.state.space.read(at, &mut b).unwrap();
            u32::from_le_bytes(b) & 0o170000
        };
        // f_flags are exactly O_PATH.
        let t = h.ok(Sysno::OpenTree, &[AT_FDCWD, file, O_CLOEXEC]);
        assert_eq!(h.call(Sysno::Fcntl, &[t, F_GETFL, 0]) as u64, O_PATH);
        assert_eq!(h.call(Sysno::Fcntl, &[t, F_GETFD, 0]), 1);
        assert_eq!(h.err(Sysno::Read, &[t, m, 1]), EBADF);
        h.ok(Sysno::Fstat, &[t, stat]);
        assert_eq!(mode(&h), 0o100000);
        // AT_SYMLINK_NOFOLLOW opens the link itself.
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, dangling, 0]), ENOENT);
        let l = h.ok(Sysno::OpenTree, &[AT_FDCWD, dangling, AT_SYMLINK_NOFOLLOW]);
        assert_eq!(h.call(Sysno::Fcntl, &[l, F_GETFL, 0]) as u64, O_PATH);
        assert_eq!(h.call(Sysno::Fcntl, &[l, F_GETFD, 0]), 0);
        h.ok(Sysno::Fstat, &[l, stat]);
        assert_eq!(mode(&h), 0o120000);
        // AT_EMPTY_PATH: a new description of a descriptor's file.
        let rw = h.ok(Sysno::Openat, &[AT_FDCWD, file, 2, 0]);
        let e = h.ok(Sysno::OpenTree, &[rw, empty, AT_EMPTY_PATH]);
        assert_eq!(h.call(Sysno::Fcntl, &[e, F_GETFL, 0]) as u64, O_PATH);
        assert_ne!(h.call(Sysno::Fcntl, &[rw, F_GETFL, 0]) as u64, O_PATH);
        assert_eq!(h.err(Sysno::OpenTree, &[rw, empty, 0]), ENOENT);
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, missing, 0]), ENOENT);
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, BAD, 0]), EFAULT);
        // Flags: unknown ones, and AT_RECURSIVE without a clone.
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, file, 2]), EINVAL);
        // The flags are an unsigned int.
        let u = h.ok(Sysno::OpenTree, &[AT_FDCWD, file, 1 << 32]);
        assert_eq!(h.call(Sysno::Fcntl, &[u, F_GETFL, 0]) as u64, O_PATH);
        assert_eq!(
            h.err(Sysno::OpenTree, &[AT_FDCWD, file, AT_RECURSIVE]),
            EINVAL
        );
        // A clone needs may_mount before the lookup.
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, missing, 1]), EPERM);
        let rc = OPEN_TREE_CLONE | AT_RECURSIVE;
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, file, rc]), EPERM);
        creds(&mut h, 0);
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, missing, 1]), ENOENT);
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, file, rc]), EOPNOTSUPP);
        // A descriptor is taken before anything is checked.
        let low = h.ok(Sysno::Dup, &[rw]);
        h.ok(Sysno::Close, &[low]);
        h.proc.state.rlimits[7].0 = low;
        assert_eq!(h.err(Sysno::OpenTree, &[AT_FDCWD, BAD, 2]), EMFILE);
        assert_eq!(
            h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, BAD, 2, 0, 0]),
            EMFILE
        );
        // But the attributes' presence is checked before that.
        assert_eq!(
            h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, BAD, 2, 0, 8]),
            EINVAL
        );
    });
}

/// Writes a `struct mount_attr` (`attr_set`, `attr_clr`, `propagation`,
/// `userns_fd`) at `at`, and `tail` after it.
fn mount_attr(h: &Harness, at: u64, w: [u64; 4], tail: &[u8]) -> u64 {
    let mut b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
    b.extend_from_slice(tail);
    put(h, at, &b);
    at
}

// `MOUNT_ATTR_*`, `MS_*`.
const RDONLY: u64 = 1;
const NOATIME: u64 = 0x10;
const STRICTATIME: u64 = 0x20;
const ATIME: u64 = 0x70;
const IDMAP: u64 = 0x10_0000;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SHARED: u64 = 1 << 20;

#[test]
fn mount_setattr_checks_the_size_then_may_mount_then_the_attributes() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(2 * P, 3, false);
        h.ok(Sysno::Munmap, &[m + P, P]);
        let slash = cstr(&h, m, "/");
        let missing = cstr(&h, m + 0x20, MISSING);
        let a = m + 0x100;
        let dir = h.ok(Sysno::Openat, &[AT_FDCWD, slash, 0, 0]);
        let setattr = |h: &mut Harness, path, flags, attr, size| {
            h.err(Sysno::MountSetattr, &[AT_FDCWD, path, flags, attr, size])
        };
        for id in [NOBODY, 0] {
            creds(&mut h, id);
            assert_eq!(setattr(&mut h, BAD, 1, BAD, 0), EINVAL);
            assert_eq!(setattr(&mut h, BAD, 0x1_0000, BAD, 0), EINVAL);
            assert_eq!(setattr(&mut h, BAD, 0, BAD, 4097), E2BIG);
            assert_eq!(setattr(&mut h, BAD, 0, BAD, 31), EINVAL);
        }
        creds(&mut h, NOBODY);
        assert_eq!(setattr(&mut h, BAD, 0x9900, BAD, 32), EPERM);
        creds(&mut h, 0);
        mount_attr(&h, a, [0; 4], &[]);
        assert_eq!(setattr(&mut h, missing, 0, BAD, 32), EFAULT);
        // Nothing to change: no lookup.
        assert_eq!(h.call(Sysno::MountSetattr, &[AT_FDCWD, BAD, 0, a, 32]), 0);
        // Bytes past the known structure must be zero; a nonzero one is
        // found before a fault after it.
        let edge = m + P - 40;
        mount_attr(&h, edge, [0; 4], &[0; 8]);
        assert_eq!(
            h.call(Sysno::MountSetattr, &[AT_FDCWD, BAD, 0, edge, 40]),
            0
        );
        assert_eq!(setattr(&mut h, BAD, 0, edge, 41), EFAULT);
        mount_attr(&h, edge, [0; 4], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(setattr(&mut h, BAD, 0, edge, 41), E2BIG);
        // build_mount_kattr.
        for w in [
            [0, 0, 1, 0],
            [0, 0, MS_PRIVATE | MS_SHARED, 0],
            [0x40_0000, 0, 0, 0],
            [0, 0x100, 0, 0],
            [NOATIME, 0, 0, 0],
            [0, NOATIME, 0, 0],
            [0x30, ATIME, 0, 0],
            [0, IDMAP, 0, 0],
            [IDMAP, 0, 0, 1 << 31],
        ] {
            mount_attr(&h, a, w, &[]);
            assert_eq!(setattr(&mut h, BAD, 0, a, 32), EINVAL, "{w:x?}");
        }
        // An idmapping's user namespace comes by descriptor, and no
        // descriptor is one.
        mount_attr(&h, a, [IDMAP, 0, 0, 99], &[]);
        assert_eq!(setattr(&mut h, BAD, 0, a, 32), EBADF);
        mount_attr(&h, a, [IDMAP, 0, 0, dir], &[]);
        assert_eq!(setattr(&mut h, BAD, 0, a, 32), EINVAL);
        // Then the lookup, then the refusal.
        for w in [
            [RDONLY, 0, 0, 0],
            [STRICTATIME, ATIME, 0, 0],
            [0, ATIME, MS_SHARED, 0],
        ] {
            mount_attr(&h, a, w, &[]);
            assert_eq!(setattr(&mut h, missing, 0, a, 32), ENOENT);
            assert_eq!(setattr(&mut h, slash, 0x9900, a, 32), EOPNOTSUPP);
        }
    });
}

#[test]
fn open_tree_attr_applies_attributes_before_publishing_the_descriptor() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let slash = cstr(&h, m, "/");
        let missing = cstr(&h, m + 0x20, MISSING);
        let a = m + 0x100;
        mount_attr(&h, a, [RDONLY, 0, 0, 0], &[]);
        let dir = h.ok(Sysno::Openat, &[AT_FDCWD, slash, 0, 0]);
        for (id, last) in [(NOBODY, EPERM), (0, EOPNOTSUPP)] {
            creds(&mut h, id);
            let low = h.ok(Sysno::Dup, &[dir]);
            h.ok(Sysno::Close, &[low]);
            // Without attributes, open_tree.
            let t = h.ok(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, 0, 0, 0]);
            assert_eq!(t, low);
            assert_eq!(h.call(Sysno::Fcntl, &[t, F_GETFL, 0]) as u64, O_PATH);
            h.ok(Sysno::Close, &[t]);
            // The tree's lookup comes before the attributes.
            assert_eq!(
                h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, missing, 0, BAD, 4097]),
                ENOENT
            );
            assert_eq!(
                h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, 0, BAD, 4097]),
                E2BIG
            );
            assert_eq!(
                h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, 0, BAD, 16]),
                EINVAL
            );
            assert_eq!(
                h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, 0, a, 32]),
                last
            );
            // The descriptor was never published.
            assert_eq!(h.ok(Sysno::Dup, &[dir]), low);
            h.ok(Sysno::Close, &[low]);
        }
        // Root: nothing to change publishes it.
        mount_attr(&h, a, [0; 4], &[]);
        let t = h.ok(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, O_CLOEXEC, a, 32]);
        assert_eq!(h.call(Sysno::Fcntl, &[t, F_GETFD, 0]), 1);
        assert_eq!(
            h.err(Sysno::OpenTreeAttr, &[AT_FDCWD, slash, 0, BAD, 32]),
            EFAULT
        );
        // A clone is refused before its attributes are read.
        assert_eq!(
            h.err(
                Sysno::OpenTreeAttr,
                &[AT_FDCWD, slash, OPEN_TREE_CLONE, BAD, 32]
            ),
            EOPNOTSUPP
        );
    });
}
