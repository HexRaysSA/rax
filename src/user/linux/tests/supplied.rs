//! Supplied files through ELF startup and all five Linux guest syscall ABIs.
use super::harness::{ARM_EABI5_HARD_FLOAT, CODE, DATA, Harness};
use super::loader::{Seg, image, image32};
use crate::user::image::elf::{
    EM_386, EM_AARCH64, EM_ARM, EM_RISCV, EM_X86_64, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X,
};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::loader::ImageFile;
use crate::user::linux::{LinuxConfig, LinuxProcess};
use crate::user::supplied_fs::{Device, Files};
use std::collections::BTreeMap;
use std::sync::Arc;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];
const AT_FDCWD: u64 = -100i64 as u64;

fn put(h: &Harness, at: u64, bytes: &[u8]) {
    h.proc.space().write_raw(at, bytes).unwrap();
}
fn path(h: &Harness, at: u64, name: &str) {
    put(h, at, &[name.as_bytes(), &[0]].concat());
}
fn get(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    h.proc.space().read(at, &mut bytes).unwrap();
    bytes
}
fn mmap(h: &mut Harness, fd: u64, prot: u64, flags: u64) -> i64 {
    let syscall = if h.abi().is_compat() {
        Sysno::Mmap2
    } else {
        Sysno::Mmap
    };
    h.call(syscall, &[0, 4096, prot, flags, fd, 0])
}
fn program(abi: LinuxAbi) -> Vec<u8> {
    let segs = [
        Seg::load(CODE, 0, 0x2000, 0x2000, PF_R | PF_X),
        Seg::load(DATA, 0x2000, 0x1000, 0x2000, PF_R | PF_W),
    ];
    match abi {
        LinuxAbi::X86_64 => image(EM_X86_64, ET_EXEC, CODE + 0x1000, &segs, None),
        LinuxAbi::Aarch64 => image(EM_AARCH64, ET_EXEC, CODE + 0x1000, &segs, None),
        LinuxAbi::Riscv64 => image(EM_RISCV, ET_EXEC, CODE + 0x1000, &segs, None),
        LinuxAbi::I386 => image32(EM_386, ET_EXEC, (CODE + 0x1000) as u32, &segs),
        LinuxAbi::Arm => {
            let mut bytes = image32(EM_ARM, ET_EXEC, (CODE + 0x1000) as u32, &segs);
            bytes[36..40].copy_from_slice(&ARM_EABI5_HARD_FLOAT.to_le_bytes());
            bytes
        }
    }
}

#[test]
fn supplied_null_uses_linux_device_semantics_on_all_guest_abis() {
    use crate::user::linux::abi::open::{
        O_ACCMODE, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_WRONLY,
    };
    use crate::user::linux::syscall::{path::stat_open, ready::raw_fd};

    let files = Files::default().with_device(Device::Null).unwrap();
    assert!(matches!(
        files.read("/dev/null"),
        Err(crate::user::supplied_fs::Error::NotRegular)
    ));
    let override_files = Files::default()
        .with_file("/dev/null".into(), Arc::from(&b"caller file"[..]))
        .unwrap()
        .with_device(Device::Null)
        .unwrap();
    assert_eq!(&*override_files.read("/dev/null").unwrap(), b"caller file");
    for abi in ABIS {
        let mut h = Harness::with_supplied(abi, files.clone());
        let (name, buf, iov) = (h.scratch, h.scratch + 512, h.scratch + 1024);
        path(&h, name, "/dev/null");
        assert_eq!(h.ok(Sysno::Faccessat2, &[AT_FDCWD, name, 6, 0]), 0);
        assert_eq!(h.err(Sysno::Faccessat2, &[AT_FDCWD, name, 1, 0]), EACCES);
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_RDWR), 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(file.host_path.is_none());
        assert!(raw_fd(&file).is_none());
        let st = stat_open(&file, (0, 0)).unwrap();
        assert_eq!(
            (st.mode, st.rdev_major, st.rdev_minor, st.blksize, st.size),
            (0o020666, 1, 3, 4096, 0)
        );

        put(&h, buf, b"keep");
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 4]), 0);
        assert_eq!(get(&h, buf, 4), b"keep");
        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 4, 0, 0, 0]), 0);
        assert_eq!(h.ok(Sysno::Write, &[fd, buf, 4]), 4);
        assert_eq!(h.ok(Sysno::Pwrite64, &[fd, buf, 4, 0, 0, 0]), 4);
        let word = if abi.is_compat() { 4 } else { 8 };
        put(&h, iov, &buf.to_le_bytes()[..word]);
        put(&h, iov + word as u64, &4u64.to_le_bytes()[..word]);
        assert_eq!(h.ok(Sysno::Readv, &[fd, iov, 1]), 0);
        assert_eq!(h.ok(Sysno::Writev, &[fd, iov, 1]), 4);
        for whence in 0..=4 {
            assert_eq!(h.ok(Sysno::Lseek, &[fd, 9, whence]), 0);
        }
        assert_eq!(h.err(Sysno::Lseek, &[fd, 0, 5]), EINVAL);

        assert_eq!(h.err(Sysno::Ioctl, &[fd, 0x541b, buf]), ENOTTY);
        put(&h, buf, &1u32.to_le_bytes());
        assert_eq!(h.ok(Sysno::Ioctl, &[fd, 0x5421, buf]), 0);
        assert_ne!(file.flags() & O_NONBLOCK, 0);
        put(&h, buf, &(fd as u32).to_le_bytes());
        put(&h, buf + 4, &5u32.to_le_bytes());
        assert_eq!(h.ok(Sysno::Ppoll, &[buf, 1, 0, 0, 0]), 1);
        assert_eq!(get(&h, buf + 6, 2), 5u16.to_le_bytes());
        let ep = h.ok(Sysno::EpollCreate1, &[0]);
        put(&h, buf, &1u128.to_le_bytes());
        assert_eq!(h.err(Sysno::EpollCtl, &[ep, 1, fd, buf]), EPERM);
        assert_eq!(mmap(&mut h, fd, 1, 2), -i64::from(ENODEV));
        assert_eq!(h.err(Sysno::Fsync, &[fd]), EINVAL);

        let input = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_RDONLY), 0]);
        let output = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_WRONLY), 0]);
        assert_eq!(h.err(Sysno::Write, &[input, buf, 1]), EBADF);
        assert_eq!(h.err(Sysno::Read, &[output, buf, 1]), EBADF);
        for flags in [O_ACCMODE, O_PATH] {
            let restricted = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(flags), 0]);
            assert_eq!(h.err(Sysno::Read, &[restricted, buf, 1]), EBADF);
            assert_eq!(h.err(Sysno::Write, &[restricted, buf, 1]), EBADF);
        }
        path(&h, name, "/dev/null/..");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOTDIR);
    }
}

#[test]
fn supplied_zero_reads_and_maps_guest_only_memory_on_all_abis() {
    use crate::user::linux::abi::open::{O_RDONLY, O_RDWR, O_WRONLY};
    use crate::user::linux::syscall::{path::stat_open, ready::raw_fd};

    let files = Files::default().with_device(Device::Zero).unwrap();
    for abi in ABIS {
        let mut h = Harness::with_supplied(abi, files.clone());
        let (name, buf, iov) = (h.scratch, h.scratch + 512, h.scratch + 1024);
        path(&h, name, "/dev/zero");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_RDWR), 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(raw_fd(&file).is_none());
        let st = stat_open(&file, (0, 0)).unwrap();
        assert_eq!((st.mode, st.rdev_major, st.rdev_minor), (0o020666, 1, 5));

        put(&h, buf, &[0xa5; 16]);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 8]), 8);
        assert_eq!(get(&h, buf, 16), [&[0; 8][..], &[0xa5; 8]].concat());
        assert_eq!(h.err(Sysno::Read, &[fd, 1, 1]), EFAULT);
        let word = if abi.is_compat() { 4 } else { 8 };
        put(&h, iov, &(buf + 8).to_le_bytes()[..word]);
        put(&h, iov + word as u64, &8u64.to_le_bytes()[..word]);
        assert_eq!(h.ok(Sysno::Readv, &[fd, iov, 1]), 8);
        assert_eq!(get(&h, buf, 16), [0; 16]);
        assert_eq!(h.ok(Sysno::Write, &[fd, 1, 4]), 4);
        assert_eq!(h.ok(Sysno::Lseek, &[fd, 19, 0]), 0);

        for flags in [1, 2] {
            let address = mmap(&mut h, fd, 3, flags);
            assert!(address > 0);
            let address = address as u64;
            assert_eq!(get(&h, address, 16), [0; 16]);
            put(&h, address, b"guest");
            assert_eq!(get(&h, address, 5), b"guest");
        }
        let input = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_RDONLY), 0]);
        let output = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_WRONLY), 0]);
        assert_eq!(mmap(&mut h, input, 3, 1), -i64::from(EACCES));
        assert_eq!(mmap(&mut h, output, 1, 2), -i64::from(EACCES));
        assert_eq!(h.err(Sysno::Read, &[output, buf, 1]), EBADF);
        assert_eq!(h.err(Sysno::Write, &[input, buf, 1]), EBADF);
    }
}

#[test]
fn supplied_urandom_shares_guest_entropy_on_all_abis() {
    use crate::user::linux::abi::open::{O_PATH, O_WRONLY};
    use crate::user::linux::syscall::{path::stat_open, ready::raw_fd};

    let files = Files::default().with_device(Device::Urandom).unwrap();
    for abi in ABIS {
        let mut h = Harness::with_supplied(abi, files.clone());
        let (name, buf, iov) = (h.scratch, h.scratch + 512, h.scratch + 1024);
        path(&h, name, "/dev/urandom");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(raw_fd(&file).is_none());
        let st = stat_open(&file, (0, 0)).unwrap();
        assert_eq!((st.mode, st.rdev_major, st.rdev_minor), (0o020666, 1, 9));
        assert_eq!(mmap(&mut h, fd, 1, 2), -i64::from(ENODEV));

        let mut entropy = h.proc.state.entropy.clone();
        let mut expected = [0; 8];
        assert_eq!(h.err(Sysno::Read, &[fd, 1, 8]), EFAULT);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 8]), 8);
        entropy.fill(&mut expected).unwrap();
        assert_eq!(get(&h, buf, 8), expected);

        let word = if abi.is_compat() { 4 } else { 8 };
        for (index, base) in [buf, buf + 32].into_iter().enumerate() {
            let at = iov + (index * 2 * word) as u64;
            put(&h, at, &base.to_le_bytes()[..word]);
            put(&h, at + word as u64, &8u64.to_le_bytes()[..word]);
        }
        assert_eq!(h.ok(Sysno::Readv, &[fd, iov, 2]), 16);
        for base in [buf, buf + 32] {
            entropy.fill(&mut expected).unwrap();
            assert_eq!(get(&h, base, 8), expected);
        }

        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 8, 0, 0, 0]), 8);
        entropy.fill(&mut expected).unwrap();
        assert_eq!(get(&h, buf, 8), expected);
        assert_eq!(h.ok(Sysno::Getrandom, &[buf, 8, 0]), 8);
        entropy.fill(&mut expected).unwrap();
        assert_eq!(get(&h, buf, 8), expected);

        for flags in [O_PATH, O_WRONLY] {
            let restricted = h.ok(Sysno::Openat, &[AT_FDCWD, name, flags.into(), 0]);
            assert_eq!(h.err(Sysno::Read, &[restricted, buf, 8]), EBADF);
        }
    }
}

#[test]
fn selected_host_files_use_demand_reads_and_guest_local_descriptors_all_abis() {
    let fixture =
        crate::user::supplied_fs::test_backing::TestFile::new(b"native-library", (64 << 20) + 1);
    for abi in ABIS {
        let files = Files::default()
            .with_host_file("/lib/native.so".into(), &fixture.path)
            .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let (name, buf) = (h.scratch, h.scratch + 512);
        path(&h, name, "/lib/native.so");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(file.host_path.is_none());
        assert!(crate::user::linux::syscall::ready::raw_fd(&file).is_none());
        assert!(matches!(
            h.proc.state.vfs.read_image("/lib/native.so"),
            Err(_)
        ));
        assert_eq!(h.ok(Sysno::Ioctl, &[fd, 0x541b, buf]), 0);
        assert_eq!(
            u32::from_le_bytes(get(&h, buf, 4).try_into().unwrap()),
            (64 << 20) + 1
        );
        let duplicate = h.ok(Sysno::Dup, &[fd]);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 6]), 6);
        assert_eq!(get(&h, buf, 6), b"native");
        assert_eq!(h.ok(Sysno::Read, &[duplicate, buf, 8]), 8);
        assert_eq!(get(&h, buf, 8), b"-library");
        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 14, 0, 0, 0]), 14);
        assert_eq!(get(&h, buf, 14), b"native-library");
        assert_eq!(h.ok(Sysno::Lseek, &[duplicate, 0, 1]), 14);
        assert_eq!(h.ok(Sysno::Lseek, &[fd, 0, 2]), (64 << 20) + 1);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 1]), 0);
        assert_eq!(h.ok(Sysno::Lseek, &[fd, 0, 0]), 0);
        let private = mmap(&mut h, fd, 3, 2);
        assert!(private > 0);
        assert_eq!(get(&h, private as u64, 14), b"native-library");
        put(&h, private as u64, b"private");
        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 14, 0, 0, 0]), 14);
        assert_eq!(get(&h, buf, 14), b"native-library");
        assert_eq!(mmap(&mut h, fd, 3, 1), -i64::from(EACCES));
        let shared = mmap(&mut h, fd, 1, 1);
        assert!(shared > 0);
        assert_eq!(h.err(Sysno::Mprotect, &[shared as u64, 4096, 3]), EACCES);
        assert_eq!(h.err(Sysno::Write, &[fd, buf, 1]), EBADF);
        assert_eq!(h.ok(Sysno::Close, &[fd]), 0);
        assert_eq!(h.ok(Sysno::Close, &[duplicate]), 0);
        assert_eq!(get(&h, shared as u64, 14), b"native-library");
        assert_eq!(
            crate::user::linux::syscall::path::stat_open(&file, (0, 0))
                .unwrap()
                .size,
            (64 << 20) + 1
        );
    }
}

#[test]
fn selected_file_stats_observe_live_truncation_all_abis() {
    for abi in ABIS {
        let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"library", 7);
        let files = Files::default()
            .with_host_file("/lib/native.so".into(), &fixture.path)
            .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let (name, buf) = (h.scratch, h.scratch + 512);
        path(&h, name, "/lib/native.so");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(3)
            .unwrap();
        assert_eq!(
            crate::user::linux::syscall::path::stat_open(&file, (0, 0))
                .unwrap()
                .size,
            3
        );
        assert_eq!(h.ok(Sysno::Statx, &[AT_FDCWD, name, 0, 0x7ff, buf]), 0);
        assert_eq!(
            u64::from_le_bytes(get(&h, buf + 40, 8).try_into().unwrap()),
            3
        );
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 16]), 3);
        assert_eq!(get(&h, buf, 3), b"lib");
    }
}

#[cfg(unix)]
#[test]
fn installed_library_links_support_metadata_and_path_descriptors_all_abis() {
    use crate::user::linux::abi::open::O_PATH;
    use crate::user::linux::syscall::path::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
    use std::os::unix::fs::symlink;

    let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"loader", 6);
    let lib64 = fixture.dir.join("usr/lib64");
    std::fs::create_dir_all(lib64.join("sub/child")).unwrap();
    std::fs::write(lib64.join("loader"), b"loader").unwrap();
    std::fs::write(lib64.join("sub/sibling"), b"sibling").unwrap();
    symlink("usr/lib64", fixture.dir.join("lib64")).unwrap();
    symlink("loader", lib64.join("ld.so")).unwrap();
    symlink("sub/child", lib64.join("directory-link")).unwrap();
    symlink("missing", lib64.join("dangling")).unwrap();
    symlink("loop", lib64.join("loop")).unwrap();
    symlink("/unselected/loader", lib64.join("outside")).unwrap();
    let files = Files::default()
        .with_linux_library_roots(
            BTreeMap::from([
                ("/lib64".into(), fixture.dir.join("lib64")),
                ("/usr/lib64".into(), lib64),
            ]),
            None,
            &[],
            &[],
        )
        .unwrap();
    assert_eq!(
        files
            .children("/")
            .unwrap()
            .iter()
            .find(|(name, _)| name == "lib64")
            .unwrap()
            .1
            .link_target(),
        Some(&b"usr/lib64"[..])
    );

    for abi in ABIS {
        let mut h = Harness::with_supplied(abi, files.clone());
        let (name, buf) = (h.scratch, h.scratch + 512);
        path(&h, name, "/lib64");
        assert_eq!(h.ok(Sysno::Readlinkat, &[AT_FDCWD, name, buf, 32]), 9);
        assert_eq!(get(&h, buf, 9), b"usr/lib64");
        path(&h, name, "/lib64/");
        assert_eq!(h.err(Sysno::Readlinkat, &[AT_FDCWD, name, buf, 32]), EINVAL);

        path(&h, name, "/lib64/ld.so");
        assert_eq!(h.ok(Sysno::Statx, &[AT_FDCWD, name, 0, 0x7ff, buf]), 0);
        let mode = u16::from_le_bytes(get(&h, buf + 28, 2).try_into().unwrap());
        assert_eq!(mode & 0o170000, 0o100000);
        assert_eq!(
            h.ok(
                Sysno::Statx,
                &[AT_FDCWD, name, u64::from(AT_SYMLINK_NOFOLLOW), 0x7ff, buf]
            ),
            0
        );
        let mode = u16::from_le_bytes(get(&h, buf + 28, 2).try_into().unwrap());
        assert_eq!(mode, 0o120777);
        let nofollow = u64::from(abi.open_flags().nofollow);
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, nofollow, 0]), ELOOP);
        let link = h.ok(
            Sysno::Openat,
            &[AT_FDCWD, name, u64::from(O_PATH) | nofollow, 0],
        );
        path(&h, name, "");
        assert_eq!(h.ok(Sysno::Readlinkat, &[link, name, buf, 3]), 3);
        assert_eq!(get(&h, buf, 3), b"loa");
        assert_eq!(h.err(Sysno::Read, &[link, buf, 3]), EBADF);
        assert_eq!(
            h.ok(
                Sysno::Statx,
                &[link, name, u64::from(AT_EMPTY_PATH), 0x7ff, buf]
            ),
            0
        );
        assert_eq!(
            u16::from_le_bytes(get(&h, buf + 28, 2).try_into().unwrap()),
            0o120777
        );

        path(&h, name, "/usr/lib64/dangling");
        assert_eq!(h.ok(Sysno::Readlinkat, &[AT_FDCWD, name, buf, 32]), 7);
        assert_eq!(get(&h, buf, 7), b"missing");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOENT);
        path(&h, name, "/usr/lib64/outside");
        assert_eq!(h.ok(Sysno::Readlinkat, &[AT_FDCWD, name, buf, 32]), 18);
        assert_eq!(get(&h, buf, 18), b"/unselected/loader");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOENT);
        path(&h, name, "/usr/lib64/loop");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ELOOP);

        path(&h, name, "/lib64/directory-link");
        let dir = h.ok(Sysno::Openat, &[AT_FDCWD, name, u64::from(O_PATH), 0]);
        path(&h, name, "../sibling");
        let fd = h.ok(Sysno::Openat, &[dir, name, 0, 0]);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 16]), 7);
        assert_eq!(get(&h, buf, 7), b"sibling");
    }
}

#[test]
fn supplied_files_read_seek_stat_map_and_enumerate_all_abis() {
    for abi in ABIS {
        let data: Arc<[u8]> = Arc::from(&b"provided bytes"[..]);
        let files = Files::new(BTreeMap::from([
            ("/data/file".into(), data.clone()),
            ("/data/other".into(), Arc::from(&b"other"[..])),
        ]))
        .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        assert!(h.proc.state.exe_host_path.is_none());
        assert!(Arc::ptr_eq(
            &data,
            &h.proc.state.vfs.read_image("/data/file").unwrap()
        ));
        assert_eq!(
            h.proc
                .state
                .vfs
                .host_path("/etc/hosts", true)
                .unwrap_err()
                .0,
            EPERM
        );
        let (name, buf) = (h.scratch, h.scratch + 512);
        path(&h, name, "/data/file");
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        assert!(file.host_path.is_none());
        assert!(crate::user::linux::syscall::ready::raw_fd(&file).is_none());
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 128]), 14);
        assert_eq!(get(&h, buf, 14), &*data);
        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 8, 0, 0, 0]), 8);
        assert_eq!(get(&h, buf, 8), b"provided");
        let stat = crate::user::linux::syscall::path::stat_open(&file, (0, 0)).unwrap();
        assert_eq!(stat.size, 14);
        assert_eq!(stat.blocks, 1);
        assert_eq!(stat.mode, 0o100555);
        assert_eq!((stat.uid, stat.gid), (0, 0));
        assert_eq!(h.ok(Sysno::Statx, &[AT_FDCWD, name, 0, 0x7ff, buf]), 0);
        assert_eq!(
            u64::from_le_bytes(get(&h, buf + 32, 8).try_into().unwrap()),
            stat.ino
        );
        let mapped = mmap(&mut h, fd, 3, 2);
        assert!(mapped > 0);
        assert_eq!(get(&h, mapped as u64, 14), &*data);
        put(&h, mapped as u64, b"private");
        assert_eq!(&*h.proc.state.vfs.read_image("/data/file").unwrap(), &*data);
        assert_eq!(mmap(&mut h, fd, 3, 1), -i64::from(EACCES));
        let shared = mmap(&mut h, fd, 1, 1);
        assert!(shared > 0);
        assert_eq!(h.err(Sysno::Mprotect, &[shared as u64, 4096, 3]), EACCES);
        let path_fd = h.ok(
            Sysno::Openat,
            &[
                AT_FDCWD,
                name,
                crate::user::linux::abi::open::O_PATH as u64,
                0,
            ],
        );
        assert_eq!(mmap(&mut h, path_fd, 1, 2), -i64::from(EBADF));
        let mmap_call = if abi.is_compat() {
            Sysno::Mmap2
        } else {
            Sysno::Mmap
        };
        assert_eq!(h.err(mmap_call, &[0, 0, 1, 2, path_fd, 0]), EBADF);
        assert_eq!(h.err(mmap_call, &[0, 0, 1, 0x22, path_fd, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 1, 0]), EROFS);
        assert_eq!(h.err(Sysno::Faccessat2, &[AT_FDCWD, name, 2, 0]), EACCES);
        path(&h, name, "/data/file/../other");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOTDIR);
        path(&h, name, "/data/file/.");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOTDIR);
        path(&h, name, "/data");
        assert_eq!(h.ok(Sysno::Chdir, &[name]), 0);
        let directory = h.ok(
            Sysno::Openat,
            &[AT_FDCWD, name, abi.open_flags().directory as u64, 0],
        );
        assert_eq!(h.err(Sysno::Pread64, &[directory, buf, 8, 0, 0, 0]), EISDIR);
        let count = h.ok(Sysno::Getdents64, &[directory, buf, 512]);
        let entries = get(&h, buf, count as usize);
        let mut at = 0;
        let mut names = Vec::new();
        while at < entries.len() {
            let reclen = u16::from_le_bytes(entries[at + 16..at + 18].try_into().unwrap()) as usize;
            let name = entries[at + 19..at + reclen]
                .split(|b| *b == 0)
                .next()
                .unwrap();
            names.push(String::from_utf8(name.to_vec()).unwrap());
            at += reclen;
        }
        assert_eq!(names, [".", "..", "file", "other"]);
        path(&h, name, "../prog");
        let main = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        assert_eq!(h.ok(Sysno::Read, &[main, buf, 4]), 4);
        assert_eq!(get(&h, buf, 4), b"\x7fELF");
    }
}

#[test]
fn supplied_programs_and_scripts_exec_without_host_paths_all_abis() {
    for abi in ABIS {
        let files = Files::new(BTreeMap::from([
            ("/bin/next".into(), Arc::from(program(abi))),
            ("/script".into(), Arc::from(&b"#!/bin/next optional\n"[..])),
        ]))
        .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let name = h.scratch;
        path(&h, name, "/script");
        assert!(h.start(0, Sysno::Execve, &[name, 0, 0]).is_some());
        assert_eq!(h.proc.state.exe_path, "/bin/next");
        assert!(h.proc.state.exe_host_path.is_none());
        assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 0x1000);
        assert_eq!(h.proc.state.exec_id, 1);
        assert_eq!(h.proc.state.cmdline, b"/bin/next\0optional\0/script\0");
    }
}

#[test]
fn elf_interpreter_is_supplied_and_missing_interpreters_do_not_fall_back() {
    let interp_path = "/supplied/ld.so";
    let main = image(
        EM_X86_64,
        ET_EXEC,
        CODE + 0x1000,
        &[Seg::load(CODE, 0, 0x2000, 0x2000, PF_R | PF_X)],
        Some(interp_path),
    );
    let interp = image(
        EM_X86_64,
        ET_DYN,
        0x1000,
        &[Seg::load(0, 0, 0x2000, 0x2000, PF_R | PF_X)],
        None,
    );
    let mut config = LinuxConfig::new("/prog", vec![b"prog".to_vec()], vec![]);
    config.cwd = "/".into();
    config.seed = Some(0);
    config.arena_bytes = 128 << 20;
    config.fsnotify = crate::user::linux::fsnotify::Backend::Host;
    config.console = crate::user::console::Console::Captured(
        crate::user::console::CapturedConsole::new(Vec::new(), 1024).unwrap(),
    );
    config.supplied_files = Some(Files::default());
    let missing = LinuxProcess::spawn(config.clone(), ImageFile::new(main.clone(), "/prog"));
    assert!(matches!(
        missing,
        Err(crate::user::linux::SpawnError::Load(
            crate::user::linux::loader::LoadError::Interpreter { .. }
        ))
    ));
    config.supplied_files = Some(
        Files::new(BTreeMap::from([(
            "/supplied/ld.so".into(),
            Arc::from(interp),
        )]))
        .unwrap(),
    );
    let process =
        LinuxProcess::spawn(config.clone(), ImageFile::new(main.clone(), "/prog")).unwrap();
    assert!(process.state.mm().program.interp_base > 0);
    assert_eq!(
        process.threads[0].cpu.pc(),
        process.state.mm().program.interp_base + 0x1000
    );
    // Non-UTF-8 PT_INTERP bytes cannot alias a replacement-character key.
    let mut invalid = main.clone();
    let start = invalid
        .windows(interp_path.len())
        .position(|p| p == interp_path.as_bytes())
        .unwrap();
    invalid[start + 1] = 0xff;
    let bytes = config
        .supplied_files
        .as_ref()
        .unwrap()
        .read(interp_path)
        .unwrap();
    config.supplied_files =
        Some(Files::new(BTreeMap::from([("/�upplied/ld.so".into(), bytes)])).unwrap());
    match LinuxProcess::spawn(config.clone(), ImageFile::new(invalid, "/prog"))
        .err()
        .expect("invalid interpreter path")
    {
        crate::user::linux::SpawnError::Load(error) => assert_eq!(error.errno(), EINVAL),
        other => panic!("unexpected failure: {other}"),
    }
    config.sysroot = Some(std::env::temp_dir());
    assert!(matches!(
        LinuxProcess::spawn(config, ImageFile::new(main, "/prog")),
        Err(crate::user::linux::SpawnError::Unsupported(_))
    ));
}

struct HostFixture(std::path::PathBuf);
impl HostFixture {
    fn new() -> Self {
        let nonce = crate::host::time::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rax-supplied-host-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for HostFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn supplied_bytes_override_existing_host_files_and_missing_names_never_fall_back() {
    let fixture = HostFixture::new();
    let shadowed = fixture.0.join("shadowed");
    let missing = fixture.0.join("not-supplied");
    let loader = fixture.0.join("ld.so");
    std::fs::write(&shadowed, b"host original").unwrap();
    std::fs::write(&missing, b"host not supplied").unwrap();
    // A valid interpreter really exists at the named host path.
    std::fs::write(
        &loader,
        image(
            EM_X86_64,
            ET_DYN,
            0x1000,
            &[Seg::load(0, 0, 0x2000, 0x2000, PF_R | PF_X)],
            None,
        ),
    )
    .unwrap();
    for abi in ABIS {
        let files = Files::new(BTreeMap::from([(
            shadowed.to_str().unwrap().into(),
            Arc::from(&b"guest"[..]),
        )]))
        .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let name = h.scratch;
        let buf = name + 512;
        path(&h, name, shadowed.to_str().unwrap());
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, name, 0, 0]);
        assert_eq!(h.ok(Sysno::Read, &[fd, buf, 128]), 5);
        assert_eq!(get(&h, buf, 5), b"guest");
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0x201, 0]), EROFS);
        assert_eq!(h.err(Sysno::Unlinkat, &[AT_FDCWD, name, 0]), EROFS);
        path(&h, name, missing.to_str().unwrap());
        assert_eq!(h.err(Sysno::Openat, &[AT_FDCWD, name, 0, 0]), ENOENT);
        assert_eq!(std::fs::read(&shadowed).unwrap(), b"host original");
        assert_eq!(std::fs::read(&missing).unwrap(), b"host not supplied");
        // The same fget rule applies to legacy host-backed O_PATH files.
        let mut host = Harness::new(abi);
        let name = host.scratch;
        path(&host, name, shadowed.to_str().unwrap());
        let path_fd = host.ok(
            Sysno::Openat,
            &[
                AT_FDCWD,
                name,
                crate::user::linux::abi::open::O_PATH as u64,
                0,
            ],
        );
        assert_eq!(mmap(&mut host, path_fd, 1, 2), -i64::from(EBADF));
    }
    let main = image(
        EM_X86_64,
        ET_EXEC,
        CODE + 0x1000,
        &[Seg::load(CODE, 0, 0x2000, 0x2000, PF_R | PF_X)],
        Some(loader.to_str().unwrap()),
    );
    let mut config = LinuxConfig::new("/prog", vec![], vec![]);
    config.cwd = "/".into();
    config.seed = Some(0);
    config.arena_bytes = 128 << 20;
    config.supplied_files = Some(Files::default());
    let error = LinuxProcess::spawn(config, ImageFile::new(main, "/prog"))
        .err()
        .expect("host interpreter must not be read");
    match error {
        crate::user::linux::SpawnError::Load(error) => assert_eq!(error.errno(), ENOENT),
        other => panic!("unexpected failure: {other}"),
    }
}

#[test]
fn supplied_execveat_empty_path_keeps_image_bytes_after_cloexec_all_abis() {
    for abi in ABIS {
        let files =
            Files::new(BTreeMap::from([("/next".into(), Arc::from(program(abi)))])).unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let name = h.scratch;
        path(&h, name, "/next");
        let fd = h.ok(
            Sysno::Openat,
            &[
                AT_FDCWD,
                name,
                crate::user::linux::abi::open::O_CLOEXEC as u64,
                0,
            ],
        );
        path(&h, name, "");
        assert!(
            h.start(0, Sysno::Execveat, &[fd, name, 0, 0, 0x1000])
                .is_some()
        );
        assert_eq!(h.proc.state.exe_path, "/next");
        assert!(h.proc.state.exe_host_path.is_none());
        assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 0x1000);
        assert!(h.proc.state.fds.get(fd as i32).is_err());
        assert_eq!(get(&h, CODE, 4), b"\x7fELF");
    }
}

#[test]
fn supplied_exec_paths_and_script_interpreters_reject_invalid_utf8_without_aliasing() {
    for abi in ABIS {
        let files = Files::new(BTreeMap::from([
            ("/�".into(), Arc::from(program(abi))),
            ("/bad-script".into(), Arc::from(&b"#!/\xff\n"[..])),
        ]))
        .unwrap();
        let mut h = Harness::with_supplied(abi, files);
        let name = h.scratch;
        put(&h, name, b"/\xff\0");
        assert_eq!(h.err(Sysno::Execve, &[name, 0, 0]), EINVAL);
        path(&h, name, "/bad-script");
        assert_eq!(h.err(Sysno::Execve, &[name, 0, 0]), EINVAL);
        assert_eq!(h.proc.state.exec_id, 0);
        assert_eq!(h.proc.state.exe_path, "/prog");
    }
}
