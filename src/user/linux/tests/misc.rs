//! Supplementary groups (`kernel/groups.c`), `readahead`
//! (`mm/readahead.c`), and `sync_file_range` (`fs/sync.c`), Linux 6.19,
//! driven through the system calls.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};

const AT_FDCWD: u64 = -100i64 as u64;

fn put_u32s(h: &Harness, off: u64, v: &[u32]) -> u64 {
    let b: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    h.proc.state.space.write_raw(h.scratch + off, &b).unwrap();
    h.scratch + off
}

fn u32s(h: &Harness, at: u64, n: usize) -> Vec<u32> {
    let mut b = vec![0u8; 4 * n];
    h.proc.state.space.read(at, &mut b).unwrap();
    b.chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

#[test]
fn groups_are_inherited_sorted_and_set_by_root() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // A new process has its parent's groups.
        assert_eq!(h.proc.state.groups, crate::user::linux::host::groups());
        let buf = h.scratch + 0x400;
        let n = h.ok(Sysno::Getgroups, &[0, 0]) as usize;
        assert_eq!(h.call(Sysno::Getgroups, &[n as u64, buf]), n as i64);
        assert_eq!(u32s(&h, buf, n), h.proc.state.groups);
        assert_eq!(h.err(Sysno::Getgroups, &[u64::MAX, buf]), EINVAL);
        if n > 0 {
            assert_eq!(h.err(Sysno::Getgroups, &[n as u64 - 1, buf]), EINVAL);
        }
        // Without CAP_SETGID, whatever the arguments.
        h.proc.state.creds.1 = 1000;
        let set = put_u32s(&h, 0x200, &[9, 3, 5]);
        assert_eq!(h.err(Sysno::Setgroups, &[3, set]), EPERM, "{abi:?}");
        assert_eq!(h.err(Sysno::Setgroups, &[70000, 8]), EPERM);
        h.proc.state.creds.1 = 0;
        assert_eq!(h.err(Sysno::Setgroups, &[65537, set]), EINVAL);
        assert_eq!(h.err(Sysno::Setgroups, &[u64::MAX, set]), EINVAL);
        assert_eq!(h.err(Sysno::Setgroups, &[1, 8]), EFAULT);
        let bad = put_u32s(&h, 0x300, &[4, u32::MAX]);
        assert_eq!(h.err(Sysno::Setgroups, &[2, bad]), EINVAL);
        assert_eq!(h.call(Sysno::Setgroups, &[3, set]), 0);
        assert_eq!(h.call(Sysno::Getgroups, &[8, buf]), 3);
        assert_eq!(u32s(&h, buf, 3), [3, 5, 9], "sorted");
        assert_eq!(h.call(Sysno::Setgroups, &[0, 0]), 0);
        assert_eq!(h.call(Sysno::Getgroups, &[0, 0]), 0);
    });
}

#[test]
fn proc_status_lists_the_groups_with_a_trailing_space() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.state.groups = vec![3, 5, 9];
    let at = h.scratch + 0x100;
    h.proc
        .state
        .space
        .write_raw(at, b"/proc/self/status\0")
        .unwrap();
    let fd = h.ok(Sysno::Openat, &[AT_FDCWD, at, 0, 0]);
    let buf = h.scratch + 0x400;
    let n = h.ok(Sysno::Read, &[fd, buf, 0xc00]) as usize;
    let mut b = vec![0u8; n];
    h.proc.state.space.read(buf, &mut b).unwrap();
    let text = String::from_utf8(b).unwrap();
    assert!(text.contains("\nGroups:\t3 5 9 \n"), "{text}");
}

#[test]
fn readahead_and_sync_file_range_check_the_file() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let f = h.file("misc", 16, b'x', 2);
    let fds = h.scratch + 0x200;
    h.ok(Sysno::Pipe2, &[fds, 0]);
    let p = u64::from(u32s(&h, fds, 1)[0]);
    let s = h.ok(Sysno::Socket, &[1, 1, 0]);
    assert_eq!(h.call(Sysno::Readahead, &[f, 0, 4096]), 0);
    assert_eq!(h.err(Sysno::Readahead, &[p, 0, 4096]), EINVAL);
    assert_eq!(h.err(Sysno::Readahead, &[s, 0, 4096]), EINVAL);
    assert_eq!(h.err(Sysno::Readahead, &[99, 0, 4096]), EBADF);
    assert_eq!(h.call(Sysno::SyncFileRange, &[f, 0, 16, 7]), 0);
    assert_eq!(h.call(Sysno::SyncFileRange, &[f, 4, 0, 2]), 0);
    assert_eq!(h.err(Sysno::SyncFileRange, &[f, 0, 16, 8]), EINVAL);
    assert_eq!(h.err(Sysno::SyncFileRange, &[f, u64::MAX, 16, 0]), EINVAL);
    assert_eq!(
        h.err(Sysno::SyncFileRange, &[f, i64::MAX as u64, 2, 0]),
        EINVAL
    );
    assert_eq!(h.err(Sysno::SyncFileRange, &[p, 0, 0, 0]), ESPIPE);
    assert_eq!(h.err(Sysno::SyncFileRange, &[s, 0, 0, 0]), ESPIPE);
    // The flags come before the file's kind.
    assert_eq!(h.err(Sysno::SyncFileRange, &[p, 0, 0, 8]), EINVAL);
}
