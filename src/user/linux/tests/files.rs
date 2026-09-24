//! Open file descriptions' status flags (`f_flags`) as `F_GETFL` reports
//! them: `open` keeps the valid open flags with `O_LARGEFILE` forced and
//! without the creation-time flags and `O_CLOEXEC` (`build_open_how`,
//! `build_open_flags`, `do_dentry_open`); an `O_PATH` open keeps only
//! `O_PATH`, `O_DIRECTORY`, and `O_NOFOLLOW`; pipes and anonymous-inode
//! files never have `O_LARGEFILE` (`create_pipe_files`,
//! `anon_inode_getfile`).

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::Sysno;
use crate::user::linux::abi::open::*;

const F_GETFL: u64 = 3;

fn put_str(h: &Harness, at: u64, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    h.proc.state.space.write_raw(at, &b).unwrap();
}

#[test]
fn status_flags_are_those_the_kernel_records() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let o = abi.open_flags();
        let getfl = |h: &mut Harness, fd: u64| h.ok(Sysno::Fcntl, &[fd, F_GETFL, 0]) as u32;
        // Creation-time flags and O_CLOEXEC go; an unknown bit is ignored.
        let fd = h.file(
            "flags",
            4,
            0,
            u64::from(O_RDWR | O_APPEND | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOCTTY) | 0x4000_0000,
        );
        assert_eq!(
            getfl(&mut h, fd),
            O_RDWR | O_APPEND | o.largefile,
            "{abi:?}: regular"
        );
        let path = h.scratch + 0x400;
        put_str(&h, path, "/");
        let dir = h.ok(
            Sysno::Openat,
            &[-100i64 as u64, path, u64::from(O_RDONLY | o.directory), 0],
        );
        assert_eq!(
            getfl(&mut h, dir),
            o.largefile | o.directory,
            "{abi:?}: directory"
        );
        let opath = h.ok(
            Sysno::Openat,
            &[
                -100i64 as u64,
                path,
                u64::from(O_PATH | o.nofollow | O_CLOEXEC | O_RDWR),
                0,
            ],
        );
        assert_eq!(getfl(&mut h, opath), O_PATH | o.nofollow, "{abi:?}: O_PATH");
        let fds = h.scratch + 0x800;
        h.ok(Sysno::Pipe2, &[fds, u64::from(O_NONBLOCK)]);
        let mut b = [0u8; 8];
        h.proc.state.space.read(fds, &mut b).unwrap();
        let (r, w) = (
            u32::from_le_bytes(b[..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..].try_into().unwrap()),
        );
        assert_eq!(getfl(&mut h, r.into()), O_NONBLOCK, "{abi:?}: pipe");
        assert_eq!(
            getfl(&mut h, w.into()),
            O_WRONLY | O_NONBLOCK,
            "{abi:?}: pipe"
        );
        let ev = h.ok(Sysno::Eventfd2, &[0, u64::from(O_NONBLOCK | O_CLOEXEC)]);
        assert_eq!(getfl(&mut h, ev), O_RDWR | O_NONBLOCK, "{abi:?}: eventfd");
    });
}
