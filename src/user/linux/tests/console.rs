//! Captured descriptors through the native and compatibility syscall tables.
use super::harness::Harness;
use crate::user::console::{CapturedConsole, OutputStream};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::syscall::ready::raw_fd;

const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

fn bytes(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    h.proc.space().read(at, &mut out).unwrap();
    out
}

#[test]
fn captured_streams_read_eof_refill_duplicates_and_faults() {
    for abi in ABIS {
        let console = CapturedConsole::new(b"input".to_vec(), 8).unwrap();
        let mut h = Harness::with_console(abi, console.clone());
        let buf = h.scratch;
        for fd in 0..3 {
            let file = h.proc.state.fds.file(fd).unwrap();
            assert!(raw_fd(&file).is_none());
            assert!(file.host_path.is_none());
            assert_eq!(file.seek(0, 0).unwrap_err().0, ESPIPE);
        }
        assert_eq!(h.err(Sysno::Read, &[0, 8, 5]), EFAULT);
        assert_eq!(
            console.pending().unwrap().0,
            5,
            "fault must not consume input"
        );
        assert_eq!(h.ok(Sysno::Ioctl, &[0, 0x541b, buf]), 0);
        assert_eq!(bytes(&h, buf, 4), 5u32.to_le_bytes());
        let dup = h.ok(Sysno::Dup, &[0]);
        assert_eq!(h.ok(Sysno::Read, &[dup, buf, 2]), 2);
        assert_eq!(bytes(&h, buf, 2), b"in");
        assert_eq!(h.ok(Sysno::Read, &[0, buf, 8]), 3);
        assert_eq!(bytes(&h, buf, 3), b"put");
        assert_eq!(h.ok(Sysno::Read, &[0, buf, 8]), 0);
        console.feed(b"again").unwrap();
        assert_eq!(h.ok(Sysno::Read, &[dup, buf, 8]), 5);
        assert_eq!(bytes(&h, buf, 5), b"again");
        assert_eq!(h.err(Sysno::Read, &[1, buf, 1]), EBADF);
        assert_eq!(h.err(Sysno::Write, &[0, buf, 1]), EBADF);
        assert_eq!(h.err(Sysno::Ioctl, &[1, 0x5401, buf]), ENOTTY);
        assert_eq!(h.err(Sysno::Pread64, &[0, buf, 1, 0, 0]), ESPIPE);
        assert_eq!(h.err(Sysno::Pwrite64, &[1, buf, 1, 0, 0]), ESPIPE);
    }
}

#[test]
fn captured_output_bounds_shared_streams_and_descriptor_lifetime() {
    for abi in ABIS {
        let console = CapturedConsole::new(Vec::new(), 8).unwrap();
        let mut h = Harness::with_console(abi, console.clone());
        let buf = h.scratch;
        h.proc.space().write_raw(buf, b"abcdefghij").unwrap();
        let dup = h.ok(Sysno::Dup, &[1]);
        assert_eq!(h.ok(Sysno::Close, &[1]), 0);
        assert_eq!(h.ok(Sysno::Write, &[dup, buf, 5]), 5);
        assert_eq!(h.ok(Sysno::Write, &[2, buf + 5, 3]), 3);
        assert_eq!(console.pending().unwrap(), (0, 5, 3));
        assert_eq!(h.err(Sysno::Write, &[dup, buf, 1]), EIO);
        assert_eq!(console.pending().unwrap(), (0, 5, 3));
        let mut out = [0; 8];
        assert_eq!(console.drain(OutputStream::Stdout, &mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"abcde");
        assert_eq!(h.ok(Sysno::Write, &[dup, buf, 5]), 5);
        assert_eq!(h.ok(Sysno::Close, &[dup]), 0);
        assert_eq!(console.drain(OutputStream::Stderr, &mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"fgh");
        assert_eq!(console.pending().unwrap(), (0, 5, 0));
        assert_eq!(h.err(Sysno::Write, &[2, 8, 1]), EFAULT);
        assert_eq!(console.pending().unwrap(), (0, 5, 0));
    }
}

#[test]
fn captured_metadata_and_poll_have_no_host_descriptor_dependency() {
    for abi in ABIS {
        let console = CapturedConsole::new(Vec::new(), 0).unwrap();
        let mut h = Harness::with_console(abi, console);
        for fd in 0..3 {
            let file = h.proc.state.fds.file(fd).unwrap();
            let stat = crate::user::linux::syscall::path::stat_open(&file, (123, 456)).unwrap();
            assert_eq!(stat.mode, 0o020600);
            assert_eq!(stat.ino, 0x5241_5810 + fd as u64);
            assert_eq!((stat.uid, stat.gid), (123, 456));
        }
        let buf = h.scratch;
        // struct pollfd: stdin requests IN, stdout/stderr OUT. Empty input
        // is EOF; even a full output reports ready because it fails immediately.
        let poll: Vec<u8> = [(0i32, 1u16), (1, 4), (2, 4)]
            .into_iter()
            .flat_map(|(fd, events)| {
                [
                    fd.to_le_bytes().to_vec(),
                    events.to_le_bytes().to_vec(),
                    vec![0; 2],
                ]
                .concat()
            })
            .collect();
        h.proc.space().write_raw(buf, &poll).unwrap();
        assert_eq!(h.ok(Sysno::Ppoll, &[buf, 3, 0, 0, 0]), 3);
        let result = bytes(&h, buf, 24);
        for (idx, mask) in [1u16, 4, 4].into_iter().enumerate() {
            assert_eq!(
                u16::from_le_bytes(result[idx * 8 + 6..idx * 8 + 8].try_into().unwrap()),
                mask
            );
        }
        let ep = h.ok(Sysno::EpollCreate1, &[0]);
        assert_eq!(h.err(Sysno::EpollCtl, &[ep, 1, 0, buf]), EPERM);
    }
}

#[test]
fn captured_vectored_and_chunked_writes_report_only_the_retained_prefix() {
    for abi in ABIS {
        let console = CapturedConsole::new(Vec::new(), 8).unwrap();
        let mut h = Harness::with_console(abi, console.clone());
        let buf = h.scratch;
        h.proc.space().write_raw(buf + 128, b"abcdefghij").unwrap();
        let vectors: Vec<u8> = [(buf + 128, 5u64), (buf + 133, 5)]
            .into_iter()
            .flat_map(|(addr, len)| {
                if abi.is_compat() {
                    [(addr as u32).to_le_bytes(), (len as u32).to_le_bytes()].concat()
                } else {
                    [addr.to_le_bytes(), len.to_le_bytes()].concat()
                }
            })
            .collect();
        h.proc.space().write_raw(buf, &vectors).unwrap();
        // Unpositioned vectored calls gather into the same bounded write.
        assert_eq!(h.err(Sysno::Writev, &[1, buf, 2]), EIO);
        assert_eq!(console.pending().unwrap(), (0, 0, 0));
        assert_eq!(
            h.err(Sysno::Pwritev2, &[1, buf, 2, u64::MAX, u64::MAX, 0]),
            EIO
        );
        assert_eq!(console.pending().unwrap(), (0, 0, 0));
        assert_eq!(h.err(Sysno::Pwritev2, &[1, buf, 2, 0, 0, 0]), ESPIPE);
        assert_eq!(h.ok(Sysno::Writev, &[1, buf, 1]), 5);
        assert_eq!(console.pending().unwrap(), (0, 5, 0));
        let mut out = [0; 8];
        assert_eq!(console.drain(OutputStream::Stdout, &mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"abcde");
        console.feed(b"12345678").unwrap();
        assert_eq!(h.ok(Sysno::Preadv2, &[0, buf, 2, u64::MAX, u64::MAX, 0]), 8);
        assert_eq!(bytes(&h, buf + 128, 8), b"12345678");
        assert_eq!(h.ok(Sysno::Readv, &[0, buf, 2]), 0);
        assert_eq!(h.err(Sysno::Preadv2, &[0, buf, 2, 0, 0, 0]), ESPIPE);

        const CHUNK: usize = 1 << 20;
        let large = CapturedConsole::new(Vec::new(), CHUNK + 7).unwrap();
        let mut h = Harness::with_console(abi, large.clone());
        let mmap = if abi.is_compat() {
            Sysno::Mmap2
        } else {
            Sysno::Mmap
        };
        let at = h.ok(mmap, &[0, (2 * CHUNK) as u64, 3, 0x22, u64::MAX, 0]);
        h.proc
            .space()
            .write_raw(at, &vec![0xA5; 2 * CHUNK])
            .unwrap();
        assert_eq!(
            h.ok(Sysno::Write, &[1, at, (2 * CHUNK) as u64]),
            CHUNK as u64
        );
        assert_eq!(large.pending().unwrap(), (0, CHUNK, 0));
        let mut out = vec![0; CHUNK];
        assert_eq!(large.drain(OutputStream::Stdout, &mut out).unwrap(), CHUNK);
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }
}
