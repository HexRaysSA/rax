//! Linux AIO against `fs/aio.c` (Linux 6.19) on every ABI: `io_setup`'s
//! checks and the ring it maps, `io_submit`'s checks in the kernel's order
//! and the completions of reads, writes, syncs, and polls (a wake-up's key
//! whole, or the events polled again), the ring's request slots, reaping
//! by `io_getevents` and by the process, `io_pgetevents`' mask,
//! `io_cancel`, `io_destroy`, and the ring's mapping under `mremap`,
//! `mlock`, and `mseal`.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{Sysno, vma_flags};
use crate::user::linux::aio::RING_MAGIC;
use crate::user::linux::fs::anon::{Anon, EventFd};
use crate::user::linux::fs::fd::FileObject;
use crate::user::linux::signal::deliver::restart::ERESTARTNOHAND;
use crate::user::linux::signal::{SIGPIPE, SIGUSR1, SIGUSR2, SigPending, sa, sigmask};
use crate::user::linux::wait::Resume;

const PREAD: u16 = 0;
const PWRITE: u16 = 1;
const FSYNC: u16 = 2;
const FDSYNC: u16 = 3;
const POLL: u16 = 5;
const PREADV: u16 = 7;
const PWRITEV: u16 = 8;
const RESFD: u32 = 1;
const IOPRIO: u32 = 2;
const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;
const RWF_ATOMIC: u32 = 0x40;
const RWF_DONTCACHE: u32 = 0x80;
const RWF_NOSIGNAL: u32 = 0x100;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_PATH: u64 = 0o10000000;
const PROT_READ: u64 = 1;
const RW: u64 = 3;
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;
const MCL_FUTURE: u64 = 2;

const POLLIN: i64 = 0x1;
const POLLPRI: i64 = 0x2;
const POLLOUT: i64 = 0x4;
const POLLHUP: i64 = 0x10;
const POLLRDNORM: i64 = 0x40;
const POLLRDBAND: i64 = 0x80;

/// Scratch-page layout: `*ctxp`, the `iocb`s, a buffer, `iovec`s, a
/// timeout, a `struct __aio_sigset` and its mask, descriptor pairs, and
/// the events read.
const CTXP: u64 = 0;
const CB: u64 = 0x40;
const BUF: u64 = 0x300;
const IOV: u64 = 0x400;
const TS: u64 = 0x480;
const USIG: u64 = 0x4a0;
const SET: u64 = 0x4c0;
const FDS: u64 = 0x4e0;
const EVS: u64 = 0x800;

/// `struct aio_ring` fields, in `u32`s.
const NR: usize = 1;
const HEAD: usize = 2;
const TAIL: usize = 3;

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

fn put(h: &Harness, at: u64, b: &[u8]) {
    h.proc.state.space.write_raw(at, b).unwrap();
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    let mut b = [0u8; 8];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    u64::from_le_bytes(b)
}

/// A `struct iocb`.
#[derive(Clone, Copy, Debug, Default)]
struct Cb {
    data: u64,
    key: u32,
    rw_flags: u32,
    op: u16,
    prio: i16,
    fd: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

impl Cb {
    fn new(op: u16, fd: u64, buf: u64, nbytes: u64, offset: i64) -> Cb {
        Cb {
            op,
            fd: fd as u32,
            buf,
            nbytes,
            offset,
            ..Cb::default()
        }
    }

    fn put(&self, h: &Harness, at: u64) -> u64 {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.data.to_le_bytes());
        b.extend_from_slice(&self.key.to_le_bytes());
        b.extend_from_slice(&self.rw_flags.to_le_bytes());
        b.extend_from_slice(&self.op.to_le_bytes());
        b.extend_from_slice(&self.prio.to_le_bytes());
        b.extend_from_slice(&self.fd.to_le_bytes());
        b.extend_from_slice(&self.buf.to_le_bytes());
        b.extend_from_slice(&self.nbytes.to_le_bytes());
        b.extend_from_slice(&self.offset.to_le_bytes());
        b.extend_from_slice(&self.reserved2.to_le_bytes());
        b.extend_from_slice(&self.flags.to_le_bytes());
        b.extend_from_slice(&self.resfd.to_le_bytes());
        put(h, at, &b);
        at
    }
}

/// A `struct io_event`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ev {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

/// `io_setup(n)`: the context.
fn setup(h: &mut Harness, n: u64) -> u64 {
    let ctxp = h.scratch + CTXP;
    put(h, ctxp, &0u64.to_le_bytes());
    h.ok(Sysno::IoSetup, &[n, ctxp]);
    u64_at(h, ctxp)
}

/// `io_submit` of the `iocb`s at `cbs`, their pointers written at `ptrs`.
fn submit_from(h: &mut Harness, ctx: u64, ptrs: u64, cbs: &[u64]) -> i64 {
    let b: Vec<u8> = cbs.iter().flat_map(|p| p.to_le_bytes()).collect();
    put(h, ptrs, &b);
    h.call(Sysno::IoSubmit, &[ctx, cbs.len() as u64, ptrs])
}

/// `io_submit` of the one `iocb` `c`, written in the scratch page.
fn submit(h: &mut Harness, ctx: u64, c: Cb) -> i64 {
    let at = c.put(h, h.scratch + CB);
    submit_from(h, ctx, h.scratch + CB + 0x200, &[at])
}

/// `io_getevents(min_nr, nr)` with `timeout`, into the scratch page.
fn getevents(
    h: &mut Harness,
    ctx: u64,
    min: i64,
    nr: i64,
    timeout: Option<(i64, i64)>,
) -> Result<Vec<Ev>, i32> {
    let ts = match timeout {
        Some((s, ns)) => {
            let at = h.scratch + TS;
            put(h, at, &[s.to_le_bytes(), ns.to_le_bytes()].concat());
            at
        }
        None => 0,
    };
    let evs = h.scratch + EVS;
    let r = h.call(Sysno::IoGetevents, &[ctx, min as u64, nr as u64, evs, ts]);
    if r < 0 {
        return Err(-r as i32);
    }
    Ok((0..r as u64)
        .map(|i| {
            let at = evs + 32 * i;
            Ev {
                data: u64_at(h, at),
                obj: u64_at(h, at + 8),
                res: u64_at(h, at + 16) as i64,
                res2: u64_at(h, at + 24) as i64,
            }
        })
        .collect())
}

/// The events waiting, taken without sleeping.
fn take(h: &mut Harness, ctx: u64) -> Vec<Ev> {
    getevents(h, ctx, 0, 64, Some((0, 0))).unwrap()
}

/// The ring header's eight words.
fn ring(h: &Harness, ctx: u64) -> [u32; 8] {
    std::array::from_fn(|i| u32_at(h, ctx + 4 * i as u64))
}

fn pipe(h: &mut Harness, flags: u64) -> (u64, u64) {
    let at = h.scratch + FDS;
    h.ok(Sysno::Pipe2, &[at, flags]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn socketpair(h: &mut Harness) -> (u64, u64) {
    let at = h.scratch + FDS;
    h.ok(Sysno::Socketpair, &[AF_UNIX, SOCK_STREAM, 0, at]);
    (u64::from(u32_at(h, at)), u64::from(u32_at(h, at + 4)))
}

fn open(h: &mut Harness, path: &str, flags: u64) -> u64 {
    let at = h.scratch + BUF + 0x80;
    put(h, at, format!("{path}\0").as_bytes());
    h.ok(Sysno::Openat, &[-100i64 as u64, at, flags, 0])
}

fn write(h: &mut Harness, fd: u64, b: &[u8]) {
    let at = h.scratch + BUF + 0xc0;
    put(h, at, b);
    assert_eq!(
        h.ok(Sysno::Write, &[fd, at, b.len() as u64]),
        b.len() as u64
    );
}

fn eventfd(h: &Harness, fd: u64) -> std::sync::Arc<crate::user::linux::fs::fd::OpenFile> {
    h.proc.state.fds.file(fd as i32).unwrap()
}

fn count(h: &Harness, fd: u64) -> u64 {
    match &eventfd(h, fd).object {
        FileObject::Anon(Anon::Event(ev)) => ev.count(),
        _ => unreachable!("an eventfd"),
    }
}

/// Writes `b` to pipe `w` from another host thread after 20 ms.
fn write_later(h: &Harness, w: u64, b: &'static [u8]) -> std::thread::JoinHandle<()> {
    let raw = match &h.proc.state.fds.file(w as i32).unwrap().object {
        FileObject::PipeWrite(p) => p.as_raw_fd(),
        _ => unreachable!("a pipe's write end"),
    };
    // SAFETY: a fresh duplicate of a live descriptor, owned once.
    let mut host =
        unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(raw)) };
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        host.write_all(b).unwrap();
    })
}

fn vmas(h: &Harness) -> usize {
    h.proc.state.space.vmas_in(0, u64::MAX).len()
}

/// A handler for `sig` (so a queued one stays queued).
fn handle(h: &mut Harness, sig: i32) {
    let act = h.scratch + 0xf00;
    let mut words = vec![0x40_1000u64];
    if h.abi().has_sa_restorer() {
        words.extend([sa::RESTORER, 0x40_1100]);
    } else {
        words.push(0);
    }
    words.push(0);
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    put(h, act, &b);
    h.ok(Sysno::RtSigaction, &[sig as u64, act, 0, 8]);
}

#[test]
fn io_setup_checks_in_the_kernels_order_and_maps_a_ring() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctxp = h.scratch + CTXP;
        let raw = |h: &mut Harness, n: u64| h.call(Sysno::IoSetup, &[n, ctxp]);
        put(&h, ctxp, &1u64.to_le_bytes());
        assert_eq!(raw(&mut h, 1), e(EINVAL), "*ctxp not 0");
        put(&h, ctxp, &0u64.to_le_bytes());
        assert_eq!(raw(&mut h, 0), e(EINVAL));
        assert_eq!(h.call(Sysno::IoSetup, &[1, 8]), e(EFAULT));
        // ioctx_alloc: twice the events past what the ring indexes, then
        // beyond aio-max-nr (and twice 2^31, which wraps to none).
        assert_eq!(raw(&mut h, 0x40_0001), e(EINVAL));
        assert_eq!(raw(&mut h, 0x40_0000), e(EAGAIN));
        assert_eq!(raw(&mut h, 65537), e(EAGAIN));
        assert_eq!(raw(&mut h, 0x8000_0000), e(EAGAIN));
        assert_eq!(u64_at(&h, ctxp), 0);
        // max(1, 4 * CPUs) * 2 + 2 events in one page: 127 slots.
        let ctx = setup(&mut h, 1);
        assert_eq!(ring(&h, ctx), [0, 127, 0, 0, RING_MAGIC, 1, 0, 32]);
        let v = h.proc.state.space.vma_at(ctx).unwrap();
        assert_eq!((v.start, v.end), (ctx, ctx + P));
        assert_eq!(v.name.as_deref(), Some("/[aio] (deleted)"));
        assert!(v.shared);
        assert_eq!(v.flags, vma_flags::SPECIAL | vma_flags::AIO_RING);
        assert_eq!(h.proc.state.aio.aio_nr, 1);
        // The next context takes the next slot; a destroyed one's is taken
        // again. 64 events: 130 in two pages, 255 slots.
        let big = setup(&mut h, 64);
        assert_eq!(ring(&h, big)[..2], [1, 255]);
        assert_eq!(h.proc.state.space.vma_at(big).unwrap().end, big + 2 * P);
        assert_eq!(h.ok(Sysno::IoDestroy, &[ctx]), 0);
        assert_eq!(h.proc.state.aio.aio_nr, 64);
        let again = setup(&mut h, 2);
        assert_eq!(ring(&h, again)[0], 0);
        // aio-max-nr counts every context's events: a context past it is
        // refused after its ring was mapped, which is unmapped again.
        let most = setup(&mut h, 65536 - 66);
        assert_eq!(h.proc.state.aio.aio_nr, 65536);
        let before = vmas(&h);
        put(&h, ctxp, &0u64.to_le_bytes());
        assert_eq!(raw(&mut h, 1), e(EAGAIN));
        assert_eq!((vmas(&h), u64_at(&h, ctxp)), (before, 0));
        h.ok(Sysno::IoDestroy, &[most]);
        assert_eq!(h.proc.state.aio.aio_nr, 66);
    });
}

#[test]
fn a_ctxp_that_cannot_be_written_destroys_the_context() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ro = h.anon(P, PROT_READ, false);
        let before = vmas(&h);
        assert_eq!(h.call(Sysno::IoSetup, &[1, ro]), e(EFAULT));
        assert_eq!((vmas(&h), h.proc.state.aio.aio_nr), (before, 0));
        assert!(h.proc.state.aio.contexts.iter().all(Option::is_none));
    });
}

#[test]
fn io_submit_checks_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 1);
        let f = h.file("aio-order", 64, b'a', O_RDWR);
        let wo = h.file("aio-order-wo", 8, b'w', O_WRONLY);
        let (r, _w) = pipe(&mut h, 0);
        let (cb, buf) = (h.scratch + CB, h.scratch + BUF);
        // The count, then the context: its ring's ID, then the slot.
        assert_eq!(h.call(Sysno::IoSubmit, &[0x1000, u64::MAX, cb]), e(EINVAL));
        assert_eq!(submit(&mut h, 0x1000, Cb::default()), e(EINVAL));
        assert_eq!(submit(&mut h, ctx + 32, Cb::default()), e(EINVAL));
        assert_eq!(h.call(Sysno::IoSubmit, &[ctx, 0, 8]), 0);
        // The pointer, then the iocb.
        assert_eq!(h.call(Sysno::IoSubmit, &[ctx, 1, 8]), e(EFAULT));
        assert_eq!(submit_from(&mut h, ctx, cb + 0x200, &[8]), e(EFAULT));
        // aio_reserved2, then the length, before the descriptor.
        let bad_fd = Cb::new(PREAD, 999, buf, 1, 0);
        let c = Cb {
            reserved2: 1,
            ..bad_fd
        };
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        let c = Cb {
            nbytes: 1 << 63,
            ..bad_fd
        };
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        // The descriptor, then the eventfd, before the key is written.
        let c = Cb {
            key: 0x55,
            ..bad_fd
        };
        assert_eq!(submit(&mut h, ctx, c), e(EBADF));
        let rd = Cb {
            key: 0x55,
            ..Cb::new(PREAD, f, buf, 1, 0)
        };
        let path = open(&mut h, "/", O_PATH);
        for (resfd, want) in [(999, EBADF), (f, EINVAL), (path, EBADF)] {
            let c = Cb {
                flags: RESFD,
                resfd: resfd as u32,
                ..rd
            };
            assert_eq!(submit(&mut h, ctx, c), e(want), "resfd {resfd}");
        }
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, path, buf, 1, 0)),
            e(EBADF)
        );
        let c = Cb { fd: 999, ..rd };
        c.put(&h, cb);
        assert_eq!(submit_from(&mut h, ctx, cb + 0x200, &[cb]), e(EBADF));
        assert_eq!(u32_at(&h, cb + 8), 0x55, "key untouched");
        // A key that cannot be written.
        let ro = h.anon(P, RW, false);
        rd.put(&h, ro);
        h.ok(Sysno::Mprotect, &[ro, P, PROT_READ]);
        assert_eq!(submit_from(&mut h, ctx, cb + 0x200, &[ro]), e(EFAULT));
        // The operation, after the key.
        rd.put(&h, cb);
        let c = Cb { op: 6, ..rd };
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        assert_eq!(u32_at(&h, cb + 8), 0, "KIOCB_KEY");
        // aio_prep_rw: the I/O priority, then the RWF_* flags, before the
        // access mode.
        let wrong = Cb::new(PREAD, wo, buf, 1, 0);
        let c = Cb {
            flags: IOPRIO,
            prio: (4 << 13) as i16,
            rw_flags: 0x200,
            ..wrong
        };
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL), "no class 4");
        for (flags, want) in [
            (0x200, EOPNOTSUPP),
            (RWF_APPEND | RWF_NOAPPEND, EINVAL),
            (RWF_ATOMIC, EOPNOTSUPP),
        ] {
            let c = Cb {
                rw_flags: flags,
                ..wrong
            };
            assert_eq!(submit(&mut h, ctx, c), e(want), "rw_flags {flags:#x}");
        }
        let c = Cb {
            rw_flags: RWF_DONTCACHE,
            ..Cb::new(PREAD, r, buf, 1, 0)
        };
        assert_eq!(
            submit(&mut h, ctx, c),
            e(EOPNOTSUPP),
            "pipes lack FOP_DONTCACHE"
        );
        assert_eq!(submit(&mut h, ctx, wrong), e(EBADF));
        assert_eq!(submit(&mut h, ctx, Cb::new(PWRITE, r, buf, 1, 0)), e(EBADF));
        // Files without read_iter.
        let dir = open(&mut h, "/", O_RDONLY);
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, dir, buf, 1, 0)),
            e(EINVAL)
        );
        let ep = h.ok(Sysno::EpollCreate1, &[0]);
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, ep, buf, 1, 0)),
            e(EINVAL)
        );
        // The buffer's range, the vectors, then the position.
        let task = h.proc.state.abi.task_size();
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, f, task - 1, 2, 0)),
            e(EFAULT)
        );
        assert_eq!(submit(&mut h, ctx, Cb::new(PREADV, f, 8, 1, 0)), e(EFAULT));
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREADV, f, buf, 1025, 0)),
            e(EINVAL)
        );
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, f, buf, 1, -1)),
            e(EINVAL)
        );
        let c = Cb::new(PREAD, f, buf, 4, i64::MAX - 1);
        assert_eq!(
            submit(&mut h, ctx, c),
            e(EINVAL),
            "past the largest position"
        );
        assert_eq!(
            submit(&mut h, ctx, Cb::new(PREAD, r, buf, 1, -1)),
            e(EINVAL)
        );
        // aio_fsync: its fields, then a file with the operation.
        assert_eq!(submit(&mut h, ctx, Cb::new(FSYNC, f, 0, 1, 0)), e(EINVAL));
        let c = Cb {
            rw_flags: 1,
            ..Cb::new(FDSYNC, f, 0, 0, 0)
        };
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        assert_eq!(submit(&mut h, ctx, Cb::new(FSYNC, r, 0, 0, 0)), e(EINVAL));
        assert!(take(&mut h, ctx).is_empty(), "nothing completed");
        // Each refused request gave its slot back: nr is capped at the
        // ring's 127, and every request the CPU can take goes (124: see
        // below).
        let ptrs = h.anon(P, RW, false);
        Cb::new(FSYNC, f, 0, 0, 0).put(&h, cb);
        assert_eq!(submit_from(&mut h, ctx, ptrs, &[cb; 200]), 124);
        assert_eq!(submit(&mut h, ctx, Cb::new(FSYNC, f, 0, 0, 0)), e(EAGAIN));
        // A failure after the first request: the count before it.
        let evs = h.anon(P, RW, false);
        assert_eq!(h.call(Sysno::IoGetevents, &[ctx, 124, 124, evs, 0]), 124);
        Cb::new(FSYNC, 999, 0, 0, 0).put(&h, cb + 0x40);
        assert_eq!(submit_from(&mut h, ctx, ptrs, &[cb, cb, cb + 0x40, cb]), 2);
    });
}

#[test]
fn transfers_complete_in_the_ring() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let f = h.file("aio-rw", 4, b'.', O_RDWR);
        let (cb, buf) = (h.scratch + CB, h.scratch + BUF);
        put(&h, buf, b"hello, aio!");
        let c = Cb {
            data: 77,
            key: 0x1234_5678,
            ..Cb::new(PWRITE, f, buf, 11, 4)
        };
        assert_eq!(submit(&mut h, ctx, c), 1);
        assert_eq!(u32_at(&h, cb + 8), 0, "KIOCB_KEY");
        assert_eq!((ring(&h, ctx)[HEAD], ring(&h, ctx)[TAIL]), (0, 1));
        let done = Ev {
            data: 77,
            obj: cb,
            res: 11,
            res2: 0,
        };
        assert_eq!(take(&mut h, ctx), vec![done]);
        assert_eq!(ring(&h, ctx)[HEAD], 1);
        // Positioned: past the end is short, and the file's own position
        // never moves.
        let into = buf + 0x40;
        assert_eq!(submit(&mut h, ctx, Cb::new(PREAD, f, into, 32, 0)), 1);
        assert_eq!(submit(&mut h, ctx, Cb::new(PREAD, f, into, 32, 13)), 1);
        let got: Vec<i64> = take(&mut h, ctx).iter().map(|e| e.res).collect();
        assert_eq!(got, [15, 2]);
        let mut b = [0u8; 2];
        h.proc.state.space.read(into, &mut b).unwrap();
        assert_eq!(&b, b"o!");
        assert_eq!(h.ok(Sysno::Lseek, &[f, 0, 1]), 0);
        // Vectors, each in turn.
        let iov = h.scratch + IOV;
        let v = [buf, 2, buf + 7, 3];
        put(
            &h,
            iov,
            &v.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>(),
        );
        assert_eq!(submit(&mut h, ctx, Cb::new(PWRITEV, f, iov, 2, 0)), 1);
        assert_eq!(submit(&mut h, ctx, Cb::new(PREADV, f, iov, 2, 10)), 1);
        let got: Vec<i64> = take(&mut h, ctx).iter().map(|e| e.res).collect();
        assert_eq!(got, [5, 5]);
        // A buffer in range but unmapped faults in the transfer: the
        // request completes with -EFAULT.
        let c = Cb {
            data: 9,
            ..Cb::new(PREAD, f, 16, 4, 0)
        };
        assert_eq!(submit(&mut h, ctx, c), 1);
        assert_eq!(take(&mut h, ctx)[0].res, e(EFAULT));
        // Syncs complete with vfs_fsync's result.
        assert_eq!(submit(&mut h, ctx, Cb::new(FSYNC, f, 0, 0, 0)), 1);
        assert_eq!(submit(&mut h, ctx, Cb::new(FDSYNC, f, 0, 0, 0)), 1);
        let got: Vec<i64> = take(&mut h, ctx).iter().map(|e| e.res).collect();
        assert_eq!(got, [0, 0]);
        // IOCB_FLAG_RESFD: one eventfd_signal per completion.
        let efd = h.ok(Sysno::Eventfd2, &[0, 0]);
        let c = Cb {
            flags: RESFD,
            resfd: efd as u32,
            ..Cb::new(FSYNC, f, 0, 0, 0)
        };
        let (a, b2) = (c.put(&h, cb), c.put(&h, cb + 0x40));
        assert_eq!(submit_from(&mut h, ctx, cb + 0x200, &[a, b2]), 2);
        assert_eq!(count(&h, efd), 2);
        assert_eq!(take(&mut h, ctx).len(), 2);
    });
}

#[test]
fn eventfd_signal_counts_to_the_top() {
    let ev = EventFd::new(0, false).unwrap();
    assert!(ev.write(u64::MAX - 2));
    ev.signal();
    assert_eq!(ev.count(), u64::MAX - 1);
    // eventfd_signal passes the limit writes stop at, then stops.
    ev.signal();
    ev.signal();
    assert_eq!(ev.count(), u64::MAX);
    assert_eq!(ev.poll(), (true, false, true), "EPOLLERR");
}

#[test]
fn pipes_and_sockets_complete_with_their_transfers_result() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let buf = h.scratch + BUF;
        // Without data: O_NONBLOCK gives -EAGAIN; a pending signal ends
        // the sleep inside io_submit with -EINTR, and the call goes on.
        let (r, w) = pipe(&mut h, O_NONBLOCK);
        assert_eq!(submit(&mut h, ctx, Cb::new(PREAD, r, buf, 8, 0)), 1);
        assert_eq!(take(&mut h, ctx)[0].res, e(EAGAIN));
        h.ok(Sysno::Fcntl, &[r, 4, 0]);
        h.proc.threads[0].sigpending = true;
        let cb = Cb::new(PREAD, r, buf, 8, 0).put(&h, h.scratch + CB);
        let ptrs = h.scratch + CB + 0x200;
        put(&h, ptrs, &cb.to_le_bytes());
        assert_eq!(h.start(0, Sysno::IoSubmit, &[ctx, 1, ptrs]), Some(1));
        h.proc.threads[0].sigpending = false;
        assert_eq!(take(&mut h, ctx)[0].res, e(EINTR));
        // Without a signal the request sleeps where it is, the requests
        // before it submitted.
        write(&mut h, w, b"xyz");
        let later = Cb::new(PREAD, r, buf, 8, 0).put(&h, h.scratch + CB + 0x40);
        put(&h, ptrs, &[cb.to_le_bytes(), later.to_le_bytes()].concat());
        assert_eq!(h.start(0, Sysno::IoSubmit, &[ctx, 2, ptrs]), None);
        let b = h.proc.threads[0].blocked.take().unwrap();
        assert!(
            matches!(b.resume, Resume::Aio { index: 1, .. }),
            "{:?}",
            b.resume
        );
        assert_eq!(take(&mut h, ctx)[0].res, 3);
        // It goes on from there once data comes from elsewhere (the first
        // read takes exactly what is there, whenever the rest comes).
        write(&mut h, w, b"ab");
        Cb::new(PREAD, r, buf, 2, 0).put(&h, cb);
        let writer = write_later(&h, w, b"late");
        assert_eq!(h.call(Sysno::IoSubmit, &[ctx, 2, ptrs]), 2);
        writer.join().unwrap();
        let got: Vec<i64> = take(&mut h, ctx).iter().map(|e| e.res).collect();
        assert_eq!(got, [2, 4]);
        // A write without readers: -EPIPE, with SIGPIPE unless
        // RWF_NOSIGNAL, from a pipe and from a stream socket alike.
        handle(&mut h, SIGPIPE);
        let pending = |h: &Harness| h.proc.threads[0].pending.contains(SIGPIPE);
        let (q, qw) = pipe(&mut h, 0);
        h.ok(Sysno::Close, &[q]);
        let (s, _peer) = socketpair(&mut h);
        h.ok(Sysno::Shutdown, &[s, 1]);
        for fd in [qw, s] {
            let c = Cb {
                rw_flags: RWF_NOSIGNAL,
                ..Cb::new(PWRITE, fd, buf, 1, 0)
            };
            assert_eq!(submit(&mut h, ctx, c), 1);
            assert_eq!(take(&mut h, ctx)[0].res, e(EPIPE));
            assert!(!pending(&h), "{abi:?} {fd}: RWF_NOSIGNAL");
            assert_eq!(submit(&mut h, ctx, Cb::new(PWRITE, fd, buf, 1, 0)), 1);
            assert_eq!(take(&mut h, ctx)[0].res, e(EPIPE));
            assert!(pending(&h), "{abi:?} {fd}");
            h.proc.threads[0].pending = SigPending::new();
        }
    });
}

#[test]
fn polls_complete_with_the_waking_key_or_the_events_polled() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let poll = |fd: u64, events: i64, data: u64| Cb {
            data,
            ..Cb::new(POLL, fd, events as u64, 0, 0)
        };
        // Its fields.
        let (r, w) = pipe(&mut h, 0);
        assert_eq!(submit(&mut h, ctx, poll(r, 0x1_0000, 0)), e(EINVAL));
        for c in [
            Cb {
                nbytes: 1,
                ..poll(r, POLLIN, 0)
            },
            Cb {
                offset: 1,
                ..poll(r, POLLIN, 0)
            },
            Cb {
                rw_flags: 1,
                ..poll(r, POLLIN, 0)
            },
        ] {
            assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        }
        // Ready at once: the events polled, within those asked for.
        write(&mut h, w, b"q");
        assert_eq!(submit(&mut h, ctx, poll(r, POLLIN | POLLOUT, 1)), 1);
        assert_eq!(take(&mut h, ctx)[0].res, POLLIN);
        h.ok(Sysno::Read, &[r, h.scratch + BUF, 1]);
        // A pipe's data: pipe_write's key.
        assert_eq!(submit(&mut h, ctx, poll(r, POLLIN, 2)), 1);
        assert!(take(&mut h, ctx).is_empty(), "waiting");
        write(&mut h, w, b"q");
        let ev = take(&mut h, ctx);
        assert_eq!((ev[0].data, ev[0].res), (2, POLLIN | POLLRDNORM));
        // An eventfd's: EPOLLIN alone, then EPOLLOUT after a read.
        let efd = h.ok(Sysno::Eventfd2, &[0, O_NONBLOCK]);
        assert_eq!(submit(&mut h, ctx, poll(efd, POLLIN, 3)), 1);
        put(&h, h.scratch + BUF, &1u64.to_le_bytes());
        h.ok(Sysno::Write, &[efd, h.scratch + BUF, 8]);
        assert_eq!(take(&mut h, ctx)[0].res, POLLIN);
        put(&h, h.scratch + BUF, &(u64::MAX - 2).to_le_bytes());
        h.ok(Sysno::Write, &[efd, h.scratch + BUF, 8]);
        assert_eq!(submit(&mut h, ctx, poll(efd, POLLOUT, 4)), 1);
        h.ok(Sysno::Read, &[efd, h.scratch + BUF, 8]);
        assert_eq!(take(&mut h, ctx)[0].res, POLLOUT);
        // A stream socket's: sock_def_readable's.
        let (a, b) = socketpair(&mut h);
        assert_eq!(submit(&mut h, ctx, poll(a, POLLIN, 5)), 1);
        write(&mut h, b, b"s");
        let want = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
        assert_eq!(take(&mut h, ctx)[0].res, want);
        // A hang-up wakes without a key: the pipe is polled again.
        let (hr, hw) = pipe(&mut h, 0);
        assert_eq!(submit(&mut h, ctx, poll(hr, POLLIN, 6)), 1);
        h.ok(Sysno::Close, &[hw]);
        assert_eq!(take(&mut h, ctx)[0].res, POLLHUP);
        // A file without a poll operation reports DEFAULT_POLLMASK, and
        // cannot wait for anything else.
        let f = h.file("aio-poll", 4, b'p', O_RDWR);
        assert_eq!(submit(&mut h, ctx, poll(f, POLLPRI, 7)), e(EINVAL));
        assert_eq!(submit(&mut h, ctx, poll(f, POLLIN | POLLPRI, 7)), 1);
        assert_eq!(take(&mut h, ctx)[0].res, POLLIN);
        // An eventfd polled for no event it reports still waits.
        assert_eq!(submit(&mut h, ctx, poll(efd, POLLPRI, 8)), 1);
        assert!(take(&mut h, ctx).is_empty());
        assert!(h.proc.state.aio.polls_pending());
    });
}

#[test]
fn a_thread_sleeping_in_another_call_wakes_for_waiting_polls() {
    // aio_poll_wake completes the request and signals its eventfd at the
    // file's wake-up: a thread reading that eventfd returns with it.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let (r, w) = pipe(&mut h, 0);
        let efd = h.ok(Sysno::Eventfd2, &[0, 0]);
        let c = Cb {
            data: 9,
            flags: RESFD,
            resfd: efd as u32,
            ..Cb::new(POLL, r, POLLIN as u64, 0, 0)
        };
        assert_eq!(submit(&mut h, ctx, c), 1);
        let writer = write_later(&h, w, b"x");
        let buf = h.scratch + BUF;
        assert_eq!(h.call(Sysno::Read, &[efd, buf, 8]), 8);
        writer.join().unwrap();
        assert_eq!(u64_at(&h, buf), 1);
        let ev = take(&mut h, ctx);
        assert_eq!((ev[0].data, ev[0].res), (9, POLLIN | POLLRDNORM));
    });
}

#[test]
fn io_cancel_and_io_destroy_complete_waiting_polls() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let (r, _w) = pipe(&mut h, 0);
        let cb = h.scratch + CB;
        let res = h.scratch + BUF;
        let cancel = |h: &mut Harness, ctx: u64, at: u64| h.call(Sysno::IoCancel, &[ctx, at, res]);
        let p = Cb {
            data: 4,
            ..Cb::new(POLL, r, POLLIN as u64, 0, 0)
        };
        assert_eq!(submit(&mut h, ctx, p), 1);
        // The key, then the context, then the request.
        assert_eq!(cancel(&mut h, 0x1000, 8), e(EFAULT));
        put(&h, cb + 8, &1u32.to_le_bytes());
        assert_eq!(cancel(&mut h, 0x1000, cb), e(EINVAL));
        put(&h, cb + 8, &0u32.to_le_bytes());
        assert_eq!(cancel(&mut h, 0x1000, cb), e(EINVAL));
        assert_eq!(cancel(&mut h, ctx, cb + 0x40), e(EINVAL), "not submitted");
        // Cancelled: completed through the ring with what the pipe
        // reports, never through `result`.
        put(&h, res, &[0xaa; 32]);
        assert_eq!(cancel(&mut h, ctx, cb), e(EINPROGRESS));
        assert_eq!(u64_at(&h, res), 0xaaaa_aaaa_aaaa_aaaa);
        let done = Ev {
            data: 4,
            obj: cb,
            res: 0,
            res2: 0,
        };
        assert_eq!(take(&mut h, ctx), vec![done]);
        assert_eq!(cancel(&mut h, ctx, cb), e(EINVAL), "once");
        // A completed request cannot be cancelled.
        let f = h.file("aio-cancel", 4, b'c', O_RDWR);
        assert_eq!(submit(&mut h, ctx, Cb::new(FSYNC, f, 0, 0, 0)), 1);
        assert_eq!(cancel(&mut h, ctx, cb), e(EINVAL));
        take(&mut h, ctx);
        // io_destroy: waiting polls complete (their eventfds hear of it),
        // the ring is unmapped, and the context is gone.
        let efd = h.ok(Sysno::Eventfd2, &[0, 0]);
        let c = Cb {
            flags: RESFD,
            resfd: efd as u32,
            ..p
        };
        assert_eq!(submit(&mut h, ctx, c), 1);
        assert_eq!(h.ok(Sysno::IoDestroy, &[ctx]), 0);
        assert_eq!(count(&h, efd), 1);
        assert!(h.proc.state.space.vma_at(ctx).is_none());
        assert_eq!(h.proc.state.aio.aio_nr, 0);
        assert!(!h.proc.state.aio.polls_pending());
        assert_eq!(h.call(Sysno::IoDestroy, &[ctx]), e(EINVAL));
        assert_eq!(submit(&mut h, ctx, p), e(EINVAL));
    });
}

#[test]
fn io_getevents_checks_waits_and_copies() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let f = h.file("aio-events", 4, b'g', O_RDWR);
        let evs = h.scratch + EVS;
        let raw = |h: &mut Harness, ctx: u64, min: i64, nr: i64, at: u64, ts: u64| {
            h.call(Sysno::IoGetevents, &[ctx, min as u64, nr as u64, at, ts])
        };
        // The timeout is read first, then the context, then the counts.
        assert_eq!(raw(&mut h, 0x1000, 0, 1, evs, 8), e(EFAULT));
        assert_eq!(raw(&mut h, 0x1000, 2, 1, evs, 0), e(EINVAL));
        assert_eq!(getevents(&mut h, ctx, 2, 1, None), Err(EINVAL));
        assert_eq!(getevents(&mut h, ctx, -1, 1, None), Err(EINVAL));
        // Zero, negative, and short timeouts.
        assert_eq!(getevents(&mut h, ctx, 1, 1, Some((0, 0))), Ok(vec![]));
        assert_eq!(getevents(&mut h, ctx, 1, 1, Some((-1, 0))), Ok(vec![]));
        let t = Instant::now();
        assert_eq!(
            getevents(&mut h, ctx, 1, 1, Some((0, 10_000_000))),
            Ok(vec![])
        );
        assert!(t.elapsed() >= Duration::from_millis(10));
        // No more than nr; min_nr met returns at once.
        for i in 0..3 {
            let c = Cb {
                data: i,
                ..Cb::new(FSYNC, f, 0, 0, 0)
            };
            assert_eq!(submit(&mut h, ctx, c), 1);
        }
        let data = |v: Vec<Ev>| v.iter().map(|e| e.data).collect::<Vec<_>>();
        assert_eq!(data(getevents(&mut h, ctx, 1, 2, None).unwrap()), [0, 1]);
        // A copy that faults leaves every event in the ring, even when
        // the first would fit.
        let edge = h.anon(2 * P, RW, false);
        h.ok(Sysno::Munmap, &[edge + P, P]);
        let head = ring(&h, ctx)[HEAD];
        assert_eq!(h.call(Sysno::IoGetevents, &[ctx, 1, 1, 8, 0]), e(EFAULT));
        assert_eq!(ring(&h, ctx)[HEAD], head);
        let c = Cb::new(FSYNC, f, 0, 0, 0);
        assert_eq!(submit(&mut h, ctx, c), 1);
        assert_eq!(raw(&mut h, ctx, 2, 2, edge + P - 32, 0), e(EFAULT));
        assert_eq!(ring(&h, ctx)[HEAD], head);
        assert_eq!(data(getevents(&mut h, ctx, 2, 2, None).unwrap()), [2, 0]);
        // The process's head and tail are taken modulo the ring's size;
        // equal ones mean an empty ring and are left alone.
        let nr = ring(&h, ctx)[NR];
        let tail = ring(&h, ctx)[TAIL];
        put(&h, ctx + 8, &(tail + nr).to_le_bytes());
        assert_eq!(take(&mut h, ctx), vec![]);
        assert_eq!(ring(&h, ctx)[HEAD], tail, "written back clamped");
        put(&h, ctx + 8, &tail.to_le_bytes());
        // A pending signal ends a wait: 0 events is EINTR.
        h.proc.threads[0].sigpending = true;
        assert_eq!(getevents(&mut h, ctx, 1, 1, Some((1, 0))), Err(EINTR));
        assert_eq!(submit(&mut h, ctx, c), 1);
        assert_eq!(getevents(&mut h, ctx, 2, 2, Some((1, 0))).unwrap().len(), 1);
        h.proc.threads[0].sigpending = false;
        // A timeout past KTIME_SEC_MAX seconds is none: the wait has no
        // end.
        let ts = h.scratch + TS;
        put(
            &h,
            ts,
            &[i64::MAX.to_le_bytes(), 0i64.to_le_bytes()].concat(),
        );
        assert_eq!(h.start(0, Sysno::IoGetevents, &[ctx, 1, 1, evs, ts]), None);
        let b = h.proc.threads[0].blocked.take().unwrap();
        assert!(matches!(
            b.resume,
            Resume::AioEvents {
                got: 0,
                deadline: None,
                ..
            }
        ));
        put(
            &h,
            ts,
            &[9_223_372_035i64.to_le_bytes(), 0i64.to_le_bytes()].concat(),
        );
        assert_eq!(h.start(0, Sysno::IoGetevents, &[ctx, 1, 1, evs, ts]), None);
        let b = h.proc.threads[0].blocked.take().unwrap();
        assert!(matches!(
            b.resume,
            Resume::AioEvents {
                deadline: Some(_),
                ..
            }
        ));
    });
}

#[test]
fn io_pgetevents_waits_under_its_mask() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 4);
        let (evs, ts, usig, set) = (
            h.scratch + EVS,
            h.scratch + TS,
            h.scratch + USIG,
            h.scratch + SET,
        );
        put(&h, ts, &[0u8; 16]);
        let pget = |h: &mut Harness, u: u64| h.call(Sysno::IoPgetevents, &[ctx, 1, 1, evs, ts, u]);
        let sig = |h: &Harness, mask: u64, size: u64| {
            put(h, usig, &[mask.to_le_bytes(), size.to_le_bytes()].concat());
        };
        // The timeout, the struct __aio_sigset, then the mask's size.
        assert_eq!(
            h.call(Sysno::IoPgetevents, &[ctx, 1, 1, evs, 8, 0]),
            e(EFAULT)
        );
        assert_eq!(pget(&mut h, 8), e(EFAULT));
        put(&h, set, &sigmask(SIGUSR1).to_le_bytes());
        sig(&h, set, 4);
        assert_eq!(pget(&mut h, usig), e(EINVAL));
        sig(&h, 0, 4);
        assert_eq!(pget(&mut h, usig), 0, "no mask, no size check");
        // The mask applies for the call and is restored after it.
        sig(&h, set, 8);
        assert_eq!(pget(&mut h, usig), 0);
        assert_eq!(h.proc.threads[0].sigmask, 0);
        assert!(h.proc.threads[0].saved_sigmask.is_none());
        // Interrupted with nothing: -ERESTARTNOHAND, the caller's mask
        // kept for after the handler.
        handle(&mut h, SIGUSR2);
        let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
        h.ok(Sysno::Tgkill, &[pid, tid, SIGUSR2 as u64]);
        assert_eq!(pget(&mut h, usig), e(ERESTARTNOHAND));
        assert_eq!(h.proc.threads[0].sigmask, sigmask(SIGUSR1));
        assert_eq!(h.proc.threads[0].saved_sigmask, Some(0));
    });
}

#[test]
fn slots_come_back_once_the_process_reaps() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctx = setup(&mut h, 1);
        let null = open(&mut h, "/dev/null", O_WRONLY);
        let c = Cb::new(PWRITE, null, h.scratch + BUF, 1, 0);
        let mut n = 0;
        while submit(&mut h, ctx, c) == 1 {
            n += 1;
        }
        // Of nr_events - 1 = 126, the CPU takes req_batch = 126 / (1 * 4)
        // = 31 at a time: four batches, and the 2 left are too few for
        // another (__get_reqs_available).
        assert_eq!(n, 124);
        assert_eq!(submit(&mut h, ctx, c), e(EAGAIN));
        let [_, nr, head, tail, ..] = ring(&h, ctx);
        assert_eq!((tail + nr - head) % nr, 124);
        // Reaped by the process itself, as libaio does.
        put(&h, ctx + 8, &tail.to_le_bytes());
        assert_eq!(submit(&mut h, ctx, c), 1);
        // The ring's ID names the context.
        put(&h, ctx, &999u32.to_le_bytes());
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        put(&h, ctx, &0u32.to_le_bytes());
        assert_eq!(submit(&mut h, ctx, c), 1);
    });
}

#[test]
fn the_ring_is_special_to_mlock_mremap_and_mseal() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = h.file("aio-moved", 4, b'm', O_RDWR);
        // Never locked, even under MCL_FUTURE; though do_mmap checks the
        // lock against RLIMIT_MEMLOCK first.
        let ctx = setup(&mut h, 1);
        h.ok(Sysno::Mlock, &[ctx, P]);
        assert_eq!(
            h.proc.state.space.vma_at(ctx).unwrap().flags & vma_flags::LOCKED,
            0
        );
        assert_eq!(
            crate::user::linux::syscall::mlock::locked_pages(&h.proc.state),
            0
        );
        h.ok(Sysno::Mlockall, &[MCL_FUTURE]);
        let locked = setup(&mut h, 1);
        assert_eq!(
            h.proc.state.space.vma_at(locked).unwrap().flags & vma_flags::LOCKED,
            0
        );
        assert_eq!(
            crate::user::linux::syscall::mlock::locked_pages(&h.proc.state),
            0
        );
        h.proc.state.creds = (65534, 65534, 65534, 65534);
        h.proc.state.rlimits[8] = (P, P);
        let ctxp = h.scratch + CTXP;
        put(&h, ctxp, &0u64.to_le_bytes());
        assert_eq!(h.call(Sysno::IoSetup, &[64, ctxp]), e(ENOMEM), "two pages");
        h.proc.state.rlimits[8] = (2 * P, 2 * P);
        assert_eq!(h.call(Sysno::IoSetup, &[64, ctxp]), 0);
        h.ok(Sysno::Munlockall, &[]);
        // mremap: not grown, duplicated, or kept; moved, it moves the
        // context.
        let remap = |h: &mut Harness, a: [u64; 5]| h.call(Sysno::Mremap, &a);
        assert_eq!(remap(&mut h, [ctx, P, 2 * P, MREMAP_MAYMOVE, 0]), e(EFAULT));
        assert_eq!(remap(&mut h, [ctx, 0, P, MREMAP_MAYMOVE, 0]), e(EFAULT));
        let keep = MREMAP_MAYMOVE | MREMAP_DONTUNMAP;
        assert_eq!(remap(&mut h, [ctx, P, P, keep, 0]), e(EINVAL));
        let spot = h.anon(3 * P, 0, false);
        let to = spot + P;
        let fixed = MREMAP_MAYMOVE | MREMAP_FIXED;
        assert_eq!(remap(&mut h, [ctx, P, P, fixed, to]), to as i64);
        let c = Cb::new(FSYNC, f, 0, 0, 0);
        assert_eq!(submit(&mut h, ctx, c), e(EINVAL));
        assert_eq!(submit(&mut h, to, c), 1);
        assert_eq!(take(&mut h, to).len(), 1);
        let dest = remap(&mut h, [to, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, spot]);
        assert_eq!(dest, spot as i64);
        assert_eq!(submit(&mut h, spot, c), 1);
        // A ring whose context is not the process's (a forked child's)
        // cannot move: the destination is unmapped first.
        let contexts = std::mem::take(&mut h.proc.state.aio);
        assert_eq!(remap(&mut h, [spot, P, P, fixed, to]), e(EINVAL));
        assert!(h.proc.state.space.vma_at(spot).is_some());
        h.proc.state.aio = contexts;
        // io_destroy unmaps from where the ring is now; a sealed ring
        // stays mapped, its context gone.
        assert_eq!(h.ok(Sysno::IoDestroy, &[spot]), 0);
        assert!(h.proc.state.space.vma_at(spot).is_none());
        h.ok(Sysno::Mseal, &[locked, P, 0]);
        assert_eq!(h.ok(Sysno::IoDestroy, &[locked]), 0);
        assert!(h.proc.state.space.vma_at(locked).is_some());
        assert_eq!(submit(&mut h, locked, c), e(EINVAL));
    });
}
