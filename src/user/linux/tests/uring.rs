//! io_uring: setup, the rings and their mappings, submission, links,
//! overflow, waits, and registration (`io_uring/`, Linux 6.19). Each
//! expectation names the kernel function it follows.

use std::time::{Duration, Instant};

mod rsrc;
mod rw;

use super::harness::{Harness, P, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::fs::anon::Anon;
use crate::user::linux::fs::fd::FileObject;

// IORING_SETUP_*.
const CQSIZE: u32 = 1 << 3;
const CLAMP: u32 = 1 << 4;
const ATTACH_WQ: u32 = 1 << 5;
const R_DISABLED: u32 = 1 << 6;
const SUBMIT_ALL: u32 = 1 << 7;
const COOP_TASKRUN: u32 = 1 << 8;
const TASKRUN_FLAG: u32 = 1 << 9;
const CQE32: u32 = 1 << 11;
const SINGLE_ISSUER: u32 = 1 << 12;
const DEFER_TASKRUN: u32 = 1 << 13;
const NO_SQARRAY: u32 = 1 << 16;
const SQPOLL: u32 = 1 << 1;
const SQ_AFF: u32 = 1 << 2;
// IORING_ENTER_*.
const GETEVENTS: u64 = 1;
const EXT_ARG: u64 = 1 << 3;
const REGISTERED_RING: u64 = 1 << 4;
const ABS_TIMER: u64 = 1 << 5;
// IOSQE_*.
const DRAIN: u8 = 1 << 1;
const LINK: u8 = 1 << 2;
const HARDLINK: u8 = 1 << 3;
const ASYNC: u8 = 1 << 4;
const BUFFER_SELECT: u8 = 1 << 5;
const SKIP: u8 = 1 << 6;
// IORING_NOP_*.
const INJECT: u32 = 1;
const NOP_FILE: u32 = 1 << 1;
const NOP_FIXED_FILE: u32 = 1 << 2;
const NOP_FIXED_BUFFER: u32 = 1 << 3;
const NOP_TW: u32 = 1 << 4;
const NOP_CQE32: u32 = 1 << 5;
// Operations.
const NOP: u8 = 0;
const URING_CMD: u8 = 46;
// Registration.
const REGISTER_EVENTFD: u64 = 4;
const UNREGISTER_EVENTFD: u64 = 5;
const REGISTER_EVENTFD_ASYNC: u64 = 7;
const REGISTER_PROBE: u64 = 8;
const REGISTER_PERSONALITY: u64 = 9;
const UNREGISTER_PERSONALITY: u64 = 10;
const REGISTER_ENABLE_RINGS: u64 = 12;
const REGISTER_RING_FDS: u64 = 20;
const UNREGISTER_RING_FDS: u64 = 21;
const USE_REGISTERED_RING: u64 = 1 << 31;
// sq_flags.
const SQ_CQ_OVERFLOW: u32 = 2;

const O_RDWR: u64 = 2;
const RW: u64 = 3;
const MAP_SHARED: u64 = 1;
const MAP_FIXED: u64 = 0x10;

// The scratch page: params at 0, the EXT_ARG at 0x100, a timespec at
// 0x140, a signal set at 0x160, the probe at 0x200, updates at 0x800.
const PARAMS: u64 = 0;
const EXTARG: u64 = 0x100;
const TS: u64 = 0x140;
const SIGSET: u64 = 0x160;
const PROBE: u64 = 0x200;
const UPDATES: u64 = 0x800;

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

/// An SQE's fields.
#[derive(Clone, Copy, Debug, Default)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    file_index: u32,
    addr3: u64,
    pad2: u64,
}

impl Sqe {
    fn nop(user_data: u64) -> Self {
        Sqe {
            opcode: NOP,
            user_data,
            ..Sqe::default()
        }
    }

    fn flags(mut self, f: u8) -> Self {
        self.flags = f;
        self
    }

    /// A NOP with `IORING_NOP_INJECT_RESULT`.
    fn inject(user_data: u64, res: i32) -> Self {
        Sqe {
            op_flags: INJECT,
            len: res as u32,
            ..Sqe::nop(user_data)
        }
    }

    fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0] = self.opcode;
        b[1] = self.flags;
        b[2..4].copy_from_slice(&self.ioprio.to_le_bytes());
        b[4..8].copy_from_slice(&self.fd.to_le_bytes());
        b[8..16].copy_from_slice(&self.off.to_le_bytes());
        b[16..24].copy_from_slice(&self.addr.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..32].copy_from_slice(&self.op_flags.to_le_bytes());
        b[32..40].copy_from_slice(&self.user_data.to_le_bytes());
        b[40..42].copy_from_slice(&self.buf_index.to_le_bytes());
        b[42..44].copy_from_slice(&self.personality.to_le_bytes());
        b[44..48].copy_from_slice(&self.file_index.to_le_bytes());
        b[48..56].copy_from_slice(&self.addr3.to_le_bytes());
        b[56..64].copy_from_slice(&self.pad2.to_le_bytes());
        b
    }
}

/// A set-up ring and its mappings.
struct Ring {
    fd: u64,
    rings: u64,
    sqes: u64,
    sq_entries: u32,
    cq_entries: u32,
    sq_off: [u32; 8],
    cq_off: [u32; 8],
    features: u32,
    cqe_size: u64,
}

/// `io_uring_setup` with `flags` (and `cq` entries for `CQSIZE`): the
/// params as returned, or the error.
fn setup_raw(h: &mut Harness, entries: u32, flags: u32, cq: u32) -> Result<(u64, [u8; 120]), i32> {
    let mut p = [0u8; 120];
    p[4..8].copy_from_slice(&cq.to_le_bytes());
    p[8..12].copy_from_slice(&flags.to_le_bytes());
    put(h, h.scratch + PARAMS, &p);
    let r = h.call(
        Sysno::IoUringSetup,
        &[u64::from(entries), h.scratch + PARAMS],
    );
    if r < 0 {
        return Err(-r as i32);
    }
    let mut out = [0u8; 120];
    h.proc
        .state
        .space
        .read_raw(h.scratch + PARAMS, &mut out)
        .unwrap();
    Ok((r as u64, out))
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// A ring of `entries` with `flags`, mapped as liburing maps it.
fn setup(h: &mut Harness, entries: u32, flags: u32, cq: u32) -> Ring {
    let (fd, p) = setup_raw(h, entries, flags, cq).expect("io_uring_setup");
    let sq_off: [u32; 8] = std::array::from_fn(|i| word(&p, 40 + 4 * i));
    let cq_off: [u32; 8] = std::array::from_fn(|i| word(&p, 80 + 4 * i));
    let (sq_entries, cq_entries) = (word(&p, 0), word(&p, 4));
    let cqe_size = if flags & CQE32 != 0 { 32 } else { 16 };
    let ring_len = if flags & NO_SQARRAY != 0 {
        u64::from(cq_off[5]) + cqe_size * u64::from(cq_entries)
    } else {
        u64::from(sq_off[6]) + 4 * u64::from(sq_entries)
    };
    let rings = h.ok(Sysno::Mmap, &[0, ring_len, RW, MAP_SHARED, fd, 0]);
    let sqes = h.ok(
        Sysno::Mmap,
        &[
            0,
            64 * u64::from(sq_entries),
            RW,
            MAP_SHARED,
            fd,
            0x1000_0000,
        ],
    );
    Ring {
        fd,
        rings,
        sqes,
        sq_entries,
        cq_entries,
        sq_off,
        cq_off,
        features: word(&p, 20),
        cqe_size,
    }
}

impl Ring {
    fn sq(&self, i: usize) -> u64 {
        self.rings + u64::from(self.sq_off[i])
    }

    fn cq(&self, i: usize) -> u64 {
        self.rings + u64::from(self.cq_off[i])
    }

    /// Queues `sqe` as liburing does: the entry in the next slot, its index
    /// in the array, the tail moved.
    fn push(&self, h: &Harness, sqe: Sqe) {
        let tail = u32_at(h, self.sq(1));
        let slot = tail & (self.sq_entries - 1);
        put(h, self.sqes + 64 * u64::from(slot), &sqe.encode());
        put(h, self.sq(6) + 4 * u64::from(slot), &slot.to_le_bytes());
        put(h, self.sq(1), &tail.wrapping_add(1).to_le_bytes());
    }

    /// Reaps every CQE: `(user_data, res, flags)`.
    fn reap(&self, h: &Harness) -> Vec<(u64, i32, u32)> {
        let mut head = u32_at(h, self.cq(0));
        let tail = u32_at(h, self.cq(1));
        let mut out = Vec::new();
        while head != tail {
            let at = self.cq(5) + self.cqe_size * u64::from(head & (self.cq_entries - 1));
            out.push((u64_at(h, at), u32_at(h, at + 8) as i32, u32_at(h, at + 12)));
            head = head.wrapping_add(1);
        }
        put(h, self.cq(0), &head.to_le_bytes());
        out
    }

    fn enter(&self, h: &mut Harness, submit: u64, min: u64, flags: u64) -> i64 {
        h.call(Sysno::IoUringEnter, &[self.fd, submit, min, flags, 0, 0])
    }

    fn state(&self, h: &Harness) -> std::sync::Arc<crate::user::linux::uring::Ring> {
        let file = h.proc.state.fds.file(self.fd as i32).unwrap();
        match &file.object {
            FileObject::Anon(Anon::Uring(r)) => r.clone(),
            _ => panic!("not a ring"),
        }
    }
}

#[test]
fn setup_rounds_the_entries_and_reports_the_ring_layout() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // io_uring_fill_params: 3 SQ entries become 4, the CQ twice that;
        // io_prepare_config: struct io_rings' offsets, the SQ array after
        // the 8 CQEs at a cache line (64 + 8 * 16 = 192).
        let (fd, p) = setup_raw(&mut h, 3, 0, 0).unwrap();
        assert_eq!((word(&p, 0), word(&p, 4), word(&p, 8)), (4, 8, 0));
        let sq_off: Vec<u32> = (0..8).map(|i| word(&p, 40 + 4 * i)).collect();
        let cq_off: Vec<u32> = (0..8).map(|i| word(&p, 80 + 4 * i)).collect();
        assert_eq!(sq_off, [0, 4, 16, 24, 36, 32, 192, 0], "{abi:?}");
        assert_eq!(cq_off, [8, 12, 20, 28, 44, 64, 40, 0], "{abi:?}");
        // IORING_FEAT_FLAGS: every feature through IORING_FEAT_NO_IOWAIT.
        assert_eq!(word(&p, 20), 0x3ffff);
        // io_uring_install_fd: O_RDWR | O_CLOEXEC.
        let entry = h.proc.state.fds.get(fd as i32).unwrap();
        assert!(entry.cloexec);
        assert_eq!(entry.file.flags() & 3, O_RDWR as u32);
        assert_eq!(entry.file.path, "anon_inode:[io_uring]");
        // IORING_SETUP_CQSIZE: a power of two at least the SQ's.
        let (_, p) = setup_raw(&mut h, 4, CQSIZE, 5).unwrap();
        assert_eq!((word(&p, 0), word(&p, 4)), (4, 8));
        // IORING_SETUP_CLAMP caps at IORING_MAX_ENTRIES.
        let (_, p) = setup_raw(&mut h, 40000, CLAMP, 0).unwrap();
        assert_eq!((word(&p, 0), word(&p, 4)), (32768, 65536));
        // IORING_SETUP_NO_SQARRAY: no array offset.
        let (_, p) = setup_raw(&mut h, 4, NO_SQARRAY, 0).unwrap();
        assert_eq!(word(&p, 40 + 24), 0);
        // CQE32 doubles the CQE array (and struct io_rings with it).
        let r = setup(&mut h, 4, CQE32, 0);
        assert_eq!(r.sq_off[6], 2 * (64 + 16 * 8));
    });
}

#[test]
fn setup_refuses_what_the_kernel_refuses() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let e = |h: &mut Harness, entries: u32, flags: u32, cq: u32| {
        setup_raw(h, entries, flags, cq).unwrap_err()
    };
    // io_uring_fill_params.
    assert_eq!(e(&mut h, 0, 0, 0), EINVAL);
    assert_eq!(e(&mut h, 32769, 0, 0), EINVAL);
    assert_eq!(e(&mut h, 4, CQSIZE, 0), EINVAL);
    assert_eq!(e(&mut h, 8, CQSIZE, 4), EINVAL);
    assert_eq!(e(&mut h, 4, CQSIZE, 65537), EINVAL);
    // io_uring_sanitise_params.
    assert_eq!(e(&mut h, 4, 1 << 20, 0), EINVAL);
    assert_eq!(e(&mut h, 4, DEFER_TASKRUN, 0), EINVAL);
    assert_eq!(e(&mut h, 4, TASKRUN_FLAG, 0), EINVAL);
    assert_eq!(e(&mut h, 4, SQPOLL | COOP_TASKRUN, 0), EINVAL);
    // io_sq_offload_create: SQ_AFF needs SQPOLL; ATTACH_WQ another ring.
    assert_eq!(e(&mut h, 4, SQ_AFF, 0), EINVAL);
    let mut p = [0u8; 120];
    p[8..12].copy_from_slice(&ATTACH_WQ.to_le_bytes());
    p[24..28].copy_from_slice(&999u32.to_le_bytes());
    put(&h, h.scratch, &p);
    assert_eq!(h.err(Sysno::IoUringSetup, &[4, h.scratch]), ENXIO);
    p[24..28].copy_from_slice(&0u32.to_le_bytes());
    put(&h, h.scratch, &p);
    assert_eq!(h.err(Sysno::IoUringSetup, &[4, h.scratch]), EINVAL);
    let (ring, _) = setup_raw(&mut h, 4, 0, 0).unwrap();
    p[24..28].copy_from_slice(&(ring as u32).to_le_bytes());
    put(&h, h.scratch, &p);
    assert!(h.call(Sysno::IoUringSetup, &[4, h.scratch]) >= 0);
    // io_uring_setup: reserved words, and the parameters' address.
    let mut p = [0u8; 120];
    p[32] = 1;
    put(&h, h.scratch, &p);
    assert_eq!(h.err(Sysno::IoUringSetup, &[4, h.scratch]), EINVAL);
    assert_eq!(h.err(Sysno::IoUringSetup, &[4, 0x10]), EFAULT);
    // Not modelled: a polling thread.
    assert_eq!(e(&mut h, 4, SQPOLL, 0), EINVAL);
}

#[test]
fn the_ring_file_maps_its_regions_and_nothing_else() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    // io_allocate_scq_urings wrote the masks and sizes.
    assert_eq!(u32_at(&h, r.sq(2)), 3);
    assert_eq!(u32_at(&h, r.sq(3)), 4);
    assert_eq!(u32_at(&h, r.cq(2)), 7);
    assert_eq!(u32_at(&h, r.cq(3)), 8);
    // The CQ ring offset maps the same region.
    let cq = h.ok(Sysno::Mmap, &[0, P, RW, MAP_SHARED, r.fd, 0x800_0000]);
    assert_eq!(u32_at(&h, cq + 20), 7);
    let vma = h.proc.state.space.vmas_in(cq, cq + 1)[0].clone();
    assert_eq!(vma.name.as_deref(), Some("anon_inode:[io_uring]"));
    // io_uring_get_unmapped_area: no address, even as a hint (EINVAL); no
    // region at the offset (ENOMEM).
    assert_eq!(
        h.err(Sysno::Mmap, &[0x7000_0000, P, RW, MAP_SHARED, r.fd, 0]),
        EINVAL
    );
    assert_eq!(
        h.err(
            Sysno::Mmap,
            &[0x7000_0000, P, RW, MAP_SHARED | MAP_FIXED, r.fd, 0]
        ),
        EINVAL
    );
    assert_eq!(
        h.err(Sysno::Mmap, &[0, P, RW, MAP_SHARED, r.fd, 0x2000_0000]),
        ENOMEM
    );
    // io_region_mmap: the SQEs map whole (a 128-entry ring's are 8 KiB).
    let big = setup(&mut h, 128, 0, 0);
    assert_eq!(
        h.err(Sysno::Mmap, &[0, P, RW, MAP_SHARED, big.fd, 0x1000_0000]),
        EFAULT
    );
    // No read, write, or llseek operations.
    assert_eq!(h.err(Sysno::Read, &[r.fd, h.scratch, 8]), EINVAL);
    assert_eq!(h.err(Sysno::Write, &[r.fd, h.scratch, 8]), EINVAL);
    assert_eq!(h.err(Sysno::Lseek, &[r.fd, 0, 0]), ESPIPE);
}

#[test]
fn nops_complete_in_submission_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let r = setup(&mut h, 4, 0, 0);
        for d in 1..=3 {
            r.push(&h, Sqe::nop(d));
        }
        assert_eq!(r.enter(&mut h, 3, 0, 0), 3);
        // io_commit_sqring and the flushed batch.
        assert_eq!(u32_at(&h, r.sq(0)), 3);
        assert_eq!(r.reap(&h), [(1, 0, 0), (2, 0, 0), (3, 0, 0)]);
        // Nothing queued: 0; asking for more than is queued submits what is.
        assert_eq!(r.enter(&mut h, 4, 0, 0), 0);
        r.push(&h, Sqe::nop(4));
        assert_eq!(r.enter(&mut h, 4, 0, 0), 1);
        assert_eq!(r.reap(&h), [(4, 0, 0)]);
    });
}

#[test]
fn nop_flags_follow_io_nop() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    r.push(&h, Sqe::inject(1, 7));
    r.push(&h, Sqe::inject(2, -5));
    // A bad descriptor fails the request (and so its link) but its CQE
    // carries the injected result.
    let bad_file = Sqe {
        op_flags: NOP_FILE,
        fd: 999,
        ..Sqe::nop(3)
    };
    r.push(&h, bad_file.flags(LINK));
    r.push(&h, Sqe::nop(4));
    let fixed = Sqe {
        op_flags: NOP_FILE | NOP_FIXED_FILE,
        fd: 0,
        ..Sqe::nop(5)
    };
    r.push(&h, fixed.flags(LINK));
    r.push(&h, Sqe::nop(6));
    let buffer = Sqe {
        op_flags: NOP_FIXED_BUFFER,
        ..Sqe::nop(7)
    };
    r.push(&h, buffer);
    // IORING_NOP_CQE32 on a ring of 16-byte CQEs; an unknown flag.
    let wide = Sqe {
        op_flags: NOP_CQE32,
        ..Sqe::nop(8)
    };
    r.push(&h, wide);
    assert_eq!(r.enter(&mut h, 8, 0, 0), 8);
    assert_eq!(
        r.reap(&h),
        [
            (1, 7, 0),
            (2, -5, 0),
            (3, 0, 0),
            (5, 0, 0),
            (7, 0, 0),
            (8, -EINVAL, 0),
            (4, -ECANCELED, 0),
            (6, -ECANCELED, 0),
        ]
    );
    let unknown = Sqe {
        op_flags: 1 << 6,
        ..Sqe::nop(9)
    };
    r.push(&h, unknown);
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(9, -EINVAL, 0)]);
    // A 32-byte CQE's extra words are `off` and `addr`.
    let r = setup(&mut h, 4, CQE32, 0);
    r.push(
        &h,
        Sqe {
            op_flags: NOP_CQE32,
            off: 11,
            addr: 22,
            ..Sqe::nop(1)
        },
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    let at = r.cq(5);
    assert_eq!(
        (u64_at(&h, at), u64_at(&h, at + 16), u64_at(&h, at + 24)),
        (1, 11, 22)
    );
}

#[test]
fn links_run_in_order_and_a_failure_cancels_the_rest() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let r = setup(&mut h, 16, 0, 0);
    // A chain that succeeds.
    r.push(&h, Sqe::nop(1).flags(LINK));
    r.push(&h, Sqe::nop(2).flags(LINK));
    r.push(&h, Sqe::nop(3));
    assert_eq!(r.enter(&mut h, 3, 0, 0), 3);
    assert_eq!(r.reap(&h), [(1, 0, 0), (2, 0, 0), (3, 0, 0)]);
    // io_fail_links: after a failure, -ECANCELED for the rest.
    r.push(&h, Sqe::nop(4).flags(LINK));
    r.push(&h, Sqe::inject(5, -9).flags(LINK));
    r.push(&h, Sqe::nop(6).flags(LINK));
    r.push(&h, Sqe::nop(7));
    assert_eq!(r.enter(&mut h, 4, 0, 0), 4);
    assert_eq!(
        r.reap(&h),
        [
            (4, 0, 0),
            (5, -9, 0),
            (6, -ECANCELED, 0),
            (7, -ECANCELED, 0)
        ]
    );
    // A hard link goes on.
    r.push(&h, Sqe::inject(8, -9).flags(HARDLINK));
    r.push(&h, Sqe::nop(9));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(8, -9, 0), (9, 0, 0)]);
    // IOSQE_CQE_SKIP_SUCCESS: successes post nothing; a skip-success
    // request that fails posts its CQE and its cancelled links none.
    r.push(&h, Sqe::nop(10).flags(LINK | SKIP));
    r.push(&h, Sqe::nop(11).flags(LINK));
    r.push(&h, Sqe::inject(12, -1).flags(LINK | SKIP));
    r.push(&h, Sqe::nop(13).flags(LINK));
    r.push(&h, Sqe::nop(14));
    assert_eq!(r.enter(&mut h, 5, 0, 0), 5);
    assert_eq!(r.reap(&h), [(11, 0, 0), (12, -1, 0)]);
    // An unfinished link at the end of a submission is queued as it is.
    r.push(&h, Sqe::nop(15).flags(LINK));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(15, 0, 0)]);
}

#[test]
fn a_request_that_fails_its_checks_ends_the_submission() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let r = setup(&mut h, 8, 0, 0);
    // io_init_req: an opcode past the last, an unknown flag, ioprio or a
    // buffer group where the operation has none, an unregistered
    // personality, an operation not modelled.
    let bad = [
        (
            Sqe {
                opcode: 65,
                ..Sqe::nop(1)
            },
            EINVAL,
        ),
        (Sqe::nop(2).flags(1 << 7), EINVAL),
        (
            Sqe {
                ioprio: 1,
                ..Sqe::nop(3)
            },
            EINVAL,
        ),
        (Sqe::nop(4).flags(BUFFER_SELECT), EOPNOTSUPP),
        (
            Sqe {
                personality: 7,
                ..Sqe::nop(5)
            },
            EINVAL,
        ),
        (
            Sqe {
                opcode: URING_CMD,
                ..Sqe::nop(6)
            },
            EOPNOTSUPP,
        ),
    ];
    for (sqe, err) in bad {
        r.push(&h, sqe);
        r.push(&h, Sqe::nop(99));
        // Submission stops at the failure, which counts as submitted.
        assert_eq!(r.enter(&mut h, 2, 0, 0), 1, "{sqe:?}");
        assert_eq!(r.reap(&h), [(sqe.user_data, -err, 0)], "{sqe:?}");
        assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
        assert_eq!(r.reap(&h), [(99, 0, 0)]);
    }
    // A failure inside a link cancels its head and completes the rest
    // with -ECANCELED, the failed one with its own error.
    r.push(&h, Sqe::nop(10).flags(LINK));
    r.push(
        &h,
        Sqe {
            ioprio: 1,
            ..Sqe::nop(11)
        }
        .flags(LINK),
    );
    r.push(&h, Sqe::nop(12));
    assert_eq!(r.enter(&mut h, 3, 0, 0), 3);
    assert_eq!(
        r.reap(&h),
        [(10, -ECANCELED, 0), (11, -EINVAL, 0), (12, -ECANCELED, 0)]
    );
    // IORING_SETUP_SUBMIT_ALL goes on past a failure.
    let r = setup(&mut h, 4, SUBMIT_ALL, 0);
    r.push(
        &h,
        Sqe {
            opcode: 70,
            ..Sqe::nop(1)
        },
    );
    r.push(&h, Sqe::nop(2));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(1, -EINVAL, 0), (2, 0, 0)]);
}

#[test]
fn an_sq_index_past_the_ring_is_dropped() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    r.push(&h, Sqe::nop(1));
    r.push(&h, Sqe::nop(2));
    // io_get_sqe: the second entry's index is 9.
    put(&h, r.sq(6) + 4, &9u32.to_le_bytes());
    r.push(&h, Sqe::nop(3));
    assert_eq!(r.enter(&mut h, 3, 0, 0), 1);
    assert_eq!(u32_at(&h, r.sq(5)), 1);
    assert_eq!(u32_at(&h, r.sq(0)), 2);
    assert_eq!(r.reap(&h), [(1, 0, 0)]);
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(3, 0, 0)]);
}

#[test]
fn completions_that_find_no_room_overflow_in_order() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    // Two SQ entries, two CQ entries.
    let r = setup(&mut h, 2, CQSIZE, 2);
    for round in 0..2 {
        r.push(&h, Sqe::nop(2 * round + 1));
        r.push(&h, Sqe::nop(2 * round + 2));
        assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    }
    // io_cqring_add_overflow: IORING_SQ_CQ_OVERFLOW while the list holds
    // any; the ring shows the first two.
    assert_eq!(u32_at(&h, r.sq(4)) & SQ_CQ_OVERFLOW, SQ_CQ_OVERFLOW);
    assert_eq!(u32_at(&h, r.cq(4)), 0);
    assert_eq!(r.reap(&h), [(1, 0, 0), (2, 0, 0)]);
    // A submission does not flush; a later completion queues behind.
    r.push(&h, Sqe::nop(5));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), []);
    // A wait flushes as much as fits.
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(r.reap(&h), [(3, 0, 0), (4, 0, 0)]);
    assert_eq!(u32_at(&h, r.sq(4)) & SQ_CQ_OVERFLOW, SQ_CQ_OVERFLOW);
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(r.reap(&h), [(5, 0, 0)]);
    assert_eq!(u32_at(&h, r.sq(4)) & SQ_CQ_OVERFLOW, 0);
}

#[test]
fn a_deferring_ring_runs_its_task_work_only_while_waiting() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    // The link's second request, and a task-work NOP, are local work.
    r.push(&h, Sqe::nop(1).flags(LINK));
    r.push(&h, Sqe::nop(2));
    r.push(
        &h,
        Sqe {
            op_flags: NOP_TW,
            ..Sqe::nop(3)
        },
    );
    assert_eq!(r.enter(&mut h, 3, 0, 0), 3);
    assert_eq!(r.reap(&h), [(1, 0, 0)]);
    // Local work runs in the order it was queued: the task-work NOP from
    // the submission, then the link's next request from its flush.
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(r.reap(&h), [(3, 0, 0), (2, 0, 0)]);
    // A ring without it runs the same work before the call returns.
    let r = setup(&mut h, 4, 0, 0);
    r.push(&h, Sqe::nop(1).flags(LINK));
    r.push(&h, Sqe::nop(2));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(1, 0, 0), (2, 0, 0)]);
}

#[test]
fn drains_and_async_requests_complete_after_what_came_before() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 8, 0, 0);
    r.push(&h, Sqe::nop(1).flags(LINK));
    r.push(&h, Sqe::nop(2));
    r.push(&h, Sqe::nop(3).flags(DRAIN));
    r.push(&h, Sqe::nop(4));
    assert_eq!(r.enter(&mut h, 4, 0, 0), 4);
    assert_eq!(r.reap(&h), [(1, 0, 0), (2, 0, 0), (3, 0, 0), (4, 0, 0)]);
    // IOSQE_ASYNC: to the workers, done by the time the call returns.
    r.push(&h, Sqe::nop(5).flags(ASYNC));
    r.push(&h, Sqe::nop(6));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(6, 0, 0), (5, 0, 0)]);
    // A drain after a skip-success request is refused.
    r.push(&h, Sqe::nop(7).flags(SKIP));
    r.push(&h, Sqe::nop(8).flags(DRAIN));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(8, -EOPNOTSUPP, 0)]);
}

#[test]
fn waits_end_with_enough_completions_a_timeout_or_a_signal() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    // Enough already: 0 at once.
    r.push(&h, Sqe::nop(1));
    assert_eq!(r.enter(&mut h, 1, 1, GETEVENTS), 1);
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    r.reap(&h);
    // IORING_ENTER_EXT_ARG with a 20 ms timespec: -ETIME.
    let ts = h.scratch + TS;
    put(
        &h,
        ts,
        &[0i64.to_le_bytes(), 20_000_000i64.to_le_bytes()].concat(),
    );
    let arg = h.scratch + EXTARG;
    let mut a = [0u8; 24];
    a[16..24].copy_from_slice(&ts.to_le_bytes());
    put(&h, arg, &a);
    let start = Instant::now();
    let r2 = h.call(
        Sysno::IoUringEnter,
        &[r.fd, 0, 1, GETEVENTS | EXT_ARG, arg, 24],
    );
    assert_eq!(r2, -(ETIME as i64));
    assert!(start.elapsed() >= Duration::from_millis(20));
    // An absolute time already past: -ETIME at once.
    put(&h, ts, &[0i64.to_le_bytes(), 1i64.to_le_bytes()].concat());
    let r2 = h.call(
        Sysno::IoUringEnter,
        &[r.fd, 0, 1, GETEVENTS | EXT_ARG | ABS_TIMER, arg, 24],
    );
    assert_eq!(r2, -(ETIME as i64));
    // The argument's size must be the structure's.
    assert_eq!(
        h.err(
            Sysno::IoUringEnter,
            &[r.fd, 0, 1, GETEVENTS | EXT_ARG, arg, 16]
        ),
        EINVAL
    );
    // Without completions or a timeout the call sleeps; a pending signal
    // ends the wait with -EINTR (io_cqring_wait_schedule).
    assert_eq!(
        h.start(0, Sysno::IoUringEnter, &[r.fd, 0, 1, GETEVENTS, 0, 0]),
        None
    );
    let b = h.proc.threads[0].blocked.take().unwrap();
    assert!(
        matches!(b.resume, crate::user::linux::wait::Resume::Uring(_)),
        "{:?}",
        b.resume
    );
    h.proc.threads[0].sigpending = true;
    assert_eq!(
        h.start(0, Sysno::IoUringEnter, &[r.fd, 0, 1, GETEVENTS, 0, 0]),
        Some(-(EINTR as i64))
    );
    h.proc.threads[0].sigpending = false;
    // Once something was submitted, the count is the result, not the
    // wait's error (here a bad argument size).
    r.push(&h, Sqe::nop(9));
    assert_eq!(r.enter(&mut h, 1, 2, GETEVENTS | EXT_ARG), 1);
    assert_eq!(r.reap(&h), [(9, 0, 0)]);
}

#[test]
fn the_ring_is_writable_until_full_and_readable_with_completions() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 2, 0, 0);
    let fds = h.scratch + 0x600;
    let poll = |h: &mut Harness| {
        put(
            h,
            fds,
            &[(r.fd as i32).to_le_bytes(), 0x5u32.to_le_bytes()].concat(),
        );
        h.ok(Sysno::Poll, &[fds, 1, 0]);
        u32_at(h, fds + 4) >> 16
    };
    // io_uring_poll: POLLOUT|POLLWRNORM while the SQ has room.
    assert_eq!(poll(&mut h), 0x4);
    r.push(&h, Sqe::nop(1));
    r.push(&h, Sqe::nop(2));
    assert_eq!(poll(&mut h), 0);
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(poll(&mut h), 0x5);
}

#[test]
fn registration_follows_io_uring_register() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    let reg = |h: &mut Harness, fd: u64, op: u64, arg: u64, n: u64| {
        h.call(Sysno::IoUringRegister, &[fd, op, arg, n])
    };
    // io_probe: zeroed on entry; the last opcode, the count, NOP and
    // READV (modelled) supported, URING_CMD (not modelled) not.
    let probe = h.scratch + PROBE;
    put(&h, probe, &[0u8; 16 + 8 * 70]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_PROBE, probe, 70), 0);
    let mut b = [0u8; 16 + 8 * 65];
    h.proc.state.space.read_raw(probe, &mut b).unwrap();
    assert_eq!((b[0], b[1]), (64, 65));
    assert_eq!((b[16], b[18]), (0, 1));
    assert_eq!((b[24], b[26]), (1, 1));
    assert_eq!((b[16 + 8 * 46], b[18 + 8 * 46]), (46, 0));
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PROBE, probe, 4),
        -(EINVAL as i64)
    );
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_PROBE, probe, 257),
        -(EINVAL as i64)
    );
    // Unknown opcodes and a descriptor that is no ring.
    assert_eq!(reg(&mut h, r.fd, 37, 0, 0), -(EINVAL as i64));
    assert_eq!(
        reg(&mut h, 0, REGISTER_PERSONALITY, 0, 0),
        -(EOPNOTSUPP as i64)
    );
    assert_eq!(
        reg(&mut h, 999, REGISTER_PERSONALITY, 0, 0),
        -(EBADF as i64)
    );
    // Personalities from 1; an unknown one is EINVAL.
    assert_eq!(reg(&mut h, r.fd, REGISTER_PERSONALITY, 0, 0), 1);
    assert_eq!(reg(&mut h, r.fd, REGISTER_PERSONALITY, 0, 0), 2);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_PERSONALITY, 0, 1), 0);
    assert_eq!(
        reg(&mut h, r.fd, UNREGISTER_PERSONALITY, 0, 1),
        -(EINVAL as i64)
    );
    r.push(
        &h,
        Sqe {
            personality: 2,
            ..Sqe::nop(1)
        },
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(1, 0, 0)]);
    // An eventfd counts commits that posted something; only one at a time.
    // EFD_NONBLOCK, so an empty count reads as EAGAIN.
    let efd = h.ok(Sysno::Eventfd2, &[0, 0o4000]);
    let arg = h.scratch + 0x700;
    put(&h, arg, &(efd as u32).to_le_bytes());
    assert_eq!(reg(&mut h, r.fd, REGISTER_EVENTFD, arg, 1), 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_EVENTFD, arg, 1), -(EBUSY as i64));
    r.push(&h, Sqe::nop(2));
    r.push(&h, Sqe::nop(3));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(h.ok(Sysno::Read, &[efd, h.scratch + 0x780, 8]), 8);
    assert_eq!(u64_at(&h, h.scratch + 0x780), 1);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_EVENTFD, 0, 0), 0);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_EVENTFD, 0, 0), -(ENXIO as i64));
    put(&h, arg, &(r.fd as u32).to_le_bytes());
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_EVENTFD, arg, 1),
        -(EINVAL as i64)
    );
    // IORING_REGISTER_EVENTFD_ASYNC counts only the workers' completions.
    put(&h, arg, &(efd as u32).to_le_bytes());
    assert_eq!(reg(&mut h, r.fd, REGISTER_EVENTFD_ASYNC, arg, 1), 0);
    r.push(&h, Sqe::nop(4));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(h.err(Sysno::Read, &[efd, h.scratch + 0x780, 8]), EAGAIN);
    r.reap(&h);
}

#[test]
fn a_disabled_ring_takes_no_submissions_until_enabled() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, R_DISABLED | SINGLE_ISSUER, 0);
    r.push(&h, Sqe::nop(1));
    assert_eq!(r.enter(&mut h, 1, 0, 0), -(EBADFD as i64));
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_ENABLE_RINGS, 0, 0]),
        0
    );
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_ENABLE_RINGS, 0, 0]),
        -(EBADFD as i64)
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(1, 0, 0)]);
    // io_uring_add_tctx_node: another task may not submit to a
    // single-issuer ring.
    r.state(&h).state().submitter = Some(12345);
    r.push(&h, Sqe::nop(2));
    assert_eq!(r.enter(&mut h, 1, 0, 0), -(EEXIST as i64));
}

#[test]
fn registered_ring_descriptors_stand_for_the_ring() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    let upd = h.scratch + UPDATES;
    // offset -1: the first free slot, written back.
    put(
        &h,
        upd,
        &[u32::MAX.to_le_bytes(), 0u32.to_le_bytes()].concat(),
    );
    put(&h, upd + 8, &r.fd.to_le_bytes());
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, REGISTER_RING_FDS, upd, 1]),
        1
    );
    assert_eq!(u32_at(&h, upd), 0);
    r.push(&h, Sqe::nop(1));
    assert_eq!(
        h.call(Sysno::IoUringEnter, &[0, 1, 0, REGISTERED_RING, 0, 0]),
        1
    );
    assert_eq!(r.reap(&h), [(1, 0, 0)]);
    assert_eq!(
        h.call(Sysno::IoUringEnter, &[16, 1, 0, REGISTERED_RING, 0, 0]),
        -(EINVAL as i64)
    );
    assert_eq!(
        h.call(Sysno::IoUringEnter, &[1, 1, 0, REGISTERED_RING, 0, 0]),
        -(EBADF as i64)
    );
    // Registration through the registered index.
    assert_eq!(
        h.call(
            Sysno::IoUringRegister,
            &[0, REGISTER_PERSONALITY | USE_REGISTERED_RING, 0, 0]
        ),
        1
    );
    // io_ringfd_unregister: `data` must be zero.
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, UNREGISTER_RING_FDS, upd, 1]),
        -(EINVAL as i64)
    );
    put(&h, upd + 8, &0u64.to_le_bytes());
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[r.fd, UNREGISTER_RING_FDS, upd, 1]),
        1
    );
    assert_eq!(
        h.call(Sysno::IoUringEnter, &[0, 0, 0, REGISTERED_RING, 0, 0]),
        -(EBADF as i64)
    );
}

#[test]
fn fdinfo_shows_the_rings_state() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let r = setup(&mut h, 4, 0, 0);
    r.push(&h, Sqe::nop(5));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    r.push(&h, Sqe::inject(6, 3));
    let own = |_: i32| true;
    let text = String::from_utf8(
        crate::user::linux::fdinfo::fdinfo(&h.proc.state, &own, r.fd as i32).unwrap(),
    )
    .unwrap();
    let body = text
        .split_once("ino:")
        .unwrap()
        .1
        .split_once('\n')
        .unwrap()
        .1;
    assert_eq!(
        body,
        "SqMask:\t0x3\nSqHead:\t1\nSqTail:\t2\nCachedSqHead:\t1\nCqMask:\t0x7\nCqHead:\t0\n\
         CqTail:\t1\nCachedCqTail:\t1\nSQEs:\t1\n    1: opcode:NOP, fd:0, flags:0, off:0, \
         addr:0x0, rw_flags:0x1, buf_index:0 user_data:6\nCQEs:\t1\n    0: user_data:5, res:0, \
         flags:0\nSqThread:\t-1\nSqThreadCpu:\t-1\nSqTotalTime:\t0\nSqWorkTime:\t0\n\
         UserFiles:\t0\nUserBufs:\t0\nPollList:\nCqOverflowList:\nNAPI:\tdisabled\n"
    );
}
