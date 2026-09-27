//! io_uring's registered files and buffers (`io_uring/rsrc.c`,
//! `io_uring/filetable.c`, Linux 6.19): registration, updates, tags,
//! allocation, cloning, and what is charged for them.

use super::*;

// IORING_REGISTER_*.
const REGISTER_BUFFERS: u64 = 0;
const UNREGISTER_BUFFERS: u64 = 1;
const REGISTER_FILES: u64 = 2;
const UNREGISTER_FILES: u64 = 3;
const REGISTER_FILES_UPDATE: u64 = 6;
const REGISTER_FILES2: u64 = 13;
const REGISTER_FILES_UPDATE2: u64 = 14;
const REGISTER_BUFFERS2: u64 = 15;
const REGISTER_BUFFERS_UPDATE: u64 = 16;
const REGISTER_FILE_ALLOC_RANGE: u64 = 25;
const REGISTER_CLONE_BUFFERS: u64 = 30;
// IORING_RSRC_REGISTER_SPARSE; IORING_REGISTER_SRC_REGISTERED and
// IORING_REGISTER_DST_REPLACE.
const SPARSE: u32 = 1;
const SRC_REGISTERED: u32 = 1;
const DST_REPLACE: u32 = 2;
// IORING_OP_FILES_UPDATE; IOSQE_FIXED_FILE; IORING_FILE_INDEX_ALLOC;
// IORING_REGISTER_FILES_SKIP.
const FILES_UPDATE: u8 = 20;
const FIXED_FILE: u8 = 1;
const INDEX_ALLOC: u64 = u32::MAX as u64;
const SKIP_FD: i32 = -2;
const RLIMIT_NOFILE: usize = 7;
const RLIMIT_MEMLOCK: usize = 8;
const O_NONBLOCK: u64 = 0o4000;
const PROT_READ: u64 = 1;

/// Scratch for the arrays and structures the calls read: descriptors at
/// 0, tags at 0x100, vectors at 0x200, the structure at 0x400.
struct Args {
    fds: u64,
    tags: u64,
    iovs: u64,
    arg: u64,
}

fn args(h: &mut Harness) -> Args {
    let a = h.anon(P, RW, false);
    Args {
        fds: a,
        tags: a + 0x100,
        iovs: a + 0x200,
        arg: a + 0x400,
    }
}

fn put_fds(h: &Harness, at: u64, fds: &[i32]) {
    let b: Vec<u8> = fds.iter().flat_map(|f| f.to_le_bytes()).collect();
    put(h, at, &b);
}

fn put_u64s(h: &Harness, at: u64, v: &[u64]) {
    let b: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    put(h, at, &b);
}

fn put_u32s(h: &Harness, at: u64, v: &[u32]) {
    let b: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    put(h, at, &b);
}

/// `struct iovec`s in the native layout.
fn put_iovs(h: &Harness, at: u64, iovs: &[(u64, u64)]) {
    let b: Vec<u8> = iovs
        .iter()
        .flat_map(|&(base, len)| [base.to_le_bytes(), len.to_le_bytes()].concat())
        .collect();
    put(h, at, &b);
}

/// `struct io_uring_rsrc_register`.
fn rsrc_register(h: &Harness, at: u64, nr: u32, flags: u32, data: u64, tags: u64) {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&nr.to_le_bytes());
    b[4..8].copy_from_slice(&flags.to_le_bytes());
    b[16..24].copy_from_slice(&data.to_le_bytes());
    b[24..32].copy_from_slice(&tags.to_le_bytes());
    put(h, at, &b);
}

/// `struct io_uring_rsrc_update2`.
fn rsrc_update2(h: &Harness, at: u64, offset: u32, data: u64, tags: u64, nr: u32) {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&offset.to_le_bytes());
    b[8..16].copy_from_slice(&data.to_le_bytes());
    b[16..24].copy_from_slice(&tags.to_le_bytes());
    b[24..28].copy_from_slice(&nr.to_le_bytes());
    put(h, at, &b);
}

fn reg(h: &mut Harness, fd: u64, op: u64, arg: u64, nr: u64) -> i64 {
    h.call(Sysno::IoUringRegister, &[fd, op, arg, nr])
}

fn neg(e: i32) -> i64 {
    -i64::from(e)
}

fn pipe(h: &mut Harness, flags: u64) -> (i32, i32) {
    let at = h.scratch + 0xf00;
    h.ok(Sysno::Pipe2, &[at, flags]);
    (u32_at(h, at) as i32, u32_at(h, at + 4) as i32)
}

/// The fdinfo lines from `UserFiles` through the buffers.
fn user_rsrc(h: &Harness, fd: u64) -> String {
    let own = |_: i32| true;
    let text = String::from_utf8(
        crate::user::linux::fdinfo::fdinfo(&h.proc.state, &own, fd as i32).unwrap(),
    )
    .unwrap();
    let from = text.find("UserFiles:").unwrap();
    let to = text.find("PollList:").unwrap();
    text[from..to].to_string()
}

/// `VmPin` of `/proc/self/status`, in kB.
fn vm_pin(h: &Harness) -> u64 {
    let s = String::from_utf8(crate::user::linux::procfs::status(
        &h.proc.state,
        &h.proc.threads[0],
        1,
    ))
    .unwrap();
    let line = s.lines().find(|l| l.starts_with("VmPin:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn non_root(h: &mut Harness) {
    h.proc.state.creds = (1000, 1000, 1000, 1000);
}

#[test]
fn registering_files_follows_io_sqe_files_register() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let (rd, wr) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd, -1, wr]);
    // __io_uring_register: an array is needed.
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, 0, 3), neg(EFAULT));
    // io_sqe_files_register: no slots, or more than IORING_MAX_FIXED_FILES
    // or RLIMIT_NOFILE.
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 0), neg(EINVAL));
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES, a.fds, (1 << 20) + 1),
        neg(EMFILE)
    );
    let nofile = h.proc.state.rlimits[RLIMIT_NOFILE].0;
    h.proc.state.rlimits[RLIMIT_NOFILE].0 = 2;
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 3), neg(EMFILE));
    h.proc.state.rlimits[RLIMIT_NOFILE].0 = nofile;
    // -1 leaves a slot empty; io_uring_show_fdinfo lists the others.
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 3), 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 3), neg(EBUSY));
    assert_eq!(
        user_rsrc(&h, r.fd),
        "UserFiles:\t3\n    0: pipe:\n    2: pipe:\nUserBufs:\t0\n"
    );
    // IORING_UNREGISTER_FILES takes no argument; without a table ENXIO.
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 1), neg(EINVAL));
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), 0);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), neg(ENXIO));
    assert_eq!(user_rsrc(&h, r.fd), "UserFiles:\t0\nUserBufs:\t0\n");
    // A ring may not be registered, nor a descriptor that is not open; the
    // table built so far goes.
    put_fds(&h, a.fds, &[rd, r.fd as i32]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 2), neg(EBADF));
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), neg(ENXIO));
    put_fds(&h, a.fds, &[rd, 99]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 2), neg(EBADF));
    // An empty slot may not have a tag; the tags of the nodes built are
    // not posted.
    put_fds(&h, a.fds, &[rd, -1]);
    put_u64s(&h, a.tags, &[5, 6]);
    rsrc_register(&h, a.arg, 2, 0, a.fds, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    assert_eq!(r.reap(&h), []);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), neg(ENXIO));
}

#[test]
fn files2_follows_io_register_rsrc() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let (rd, _) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd, rd]);
    rsrc_register(&h, a.arg, 2, 0, a.fds, 0);
    // The structure's size exactly; slots; no reserved word or unknown
    // flag; a sparse table takes no descriptors.
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 24), neg(EINVAL));
    rsrc_register(&h, a.arg, 0, 0, a.fds, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    rsrc_register(&h, a.arg, 2, 2, a.fds, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    rsrc_register(&h, a.arg, 2, SPARSE, a.fds, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    rsrc_register(&h, a.arg, 2, 0, a.fds, 0);
    put(&h, a.arg + 8, &1u64.to_le_bytes());
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    // Sparse: every slot empty (and so, without a tag).
    rsrc_register(&h, a.arg, 3, SPARSE, 0, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), 0);
    assert_eq!(user_rsrc(&h, r.fd), "UserFiles:\t3\nUserBufs:\t0\n");
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), 0);
    // No descriptors without the flag is sparse too; a tag is refused.
    put_u64s(&h, a.tags, &[0, 9]);
    rsrc_register(&h, a.arg, 2, 0, 0, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), neg(EINVAL));
    rsrc_register(&h, a.arg, 2, 0, 0, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), 0);
    assert_eq!(user_rsrc(&h, r.fd), "UserFiles:\t2\nUserBufs:\t0\n");
}

#[test]
fn released_nodes_post_their_tags() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let (rd, wr) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd, wr, rd]);
    put_u64s(&h, a.tags, &[0x10, 0x20, 0]);
    rsrc_register(&h, a.arg, 3, 0, a.fds, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), 0);
    assert_eq!(r.reap(&h), []);
    // __io_sqe_files_update: the node a slot held is released, its tag
    // posted (io_free_rsrc_node).
    put_fds(&h, a.fds, &[wr]);
    put_u64s(&h, a.tags, &[0x30]);
    rsrc_update2(&h, a.arg, 0, a.fds, a.tags, 1);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32), 1);
    assert_eq!(r.reap(&h), [(0x10, 0, 0)]);
    // IORING_REGISTER_FILES_SKIP leaves a slot, -1 empties one; neither
    // takes a tag.
    put_fds(&h, a.fds, &[SKIP_FD, -1]);
    put_u64s(&h, a.tags, &[0, 0]);
    rsrc_update2(&h, a.arg, 0, a.fds, a.tags, 2);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32), 2);
    assert_eq!(r.reap(&h), [(0x20, 0, 0)]);
    put_u64s(&h, a.tags, &[7]);
    rsrc_update2(&h, a.arg, 0, a.fds, a.tags, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32),
        neg(EINVAL)
    );
    // io_rsrc_data_free: from the last slot down.
    put_fds(&h, a.fds, &[rd, rd]);
    put_u64s(&h, a.tags, &[0x40, 0x50]);
    rsrc_update2(&h, a.arg, 1, a.fds, a.tags, 2);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32), 2);
    assert_eq!(r.reap(&h), []);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), 0);
    assert_eq!(r.reap(&h), [(0x50, 0, 0), (0x40, 0, 0), (0x30, 0, 0)]);
}

#[test]
fn file_updates_follow_io_register_rsrc_update() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let (rd, _) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd, rd]);
    // io_register_files_update: a struct io_uring_rsrc_update, slots, no
    // table ENXIO.
    put_u32s(&h, a.arg, &[0, 0]);
    put_u64s(&h, a.arg + 8, &[a.fds]);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 0),
        neg(EINVAL)
    );
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 1),
        neg(ENXIO)
    );
    put_u32s(&h, a.arg, &[0, 1]);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 1),
        neg(EINVAL)
    );
    rsrc_register(&h, a.arg + 0x80, 2, SPARSE, 0, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg + 0x80, 32), 0);
    put_u32s(&h, a.arg, &[1, 0]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 1), 1);
    // Past the table EINVAL; wrapping EOVERFLOW.
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 2),
        neg(EINVAL)
    );
    put_u32s(&h, a.arg, &[u32::MAX, 0]);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE, a.arg, 2),
        neg(EOVERFLOW)
    );
    // io_register_rsrc_update: the structure's size, slots, reserved zero.
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 16),
        neg(EINVAL)
    );
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 0);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32),
        neg(EINVAL)
    );
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 1);
    put(&h, a.arg + 28, &1u32.to_le_bytes());
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32),
        neg(EINVAL)
    );
    // A bad descriptor ends the update after what was done; alone, its slot
    // was emptied first.
    put_fds(&h, a.fds, &[rd, 99]);
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 2);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32), 1);
    assert_eq!(
        user_rsrc(&h, r.fd),
        "UserFiles:\t2\n    0: pipe:\nUserBufs:\t0\n"
    );
    put_fds(&h, a.fds, &[99]);
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32),
        neg(EBADF)
    );
    assert_eq!(user_rsrc(&h, r.fd), "UserFiles:\t2\nUserBufs:\t0\n");
}

#[test]
fn a_node_in_use_is_released_with_its_last_request() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, SINGLE_ISSUER | DEFER_TASKRUN, 0);
    let (rd, _) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd]);
    put_u64s(&h, a.tags, &[0x77]);
    rsrc_register(&h, a.arg, 1, 0, a.fds, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), 0);
    // io_file_get_fixed: the NOP references the node until it is freed,
    // which on this ring is when its task work runs in a wait.
    r.push(
        &h,
        Sqe {
            op_flags: NOP_FILE | NOP_FIXED_FILE | NOP_TW,
            fd: 0,
            ..Sqe::nop(1)
        },
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    put_fds(&h, a.fds, &[-1]);
    rsrc_update2(&h, a.arg, 0, a.fds, 0, 1);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES_UPDATE2, a.arg, 32), 1);
    assert_eq!(r.reap(&h), []);
    // io_free_batch_list: the request's CQE, then its node's tag.
    assert_eq!(r.enter(&mut h, 0, 1, GETEVENTS), 0);
    assert_eq!(r.reap(&h), [(1, 0, 0), (0x77, 0, 0)]);
}

#[test]
fn a_registered_file_stays_open_until_its_node_goes() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let (rd, wr) = pipe(&mut h, O_NONBLOCK);
    put_fds(&h, a.fds, &[wr]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 1), 0);
    h.ok(Sysno::Close, &[wr as u64]);
    // The write end lives on in the table: no end of file yet.
    let buf = a.arg;
    assert_eq!(h.err(Sysno::Read, &[rd as u64, buf, 1]), EAGAIN);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_FILES, 0, 0), 0);
    assert_eq!(h.call(Sysno::Read, &[rd as u64, buf, 1]), 0);
}

#[test]
fn nop_looks_up_registered_files_and_buffers() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 8, 0, 0);
    let fixed = |ud: u64, fd: i32| Sqe {
        op_flags: NOP_FILE | NOP_FIXED_FILE,
        fd,
        ..Sqe::nop(ud)
    };
    // io_nop: no such registered file fails the request (and its link),
    // its CQE carrying the result.
    r.push(&h, fixed(1, 0).flags(LINK));
    r.push(&h, Sqe::nop(2));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(1, 0, 0), (2, -ECANCELED, 0)]);
    let (rd, _) = pipe(&mut h, 0);
    put_fds(&h, a.fds, &[rd]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 1), 0);
    // (A link's next request is task work, after the submission's batch.)
    r.push(&h, fixed(3, 0).flags(LINK));
    r.push(&h, Sqe::nop(4));
    r.push(&h, fixed(5, 1).flags(LINK));
    r.push(&h, Sqe::nop(6));
    assert_eq!(r.enter(&mut h, 4, 0, 0), 4);
    assert_eq!(
        r.reap(&h),
        [(3, 0, 0), (5, 0, 0), (4, 0, 0), (6, -ECANCELED, 0)]
    );
    // io_find_buf_node: likewise for a registered buffer.
    let buffer = |ud: u64, index: u16| Sqe {
        op_flags: NOP_FIXED_BUFFER,
        buf_index: index,
        ..Sqe::nop(ud)
    };
    r.push(&h, buffer(7, 0).flags(LINK));
    r.push(&h, Sqe::nop(8));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(7, 0, 0), (8, -ECANCELED, 0)]);
    let buf = h.anon(P, RW, false);
    put_iovs(&h, a.iovs, &[(buf, P)]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 1), 0);
    r.push(&h, buffer(9, 0).flags(LINK));
    r.push(&h, Sqe::nop(10));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(9, 0, 0), (10, 0, 0)]);
}

#[test]
fn the_files_update_operation_installs_and_allocates() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, wr) = pipe(&mut h, 0);
    let update = |ud: u64, off: u64, n: u32| Sqe {
        opcode: FILES_UPDATE,
        off,
        addr: a.fds,
        len: n,
        user_data: ud,
        ..Sqe::default()
    };
    // io_files_update_prep: slots, and neither a registered file, flags,
    // nor splice_fd_in.
    r.push(&h, update(1, 0, 0));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    r.push(&h, update(2, 0, 1).flags(FIXED_FILE));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    r.push(
        &h,
        Sqe {
            op_flags: 1,
            ..update(3, 0, 1)
        },
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(
        r.reap(&h),
        [(1, -EINVAL, 0), (2, -EINVAL, 0), (3, -EINVAL, 0)]
    );
    // io_files_update: without a table ENXIO, which fails a link.
    put_fds(&h, a.fds, &[rd, wr]);
    r.push(&h, update(4, 0, 1).flags(LINK));
    r.push(&h, Sqe::nop(5));
    assert_eq!(r.enter(&mut h, 2, 0, 0), 2);
    assert_eq!(r.reap(&h), [(4, -ENXIO, 0), (5, -ECANCELED, 0)]);
    rsrc_register(&h, a.arg, 4, SPARSE, 0, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg, 32), 0);
    r.push(&h, update(6, 1, 2));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(6, 2, 0)]);
    // io_files_update_with_index_alloc: the hint is after slot 2, so slot
    // 3, then from the start slot 0, then none (ENFILE ends it).
    put_fds(&h, a.fds, &[rd, rd, rd]);
    r.push(&h, update(7, INDEX_ALLOC, 3));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(7, 2, 0)]);
    assert_eq!(
        (
            u32_at(&h, a.fds),
            u32_at(&h, a.fds + 4),
            u32_at(&h, a.fds + 8)
        ),
        (3, 0, rd as u32)
    );
    r.push(&h, update(8, INDEX_ALLOC, 1));
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(8, -ENFILE, 0)]);
}

#[test]
fn the_allocation_range_follows_io_register_file_alloc_range() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 8, 0, 0);
    let (rd, _) = pipe(&mut h, 0);
    let range = |h: &Harness, off: u32, len: u32, resv: u64| {
        put_u32s(h, a.arg, &[off, len]);
        put_u64s(h, a.arg + 8, &[resv]);
    };
    range(&h, 0, 0, 0);
    // __io_uring_register: an argument and nothing else.
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, 0, 0),
        neg(EINVAL)
    );
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 1),
        neg(EINVAL)
    );
    // Within the table (an empty range fits none).
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0), 0);
    range(&h, 0, 1, 0);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0),
        neg(EINVAL)
    );
    rsrc_register(&h, a.arg + 0x80, 8, SPARSE, 0, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES2, a.arg + 0x80, 32), 0);
    range(&h, u32::MAX, 2, 0);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0),
        neg(EOVERFLOW)
    );
    range(&h, 6, 3, 0);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0),
        neg(EINVAL)
    );
    range(&h, 2, 3, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0),
        neg(EINVAL)
    );
    range(&h, 2, 3, 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILE_ALLOC_RANGE, a.arg, 0), 0);
    // Slots 2 to 4, then ENFILE.
    put_fds(&h, a.fds, &[rd, rd, rd, rd]);
    r.push(
        &h,
        Sqe {
            opcode: FILES_UPDATE,
            off: INDEX_ALLOC,
            addr: a.fds,
            len: 4,
            user_data: 1,
            ..Sqe::default()
        },
    );
    assert_eq!(r.enter(&mut h, 1, 0, 0), 1);
    assert_eq!(r.reap(&h), [(1, 3, 0)]);
    let slots: Vec<u32> = (0..4).map(|i| u32_at(&h, a.fds + 4 * i)).collect();
    assert_eq!(slots, [2, 3, 4, rd as u32]);
}

#[test]
fn registering_buffers_follows_io_sqe_buffers_register() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let buf = h.anon(3 * P, RW, false);
    let ro = h.anon(P, PROT_READ, false);
    // Pages 1 and 3 unmapped: a hole, and a range running into one.
    let holes = h.anon(4 * P, RW, false);
    h.ok(Sysno::Munmap, &[holes + P, P]);
    h.ok(Sysno::Munmap, &[holes + 3 * P, P]);
    // __io_uring_register: an array is needed.
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, 0, 1), neg(EFAULT));
    // io_sqe_buffers_register: 1 to IORING_MAX_REG_BUFFERS slots.
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 0), neg(EINVAL));
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, (1 << 14) + 1),
        neg(EINVAL)
    );
    // No address and no length is an empty slot; io_pin_pages charges each
    // page the range touches (2 here) to VmPin.
    assert_eq!(vm_pin(&h), 0);
    put_iovs(&h, a.iovs, &[(buf + 0x10, 0x1ff0), (0, 0)]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 2), 0);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 2), neg(EBUSY));
    assert_eq!(
        user_rsrc(&h, r.fd),
        format!(
            "UserFiles:\t0\nUserBufs:\t2\n    0: 0x{:x}/8176\n    1: <none>\n",
            buf + 0x10
        )
    );
    assert_eq!(vm_pin(&h), 8);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_BUFFERS, 0, 1), neg(EINVAL));
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_BUFFERS, 0, 0), 0);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_BUFFERS, 0, 0), neg(ENXIO));
    assert_eq!(vm_pin(&h), 0);
    // io_buffer_validate: a length without an address, an address without
    // a length or with more than 1 GiB, a range wrapping; io_pin_pages:
    // pages not mapped writable. A negative length is iovec_from_user's.
    let refused = [
        ((0, 5), EFAULT),
        ((buf, 0), EFAULT),
        ((buf, (1 << 30) + 1), EFAULT),
        ((!(P - 1), 1), EOVERFLOW),
        ((ro, P), EFAULT),
        ((holes + P, P), EFAULT),
        ((holes + 2 * P, 2 * P), EFAULT),
        ((buf, 1 << 63), EINVAL),
    ];
    for (iov, e) in refused {
        put_iovs(&h, a.iovs, &[(buf, P), iov]);
        assert_eq!(
            reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 2),
            neg(e),
            "{iov:x?}"
        );
        // What was built goes.
        assert_eq!(reg(&mut h, r.fd, UNREGISTER_BUFFERS, 0, 0), neg(ENXIO));
        assert_eq!(vm_pin(&h), 0);
    }
}

#[test]
fn buffer_updates_follow_io_sqe_buffers_update() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let buf = h.anon(3 * P, RW, false);
    put_iovs(&h, a.iovs, &[(buf, P), (buf + P, P)]);
    put_u64s(&h, a.tags, &[0x100, 0]);
    // io_register_rsrc: a sparse table takes no vectors.
    rsrc_register(&h, a.arg, 2, SPARSE, a.iovs, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS2, a.arg, 32), neg(EINVAL));
    rsrc_register(&h, a.arg, 2, 0, a.iovs, a.tags);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS2, a.arg, 32), 0);
    assert_eq!(vm_pin(&h), 8);
    // __io_sqe_buffers_update: the replaced node's tag posts.
    put_iovs(&h, a.iovs, &[(buf + 2 * P, P)]);
    put_u64s(&h, a.tags, &[0x200]);
    rsrc_update2(&h, a.arg, 0, a.iovs, a.tags, 1);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS_UPDATE, a.arg, 32), 1);
    assert_eq!(r.reap(&h), [(0x100, 0, 0)]);
    assert_eq!(vm_pin(&h), 8);
    // An empty slot may not have a tag; untagged, it empties the slot.
    put_iovs(&h, a.iovs, &[(0, 0)]);
    rsrc_update2(&h, a.arg, 1, a.iovs, a.tags, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_BUFFERS_UPDATE, a.arg, 32),
        neg(EINVAL)
    );
    rsrc_update2(&h, a.arg, 1, a.iovs, 0, 1);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS_UPDATE, a.arg, 32), 1);
    assert_eq!(vm_pin(&h), 4);
    assert_eq!(
        user_rsrc(&h, r.fd),
        format!(
            "UserFiles:\t0\nUserBufs:\t2\n    0: 0x{:x}/4096\n    1: <none>\n",
            buf + 2 * P
        )
    );
    // Past the table; the first bad vector ends it.
    rsrc_update2(&h, a.arg, 2, a.iovs, 0, 1);
    assert_eq!(
        reg(&mut h, r.fd, REGISTER_BUFFERS_UPDATE, a.arg, 32),
        neg(EINVAL)
    );
    // The first replaces slot 0, whose node's tag posts; the second is
    // refused and ends the update.
    put_iovs(&h, a.iovs, &[(buf, P), (0, 1)]);
    rsrc_update2(&h, a.arg, 0, a.iovs, 0, 2);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS_UPDATE, a.arg, 32), 1);
    assert_eq!(r.reap(&h), [(0x200, 0, 0)]);
    assert_eq!(reg(&mut h, r.fd, UNREGISTER_BUFFERS, 0, 0), 0);
    assert_eq!(r.reap(&h), []);
    assert_eq!(vm_pin(&h), 0);
}

#[test]
fn pinned_memory_is_charged_to_a_user_without_cap_ipc_lock() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    non_root(&mut h);
    // A 4-entry ring's regions: one page of rings, one of SQEs.
    h.proc.state.rlimits[RLIMIT_MEMLOCK].0 = 4 * P;
    let r = setup(&mut h, 4, 0, 0);
    let buf = h.anon(3 * P, RW, false);
    // __io_account_mem: 2 + 3 pages is past the limit.
    put_iovs(&h, a.iovs, &[(buf, 3 * P)]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 1), neg(ENOMEM));
    assert_eq!(vm_pin(&h), 0);
    put_iovs(&h, a.iovs, &[(buf, 2 * P)]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 1), 0);
    assert_eq!(vm_pin(&h), 8);
    // io_create_region: a second ring does not fit.
    assert_eq!(setup_raw(&mut h, 4, 0, 0).unwrap_err(), ENOMEM);
    // Its release uncharges its regions and buffers.
    h.ok(Sysno::Close, &[r.fd]);
    assert_eq!(vm_pin(&h), 0);
    let r = setup(&mut h, 4, 0, 0);
    // With CAP_IPC_LOCK nothing is charged to the user, but VmPin counts.
    h.proc.state.creds = (0, 0, 0, 0);
    let r2 = setup(&mut h, 4, 0, 0);
    put_iovs(&h, a.iovs, &[(buf, 3 * P)]);
    assert_eq!(reg(&mut h, r2.fd, REGISTER_BUFFERS, a.iovs, 1), 0);
    assert_eq!(vm_pin(&h), 12);
    // The user's charge stays with the ring it was made for.
    assert_eq!(reg(&mut h, r.fd, REGISTER_BUFFERS, a.iovs, 1), neg(ENOMEM));
}

#[test]
fn cloned_buffers_share_the_source_buffers() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let src = setup(&mut h, 4, 0, 0);
    let dst = setup(&mut h, 4, 0, 0);
    let none = setup(&mut h, 4, 0, 0);
    let buf = h.anon(2 * P, RW, false);
    put_iovs(&h, a.iovs, &[(buf, P), (buf + P, P)]);
    put_u64s(&h, a.tags, &[1, 2]);
    rsrc_register(&h, a.arg, 2, 0, a.iovs, a.tags);
    assert_eq!(reg(&mut h, src.fd, REGISTER_BUFFERS2, a.arg, 32), 0);
    let clone = |h: &Harness, fd: u64, flags: u32, src_off: u32, dst_off: u32, nr: u32| {
        put_u32s(h, a.arg, &[fd as u32, flags, src_off, dst_off, nr, 0, 0, 0]);
    };
    // __io_uring_register: an argument, one.
    clone(&h, src.fd, 0, 0, 0, 0);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, 0, 1),
        neg(EINVAL)
    );
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 0),
        neg(EINVAL)
    );
    // io_register_clone_buffers: known flags, zero padding, a ring.
    clone(&h, src.fd, 4, 0, 0, 0);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(EINVAL)
    );
    clone(&h, src.fd, 0, 0, 0, 0);
    put(&h, a.arg + 28, &1u32.to_le_bytes());
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(EINVAL)
    );
    let (rd, _) = pipe(&mut h, 0);
    clone(&h, rd as u64, 0, 0, 0, 0);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(EOPNOTSUPP)
    );
    clone(&h, 99, 0, 0, 0, 0);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(EBADF)
    );
    // io_clone_buffers: a source with buffers; offsets need a count; the
    // range within the source (EOVERFLOW) and the result within
    // IORING_MAX_REG_BUFFERS.
    clone(&h, none.fd, 0, 0, 0, 0);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(ENXIO)
    );
    let refused = [
        ((1, 0, 0), EINVAL),
        ((0, 0, 3), EINVAL),
        ((1, 0, 2), EOVERFLOW),
        ((0, 1 << 14, 1), EINVAL),
    ];
    for ((src_off, dst_off, nr), e) in refused {
        clone(&h, src.fd, 0, src_off, dst_off, nr);
        assert_eq!(
            reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
            neg(e),
            "{src_off} {dst_off} {nr}"
        );
    }
    // All of them, pinned once; the clones have no tags.
    clone(&h, src.fd, 0, 0, 0, 0);
    assert_eq!(reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1), 0);
    assert_eq!(user_rsrc(&h, dst.fd), user_rsrc(&h, src.fd));
    assert_eq!(vm_pin(&h), 8);
    assert_eq!(
        reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1),
        neg(EBUSY)
    );
    // IORING_REGISTER_DST_REPLACE: source slot 0 into slot 1, slot 0 kept.
    clone(&h, src.fd, DST_REPLACE, 0, 1, 1);
    assert_eq!(reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1), 0);
    assert_eq!(
        user_rsrc(&h, dst.fd),
        format!("UserFiles:\t0\nUserBufs:\t2\n    0: 0x{buf:x}/4096\n    1: 0x{buf:x}/4096\n")
    );
    // The source's buffers go as their last holder lets go: its second
    // now, its first with the clone.
    assert_eq!(reg(&mut h, src.fd, UNREGISTER_BUFFERS, 0, 0), 0);
    assert_eq!(src.reap(&h), [(2, 0, 0), (1, 0, 0)]);
    assert_eq!(vm_pin(&h), 4);
    assert_eq!(reg(&mut h, dst.fd, UNREGISTER_BUFFERS, 0, 0), 0);
    assert_eq!(dst.reap(&h), []);
    assert_eq!(vm_pin(&h), 0);
    // A registered source, and a ring cloning into itself.
    put_iovs(&h, a.iovs, &[(buf, P)]);
    assert_eq!(reg(&mut h, src.fd, REGISTER_BUFFERS, a.iovs, 1), 0);
    let upd = a.arg + 0x80;
    put_u32s(&h, upd, &[5, 0]);
    put_u64s(&h, upd + 8, &[src.fd]);
    assert_eq!(
        h.call(Sysno::IoUringRegister, &[src.fd, REGISTER_RING_FDS, upd, 1]),
        1
    );
    clone(&h, 5, SRC_REGISTERED, 0, 0, 0);
    assert_eq!(reg(&mut h, dst.fd, REGISTER_CLONE_BUFFERS, a.arg, 1), 0);
    clone(&h, src.fd, DST_REPLACE, 0, 1, 1);
    assert_eq!(reg(&mut h, src.fd, REGISTER_CLONE_BUFFERS, a.arg, 1), 0);
    assert_eq!(
        user_rsrc(&h, src.fd),
        format!("UserFiles:\t0\nUserBufs:\t2\n    0: 0x{buf:x}/4096\n    1: 0x{buf:x}/4096\n")
    );
    assert_eq!(vm_pin(&h), 4);
}

#[test]
fn compat_rings_read_compat_vectors() {
    for abi in [LinuxAbi::I386, LinuxAbi::Arm] {
        let mut h = Harness::new(abi);
        let map = |h: &mut Harness, len: u64| {
            h.ok(Sysno::Mmap2, &[0, len, RW, 0x22, u64::from(u32::MAX), 0])
        };
        // The ring need not be mapped (and the unit harness maps with
        // mmap, which these ABIs lack).
        let (fd, _) = setup_raw(&mut h, 4, 0, 0).unwrap();
        let buf = map(&mut h, 2 * P);
        let iovs = map(&mut h, P);
        // struct compat_iovec: two 32-bit words.
        put_u32s(&h, iovs, &[buf as u32, 0x1800, (buf + P) as u32, 0x10]);
        assert_eq!(reg(&mut h, fd, REGISTER_BUFFERS, iovs, 2), 0, "{abi:?}");
        assert_eq!(
            user_rsrc(&h, fd),
            format!(
                "UserFiles:\t0\nUserBufs:\t2\n    0: 0x{buf:x}/6144\n    1: 0x{:x}/16\n",
                buf + P
            ),
            "{abi:?}"
        );
        // compat_ssize_t: a length with its top bit set is negative.
        put_u32s(&h, iovs, &[buf as u32, 0x8000_0000]);
        assert_eq!(reg(&mut h, fd, UNREGISTER_BUFFERS, 0, 0), 0);
        assert_eq!(
            reg(&mut h, fd, REGISTER_BUFFERS, iovs, 1),
            neg(EINVAL),
            "{abi:?}"
        );
    }
}

#[test]
fn fdinfo_escapes_registered_file_paths() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let a = args(&mut h);
    let r = setup(&mut h, 4, 0, 0);
    let fd = h.file("a b\\c", 1, 0, 0);
    put_fds(&h, a.fds, &[fd as i32]);
    assert_eq!(reg(&mut h, r.fd, REGISTER_FILES, a.fds, 1), 0);
    // seq_file_path with " \t\n\\": octal escapes.
    let text = user_rsrc(&h, r.fd);
    assert!(text.contains("a\\040b\\134c"), "{text}");
    assert!(!text.contains("a b"), "{text}");
}
