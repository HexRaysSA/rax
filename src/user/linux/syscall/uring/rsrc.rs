//! Registering files and buffers (`io_uring/rsrc.c`,
//! `io_uring/filetable.c`, Linux 6.19): the `IORING_REGISTER_FILES`,
//! `_FILES2`, `_FILES_UPDATE`, `_FILES_UPDATE2`, `_BUFFERS`, `_BUFFERS2`,
//! `_BUFFERS_UPDATE`, `_FILE_ALLOC_RANGE`, and `_CLONE_BUFFERS`
//! registrations and their `IORING_UNREGISTER_*` counterparts,
//! `IORING_OP_FILES_UPDATE`, and the release of the nodes they hold.
//!
//! A released node with a tag posts a CQE with the tag as its `user_data`
//! and a result of 0; a table freed whole releases its nodes from the last
//! slot down. A registration that fails part way frees what it built
//! without posting any tag.

use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::fs::fd::OpenFile;
use super::super::super::uring::rsrc::{
    FILE_INDEX_ALLOC, FILES_SKIP, Imu, MAX_FIXED_FILES, MAX_REG_BUFFERS, NodeId, Rsrc,
};
use super::super::super::uring::{Req, Ring, State, req_flags as rf};
use super::super::iov::iovec_from_user_as;
use super::super::{Ctx, SysResult};
use super::{memlock_pages, ops, ring_file, submit};
use crate::error::MemoryAccessKind;
use crate::user::mm::Perms;

/// `PAGE_SIZE`.
const P: u64 = 4096;
/// `IORING_RSRC_REGISTER_SPARSE`.
const REGISTER_SPARSE: u32 = 1;
/// `IORING_REGISTER_SRC_REGISTERED`, `IORING_REGISTER_DST_REPLACE`.
const SRC_REGISTERED: u32 = 1;
const DST_REPLACE: u32 = 2;
/// `sizeof(struct io_uring_rsrc_register)`,
/// `sizeof(struct io_uring_rsrc_update2)`, and
/// `sizeof(struct io_uring_rsrc_update)`.
const RSRC_REGISTER: u32 = 32;
const RSRC_UPDATE2: u32 = 32;
const RSRC_UPDATE: usize = 16;
/// `sizeof(struct io_uring_clone_buffers)` and
/// `sizeof(struct io_uring_file_index_range)`.
const CLONE_BUFFERS: usize = 32;
const INDEX_RANGE: usize = 16;
/// `SZ_1G`: the largest buffer (`io_validate_user_buf_range`).
const MAX_BUF: u64 = 1 << 30;

/// A table (`IORING_RSRC_FILE`, `IORING_RSRC_BUFFER`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Buffer,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `io_put_rsrc_node`: the last reference frees the node, posting its tag
/// (`io_free_rsrc_node`, `io_post_aux_cqe`).
pub(super) fn put_node(ring: &Ring, st: &mut State, id: NodeId) {
    if let Some(tag) = st.rsrc.put(id)
        && tag != 0
    {
        ring.post_aux(st, tag, 0, 0);
        submit::commit(ring, st, false);
    }
}

/// `io_put_file` and `io_req_put_rsrc_nodes`: what a freed request held.
pub(super) fn free_req(ring: &Ring, st: &mut State, req: Req) {
    if let Some(f) = req.file {
        st.rsrc.dead.push(Rsrc::File(f));
    }
    if let Some(id) = req.file_node {
        put_node(ring, st, id);
    }
    if let Some(id) = req.buf_node {
        put_node(ring, st, id);
    }
}

/// `io_file_get_fixed`: the registered file in slot `index`, its node
/// referenced by the request.
pub(super) fn get_fixed_file(st: &mut State, req: &mut Req, index: i32) -> Option<Arc<OpenFile>> {
    let id = st.rsrc.file(index as u32)?;
    st.rsrc.get(id);
    req.file_node = Some(id);
    st.rsrc.node_file(id).cloned()
}

/// `io_find_buf_node`: the registered buffer the request names
/// (`buf_index`), its node referenced by the request once.
pub(super) fn find_buf_node(st: &mut State, req: &mut Req) -> Option<NodeId> {
    if let Some(id) = req.buf_node {
        return Some(id);
    }
    let id = st.rsrc.buf(u32::from(req.sqe.buf_index))?;
    st.rsrc.get(id);
    req.buf_node = Some(id);
    Some(id)
}

/// A table's slots.
fn table(st: &mut State, kind: Kind) -> &mut Vec<Option<NodeId>> {
    match kind {
        Kind::File => &mut st.rsrc.files,
        Kind::Buffer => &mut st.rsrc.bufs,
    }
}

/// `io_reset_rsrc_node`: empties a slot; whether it held a node.
fn reset(ring: &Ring, st: &mut State, kind: Kind, index: u32) -> bool {
    match table(st, kind)[index as usize].take() {
        Some(id) => {
            put_node(ring, st, id);
            true
        }
        None => false,
    }
}

/// `io_rsrc_data_free`: the table's nodes released from the last slot down.
fn free_table(ring: &Ring, st: &mut State, kind: Kind) {
    let slots = std::mem::take(table(st, kind));
    for id in slots.into_iter().rev().flatten() {
        put_node(ring, st, id);
    }
}

/// A registration that failed: its nodes go without posting their tags
/// (`io_clear_table_tags`), and the table with them.
fn unwind(ring: &Ring, st: &mut State, kind: Kind) {
    for id in table(st, kind).clone().into_iter().flatten() {
        st.rsrc.clear_tag(id);
    }
    free_table(ring, st, kind);
    if kind == Kind::File {
        st.rsrc.set_alloc_range(0, 0);
    }
}

/// `io_sqe_files_unregister`: `ENXIO` without a table.
pub(super) fn files_unregister(ring: &Ring, st: &mut State) -> SysResult {
    if st.rsrc.files.is_empty() {
        return Err(Errno(ENXIO));
    }
    free_table(ring, st, Kind::File);
    st.rsrc.set_alloc_range(0, 0);
    Ok(0)
}

/// `io_sqe_buffers_unregister`: `ENXIO` without a table.
pub(super) fn buffers_unregister(ring: &Ring, st: &mut State) -> SysResult {
    if st.rsrc.bufs.is_empty() {
        return Err(Errno(ENXIO));
    }
    free_table(ring, st, Kind::Buffer);
    Ok(0)
}

/// `io_sqe_files_register`: a table of `nr` slots (at most
/// `IORING_MAX_FIXED_FILES` and `RLIMIT_NOFILE`, else `EMFILE`), slot `i`
/// holding descriptor `fds[i]` with tag `tags[i]`; without `fds`, or for
/// descriptor -1, the slot stays empty and may have no tag (`EINVAL`). A
/// descriptor not open is `EBADF`, and so is a ring. The whole table is
/// the allocation range.
pub(super) fn files_register(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    fds: u64,
    nr: u32,
    tags: u64,
) -> SysResult {
    if !st.rsrc.files.is_empty() {
        return Err(Errno(EBUSY));
    }
    if nr == 0 {
        return Err(Errno(EINVAL));
    }
    if nr > MAX_FIXED_FILES || u64::from(nr) > super::super::io::nofile(c) {
        return Err(Errno(EMFILE));
    }
    st.rsrc.files = vec![None; nr as usize];
    if let Err(e) = fill_files(c, st, fds, nr, tags) {
        unwind(ring, st, Kind::File);
        return Err(e);
    }
    st.rsrc.set_alloc_range(0, nr);
    Ok(0)
}

fn fill_files(c: &Ctx<'_>, st: &mut State, fds: u64, nr: u32, tags: u64) -> Result<(), Errno> {
    for i in 0..nr {
        let tag = if tags != 0 {
            c.read_u64(tags.wrapping_add(8 * u64::from(i)))
                .map_err(|_| Errno(EFAULT))?
        } else {
            0
        };
        let fd = if fds != 0 {
            c.read_u32(fds.wrapping_add(4 * u64::from(i)))
                .map_err(|_| Errno(EFAULT))? as i32
        } else {
            -1
        };
        if fd == -1 {
            if tag != 0 {
                return Err(Errno(EINVAL));
            }
            continue;
        }
        let file = ops::fget(c, fd)?;
        if ring_file(&file).is_some() {
            return Err(Errno(EBADF));
        }
        let id = st.rsrc.alloc(tag, Rsrc::File(file));
        st.rsrc.files[i as usize] = Some(id);
        st.rsrc.bitmap_set(i);
    }
    Ok(())
}

/// `__io_sqe_files_update`: slots `offset..offset + nr` take descriptors
/// `fds[..]` with tags `tags[..]`: `IORING_REGISTER_FILES_SKIP` leaves a
/// slot, -1 empties it, and neither takes a tag (`EINVAL`). A slot is
/// emptied before its new descriptor is looked up, so a bad one (`EBADF`)
/// leaves it empty. The number of slots done, or the error if none was.
fn files_update(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    offset: u32,
    fds: u64,
    tags: u64,
    nr: u32,
) -> SysResult {
    if st.rsrc.files.is_empty() {
        return Err(Errno(ENXIO));
    }
    if u64::from(offset) + u64::from(nr) > st.rsrc.files.len() as u64 {
        return Err(Errno(EINVAL));
    }
    let mut done = 0u32;
    let mut err = Errno(0);
    while done < nr {
        let at = u64::from(done);
        let tag = if tags != 0 {
            c.read_u64(tags.wrapping_add(8 * at))
        } else {
            Ok(0)
        };
        let fd = c.read_u32(fds.wrapping_add(4 * at));
        let (Ok(tag), Ok(fd)) = (tag, fd) else {
            err = Errno(EFAULT);
            break;
        };
        let fd = fd as i32;
        if (fd == FILES_SKIP || fd == -1) && tag != 0 {
            err = Errno(EINVAL);
            break;
        }
        if fd == FILES_SKIP {
            done += 1;
            continue;
        }
        let i = offset + done;
        if reset(ring, st, Kind::File, i) {
            st.rsrc.bitmap_clear(i);
        }
        if fd != -1 {
            let file = match ops::fget(c, fd) {
                Ok(f) if ring_file(&f).is_none() => f,
                _ => {
                    err = Errno(EBADF);
                    break;
                }
            };
            let id = st.rsrc.alloc(tag, Rsrc::File(file));
            st.rsrc.files[i as usize] = Some(id);
            st.rsrc.bitmap_set(i);
        }
        done += 1;
    }
    if done != 0 {
        Ok(u64::from(done))
    } else {
        Err(err)
    }
}

/// One `struct iovec` in the instance's layout (`iovec_from_user`).
fn read_iov(c: &Ctx<'_>, ring: &Ring, at: u64) -> Result<(u64, u64), Errno> {
    Ok(iovec_from_user_as(c, at, 1, ring.compat)?[0])
}

/// The size of a `struct iovec` in the instance's layout.
fn iov_size(ring: &Ring) -> u64 {
    if ring.compat { 8 } else { 16 }
}

/// `io_buffer_validate`: no address and no length is an empty slot; an
/// address needs a length of at most 1 GiB (`EFAULT`) whose page-rounded
/// end does not wrap (`EOVERFLOW`).
fn buffer_validate(base: u64, len: u64) -> Result<(), Errno> {
    if base == 0 {
        return if len != 0 { Err(Errno(EFAULT)) } else { Ok(()) };
    }
    if len > MAX_BUF || len == 0 {
        return Err(Errno(EFAULT));
    }
    base.checked_add(len.next_multiple_of(P))
        .map(|_| ())
        .ok_or(Errno(EOVERFLOW))
}

/// `io_pin_pages`: the pages `[addr, addr + len)` touches, each mapped
/// writable and faulted in (`pin_user_pages_fast` with `FOLL_WRITE`);
/// `EFAULT` if one is not, `EOVERFLOW` if the range wraps.
fn pin_pages(c: &Ctx<'_>, addr: u64, len: u64) -> Result<u64, Errno> {
    let end = addr
        .checked_add(len)
        .and_then(|e| e.checked_add(P - 1))
        .ok_or(Errno(EOVERFLOW))?;
    let (start, end) = (addr / P, end / P);
    let nr = end - start;
    if nr == 0 {
        return Err(Errno(EINVAL));
    }
    if nr > i32::MAX as u64 {
        return Err(Errno(EOVERFLOW));
    }
    for page in start..end {
        let at = page * P;
        let writable =
            c.p.space
                .vma_at(at)
                .is_some_and(|v| v.perms.contains(Perms::WRITE));
        if !writable || c.p.space.probe(at, 1, MemoryAccessKind::Write).is_err() {
            return Err(Errno(EFAULT));
        }
    }
    Ok(nr)
}

/// `io_sqe_buffer_register`: none for no address; otherwise the pages
/// pinned (`EFAULT`) and charged (`ENOMEM`), each page once
/// (`io_buffer_account_pin`).
fn buffer_register(
    c: &Ctx<'_>,
    ring: &Ring,
    base: u64,
    len: u64,
) -> Result<Option<Arc<Imu>>, Errno> {
    if base == 0 {
        return Ok(None);
    }
    let pages = pin_pages(c, base, len)?;
    ring.account.charge_user(pages, memlock_pages(c))?;
    ring.account
        .mm
        .fetch_add(pages, std::sync::atomic::Ordering::Relaxed);
    Ok(Some(Arc::new(Imu {
        addr: base,
        len: len as u32,
        acct_pages: pages,
        account: ring.account.clone(),
    })))
}

/// `io_sqe_buffers_register`: a table of `nr` slots (at most
/// `IORING_MAX_REG_BUFFERS`), slot `i` the buffer `iovs[i]` with tag
/// `tags[i]`; without `iovs` every slot is empty, and an empty slot may
/// have no tag (`EINVAL`).
pub(super) fn buffers_register(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    iovs: u64,
    nr: u32,
    tags: u64,
) -> SysResult {
    if !st.rsrc.bufs.is_empty() {
        return Err(Errno(EBUSY));
    }
    if nr == 0 || nr > MAX_REG_BUFFERS {
        return Err(Errno(EINVAL));
    }
    st.rsrc.bufs = vec![None; nr as usize];
    if let Err(e) = fill_bufs(c, ring, st, iovs, nr, tags) {
        unwind(ring, st, Kind::Buffer);
        return Err(e);
    }
    Ok(0)
}

fn fill_bufs(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    iovs: u64,
    nr: u32,
    tags: u64,
) -> Result<(), Errno> {
    for i in 0..nr {
        let (base, len) = if iovs != 0 {
            let iov = read_iov(c, ring, iovs.wrapping_add(iov_size(ring) * u64::from(i)))?;
            buffer_validate(iov.0, iov.1)?;
            iov
        } else {
            (0, 0)
        };
        let tag = if tags != 0 {
            c.read_u64(tags.wrapping_add(8 * u64::from(i)))
                .map_err(|_| Errno(EFAULT))?
        } else {
            0
        };
        let imu = buffer_register(c, ring, base, len)?;
        let Some(imu) = imu else {
            if tag != 0 {
                return Err(Errno(EINVAL));
            }
            continue;
        };
        let id = st.rsrc.alloc(tag, Rsrc::Buf(imu));
        st.rsrc.bufs[i as usize] = Some(id);
    }
    Ok(())
}

/// `__io_sqe_buffers_update`: slots `offset..offset + nr` take the
/// buffers `iovs[..]` with tags `tags[..]` (an empty one no tag,
/// `EINVAL`); the number done, or the error if none was.
fn buffers_update(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    offset: u32,
    iovs: u64,
    tags: u64,
    nr: u32,
) -> SysResult {
    if st.rsrc.bufs.is_empty() {
        return Err(Errno(ENXIO));
    }
    if u64::from(offset) + u64::from(nr) > st.rsrc.bufs.len() as u64 {
        return Err(Errno(EINVAL));
    }
    let mut at = iovs;
    let mut done = 0u32;
    let mut err = Errno(0);
    while done < nr {
        let step = (|| -> Result<Option<NodeId>, Errno> {
            let (base, len) = read_iov(c, ring, at)?;
            let tag = if tags != 0 {
                c.read_u64(tags.wrapping_add(8 * u64::from(done)))
                    .map_err(|_| Errno(EFAULT))?
            } else {
                0
            };
            buffer_validate(base, len)?;
            match buffer_register(c, ring, base, len)? {
                Some(imu) => Ok(Some(st.rsrc.alloc(tag, Rsrc::Buf(imu)))),
                None if tag != 0 => Err(Errno(EINVAL)),
                None => Ok(None),
            }
        })();
        let id = match step {
            Ok(id) => id,
            Err(e) => {
                err = e;
                break;
            }
        };
        let i = offset + done;
        reset(ring, st, Kind::Buffer, i);
        st.rsrc.bufs[i as usize] = id;
        at = at.wrapping_add(iov_size(ring));
        done += 1;
    }
    if done != 0 {
        Ok(u64::from(done))
    } else {
        Err(err)
    }
}

/// `__io_register_rsrc_update`: the slots past `offset` may not wrap
/// (`EOVERFLOW`).
#[allow(clippy::too_many_arguments)]
fn rsrc_update(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    kind: Kind,
    offset: u32,
    data: u64,
    tags: u64,
    nr: u32,
) -> SysResult {
    if offset.checked_add(nr).is_none() {
        return Err(Errno(EOVERFLOW));
    }
    match kind {
        Kind::File => files_update(c, ring, st, offset, data, tags, nr),
        Kind::Buffer => buffers_update(c, ring, st, offset, data, tags, nr),
    }
}

/// `io_register_files_update`: a `struct io_uring_rsrc_update` (`resv`
/// zero) for `nr_args` slots.
pub(super) fn register_files_update(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    arg: u64,
    nr_args: u32,
) -> SysResult {
    if nr_args == 0 {
        return Err(Errno(EINVAL));
    }
    let b = c.read_mem(arg, RSRC_UPDATE).map_err(|_| Errno(EFAULT))?;
    if le32(&b, 4) != 0 {
        return Err(Errno(EINVAL));
    }
    rsrc_update(
        c,
        ring,
        st,
        Kind::File,
        le32(&b, 0),
        le64(&b, 8),
        0,
        nr_args,
    )
}

/// `io_register_rsrc_update`: a `struct io_uring_rsrc_update2` of `size`
/// bytes exactly, for `nr` (nonzero) slots, reserved words zero.
pub(super) fn register_rsrc_update(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    arg: u64,
    size: u32,
    kind: Kind,
) -> SysResult {
    if size != RSRC_UPDATE2 {
        return Err(Errno(EINVAL));
    }
    let b = c
        .read_mem(arg, RSRC_UPDATE2 as usize)
        .map_err(|_| Errno(EFAULT))?;
    let (offset, resv, data, tags, nr, resv2) = (
        le32(&b, 0),
        le32(&b, 4),
        le64(&b, 8),
        le64(&b, 16),
        le32(&b, 24),
        le32(&b, 28),
    );
    if nr == 0 || resv != 0 || resv2 != 0 {
        return Err(Errno(EINVAL));
    }
    rsrc_update(c, ring, st, kind, offset, data, tags, nr)
}

/// `io_register_rsrc`: a `struct io_uring_rsrc_register` of `size` bytes
/// exactly, for `nr` (nonzero) slots; `IORING_RSRC_REGISTER_SPARSE` (the
/// only flag) leaves them empty and takes no `data`.
pub(super) fn register_rsrc(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    arg: u64,
    size: u32,
    kind: Kind,
) -> SysResult {
    if size != RSRC_REGISTER {
        return Err(Errno(EINVAL));
    }
    let b = c
        .read_mem(arg, RSRC_REGISTER as usize)
        .map_err(|_| Errno(EFAULT))?;
    let (nr, flags, resv2, data, tags) = (
        le32(&b, 0),
        le32(&b, 4),
        le64(&b, 8),
        le64(&b, 16),
        le64(&b, 24),
    );
    if nr == 0 || resv2 != 0 || flags & !REGISTER_SPARSE != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & REGISTER_SPARSE != 0 && data != 0 {
        return Err(Errno(EINVAL));
    }
    match kind {
        Kind::File => files_register(c, ring, st, data, nr, tags),
        Kind::Buffer => buffers_register(c, ring, st, data, nr, tags),
    }
}

/// `io_register_file_alloc_range`: a `struct io_uring_file_index_range`
/// within the table (`EINVAL`), not wrapping (`EOVERFLOW`), `resv` zero.
pub(super) fn file_alloc_range(c: &Ctx<'_>, st: &mut State, arg: u64) -> SysResult {
    let b = c.read_mem(arg, INDEX_RANGE).map_err(|_| Errno(EFAULT))?;
    let (off, len, resv) = (le32(&b, 0), le32(&b, 4), le64(&b, 8));
    let end = off.checked_add(len).ok_or(Errno(EOVERFLOW))?;
    if resv != 0 || end as usize > st.rsrc.files.len() {
        return Err(Errno(EINVAL));
    }
    st.rsrc.set_alloc_range(off, len);
    Ok(0)
}

/// `io_register_clone_buffers`: a `struct io_uring_clone_buffers` naming
/// the source ring by descriptor or, with `IORING_REGISTER_SRC_REGISTERED`,
/// by registered index; the buffers it names are cloned in (`io_clone_buffers`).
pub(super) fn clone_buffers(c: &Ctx<'_>, ring: &Arc<Ring>, arg: u64) -> SysResult {
    let b = c.read_mem(arg, CLONE_BUFFERS).map_err(|_| Errno(EFAULT))?;
    let (src_fd, flags) = (le32(&b, 0), le32(&b, 4));
    if flags & !(SRC_REGISTERED | DST_REPLACE) != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & DST_REPLACE == 0 && !ring.state().rsrc.bufs.is_empty() {
        return Err(Errno(EBUSY));
    }
    if b[20..32].iter().any(|&x| x != 0) {
        return Err(Errno(EINVAL));
    }
    let src = super::register::get_ring(c, src_fd, flags & SRC_REGISTERED != 0)?;
    let arg = CloneArg {
        flags,
        src_off: le32(&b, 8),
        dst_off: le32(&b, 12),
        nr: le32(&b, 16),
    };
    if Arc::ptr_eq(&src, ring) {
        let mut st = ring.state();
        let src_bufs = src_table(&st);
        return clone_into(ring, &mut st, &ring.account, &src_bufs, &arg);
    }
    // lock_two_rings: by address.
    let (mut st, src_st) = if Arc::as_ptr(ring) < Arc::as_ptr(&src) {
        let a = ring.state();
        (a, src.state())
    } else {
        let s = src.state();
        (ring.state(), s)
    };
    if src_st.submitter.is_some_and(|t| t != c.t.tid) {
        return Err(Errno(EEXIST));
    }
    let src_bufs = src_table(&src_st);
    drop(src_st);
    clone_into(ring, &mut st, &src.account, &src_bufs, &arg)
}

/// What `io_clone_buffers` takes from its argument.
struct CloneArg {
    flags: u32,
    src_off: u32,
    dst_off: u32,
    nr: u32,
}

/// The source ring's buffers, slot by slot.
fn src_table(st: &State) -> Vec<Option<Arc<Imu>>> {
    st.rsrc
        .bufs
        .iter()
        .map(|slot| slot.and_then(|id| st.rsrc.node_buf(id).cloned()))
        .collect()
}

/// `io_clone_buffers`: both rings charge the same user and address space
/// (`EINVAL`); `nr` buffers (0 for all) from `src_off` of the source's
/// table (`ENXIO` if it has none) into slots from `dst_off`, the
/// destination's other nodes kept around them; its old table is released
/// with `IORING_REGISTER_DST_REPLACE` (and must be empty without it,
/// `EBUSY`). Cloned slots share the source's buffers and have no tags.
fn clone_into(
    ring: &Ring,
    st: &mut State,
    src_account: &super::super::super::uring::rsrc::Account,
    src: &[Option<Arc<Imu>>],
    arg: &CloneArg,
) -> SysResult {
    if !ring.account.same(src_account) {
        return Err(Errno(EINVAL));
    }
    if arg.nr == 0 && (arg.dst_off != 0 || arg.src_off != 0) {
        return Err(Errno(EINVAL));
    }
    let old = st.rsrc.bufs.len() as u32;
    if old != 0 && arg.flags & DST_REPLACE == 0 {
        return Err(Errno(EBUSY));
    }
    let nbufs = src.len() as u32;
    if nbufs == 0 {
        return Err(Errno(ENXIO));
    }
    let nr = if arg.nr == 0 {
        nbufs
    } else if arg.nr > nbufs || arg.nr > MAX_REG_BUFFERS {
        return Err(Errno(EINVAL));
    } else {
        arg.nr
    };
    match nr.checked_add(arg.src_off) {
        Some(end) if end <= nbufs => {}
        _ => return Err(Errno(EOVERFLOW)),
    }
    let total = nr.checked_add(arg.dst_off).ok_or(Errno(EOVERFLOW))?;
    if total > MAX_REG_BUFFERS {
        return Err(Errno(EINVAL));
    }
    let mut data: Vec<Option<NodeId>> = vec![None; total.max(old) as usize];
    // The destination's nodes before and after the cloned range stay.
    let before = 0..arg.dst_off.min(old) as usize;
    let after = total as usize..old as usize;
    let slots = st.rsrc.bufs.clone();
    for i in before.chain(after) {
        if let Some(id) = slots[i] {
            st.rsrc.get(id);
            data[i] = Some(id);
        }
    }
    for k in 0..nr {
        let imu = src[(arg.src_off + k) as usize].clone();
        data[(arg.dst_off + k) as usize] = imu.map(|b| st.rsrc.alloc(0, Rsrc::Buf(b)));
    }
    if arg.flags & DST_REPLACE != 0 {
        free_table(ring, st, Kind::Buffer);
    }
    st.rsrc.bufs = data;
    Ok(0)
}

/// `io_install_fixed_file` through `__io_fixed_fd_install`: `file` into
/// the free slot the allocation range gives (`IORING_FILE_INDEX_ALLOC`,
/// returned) or into slot `slot - 1`, replacing what it held. A ring is
/// `EBADF`, no table `ENXIO`, a slot past it `EINVAL`.
pub(super) fn fixed_fd_install(
    ring: &Ring,
    st: &mut State,
    file: Arc<OpenFile>,
    slot: u32,
) -> Result<u32, Errno> {
    let alloc = slot == FILE_INDEX_ALLOC;
    let index = if alloc {
        st.rsrc.bitmap_get()?
    } else {
        slot.wrapping_sub(1)
    };
    if ring_file(&file).is_some() {
        return Err(Errno(EBADF));
    }
    if st.rsrc.files.is_empty() {
        return Err(Errno(ENXIO));
    }
    if index as usize >= st.rsrc.files.len() {
        return Err(Errno(EINVAL));
    }
    let id = st.rsrc.alloc(0, Rsrc::File(file));
    if !reset(ring, st, Kind::File, index) {
        st.rsrc.bitmap_set(index);
    }
    st.rsrc.files[index as usize] = Some(id);
    Ok(if alloc { index } else { 0 })
}

/// `io_fixed_fd_remove`: empties slot `offset` (`ENXIO` without a table,
/// `EINVAL` past it, `EBADF` if empty).
pub(super) fn fixed_fd_remove(ring: &Ring, st: &mut State, offset: u32) -> Result<(), Errno> {
    if st.rsrc.files.is_empty() {
        return Err(Errno(ENXIO));
    }
    if offset as usize >= st.rsrc.files.len() {
        return Err(Errno(EINVAL));
    }
    if st.rsrc.file(offset).is_none() {
        return Err(Errno(EBADF));
    }
    reset(ring, st, Kind::File, offset);
    st.rsrc.bitmap_clear(offset);
    Ok(())
}

/// `io_files_update_prep`: not on a registered file nor with a buffer
/// group (`EINVAL`), `rw_flags` and `splice_fd_in` zero, `len` slots from
/// `off` (truncated to 32 bits).
pub(super) fn files_update_prep(req: &Req) -> Result<(), Errno> {
    if req.flags & (rf::FIXED_FILE | rf::BUFFER_SELECT) != 0 {
        return Err(Errno(EINVAL));
    }
    if req.sqe.op_flags != 0 || req.sqe.file_index != 0 {
        return Err(Errno(EINVAL));
    }
    if req.sqe.len == 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `io_files_update`: `IORING_REGISTER_FILES_UPDATE` from the SQE, or,
/// with `off` `IORING_FILE_INDEX_ALLOC`, each descriptor at `addr`
/// installed in a free slot and replaced by its index
/// (`io_files_update_with_index_alloc`); the result is the number done.
pub(super) fn files_update_issue(c: &Ctx<'_>, ring: &Ring, st: &mut State, req: &mut Req) {
    let offset = req.sqe.off as u32;
    let (arg, nr) = (req.sqe.addr, req.sqe.len);
    let ret = if offset == FILE_INDEX_ALLOC {
        update_with_index_alloc(c, ring, st, arg, nr)
    } else {
        rsrc_update(c, ring, st, Kind::File, offset, arg, 0, nr)
    };
    let res = match ret {
        Ok(n) => n as i32,
        Err(e) => {
            req.set_fail();
            -e.0
        }
    };
    req.res = res;
    req.cflags = 0;
}

fn update_with_index_alloc(
    c: &Ctx<'_>,
    ring: &Ring,
    st: &mut State,
    fds: u64,
    nr: u32,
) -> SysResult {
    if st.rsrc.files.is_empty() {
        return Err(Errno(ENXIO));
    }
    let mut done = 0u32;
    let mut err = Errno(0);
    while done < nr {
        let at = fds.wrapping_add(4 * u64::from(done));
        let Ok(fd) = c.read_u32(at) else {
            err = Errno(EFAULT);
            break;
        };
        let Ok(file) = ops::fget(c, fd as i32) else {
            err = Errno(EBADF);
            break;
        };
        let slot = match fixed_fd_install(ring, st, file, FILE_INDEX_ALLOC) {
            Ok(s) => s,
            Err(e) => {
                err = e;
                break;
            }
        };
        if c.write_u32(at, slot).is_err() {
            let _ = fixed_fd_remove(ring, st, slot);
            err = Errno(EFAULT);
            break;
        }
        done += 1;
    }
    if done != 0 {
        Ok(u64::from(done))
    } else {
        Err(err)
    }
}
