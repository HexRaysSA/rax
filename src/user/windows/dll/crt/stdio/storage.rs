//! Host-authoritative CRT descriptor, stream and guest-buffer ownership.
//!
//! FILE presentation and initial buffering are checked personality profiles,
//! not a claim about UCRT private FILE layout. Private VM allocations must not
//! be freed by callers; equal-address/equal-size raw VM reuse is undetectable.
//! Likewise callers must not CloseHandle handles transferred to a descriptor.
//! ObjId/grant checks reject non-ABA invalidation; same-object handle ABA is
//! unknown because the shared handle table does not have lifetime generations.

use std::cell::RefCell;
use std::rc::Rc;

use crate::error::MemoryAccessKind;
use crate::user::windows::dll::BuiltinDll;
use crate::user::windows::hle::{DataSize, Item};
use crate::user::windows::layout::offsets;
use crate::user::windows::loader::{LoadError, builtin::BuiltinSym};
use crate::user::windows::memory::{AllocKind, Mem, MemFault, mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DLL_INIT_FAILED, STATUS_INVALID_IMAGE_FORMAT,
    STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY,
};
use crate::user::windows::objects::{ObjId, Object, StdStream};
use crate::user::windows::process::Proc;

use super::super::RuntimeKind;

pub(super) const O_APPEND: i32 = 0x0008;
pub(super) const O_TEXT: i32 = 0x4000;
pub(super) const O_BINARY: i32 = 0x8000;
pub(super) const O_WTEXT: i32 = 0x10000;
pub(super) const O_U16TEXT: i32 = 0x20000;
pub(super) const O_U8TEXT: i32 = 0x40000;
pub(super) const IOFBF: i32 = 0;
pub(super) const IOLBF: i32 = 0x40;
pub(super) const IONBF: i32 = 4;
const DEFAULT_BUFFER: u64 = 4096;

#[derive(Debug)]
pub(crate) enum StdioError {
    Fault(MemFault),
    NoMemory,
    Invalid,
    GenerationExhausted,
    Internal(String),
    Host(u32),
}
impl From<MemFault> for StdioError {
    fn from(fault: MemFault) -> Self {
        Self::Fault(fault)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Direction {
    None,
    Read,
    Write,
}

/// Automatic buffers are real guest allocations, not ignored host buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Buffer {
    Unbuffered,
    Automatic { address: u64, capacity: u64 },
    User { address: u64, capacity: u64 },
}
impl Buffer {
    pub(super) fn address(self) -> u64 {
        match self {
            Self::Unbuffered => 0,
            Self::Automatic { address, .. } | Self::User { address, .. } => address,
        }
    }
    pub(super) fn capacity(self) -> u64 {
        match self {
            Self::Unbuffered => 0,
            Self::Automatic { capacity, .. } | Self::User { capacity, .. } => capacity,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Stream {
    pub(super) file: u64,
    pub(super) generation: u64,
    pub(super) revision: u64,
    pub(super) descriptor: i32,
    pub(super) open: bool,
    pub(super) readable: bool,
    pub(super) writable: bool,
    pub(super) commit: bool,
    pub(super) commit_inherit: bool,
    pub(super) buffer: Buffer,
    pub(super) read_cursor: u64,
    pub(super) read_end: u64,
    pub(super) write_pending: u64,
    pub(super) write_start: u64,
    pub(super) last: Direction,
    pub(super) eof: bool,
    pub(super) error: bool,
    pub(super) io_started: bool,
    pub(super) pushback: Option<u8>,
    pub(super) pending_cr: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Descriptor {
    pub(super) fd: i32,
    pub(super) generation: u64,
    pub(super) revision: u64,
    pub(super) handle: u64,
    pub(super) object: Option<ObjId>,
    pub(super) grant: u32,
    pub(super) readable: bool,
    pub(super) writable: bool,
    pub(super) append: bool,
    pub(super) translation: i32,
    pub(super) stream: Option<u64>,
    pub(super) text_eof: bool,
    pub(super) lookahead: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
struct OwnedBlock {
    base: u64,
    size: u64,
}

#[derive(Default)]
pub(super) struct Registry {
    pub(super) mode_cells: [u64; 2],
    pub(super) files_base: u64,
    pub(super) file_stride: u64,
    pub(super) legacy: bool,
    pub(super) streams: Vec<Stream>,
    pub(super) descriptors: Vec<Option<Descriptor>>,
    blocks: Vec<OwnedBlock>,
    next_generation: u64,
    discarded: bool,
}

/// No registry borrow may survive a guest callback or an I/O operation.
#[derive(Clone, Default)]
pub(in crate::user::windows::dll::crt) struct StdioState(pub(super) Rc<RefCell<Registry>>);

pub(crate) struct PreparedStdio {
    kind: RuntimeKind,
    pub(super) state: StdioState,
}
impl PreparedStdio {
    pub(crate) fn commit(self, p: &mut Proc) {
        p.crt.runtimes[self.kind.index()].stdio = Some(self.state);
    }
    pub(crate) fn abort(self, p: &mut Proc) -> Result<(), LoadError> {
        self.state.discard(p).map_err(load_error)
    }
}

fn load_error(error: StdioError) -> LoadError {
    let status = match &error {
        StdioError::Fault(_) => STATUS_ACCESS_VIOLATION,
        StdioError::NoMemory => STATUS_NO_MEMORY,
        StdioError::Invalid => STATUS_INVALID_PARAMETER,
        _ => STATUS_DLL_INIT_FAILED,
    };
    LoadError {
        status,
        message: format!("CRT stdio storage: {error:?}"),
    }
}
fn internal(message: &str) -> StdioError {
    StdioError::Internal(message.into())
}
fn address(p: &Proc, base: u64, offset: u64, bytes: u64, write: bool) -> Result<u64, StdioError> {
    let max = p.arch.ptr(u64::MAX);
    let fault = || {
        StdioError::Fault(MemFault {
            addr: max.saturating_add(1),
            write,
        })
    };
    let at = base.checked_add(offset).ok_or_else(fault)?;
    let last = at.checked_add(bytes.saturating_sub(1)).ok_or_else(fault)?;
    if last > max {
        return Err(fault());
    }
    Ok(at)
}
pub(super) fn probe(p: &Proc, at: u64, bytes: u64, write: bool) -> Result<(), StdioError> {
    address(p, at, 0, bytes, write)?;
    let bytes = usize::try_from(bytes).map_err(|_| StdioError::NoMemory)?;
    p.space
        .probe(
            at,
            bytes,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|fault| {
            StdioError::Fault(MemFault {
                addr: fault.address,
                write,
            })
        })
}
fn allocate(p: &mut Proc, bytes: u64) -> Result<OwnedBlock, StdioError> {
    let base =
        p.vm.reserve(
            None,
            bytes.max(1),
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .map_err(|_| StdioError::NoMemory)?;
    let result = (|| {
        address(p, base, 0, bytes.max(1), true)?;
        p.vm.commit(base, bytes.max(1), prot::READWRITE)
            .map_err(|_| StdioError::NoMemory)?;
        let size =
            p.vm.allocation(base)
                .ok_or_else(|| internal("new VM allocation missing"))?
                .size;
        Ok(OwnedBlock { base, size })
    })();
    if let Err(original) = &result
        && let Err(cleanup) = p.vm.release(base)
    {
        p.fail(format!(
            "CRT stdio allocation rollback: {cleanup:?}; original: {original:?}"
        ));
    }
    result
}
fn validate_block(p: &Proc, block: OwnedBlock) -> Result<(), StdioError> {
    if p.vm.allocation(block.base).is_some_and(|a| {
        a.base == block.base && a.size == block.size && a.kind == AllocKind::Private
    }) {
        Ok(())
    } else {
        Err(internal("private CRT stdio allocation invalidated"))
    }
}
fn release_block(p: &mut Proc, block: OwnedBlock) -> Result<(), StdioError> {
    validate_block(p, block)?;
    p.vm.release(block.base)
        .map(|_| ())
        .map_err(|e| StdioError::Internal(format!("CRT stdio VM release: {e:?}")))
}
fn file_kind(object: &Object) -> bool {
    matches!(
        object,
        Object::File(_) | Object::Console(_) | Object::Null | Object::Pipe { .. }
    )
}
fn capture(
    p: &Proc,
    fd: i32,
    handle: u64,
    flags: i32,
    generation: u64,
) -> Result<Descriptor, StdioError> {
    if handle == 0 || handle == p.arch.ptr(u64::MAX) {
        return Err(StdioError::Invalid);
    }
    address(p, handle, 0, 1, false)?;
    let id = p.objects.id(handle).ok_or(StdioError::Invalid)?;
    if !p.objects.obj(id).is_some_and(file_kind) {
        return Err(StdioError::Invalid);
    }
    let access = flags & 3;
    if access == 3
        || flags & !(3 | O_APPEND | O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT | 0x80) != 0
    {
        return Err(StdioError::Invalid);
    }
    let translation = flags & (O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT);
    if translation.count_ones() > 1 {
        return Err(StdioError::Invalid);
    }
    Ok(Descriptor {
        fd,
        generation,
        revision: 0,
        handle,
        object: Some(id),
        grant: p.objects.access(handle).ok_or(StdioError::Invalid)?,
        readable: access != 1,
        writable: access != 0,
        append: flags & O_APPEND != 0,
        translation: if translation == 0 {
            O_BINARY
        } else {
            translation
        },
        stream: None,
        text_eof: false,
        lookahead: None,
    })
}
fn next(registry: &Registry) -> Result<u64, StdioError> {
    registry
        .next_generation
        .checked_add(1)
        .ok_or(StdioError::GenerationExhausted)
}
fn initial_stream(
    file: u64,
    descriptor: i32,
    generation: u64,
    readable: bool,
    writable: bool,
    commit: bool,
) -> Stream {
    Stream {
        file,
        generation,
        revision: 0,
        descriptor,
        open: true,
        readable,
        writable,
        commit,
        commit_inherit: true,
        buffer: if descriptor == 2 {
            Buffer::Unbuffered
        } else {
            Buffer::Automatic {
                address: 0,
                capacity: DEFAULT_BUFFER,
            }
        },
        read_cursor: 0,
        read_end: 0,
        write_pending: 0,
        write_start: 0,
        last: Direction::None,
        eof: false,
        error: false,
        io_started: false,
        pushback: None,
        pending_cr: false,
    }
}

/// Fixed-size presentation; checked preflight precedes every guest publication.
fn presentation(p: &Proc, legacy: bool, stream: Stream) -> Result<([u8; 48], usize), StdioError> {
    let mut bytes = [0; 48];
    let width = p.arch.ptr_size() as usize;
    let size = if !legacy {
        width
    } else if width == 4 {
        32
    } else {
        48
    };
    if !stream.open {
        return Ok((bytes, size));
    }
    let capacity = stream.buffer.capacity();
    if stream.read_cursor > stream.read_end
        || stream.read_end > capacity
        || stream.write_start > stream.write_pending
        || stream.write_pending > capacity
    {
        return Err(internal("invalid CRT stream buffer cursors"));
    }
    let base = stream.buffer.address();
    if base == 0 && (stream.read_end != 0 || stream.write_pending != 0) {
        return Err(internal("CRT buffer cursors without allocated storage"));
    }
    if !legacy {
        return Ok((bytes, width));
    }
    let cursor = if stream.last == Direction::Write {
        stream.write_pending
    } else {
        stream.read_cursor
    };
    let ptr = if base == 0 {
        0
    } else {
        address(p, base, cursor, 1, false)?
    };
    let cnt = match stream.last {
        Direction::Read => stream.read_end - stream.read_cursor,
        Direction::Write => capacity - stream.write_pending,
        Direction::None => 0,
    };
    if cnt > i32::MAX as u64 || capacity > i32::MAX as u64 {
        return Err(StdioError::Invalid);
    }
    let (cnt_at, base_at, flag_at, fd_at, bufsiz_at) = if width == 4 {
        (4, 8, 12, 16, 24)
    } else {
        (8, 16, 24, 28, 36)
    };
    bytes[..width].copy_from_slice(&ptr.to_le_bytes()[..width]);
    bytes[cnt_at..cnt_at + 4].copy_from_slice(&(cnt as i32).to_le_bytes());
    bytes[base_at..base_at + width].copy_from_slice(&base.to_le_bytes()[..width]);
    let mut flags = if stream.readable && stream.writable {
        0x80u32
    } else if stream.readable {
        1
    } else {
        2
    };
    if matches!(stream.buffer, Buffer::Unbuffered) {
        flags |= 4;
    }
    if matches!(stream.buffer, Buffer::Automatic { address, .. } if address != 0) {
        flags |= 8;
    }
    if stream.eof {
        flags |= 0x10;
    }
    if stream.error {
        flags |= 0x20;
    }
    bytes[flag_at..flag_at + 4].copy_from_slice(&flags.to_le_bytes());
    bytes[fd_at..fd_at + 4].copy_from_slice(&stream.descriptor.to_le_bytes());
    bytes[bufsiz_at..bufsiz_at + 4].copy_from_slice(&(capacity as i32).to_le_bytes());
    Ok((bytes, size))
}

impl StdioState {
    pub(super) fn standard_file(&self, index: usize) -> Option<u64> {
        if index >= 3 {
            return None;
        }
        self.0.borrow().streams.get(index).map(|stream| stream.file)
    }
    pub(super) fn mode_cell(&self, index: usize) -> Option<u64> {
        self.0.borrow().mode_cells.get(index).copied()
    }
    pub(super) fn stream(&self, file: u64) -> Result<Stream, StdioError> {
        let r = self.0.borrow();
        if r.discarded {
            return Err(internal("discarded CRT stdio state"));
        }
        r.streams
            .iter()
            .find(|s| s.file == file && s.open)
            .copied()
            .ok_or(StdioError::Invalid)
    }
    pub(super) fn descriptor(&self, fd: i32) -> Result<Descriptor, StdioError> {
        usize::try_from(fd)
            .ok()
            .and_then(|fd| self.0.borrow().descriptors.get(fd).copied().flatten())
            .ok_or(StdioError::Invalid)
    }
    pub(super) fn publish_descriptor(
        &self,
        fd: i32,
        generation: u64,
        mut updated: Descriptor,
    ) -> Result<Descriptor, StdioError> {
        let current = self.descriptor(fd)?;
        if current.generation != generation
            || updated.generation != generation
            || updated.revision != current.revision
            || updated.fd != fd
            || updated.handle != current.handle
            || updated.object != current.object
            || updated.grant != current.grant
            || updated.stream != current.stream
        {
            return Err(internal("stale CRT descriptor publication"));
        }
        updated.revision = current
            .revision
            .checked_add(1)
            .ok_or(StdioError::GenerationExhausted)?;
        self.0.borrow_mut().descriptors[fd as usize] = Some(updated);
        Ok(updated)
    }
    pub(super) fn open_streams(&self) -> Result<Vec<(u64, u64, u64)>, StdioError> {
        let r = self.0.borrow();
        let mut result = Vec::new();
        result
            .try_reserve_exact(r.streams.len())
            .map_err(|_| StdioError::NoMemory)?;
        result.extend(
            r.streams
                .iter()
                .filter(|s| s.open)
                .map(|s| (s.file, s.generation, s.revision)),
        );
        Ok(result)
    }
    pub(super) fn validate_descriptor(
        &self,
        p: &Proc,
        fd: i32,
        write: bool,
    ) -> Result<Descriptor, StdioError> {
        let d = self.descriptor(fd)?;
        let id = d.object.ok_or(StdioError::Invalid)?;
        if p.objects.id(d.handle) != Some(id) || p.objects.access(d.handle) != Some(d.grant) {
            return Err(internal("CRT-owned handle invalidated"));
        }
        if (write && !d.writable) || (!write && !d.readable) {
            return Err(StdioError::Invalid);
        }
        let grant = if write {
            0x4000_0000 | 2 | 4
        } else {
            0x8000_0000 | 1
        };
        if d.grant & grant == 0 {
            return Err(StdioError::Invalid);
        }
        match p.objects.obj(id) {
            Some(Object::Console(stream)) if (*stream == StdStream::In) == write => {
                Err(StdioError::Invalid)
            }
            Some(object) if file_kind(object) => Ok(d),
            _ => Err(internal("CRT descriptor object disappeared")),
        }
    }
    pub(super) fn preflight(&self, p: &Proc, file: u64) -> Result<(), StdioError> {
        let stream = self.stream(file)?;
        let r = self.0.borrow();
        if let Some(block) = r
            .blocks
            .iter()
            .find(|b| file >= b.base && file < b.base + b.size)
        {
            validate_block(p, *block)?;
        }
        let (_, length) = presentation(p, r.legacy, stream)?;
        probe(p, file, length as u64, true)
    }
    /// Expected generation preserves HLE identity across callback/SEH repair.
    pub(super) fn publish(
        &self,
        p: &mut Proc,
        file: u64,
        expected_generation: u64,
        mut updated: Stream,
    ) -> Result<Stream, StdioError> {
        let current = self.stream(file)?;
        if current.generation != expected_generation
            || updated.file != file
            || updated.generation != expected_generation
            || updated.descriptor != current.descriptor
            || updated.revision != current.revision
        {
            return Err(internal("stale CRT stream publication"));
        }
        updated.revision = current
            .revision
            .checked_add(1)
            .ok_or(StdioError::GenerationExhausted)?;
        self.preflight(p, file)?;
        let legacy = self.0.borrow().legacy;
        let (bytes, size) = presentation(p, legacy, updated)?;
        p.space.wr(file, &bytes[..size])?;
        let mut r = self.0.borrow_mut();
        *r.streams
            .iter_mut()
            .find(|s| s.file == file)
            .ok_or(StdioError::Invalid)? = updated;
        Ok(updated)
    }
    /// O(F+B) ownership checks, constant auxiliary storage; guest residency is
    /// additional. Replacement is admitted only before I/O, a checked profile.
    pub(super) fn replace_buffer(
        &self,
        p: &mut Proc,
        file: u64,
        mode: i32,
        user: u64,
        size: u64,
    ) -> Result<(), StdioError> {
        let old = self.stream(file)?;
        if old.io_started {
            return Err(StdioError::Invalid);
        }
        let capacity = if mode == IONBF {
            0
        } else {
            if !matches!(mode, IOFBF | IOLBF) || !(2..=i32::MAX as u64).contains(&size) {
                return Err(StdioError::Invalid);
            }
            size & !1
        };
        self.preflight(p, file)?;
        let generation = {
            let r = self.0.borrow();
            next(&r)?
        };
        let revision = old
            .revision
            .checked_add(1)
            .ok_or(StdioError::GenerationExhausted)?;
        self.validate_buffer(p, old.buffer)?;
        let new_block = if mode != IONBF && user == 0 {
            self.0
                .borrow_mut()
                .blocks
                .try_reserve(1)
                .map_err(|_| StdioError::NoMemory)?;
            Some(allocate(p, capacity)?)
        } else {
            None
        };
        let replacement = if mode == IONBF {
            Buffer::Unbuffered
        } else if let Some(block) = new_block {
            Buffer::Automatic {
                address: block.base,
                capacity,
            }
        } else {
            if let Err(error) = probe(p, user, capacity, true) {
                return Err(error);
            }
            Buffer::User {
                address: user,
                capacity,
            }
        };
        let mut updated = old;
        updated.generation = generation;
        updated.revision = revision;
        updated.buffer = replacement;
        updated.read_cursor = 0;
        updated.read_end = 0;
        updated.write_pending = 0;
        updated.write_start = 0;
        updated.last = Direction::None;
        updated.pushback = None;
        updated.pending_cr = false;
        let result = (|| {
            let (bytes, size) = presentation(p, self.0.borrow().legacy, updated)?;
            p.space.wr(file, &bytes[..size])?;
            Ok(())
        })();
        if let Err(error) = result {
            if let Some(block) = new_block
                && let Err(cleanup) = release_block(p, block)
            {
                p.fail(format!("CRT buffer rollback: {cleanup:?}"));
            }
            return Err(error);
        }
        let mut r = self.0.borrow_mut();
        if let Some(block) = new_block {
            r.blocks.push(block);
        }
        *r.streams
            .iter_mut()
            .find(|s| s.file == file)
            .ok_or(StdioError::Invalid)? = updated;
        r.next_generation = generation;
        drop(r);
        self.release_buffer(p, old.buffer)
    }
    pub(super) fn ensure_buffer(&self, p: &mut Proc, file: u64) -> Result<Stream, StdioError> {
        let old = self.stream(file)?;
        if let Buffer::Automatic {
            address: 0,
            capacity,
        } = old.buffer
        {
            self.preflight(p, file)?;
            self.0
                .borrow_mut()
                .blocks
                .try_reserve(1)
                .map_err(|_| StdioError::NoMemory)?;
            let block = allocate(p, capacity)?;
            let mut updated = old;
            updated.buffer = Buffer::Automatic {
                address: block.base,
                capacity,
            };
            let updated = match self.publish(p, file, old.generation, updated) {
                Ok(updated) => updated,
                Err(error) => {
                    if let Err(cleanup) = release_block(p, block) {
                        p.fail(format!("CRT lazy buffer rollback: {cleanup:?}"));
                    }
                    return Err(error);
                }
            };
            self.0.borrow_mut().blocks.push(block);
            Ok(updated)
        } else {
            self.validate_buffer(p, old.buffer)?;
            Ok(old)
        }
    }
    pub(super) fn validate_buffer(&self, p: &Proc, buffer: Buffer) -> Result<(), StdioError> {
        if let Buffer::Automatic { address, .. } = buffer
            && address != 0
        {
            let block = self
                .0
                .borrow()
                .blocks
                .iter()
                .find(|b| b.base == address)
                .copied()
                .ok_or_else(|| internal("automatic CRT buffer has no ownership"))?;
            validate_block(p, block)?;
        }
        Ok(())
    }
    fn release_buffer(&self, p: &mut Proc, buffer: Buffer) -> Result<(), StdioError> {
        if let Buffer::Automatic { address, .. } = buffer
            && address != 0
        {
            let block = self
                .0
                .borrow()
                .blocks
                .iter()
                .find(|b| b.base == address)
                .copied()
                .ok_or_else(|| internal("automatic CRT buffer ownership missing"))?;
            release_block(p, block)?;
            self.0.borrow_mut().blocks.retain(|b| b.base != address);
        }
        Ok(())
    }
    pub(super) fn set_mode(&self, fd: i32, mode: i32) -> Result<i32, StdioError> {
        if !matches!(mode, O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT) {
            return Err(StdioError::Invalid);
        }
        let old = self.descriptor(fd)?;
        let mut updated = old;
        updated.translation = mode;
        self.publish_descriptor(fd, old.generation, updated)?;
        Ok(old.translation)
    }
    /// Adopts the original handle; no duplication and no host file reopening.
    pub(super) fn attach_descriptor(
        &self,
        p: &mut Proc,
        handle: u64,
        flags: i32,
    ) -> Result<i32, StdioError> {
        let (fd, generation) = {
            let mut r = self.0.borrow_mut();
            if r.discarded {
                return Err(internal("discarded CRT stdio state"));
            }
            let fd = r
                .descriptors
                .iter()
                .position(Option::is_none)
                .unwrap_or(r.descriptors.len());
            let fd = i32::try_from(fd).map_err(|_| StdioError::NoMemory)?;
            if fd as usize == r.descriptors.len() {
                r.descriptors
                    .try_reserve(1)
                    .map_err(|_| StdioError::NoMemory)?;
            }
            (fd, next(&r)?)
        };
        let descriptor = capture(p, fd, handle, flags, generation)?;
        // Two live descriptors cannot both claim one transferred HANDLE.
        if self
            .0
            .borrow()
            .descriptors
            .iter()
            .flatten()
            .any(|d| d.handle & !3 == handle & !3 && d.object.is_some())
        {
            return Err(StdioError::Invalid);
        }
        p.objects
            .retain_many(&[descriptor.object.ok_or(StdioError::Invalid)?])
            .map_err(|e| StdioError::Internal(e.into()))?;
        let mut r = self.0.borrow_mut();
        if fd as usize == r.descriptors.len() {
            r.descriptors.push(Some(descriptor));
        } else {
            r.descriptors[fd as usize] = Some(descriptor);
        }
        r.next_generation = generation;
        Ok(fd)
    }
    /// fdopen ownership transfer only; never truncates/creates its file.
    pub(super) fn attach_stream(
        &self,
        p: &mut Proc,
        fd: i32,
        read: bool,
        write: bool,
        commit: bool,
        translation: Option<i32>,
        append: bool,
    ) -> Result<u64, StdioError> {
        let descriptor = self.descriptor(fd)?;
        if descriptor.stream.is_some()
            || (!read && !write)
            || (read && !descriptor.readable)
            || (write && !descriptor.writable)
        {
            return Err(StdioError::Invalid);
        }
        if read {
            self.validate_descriptor(p, fd, false)?;
        }
        if write {
            self.validate_descriptor(p, fd, true)?;
        }
        if translation
            .is_some_and(|mode| !matches!(mode, O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT))
        {
            return Err(StdioError::Invalid);
        }
        let revision = descriptor
            .revision
            .checked_add(1)
            .ok_or(StdioError::GenerationExhausted)?;
        let (slot, generation, legacy, stride) = {
            let mut r = self.0.borrow_mut();
            let slot = r.streams.iter().position(|s| !s.open);
            if slot.is_none() {
                r.streams.try_reserve(1).map_err(|_| StdioError::NoMemory)?;
                r.blocks.try_reserve(1).map_err(|_| StdioError::NoMemory)?;
            }
            (slot, next(&r)?, r.legacy, r.file_stride)
        };
        let block = if slot.is_none() {
            Some(allocate(p, stride)?)
        } else {
            None
        };
        let file = if let Some(slot) = slot {
            self.0.borrow().streams[slot].file
        } else {
            block.ok_or_else(|| internal("missing FILE shell"))?.base
        };
        let mut stream = initial_stream(file, fd, generation, read, write, commit);
        stream.commit_inherit = false;
        // fd2 is not intrinsically stderr after descriptor recycling.
        stream.buffer = Buffer::Automatic {
            address: 0,
            capacity: DEFAULT_BUFFER,
        };
        let result = (|| {
            let (bytes, size) = presentation(p, legacy, stream)?;
            probe(p, file, size as u64, true)?;
            p.space.wr(file, &bytes[..size])?;
            Ok(())
        })();
        if let Err(error) = result {
            if let Some(block) = block
                && let Err(cleanup) = release_block(p, block)
            {
                p.fail(format!("CRT FILE rollback: {cleanup:?}"));
            }
            return Err(error);
        }
        let mut r = self.0.borrow_mut();
        if let Some(block) = block {
            r.blocks.push(block);
        }
        if let Some(slot) = slot {
            r.streams[slot] = stream;
        } else {
            r.streams.push(stream);
        }
        let d = r.descriptors[fd as usize]
            .as_mut()
            .ok_or(StdioError::Invalid)?;
        d.stream = Some(file);
        d.revision = revision;
        if let Some(mode) = translation {
            d.translation = mode;
        }
        if append {
            d.append = true;
        }
        r.next_generation = generation;
        Ok(file)
    }
    /// The caller flushes first; writable FILE preflight precedes close effects.
    pub(super) fn close_stream(&self, p: &mut Proc, file: u64) -> Result<(), StdioError> {
        let old = self.stream(file)?;
        self.preflight(p, file)?;
        let generation = {
            let r = self.0.borrow();
            next(&r)?
        };
        let revision = old
            .revision
            .checked_add(1)
            .ok_or(StdioError::GenerationExhausted)?;
        self.validate_buffer(p, old.buffer)?;
        let closed = self.close_fd(p, old.descriptor, Some(file));
        // A final host deletion error is after the OS handle/descriptor close.
        // Complete logical close exactly once; never retry the OS close.
        let close_error = match closed {
            Ok(()) => None,
            Err(error @ StdioError::Host(_)) if self.descriptor(old.descriptor).is_err() => {
                Some(error)
            }
            Err(error) => return Err(error),
        };
        self.release_buffer(p, old.buffer)?;
        let mut updated = old;
        updated.open = false;
        updated.generation = generation;
        updated.revision = revision;
        updated.buffer = Buffer::Unbuffered;
        let (bytes, size) = presentation(p, self.0.borrow().legacy, updated)?;
        p.space.wr(file, &bytes[..size])?;
        let mut r = self.0.borrow_mut();
        *r.streams
            .iter_mut()
            .find(|s| s.file == file)
            .ok_or(StdioError::Invalid)? = updated;
        r.next_generation = generation;
        close_error.map_or(Ok(()), Err)
    }
    pub(super) fn close_descriptor(&self, p: &mut Proc, fd: i32) -> Result<(), StdioError> {
        self.close_fd(p, fd, None)
    }
    fn close_fd(&self, p: &mut Proc, fd: i32, stream: Option<u64>) -> Result<(), StdioError> {
        let descriptor = self.descriptor(fd)?;
        if descriptor.stream != stream {
            return Err(StdioError::Invalid);
        }
        if let Some(id) = descriptor.object {
            if p.objects.id(descriptor.handle) != Some(id)
                || p.objects.access(descriptor.handle) != Some(descriptor.grant)
            {
                return Err(internal("CRT-owned handle invalidated before close"));
            }
            let last = p
                .objects
                .close(descriptor.handle)
                .map_err(|_| StdioError::Host(6))?;
            // The internal descriptor pin normally prevents last destruction.
            if let Err(error) = crate::user::windows::dll::finish_close(last) {
                return Err(StdioError::Host(error));
            }
            let last = p.objects.release(id);
            self.0.borrow_mut().descriptors[fd as usize] = None;
            crate::user::windows::dll::finish_close(last).map_err(StdioError::Host)?;
        } else {
            self.0.borrow_mut().descriptors[fd as usize] = None;
        }
        Ok(())
    }
    /// Host-only terminal cleanup. Does not flush, close guest handle entries,
    /// or write FILE/mode cells; the process's handle-table drain owns those.
    pub(super) fn discard(&self, p: &mut Proc) -> Result<(), StdioError> {
        let (blocks, descriptors) = {
            let mut r = self.0.borrow_mut();
            r.discarded = true;
            for stream in &mut r.streams {
                stream.open = false;
            }
            (
                std::mem::take(&mut r.blocks),
                std::mem::take(&mut r.descriptors),
            )
        };
        let mut failure = None;
        for descriptor in descriptors.into_iter().flatten() {
            if let Some(id) = descriptor.object
                && let Err(error) = crate::user::windows::dll::finish_close(p.objects.release(id))
            {
                failure.get_or_insert(StdioError::Host(error));
            }
        }
        for block in blocks.into_iter().rev() {
            if let Err(error) = release_block(p, block) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn exported(
    p: &Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, BuiltinSym)],
    name: &str,
    bytes: u64,
) -> Result<u64, LoadError> {
    let Some((_, symbol)) = symbols.iter().find(|(candidate, _)| *candidate == name) else {
        return Ok(0);
    };
    let data = dll
        .exports
        .iter()
        .flat_map(|t| t.iter())
        .find(|e| e.name == name && e.archs.has(p.arch));
    let declared = match data.map(|e| &e.item) {
        Some(Item::Data(DataSize::Bytes(n))) => u64::from(*n),
        Some(Item::Data(DataSize::Ptrs(n))) => u64::from(*n) * p.arch.ptr_size(),
        _ => 0,
    };
    let invalid = || LoadError {
        status: STATUS_INVALID_IMAGE_FORMAT,
        message: format!("invalid CRT stdio data export {name}"),
    };
    if declared != bytes {
        return Err(invalid());
    }
    let BuiltinSym::Rva(rva) = symbol else {
        return Err(invalid());
    };
    let at = address(p, base, u64::from(*rva), bytes, true).map_err(load_error)?;
    let last = address(p, at, bytes - 1, 1, true).map_err(load_error)?;
    if at % p.arch.ptr_size().min(bytes) != 0
        || [at, last].into_iter().any(|at| {
            p.vm.query(at)
                .is_none_or(|a| a.allocation_base != base || a.kind != mem::IMAGE)
        })
    {
        return Err(invalid());
    }
    probe(p, at, bytes, true).map_err(load_error)?;
    Ok(at)
}

/// Preflight all sources/targets, then pin and publish only an unpublished
/// candidate. O(F+B) operations with F streams/B owned blocks; no guest-count
/// sized host buffers. Initial metadata has constant (20-slot) bounded size.
pub(crate) fn prepare(
    p: &mut Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, BuiltinSym)],
) -> Result<PreparedStdio, LoadError> {
    let kind = match dll.name {
        "msvcrt.dll" => RuntimeKind::Msvcrt,
        "ucrtbase.dll" => RuntimeKind::Ucrt,
        _ => return Err(load_error(StdioError::Invalid)),
    };
    let legacy = kind == RuntimeKind::Msvcrt;
    let stride = if legacy {
        if p.arch.ptr_size() == 4 { 32 } else { 48 }
    } else {
        p.arch.ptr_size()
    };
    let slots = if legacy { 20 } else { 3 };
    let cells = [
        exported(p, dll, base, symbols, "_fmode", 4)?,
        exported(p, dll, base, symbols, "_commode", 4)?,
    ];
    let iob = if legacy {
        exported(p, dll, base, symbols, "_iob", slots * stride)?
    } else {
        0
    };
    let mut handles = [0; 3];
    if p.params != 0 {
        let o = offsets(p.arch);
        for (index, off) in [o.pp_std_input, o.pp_std_output, o.pp_std_error]
            .into_iter()
            .enumerate()
        {
            let at = address(p, p.params, off, o.ptr, false).map_err(load_error)?;
            handles[index] = p.space.ptr(at, o.ptr).map_err(|f| load_error(f.into()))?;
        }
    }
    let mut registry = Registry {
        mode_cells: cells,
        files_base: iob,
        file_stride: stride,
        legacy,
        next_generation: 3,
        ..Registry::default()
    };
    registry
        .streams
        .try_reserve_exact(slots as usize)
        .map_err(|_| load_error(StdioError::NoMemory))?;
    registry
        .descriptors
        .try_reserve_exact(3)
        .map_err(|_| load_error(StdioError::NoMemory))?;
    registry
        .blocks
        .try_reserve_exact(1)
        .map_err(|_| load_error(StdioError::NoMemory))?;
    let mut pins = Vec::new();
    pins.try_reserve_exact(3)
        .map_err(|_| load_error(StdioError::NoMemory))?;
    for (index, handle) in handles.into_iter().enumerate() {
        let descriptor = match capture(
            p,
            index as i32,
            handle,
            if index == 0 { O_TEXT } else { 1 | O_TEXT },
            index as u64 + 1,
        ) {
            Ok(d) => {
                pins.push(
                    d.object
                        .ok_or_else(|| load_error(internal("missing STD object")))?,
                );
                d
            }
            Err(StdioError::Invalid) => Descriptor {
                fd: index as i32,
                generation: index as u64 + 1,
                revision: 0,
                handle: p.arch.ptr(u64::MAX - 1),
                object: None,
                grant: 0,
                readable: index == 0,
                writable: index != 0,
                append: false,
                translation: O_TEXT,
                stream: None,
                text_eof: false,
                lookahead: None,
            },
            Err(error) => return Err(load_error(error)),
        };
        registry.descriptors.push(Some(descriptor));
    }
    if registry.files_base == 0 || registry.mode_cells.contains(&0) {
        let bytes = if registry.files_base == 0 {
            16 + slots * stride
        } else {
            16
        };
        let block = allocate(p, bytes).map_err(load_error)?;
        registry.blocks.push(block);
        for (index, cell) in registry.mode_cells.iter_mut().enumerate() {
            if *cell == 0 {
                *cell = block.base + index as u64 * 4;
            }
        }
        if registry.files_base == 0 {
            registry.files_base = block.base + 16;
        }
    }
    for index in 0..slots {
        let file = registry.files_base + index * stride;
        let mut stream =
            initial_stream(file, index as i32, index + 1, index == 0, index != 0, false);
        if index >= 3 {
            stream.open = false;
            stream.generation = 0;
        }
        registry.streams.push(stream);
        if index < 3 {
            registry.descriptors[index as usize]
                .as_mut()
                .ok_or_else(|| load_error(StdioError::Invalid))?
                .stream = Some(file);
        }
    }
    let state = StdioState(Rc::new(RefCell::new(registry)));
    let mut pinned = false;
    let initialized = (|| -> Result<(), StdioError> {
        // All publication ranges preflighted; no callback can change mappings.
        {
            let r = state.0.borrow();
            probe(p, r.files_base, slots * stride, true)?;
            for cell in r.mode_cells {
                probe(p, cell, 4, true)?;
            }
        }
        p.objects
            .retain_many(&pins)
            .map_err(|e| StdioError::Internal(e.into()))?;
        pinned = true;
        let r = state.0.borrow();
        p.space.w32(r.mode_cells[0], O_TEXT as u32)?;
        p.space.w32(r.mode_cells[1], 0)?;
        for stream in r.streams.iter().copied() {
            let (bytes, size) = presentation(p, legacy, stream)?;
            p.space.wr(stream.file, &bytes[..size])?;
        }
        Ok(())
    })();
    if let Err(original) = initialized {
        if !pinned {
            for descriptor in &mut state.0.borrow_mut().descriptors {
                if let Some(d) = descriptor {
                    d.object = None;
                }
            }
        }
        if let Err(cleanup) = state.discard(p) {
            p.fail(format!(
                "CRT stdio preparation cleanup: {cleanup:?}; original: {original:?}"
            ));
        }
        return Err(load_error(original));
    }
    Ok(PreparedStdio { kind, state })
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
