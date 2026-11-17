//! An independently mapped worker view of the owner's physical storage.
//!
//! Every translation is authoritative. This view owns no frame allocator,
//! page table or VMA map, and all access requires its active host-thread turn.
//! CPU callers must also invalidate caches at foreign-turn/structural changes;
//! mapping storage does not by itself establish that entry barrier.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vm_memory::{
    Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryMmap, GuestRegionMmap, MmapRegion,
};

use super::wire::{Translation, ViewOperation, ViewValue};
use super::{Access, ReadKind, RemoteError};
use crate::error::MemoryAccessKind;
use crate::user::mm::{EXTENT, PAGE_SIZE};

pub(crate) struct View {
    access: Access,
    memory: Arc<GuestMemoryMmap>,
    arena: Arc<File>,
    bytes: u64,
    change_epoch: AtomicU64,
    overlays: Mutex<BTreeMap<u64, Overlay>>,
}

/// A mapping's storage identity is independent of the particular byte that
/// was translated within it. Retain no per-access address in this cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Overlay {
    len: u64,
    offset: u64,
    writable: bool,
    identity: [u64; 2],
}

impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerPhysicalView")
            .field("access", &self.access)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl View {
    pub(crate) fn import(access: Access) -> Result<Self, RemoteError> {
        let (value, mut files) = access.view(ViewOperation::Arena)?;
        let ViewValue::Arena { bytes } = value else {
            return Err(access.fail(invalid()));
        };
        if files.len() != 1 || bytes == 0 || bytes > usize::MAX as u64 || bytes % PAGE_SIZE != 0 {
            return Err(access.fail(invalid()));
        }
        let file = Arc::new(File::from(files.pop().unwrap()));
        let result = (|| {
            if !file.metadata()?.is_file() || file.metadata()?.len() != bytes {
                return Err(invalid());
            }
            let mapping =
                MmapRegion::<()>::from_file(FileOffset::from_arc(file.clone(), 0), bytes as usize)
                    .map_err(|error| io::Error::other(error.to_string()))?;
            let region = GuestRegionMmap::new(mapping, GuestAddress(0)).ok_or_else(invalid)?;
            GuestMemoryMmap::from_regions(vec![region])
                .map_err(|error| io::Error::other(error.to_string()))
        })();
        let memory = Arc::new(result.map_err(|error| access.fail(error))?);
        Ok(Self {
            access,
            memory,
            arena: file,
            bytes,
            change_epoch: AtomicU64::new(0),
            overlays: Mutex::new(BTreeMap::new()),
        })
    }

    pub(super) fn change_epoch(&self) -> u64 {
        self.change_epoch.load(Ordering::Acquire)
    }

    pub(crate) fn active(&self) -> bool {
        self.access.active()
    }

    /// CPU construction may retain the Arc, but execution and physical
    /// pointers must remain inside an acknowledged/imported owner turn.
    pub(crate) fn physical_memory(&self) -> Result<&Arc<GuestMemoryMmap>, RemoteError> {
        self.access.check()?;
        Ok(&self.memory)
    }

    pub(crate) fn translate(
        &self,
        address: u64,
        access: MemoryAccessKind,
        raw: bool,
    ) -> Result<u64, RemoteError> {
        let (value, mut files) = self.access.view(ViewOperation::Translate {
            address,
            access,
            raw,
        })?;
        let ViewValue::Translation { translation } = value else {
            return Err(self.access.fail(invalid()));
        };
        let physical = match translation {
            Translation::Private { address } | Translation::File { address, .. } => address,
        };
        if physical >= self.bytes || physical % PAGE_SIZE != address % PAGE_SIZE {
            return Err(self.access.fail(invalid()));
        }
        let mut overlays = self.overlays.lock().map_err(|_| {
            self.access
                .fail(io::Error::other("worker physical view poisoned"))
        })?;
        match translation {
            Translation::Private { .. } => {
                if !files.is_empty() {
                    return Err(self.access.fail(invalid()));
                }
                let base = physical & !(EXTENT - 1);
                if overlays.contains_key(&base) {
                    self.map(
                        base,
                        self.bytes.saturating_sub(base).min(EXTENT),
                        &self.arena,
                        base,
                        true,
                    )?;
                    overlays.remove(&base);
                }
            }
            Translation::File {
                base,
                len,
                offset,
                writable,
                identity,
                ..
            } => {
                // Host-page alignment is stricter than the 4 KiB guest page
                // on arm64 macOS. mmap must never replace an adjacent view.
                // SAFETY: sysconf takes no caller-owned pointers.
                let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                if files.len() != 1
                    || host_page <= 0
                    || base % EXTENT != 0
                    || offset % EXTENT != 0
                    || len == 0
                    || len > EXTENT
                    || len % host_page as u64 != 0
                    || base
                        .checked_add(len)
                        .is_none_or(|end| end > self.bytes || physical < base || physical >= end)
                {
                    return Err(self.access.fail(invalid()));
                }
                let file = File::from(files.pop().unwrap());
                let overlay = Overlay {
                    len,
                    offset,
                    writable,
                    identity,
                };
                if overlays.get(&base) != Some(&overlay) {
                    if overlays.contains_key(&base) {
                        // The owner detaches the entire old extent before
                        // reusing it. A shorter replacement must not leave
                        // its predecessor's file mapped in the tail.
                        self.map(base, EXTENT, &self.arena, base, true)?;
                    }
                    self.map(base, len, &file, offset, writable)?;
                    overlays.insert(base, overlay);
                }
            }
        }
        if access == MemoryAccessKind::Write {
            self.change_epoch
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                    epoch.checked_add(1)
                })
                .map_err(|_| self.access.fail(invalid()))?;
        }
        Ok(physical)
    }

    pub(crate) fn read(
        &self,
        address: u64,
        bytes: &mut [u8],
        kind: ReadKind,
    ) -> Result<(), RemoteError> {
        let (access, raw) = match kind {
            ReadKind::Read => (MemoryAccessKind::Read, false),
            ReadKind::Fetch => (MemoryAccessKind::Fetch, false),
            ReadKind::Raw => (MemoryAccessKind::Read, true),
        };
        let chunks = self.chunks(address, bytes.len(), access, raw)?;
        let mut cursor = 0;
        for (physical, len) in chunks {
            self.memory
                .read_slice(&mut bytes[cursor..cursor + len], GuestAddress(physical))
                .map_err(|error| self.access.fail(io::Error::other(error.to_string())))?;
            cursor += len;
        }
        Ok(())
    }

    pub(crate) fn write(&self, address: u64, bytes: &[u8], raw: bool) -> Result<(), RemoteError> {
        let chunks = self.chunks(address, bytes.len(), MemoryAccessKind::Write, raw)?;
        let mut cursor = 0;
        for (physical, len) in chunks {
            crate::vm::memory::write_guest_memory(
                &self.memory,
                physical,
                &bytes[cursor..cursor + len],
            )
            .map_err(|error| self.access.fail(io::Error::other(error.to_string())))?;
            cursor += len;
        }
        Ok(())
    }

    fn chunks(
        &self,
        address: u64,
        len: usize,
        access: MemoryAccessKind,
        raw: bool,
    ) -> Result<Vec<(u64, usize)>, RemoteError> {
        self.access.check()?;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(len / PAGE_SIZE as usize + 2)
            .map_err(|_| {
                RemoteError::Preparation(io::Error::from(io::ErrorKind::OutOfMemory).into())
            })?;
        let mut current = address;
        let mut left = len;
        while left != 0 {
            let count = ((PAGE_SIZE - current % PAGE_SIZE) as usize).min(left);
            let physical = self.translate(current, access, raw)?;
            if physical
                .checked_add(count as u64)
                .is_none_or(|end| end > self.bytes)
            {
                return Err(self.access.fail(invalid()));
            }
            chunks.push((physical, count));
            left -= count;
            current = current
                .checked_add(count as u64)
                .ok_or_else(|| self.access.fail(invalid()))?;
        }
        Ok(chunks)
    }

    fn map(
        &self,
        base: u64,
        len: u64,
        file: &File,
        offset: u64,
        writable: bool,
    ) -> Result<(), RemoteError> {
        let offset = libc::off_t::try_from(offset).map_err(|_| self.access.fail(invalid()))?;
        let at = self
            .memory
            .get_host_address(GuestAddress(base))
            .map_err(|_| self.access.fail(invalid()))?;
        let prot = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
        // SAFETY: validated arena/extent bounds and host-page alignment place
        // this replacement wholly within this view's own mmap reservation.
        // The active native lease and current host thread exclude CPU access
        // and structural owner mutation throughout replacement. No reference
        // into the target mapping escapes this operation.
        let result = unsafe {
            libc::mmap(
                at.cast(),
                len as usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                file.as_raw_fd(),
                offset,
            )
        };
        if result == libc::MAP_FAILED {
            return Err(self.access.fail(io::Error::last_os_error()));
        }
        self.change_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| self.access.fail(invalid()))?;
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid owner physical view")
}

#[cfg(test)]
mod tests;
