//! `memfd` objects (`mm/memfd.c`): anonymous shared-memory files and their
//! seals.
//!
//! A `memfd` is a host object with no name (see
//! [`anonymous_file`](crate::user::mm::anonymous_file)); its seals belong
//! to the inode, so they live in a word of memory shared with forked
//! processes, and every description of the object (`dup`, `fork`, a pass
//! within the process) sees them change. Seals are enforced where
//! `mm/shmem.c` enforces them: [`Memfd::write_len`] for writes,
//! [`Memfd::check_resize`] for `ftruncate` and `fallocate`,
//! [`Memfd::check_mode`] for `fchmod`, and the `mmap` and `F_ADD_SEALS`
//! checks of the system calls.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::host::SharedWords;
use crate::user::mm::SourceIdentity;

/// `F_SEAL_*` (`linux/fcntl.h`).
pub mod seal {
    pub const SEAL: u32 = 0x1;
    pub const SHRINK: u32 = 0x2;
    pub const GROW: u32 = 0x4;
    pub const WRITE: u32 = 0x8;
    pub const FUTURE_WRITE: u32 = 0x10;
    pub const EXEC: u32 = 0x20;
    /// `F_ALL_SEALS`.
    pub const ALL: u32 = SEAL | SHRINK | GROW | WRITE | FUTURE_WRITE | EXEC;
}

/// Page size of the `shmem` write path's chunks.
const PAGE: u64 = 4096;

/// A `memfd`'s inode state.
#[derive(Debug)]
pub struct Memfd {
    /// The seals, one word shared with forked processes.
    seals: SharedWords,
    /// A `hugetlbfs` file (`MFD_HUGETLB`), whose pool is empty.
    pub hugetlb: bool,
    /// The host object's identity.
    pub identity: SourceIdentity,
}

/// Every live `memfd` of this process, by identity, for the calls that
/// reach one through a mapping rather than a descriptor.
static REGISTRY: Mutex<Vec<(SourceIdentity, Weak<Memfd>)>> = Mutex::new(Vec::new());

impl Memfd {
    /// A `memfd` inode with `seals`.
    pub fn new(seals: u32, hugetlb: bool, identity: SourceIdentity) -> Result<Arc<Self>, Errno> {
        let words = SharedWords::new(1)?;
        words.words()[0].store(u64::from(seals), Ordering::Release);
        let m = Arc::new(Memfd {
            seals: words,
            hugetlb,
            identity,
        });
        let mut reg = REGISTRY.lock().unwrap();
        reg.retain(|(_, w)| w.strong_count() > 0);
        reg.push((identity, Arc::downgrade(&m)));
        Ok(m)
    }

    /// The `memfd` whose object is `id`, if this process has it (a
    /// closed one whose identity the host gave again is not it).
    pub fn find(id: SourceIdentity) -> Option<Arc<Memfd>> {
        REGISTRY
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _)| *i == id)
            .find_map(|(_, w)| w.upgrade())
    }

    /// The seals.
    pub fn seals(&self) -> u32 {
        self.seals.words()[0].load(Ordering::Acquire) as u32
    }

    /// Adds `seals`.
    pub fn add(&self, seals: u32) {
        self.seals.words()[0].fetch_or(u64::from(seals), Ordering::AcqRel);
    }

    /// Whether writes are sealed (`is_write_sealed`).
    pub fn write_sealed(&self) -> bool {
        self.seals() & (seal::WRITE | seal::FUTURE_WRITE) != 0
    }

    /// `shmem_write_begin` over a write of `len` bytes at `pos` to an object
    /// of `size` bytes: the bytes it may write. A write seal refuses it; a
    /// grow seal stops it before the first page-sized chunk that would
    /// extend the object (`EPERM` when that is the first).
    pub fn write_len(&self, pos: u64, len: usize, size: u64) -> Result<usize, Errno> {
        let seals = self.seals();
        if seals & (seal::WRITE | seal::FUTURE_WRITE) != 0 {
            return Err(Errno(EPERM));
        }
        let end = pos.saturating_add(len as u64);
        if seals & seal::GROW == 0 || end <= size {
            return Ok(len);
        }
        // The chunks end at page boundaries; the one past `size` fails.
        let ok_end = size / PAGE * PAGE;
        if ok_end <= pos {
            return Err(Errno(EPERM));
        }
        Ok((ok_end - pos) as usize)
    }

    /// `shmem_setattr` and `shmem_fallocate` for a size change from `old`
    /// to `new`.
    pub fn check_resize(&self, old: u64, new: u64) -> Result<(), Errno> {
        let seals = self.seals();
        if (new < old && seals & seal::SHRINK != 0) || (new > old && seals & seal::GROW != 0) {
            return Err(Errno(EPERM));
        }
        Ok(())
    }

    /// `shmem_setattr` for a mode change: the execute bits are sealed by
    /// `F_SEAL_EXEC`.
    pub fn check_mode(&self, old: u32, new: u32) -> Result<(), Errno> {
        if self.seals() & seal::EXEC != 0 && (old ^ new) & 0o111 != 0 {
            return Err(Errno(EPERM));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memfd(seals: u32) -> Arc<Memfd> {
        Memfd::new(seals, false, SourceIdentity { dev: 1, ino: 2 }).unwrap()
    }

    #[test]
    fn writes_follow_shmem_write_begin() {
        let m = memfd(0);
        assert_eq!(m.write_len(0, 10, 0), Ok(10));
        m.add(seal::GROW);
        // Within the object; past it from a page boundary inside it; past
        // it from its end.
        assert_eq!(m.write_len(0, 10, 100), Ok(10));
        assert_eq!(
            m.write_len(10, 2 * PAGE as usize, PAGE + 5),
            Ok(PAGE as usize - 10)
        );
        assert_eq!(m.write_len(100, 1, 100), Err(Errno(EPERM)));
        assert_eq!(m.write_len(PAGE, 10, PAGE + 5), Err(Errno(EPERM)));
        m.add(seal::FUTURE_WRITE);
        assert_eq!(m.write_len(0, 1, 100), Err(Errno(EPERM)));
    }

    #[test]
    fn a_closed_memfd_does_not_hide_a_live_one() {
        let id = SourceIdentity { dev: 1, ino: 3 };
        let old = Memfd::new(0, false, id).unwrap();
        let new = Memfd::new(seal::GROW, false, id).unwrap();
        drop(old);
        let found = Memfd::find(id).expect("the live memfd");
        assert!(Arc::ptr_eq(&found, &new));
    }

    #[test]
    fn resizes_and_modes_follow_shmem_setattr() {
        let m = memfd(seal::SHRINK);
        assert_eq!(m.check_resize(10, 5), Err(Errno(EPERM)));
        assert_eq!(m.check_resize(10, 20), Ok(()));
        m.add(seal::GROW);
        assert_eq!(m.check_resize(10, 20), Err(Errno(EPERM)));
        assert_eq!(m.check_resize(10, 10), Ok(()));
        assert_eq!(m.check_mode(0o777, 0o666), Ok(()));
        m.add(seal::EXEC);
        assert_eq!(m.check_mode(0o777, 0o666), Err(Errno(EPERM)));
        assert_eq!(m.check_mode(0o777, 0o755), Ok(()));
        // Found by identity while alive.
        assert!(Memfd::find(SourceIdentity { dev: 1, ino: 2 }).is_some());
    }
}
