//! Memory-management system calls.
//!
//! Argument validation follows Linux 6.19 in order (`mm/mmap.c`,
//! `mm/mprotect.c`, `mm/mremap.c`, `mm/madvise.c`, `mm/msync.c`), so the
//! first failing check determines the error just as on a real kernel.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE, READ_IMPLIES_EXEC, vma_flags};
use super::super::fs::fd::{FileObject, FileType};
use super::super::loader::prot_to_perms;
use super::{Ctx, SysResult};
use crate::user::mm::{Backing, HostFileSource, Mapping, MmError, PageSource, Perms, SharedObject};

/// `mmap`/`mprotect` constants (`asm-generic/mman-common.h`, `mman.h`).
pub mod mman {
    /// `PROT_READ`.
    pub const PROT_READ: u32 = 0x1;
    /// `PROT_WRITE`.
    pub const PROT_WRITE: u32 = 0x2;
    /// `PROT_EXEC`.
    pub const PROT_EXEC: u32 = 0x4;
    /// `PROT_SEM`.
    pub const PROT_SEM: u32 = 0x8;
    /// arm64 `PROT_BTI`.
    pub const PROT_BTI: u32 = 0x10;
    /// `PROT_GROWSDOWN`.
    pub const PROT_GROWSDOWN: u32 = 0x0100_0000;
    /// `PROT_GROWSUP`.
    pub const PROT_GROWSUP: u32 = 0x0200_0000;
    /// `MAP_SHARED`.
    pub const MAP_SHARED: u32 = 0x01;
    /// `MAP_PRIVATE`.
    pub const MAP_PRIVATE: u32 = 0x02;
    /// `MAP_SHARED_VALIDATE`.
    pub const MAP_SHARED_VALIDATE: u32 = 0x03;
    /// `MAP_TYPE`.
    pub const MAP_TYPE: u32 = 0x0f;
    /// `MAP_FIXED`.
    pub const MAP_FIXED: u32 = 0x10;
    /// `MAP_ANONYMOUS`.
    pub const MAP_ANONYMOUS: u32 = 0x20;
    /// x86 `MAP_32BIT`.
    pub const MAP_32BIT: u32 = 0x40;
    /// `MAP_GROWSDOWN`.
    pub const MAP_GROWSDOWN: u32 = 0x0100;
    /// `MAP_DENYWRITE`.
    pub const MAP_DENYWRITE: u32 = 0x0800;
    /// `MAP_EXECUTABLE`.
    pub const MAP_EXECUTABLE: u32 = 0x1000;
    /// `MAP_LOCKED`.
    pub const MAP_LOCKED: u32 = 0x2000;
    /// `MAP_NORESERVE`.
    pub const MAP_NORESERVE: u32 = 0x4000;
    /// `MAP_POPULATE`.
    pub const MAP_POPULATE: u32 = 0x8000;
    /// `MAP_NONBLOCK`.
    pub const MAP_NONBLOCK: u32 = 0x10000;
    /// `MAP_STACK`.
    pub const MAP_STACK: u32 = 0x20000;
    /// `MAP_HUGETLB`.
    pub const MAP_HUGETLB: u32 = 0x40000;
    /// `MAP_SYNC`.
    pub const MAP_SYNC: u32 = 0x80000;
    /// `MAP_FIXED_NOREPLACE`.
    pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;
    /// `LEGACY_MAP_MASK`: flags `MAP_SHARED_VALIDATE` accepts.
    pub const LEGACY_MAP_MASK: u32 = MAP_SHARED
        | MAP_PRIVATE
        | MAP_FIXED
        | MAP_ANONYMOUS
        | MAP_DENYWRITE
        | MAP_EXECUTABLE
        | MAP_UNINITIALIZED
        | MAP_GROWSDOWN
        | MAP_LOCKED
        | MAP_NORESERVE
        | MAP_POPULATE
        | MAP_NONBLOCK
        | MAP_STACK
        | MAP_HUGETLB
        | MAP_32BIT
        | MAP_FIXED_NOREPLACE;
    /// `MAP_UNINITIALIZED`.
    pub const MAP_UNINITIALIZED: u32 = 0x4000000;
}
use mman::*;

pub(super) const PAGE_MASK: u64 = PAGE_SIZE - 1;

pub(in crate::user::linux) fn page_align(x: u64) -> Option<u64> {
    x.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

pub(in crate::user::linux) fn map_err(e: MmError) -> Errno {
    match e {
        MmError::InvalidArgument(_) => Errno(EINVAL),
        MmError::OutOfRange | MmError::OutOfMemory | MmError::NotMapped { .. } => Errno(ENOMEM),
    }
}

pub(in crate::user::linux) fn perms(abi: LinuxAbi, prot: u32) -> Perms {
    prot_to_perms(
        abi,
        prot & PROT_READ != 0,
        prot & PROT_WRITE != 0,
        prot & PROT_EXEC != 0,
    )
}

/// The VMA flag a protection records beside its page permissions:
/// [`vma_flags::NO_READ`] without `PROT_READ` (`calc_vm_prot_bits`).
pub(in crate::user::linux) fn read_flag(prot: u32) -> u32 {
    if prot & PROT_READ == 0 {
        vma_flags::NO_READ
    } else {
        0
    }
}

/// `vma->vm_flags & VM_READ`: the mapping was asked to be readable, which
/// the permissions alone cannot tell (write and, on some architectures,
/// execute imply read access to the pages).
pub(crate) fn vm_read(vma: &crate::user::mm::Vma) -> bool {
    vma.perms.contains(Perms::READ) && vma.flags & vma_flags::NO_READ == 0
}

/// `brk`.
pub fn brk(c: &mut Ctx<'_>, addr: u64) -> SysResult {
    let policy = super::super::process::BrkPolicy::from(&*c.p);
    c.p.mm.change_brk(&c.p.space, policy, addr)
}

/// `get_unmapped_area` for a non-fixed request.
pub(super) fn unmapped_area(c: &Ctx<'_>, hint: u64, len: u64, flags: u32) -> Result<u64, Errno> {
    c.p.mm.unmapped_area(&c.p.space, c.p.abi, hint, len, flags)
}

/// `mmap`.
pub fn mmap(
    c: &mut Ctx<'_>,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    off: u64,
) -> SysResult {
    if off & PAGE_MASK != 0 {
        return Err(Errno(EINVAL));
    }
    // ksys_mmap_pgoff obtains the file before vm_mmap_pgoff validates the
    // length/map type. fget excludes FMODE_PATH descriptions (fs/file.c).
    let anonymous = flags & MAP_ANONYMOUS != 0;
    let file = if anonymous {
        None
    } else {
        let file = c.p.fds.file(fd)?;
        if file.flags() & super::super::abi::open::O_PATH != 0 {
            return Err(Errno(EBADF));
        }
        Some(file)
    };
    let arguments = super::super::process::mm::MmapArgs {
        address: addr,
        length: len,
        protection: prot,
        flags,
        offset: off,
    }
    .checked()?;
    let len = arguments.length;
    let shared = arguments.shared();
    let mut prot = prot;
    if prot & PROT_READ != 0 && c.p.persona & READ_IMPLIES_EXEC != 0 {
        prot |= PROT_EXEC;
    }

    let mut backing = Backing::Anonymous;
    let mut name: Option<Arc<str>> = None;
    let mut vm_flags = 0;
    if let Some(file) = file {
        match (&file.object, file.ftype) {
            #[cfg(not(unix))]
            (FileObject::Host(_), _) => return Err(Errno(EPERM)),
            #[cfg(unix)]
            (FileObject::Host(f), FileType::Regular | FileType::BlockDevice) => {
                if !file.readable() {
                    return Err(Errno(EACCES));
                }
                if shared && !file.writable() {
                    if prot & PROT_WRITE != 0 {
                        return Err(Errno(EACCES));
                    }
                    vm_flags |= vma_flags::DENY_WRITE;
                }
                if let Some(m) = &file.memfd {
                    // memfd_check_seals_mmap: a write-sealed object maps
                    // shared only for reading, never to become writable.
                    if shared && m.write_sealed() {
                        if prot & PROT_WRITE != 0 {
                            return Err(Errno(EPERM));
                        }
                        vm_flags |= vma_flags::DENY_WRITE;
                    }
                    // hugetlbfs_file_mmap: the pool is empty.
                    if m.hugetlb {
                        return Err(Errno(ENOMEM));
                    }
                }
                // vm_file retains the inode seals and notification close,
                // while the guest description may close independently.
                let keep = file.mapping_keep();
                backing = if shared && file.ftype == FileType::Regular {
                    // The file's own pages (write-back and coherence).
                    let writable = file.writable() && vm_flags & vma_flags::DENY_WRITE == 0;
                    let object = SharedObject::file_keeping(f.try_clone()?, writable, keep)
                        .map_err(Errno::from)?;
                    Backing::Shared {
                        object: Arc::new(object),
                        offset: off,
                    }
                } else {
                    let source: Arc<dyn PageSource> = Arc::new(
                        HostFileSource::keeping(f.try_clone()?, keep).map_err(Errno::from)?,
                    );
                    Backing::Source {
                        source,
                        offset: off,
                    }
                };
                name = Some(match &file.host_path {
                    Some(h) => c.p.vfs.guest_path_of(h).into(),
                    None => file.path.as_str().into(),
                });
            }
            // /dev/zero maps anonymous memory (shared: shmem_zero_setup).
            (FileObject::Host(_), FileType::CharDevice) if file.path.ends_with("/dev/zero") => {
                if shared {
                    (backing, name) = shmem(len)?;
                }
            }
            // io_uring_mmap: the ring or SQE region itself, shared
            // (VM_DONTEXPAND, VM_MIXEDMAP).
            (FileObject::Anon(super::super::fs::anon::Anon::Uring(r)), _) => {
                let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
                backing = super::uring::mmap_region(r, addr, fixed, off, len)?;
                name = Some("anon_inode:[io_uring]".into());
                vm_flags |= vma_flags::SPECIAL;
            }
            (FileObject::Supplied(entry), FileType::Regular) => {
                if !file.readable() {
                    return Err(Errno(EACCES));
                }
                if shared && !file.writable() {
                    if prot & PROT_WRITE != 0 {
                        return Err(Errno(EACCES));
                    }
                    vm_flags |= vma_flags::DENY_WRITE;
                }
                backing = Backing::Source {
                    source: entry.source()?,
                    offset: off,
                };
                name = Some(file.path.as_str().into());
            }
            (FileObject::Synthetic(d), FileType::Regular) => {
                if !file.readable() {
                    return Err(Errno(EACCES));
                }
                if shared && !file.writable() {
                    if prot & PROT_WRITE != 0 {
                        return Err(Errno(EACCES));
                    }
                    // A read-only shared file cannot become writable later.
                    vm_flags |= vma_flags::DENY_WRITE;
                }
                backing = Backing::Source {
                    source: Arc::new(crate::user::mm::BytesSource::new(d.clone())),
                    offset: off,
                };
                name = Some(file.path.as_str().into());
            }
            _ => return Err(Errno(ENODEV)),
        }
    } else if flags & MAP_HUGETLB != 0 {
        // No huge pages are reserved (vm.nr_hugepages = 0).
        return Err(Errno(ENOMEM));
    } else if shared {
        (backing, name) = shmem(len)?;
    }

    let policy = super::super::process::mm::MmapPolicy::from(&*c.p);
    c.p.mm.map_prepared(
        &c.p.space,
        policy,
        arguments,
        super::super::process::mm::PreparedMmap {
            backing,
            name,
            flags: vm_flags,
        },
    )
}

/// Anonymous shared memory of `len` bytes (`shmem_zero_setup`): a new
/// object, named as `/proc/<pid>/maps` shows it.
fn shmem(len: u64) -> Result<(Backing, Option<Arc<str>>), Errno> {
    super::super::process::mm::mapping::shared_anonymous(len)
}

/// `munmap`.
pub fn munmap(c: &mut Ctx<'_>, addr: u64, len: u64) -> SysResult {
    c.p.mm.unmap_range(&c.p.space, c.p.abi, addr, len)
}

/// `mprotect`: earlier VMAs keep their changes if a later VMA refuses.
pub fn mprotect(c: &mut Ctx<'_>, addr: u64, len: u64, prot: u32) -> SysResult {
    let policy = super::super::process::mm::ProtectPolicy::from(&*c.p);
    c.p.mm.protect_range(&c.p.space, policy, addr, len, prot)
}

/// `mremap`.
pub fn mremap(
    c: &mut Ctx<'_>,
    old: u64,
    old_len: u64,
    new_len: u64,
    flags: u32,
    new_addr: u64,
) -> SysResult {
    let policy = super::super::process::mm::LockPolicy::from(&*c.p);
    c.p.mm.remap_range(
        &c.p.space,
        &mut c.p.aio,
        policy,
        super::super::process::mm::RemapArgs {
            old_address: old,
            old_length: old_len,
            new_length: new_len,
            flags,
            new_address: new_addr,
        },
    )
}

/// `madvise`.
pub fn madvise(c: &mut Ctx<'_>, addr: u64, len: u64, advice: u32) -> SysResult {
    c.p.mm.advise_range(&c.p.space, addr, len, advice)
}

/// `msync`.
pub fn msync(c: &mut Ctx<'_>, addr: u64, len: u64, flags: u32) -> SysResult {
    c.p.mm.sync_range(&c.p.space, addr, len, flags)
}

/// `mincore`: one byte per page, bit 0 set for resident pages.
pub fn mincore(c: &mut Ctx<'_>, addr: u64, len: u64, vec: u64) -> SysResult {
    c.p.mm.residency_into(&c.p.space, c.p.abi, addr, len, vec)
}
