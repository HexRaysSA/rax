//! `memfd_create` and the seal commands of `fcntl` (`mm/memfd.c`).
//!
//! A `memfd` is a nameless host object wrapped as a regular file: mode
//! `0777` (`0666` with `MFD_NOEXEC_SEAL`) and no links, `O_RDWR |
//! O_LARGEFILE`, `/memfd:<name> (deleted)` in `/proc`, sealable with
//! `MFD_ALLOW_SEALING` (otherwise `F_SEAL_SEAL` from the start). A shared
//! mapping of it is the object's pages, like any shared file mapping. The
//! kernel's `vm.memfd_noexec` is 0, so a `memfd` created with neither
//! `MFD_EXEC` nor `MFD_NOEXEC_SEAL` is executable. `MFD_HUGETLB` makes a
//! `hugetlbfs` file whose pool is empty, which cannot be mapped (`ENOMEM`,
//! as `MAP_HUGETLB`).

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::abi::vma_flags;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::memfd::{Memfd, seal};
use super::{Ctx, SysResult};
use crate::user::mm::{Backing, PageSource, SourceIdentity};

/// `MFD_*` (`linux/memfd.h`).
mod mfd {
    pub const CLOEXEC: u32 = 0x1;
    pub const ALLOW_SEALING: u32 = 0x2;
    pub const HUGETLB: u32 = 0x4;
    pub const NOEXEC_SEAL: u32 = 0x8;
    pub const EXEC: u32 = 0x10;
    /// `MFD_ALL_FLAGS`.
    pub const ALL: u32 = CLOEXEC | ALLOW_SEALING | HUGETLB | NOEXEC_SEAL | EXEC;
    /// The huge-page size encoding (`MFD_HUGE_MASK << MFD_HUGE_SHIFT`).
    pub const HUGE_SIZE: u32 = 0x3f << 26;
}

/// `MFD_NAME_MAX_LEN`: `NAME_MAX` less the `memfd:` prefix.
const NAME_MAX_LEN: usize = 255 - 6;

/// `memfd_create`: the flags (`sanitize_flags`), then the name
/// (`alloc_name`), then the file.
pub fn memfd_create(c: &mut Ctx<'_>, uname: u64, flags: u32) -> SysResult {
    let allowed = if flags & mfd::HUGETLB != 0 {
        mfd::ALL | mfd::HUGE_SIZE
    } else {
        mfd::ALL
    };
    if flags & !allowed != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & mfd::EXEC != 0 && flags & mfd::NOEXEC_SEAL != 0 {
        return Err(Errno(EINVAL));
    }
    let name = c.read_cstr_raw(uname, NAME_MAX_LEN).map_err(|e| {
        if e.0 == ENAMETOOLONG {
            Errno(EINVAL)
        } else {
            e
        }
    })?;
    let noexec = flags & mfd::NOEXEC_SEAL != 0;
    let mode = if noexec { 0o666 } else { 0o777 };
    let link = [b"/memfd:".as_slice(), &name, b" (deleted)"].concat();
    let path = String::from_utf8_lossy(&link).into_owned();
    let (object, identity, workspace_link) = if let Some(files) = c.p.vfs.supplied() {
        c.p.fds.free_fds(1, super::io::nofile(c))?;
        let entry =
            files.create_workspace_detached(path.clone(), mode, (c.p.creds.1, c.p.creds.3))?;
        let identity = entry
            .workspace_file()
            .expect("detached workspace file")
            .identity();
        (FileObject::Supplied(entry), identity, Some(link.into()))
    } else {
        let (object, identity) = host_backing(mode)?;
        (object, identity, None)
    };
    // shmem_get_inode starts with F_SEAL_SEAL; memfd_alloc_file lifts it
    // for sealing and replaces it with F_SEAL_EXEC for MFD_NOEXEC_SEAL.
    let seals = if noexec {
        seal::EXEC
    } else if flags & mfd::ALLOW_SEALING != 0 {
        0
    } else {
        seal::SEAL
    };
    let memfd =
        Memfd::with_workspace_link(seals, flags & mfd::HUGETLB != 0, identity, workspace_link)?;
    let status = O_RDWR | c.p.abi.open_flags().largefile;
    let open = OpenFile::with_memfd(object, FileType::Regular, path, None, status, Some(memfd));
    super::io::install(c, open, flags & mfd::CLOEXEC != 0)
}

#[cfg(unix)]
fn host_backing(mode: u32) -> Result<(FileObject, SourceIdentity), Errno> {
    use std::os::unix::fs::PermissionsExt;
    let file = crate::user::mm::anonymous_file().map_err(|_| Errno(ENOMEM))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    let identity = super::super::fs::identity(&file)?;
    Ok((FileObject::Host(file), identity))
}

#[cfg(not(unix))]
fn host_backing(_mode: u32) -> Result<(FileObject, SourceIdentity), Errno> {
    Err(Errno(ENOSYS))
}

/// Whether a shared mapping of `m`'s object in this process may be written
/// (`VM_MAYWRITE`), which keeps `F_SEAL_WRITE` off (`mapping_deny_writable`).
fn mapped_writable(c: &Ctx<'_>, m: &Memfd) -> bool {
    c.p.space.vma_snapshot().iter().any(|v| {
        matches!(&v.backing, Backing::Shared { object, .. } if object.identity() == m.identity)
            && v.flags & vma_flags::DENY_WRITE == 0
    })
}

/// `F_ADD_SEALS` (`memfd_add_seals`).
pub fn add_seals(c: &Ctx<'_>, file: &Arc<OpenFile>, seals: u32) -> SysResult {
    if !file.writable() {
        return Err(Errno(EPERM));
    }
    if seals & !seal::ALL != 0 {
        return Err(Errno(EINVAL));
    }
    let Some(m) = &file.memfd else {
        return Err(Errno(EINVAL));
    };
    let _operation = file.lock_workspace_memfd()?;
    let have = m.seals();
    if have & seal::SEAL != 0 {
        return Err(Errno(EPERM));
    }
    if seals & seal::WRITE != 0 && have & seal::WRITE == 0 {
        let writable = match &file.object {
            FileObject::Supplied(entry) => entry
                .workspace_file()
                .expect("workspace memfd")
                .any_shared_mapping(|vma| vma.flags & vma_flags::DENY_WRITE == 0)?,
            _ => mapped_writable(c, m),
        };
        if writable {
            return Err(Errno(EBUSY));
        }
    }
    // F_SEAL_EXEC on an executable object seals writes too (W^X).
    let mode = match &file.object {
        #[cfg(not(unix))]
        FileObject::Host(_) => return Err(Errno(EPERM)),
        #[cfg(unix)]
        FileObject::Host(f) => {
            use std::os::unix::fs::PermissionsExt;
            f.metadata()?.permissions().mode()
        }
        FileObject::Supplied(entry) => entry.workspace_mode().expect("workspace memfd"),
        _ => 0,
    };
    let mut add = seals;
    if seals & seal::EXEC != 0 && mode & 0o111 != 0 {
        add |= seal::SHRINK | seal::GROW | seal::WRITE | seal::FUTURE_WRITE;
    }
    m.add(add);
    Ok(0)
}

/// `F_GET_SEALS` (`memfd_get_seals`): `EINVAL` for a file that is not a
/// `memfd`.
pub fn get_seals(file: &OpenFile) -> SysResult {
    file.memfd
        .as_ref()
        .map(|m| u64::from(m.seals()))
        .ok_or(Errno(EINVAL))
}
