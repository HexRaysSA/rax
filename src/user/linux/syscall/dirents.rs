//! Directory entries (`fs/readdir.c`): `getdents64`, `getdents`, and a
//! compatibility task's `getdents` and `readdir`.
//!
//! A directory's entries are read from the host when a listing starts and
//! then served from the open description, whose cursor is the index of the
//! next entry; an entry's offset (`d_off`) is the cursor after it.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::fs::fd::{DirEntry, FileType, OpenFile};
use super::{Ctx, SysResult};

/// The entry layouts `getdents` fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dirent {
    /// `struct linux_dirent64` (`getdents64`): 64-bit inode and offset,
    /// the type before the name.
    Dirent64,
    /// `struct linux_dirent` of a 64-bit ABI (`getdents`): `unsigned
    /// long` inode and offset, the type in the record's last byte.
    Long,
    /// `struct compat_linux_dirent` (`compat_sys_getdents`): as
    /// [`Dirent::Long`] with 32-bit fields and 4-byte alignment; an inode
    /// number past 32 bits is `EOVERFLOW` (`compat_filldir`).
    Compat,
}

impl Dirent {
    /// `offsetof(d_name)` plus the name, its NUL, and (outside
    /// `linux_dirent64`) the type byte, aligned: what `filldir` compares
    /// with the room left before it looks at the inode number.
    fn reclen(self, e: &DirEntry) -> usize {
        match self {
            Dirent::Dirent64 => (19 + e.name.len() + 1).div_ceil(8) * 8,
            Dirent::Long => (18 + e.name.len() + 2).div_ceil(8) * 8,
            Dirent::Compat => (10 + e.name.len() + 2).div_ceil(4) * 4,
        }
    }

    /// The record of entry `e`, whose offset is `off`; `EOVERFLOW` for an
    /// inode number the layout cannot hold. The compatibility layout
    /// stores the offset truncated.
    fn record(self, e: &DirEntry, off: u64) -> Result<Vec<u8>, Errno> {
        let reclen = self.reclen(e);
        let mut r = Vec::with_capacity(reclen);
        match self {
            Dirent::Dirent64 | Dirent::Long => {
                r.extend_from_slice(&e.ino.to_le_bytes());
                r.extend_from_slice(&off.to_le_bytes());
            }
            Dirent::Compat => {
                let ino = u32::try_from(e.ino).map_err(|_| Errno(EOVERFLOW))?;
                r.extend_from_slice(&ino.to_le_bytes());
                r.extend_from_slice(&(off as u32).to_le_bytes());
            }
        }
        r.extend_from_slice(&(reclen as u16).to_le_bytes());
        if self == Dirent::Dirent64 {
            r.push(e.dtype);
            r.extend_from_slice(&e.name);
            r.resize(reclen, 0);
        } else {
            r.extend_from_slice(&e.name);
            r.resize(reclen - 1, 0);
            r.push(e.dtype);
        }
        Ok(r)
    }
}

/// The directory `fd` names, its entries read from the host if its
/// listing has not started.
fn directory(c: &Ctx<'_>, fd: i32) -> Result<std::sync::Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    if file.ftype != FileType::Directory {
        return Err(Errno(ENOTDIR));
    }
    let mut st = file.state.lock().unwrap();
    if st.dir.is_none() {
        let entries = match &file.host_path {
            Some(h) => super::super::fs::read_directory(h)?,
            None => Vec::new(),
        };
        st.dir = Some((entries, 0));
    }
    drop(st);
    Ok(file)
}

/// `getdents64` and `getdents`: as many entries as fit in `count` bytes.
/// The first entry that does not fit (`EINVAL`), or whose inode number the
/// layout cannot hold (`EOVERFLOW`), ends the listing; that error is the
/// result only when no entry was copied.
pub fn getdents(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, layout: Dirent) -> SysResult {
    let file = directory(c, fd)?;
    let mut st = file.state.lock().unwrap();
    let (entries, cursor) = st.dir.as_mut().unwrap();
    let mut out = Vec::new();
    let mut i = *cursor;
    let mut stop = None;
    while i < entries.len() {
        let e = &entries[i];
        if out.len() + layout.reclen(e) > count as usize {
            stop = Some(Errno(EINVAL));
            break;
        }
        match layout.record(e, (i + 1) as u64) {
            Ok(rec) => out.extend_from_slice(&rec),
            Err(err) => {
                stop = Some(err);
                break;
            }
        }
        i += 1;
    }
    drop(st);
    // iterate_dir reports the access whatever the entries' copies do.
    super::notify::listed(&file);
    if out.is_empty()
        && let Some(e) = stop
    {
        return Err(e);
    }
    c.write_mem(buf, &out)?;
    if let Some((_, cur)) = file.state.lock().unwrap().dir.as_mut() {
        *cur = i;
    }
    Ok(out.len() as u64)
}

/// `compat_sys_old_readdir`: the next entry as a `struct
/// compat_old_linux_dirent` (`d_ino`, `d_offset`, `d_namlen`, then the
/// name and a NUL), 1 for an entry or 0 at the end. `d_offset` is the
/// entry's own offset (`compat_fillonedir`), not the next one's; `count`
/// is ignored.
pub fn old_readdir(c: &mut Ctx<'_>, fd: i32, dirent: u64) -> SysResult {
    // fd_pos: EBADF before the directory check of iterate_dir.
    let file = directory(c, fd)?;
    let mut st = file.state.lock().unwrap();
    let (entries, cursor) = st.dir.as_mut().unwrap();
    let Some(e) = entries.get(*cursor) else {
        drop(st);
        super::notify::listed(&file);
        return Ok(0);
    };
    let ino = u32::try_from(e.ino).map_err(|_| Errno(EOVERFLOW));
    let mut rec = Vec::new();
    if let Ok(ino) = ino {
        rec.extend_from_slice(&ino.to_le_bytes());
        rec.extend_from_slice(&(*cursor as u32).to_le_bytes());
        rec.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        rec.extend_from_slice(&e.name);
        rec.push(0);
    }
    let at = *cursor;
    drop(st);
    super::notify::listed(&file);
    ino?;
    c.write_mem(dirent, &rec)?;
    if let Some((_, cur)) = file.state.lock().unwrap().dir.as_mut()
        && *cur == at
    {
        *cur = at + 1;
    }
    Ok(1)
}
