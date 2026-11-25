//! Directory entries (`fs/readdir.c`): `getdents64`, `getdents`, and a
//! compatibility task's `getdents` and `readdir`.
//!
//! Host and private guest directories take a snapshot when a listing starts.
//! Their cursor is the index of the next entry. Procfs descriptor directories
//! enumerate live slots and use the descriptor number plus two as the cookie.

use std::borrow::Cow;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::O_PATH;
use super::super::fs::fd::{DirEntry, FileObject, FileState, FileType, OpenFile, ProcFdSlots, dt};
use super::super::procfs::DescriptorDirectory;
use super::{Ctx, SysResult};
use crate::user::supplied_fs::{Entry, Files, Kind};

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
    fn record(self, e: &DirEntry) -> Result<Vec<u8>, Errno> {
        let reclen = self.reclen(e);
        let mut r = Vec::with_capacity(reclen);
        match self {
            Dirent::Dirent64 | Dirent::Long => {
                r.extend_from_slice(&e.ino.to_le_bytes());
                r.extend_from_slice(&[0; 8]);
            }
            Dirent::Compat => {
                let ino = u32::try_from(e.ino).map_err(|_| Errno(EOVERFLOW))?;
                r.extend_from_slice(&ino.to_le_bytes());
                r.extend_from_slice(&[0; 4]);
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

    fn set_offset(self, record: &mut [u8], offset: u64) {
        match self {
            Dirent::Dirent64 | Dirent::Long => record[8..16].copy_from_slice(&offset.to_le_bytes()),
            Dirent::Compat => record[4..8].copy_from_slice(&(offset as u32).to_le_bytes()),
        }
    }
}

/// Encode a closed namespace's immediate children and dot entries.
pub(super) fn supplied_entries(
    files: &Files,
    path: &str,
    entry: &Entry,
) -> Result<Vec<DirEntry>, Errno> {
    Ok(files
        .directory_entries(path, entry)?
        .into_iter()
        .map(|(name, entry)| {
            let dtype = match entry.kind {
                Kind::Directory | Kind::WorkspaceDirectory(_) => dt::DT_DIR,
                Kind::Symlink(_) | Kind::WorkspaceSymlink(_) => dt::DT_LNK,
                Kind::NullDevice | Kind::ZeroDevice | Kind::UrandomDevice => dt::DT_CHR,
                _ => dt::DT_REG,
            };
            DirEntry {
                ino: entry.ino,
                dtype,
                name: name.into_bytes(),
            }
        })
        .collect())
}

/// Start an open description's directory snapshot on its first read.
fn directory(c: &Ctx<'_>, fd: i32) -> Result<std::sync::Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    if file.ftype != FileType::Directory {
        return Err(Errno(ENOTDIR));
    }
    let mut st = file.state.lock().unwrap();
    if st.flags & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    let detached = matches!(&file.object, FileObject::Supplied(entry)
        if entry.workspace_directory().is_some_and(|directory| !directory.linked()));
    if detached {
        st.dir = Some((Vec::new(), 0));
    } else if st.dir.is_none() && st.proc_dir.is_none() {
        let entries = match (&file.object, &file.host_path) {
            (FileObject::Supplied(entry), _) if entry.workspace_directory().is_some() => {
                let files = c.p.vfs.supplied().ok_or(Errno(EIO))?;
                supplied_entries(files, &file.path, entry)?
            }
            #[cfg(unix)]
            (_, Some(h)) => super::super::fs::read_directory(h)?,
            #[cfg(not(unix))]
            (_, Some(_)) => return Err(Errno(EPERM)),
            (_, None) => Vec::new(),
        };
        let cursor = st.synth_pos.min(entries.len() as u64) as usize;
        st.dir = Some((entries, cursor));
    }
    drop(st);
    Ok(file)
}

/// The next entry at or after a directory position, and its cookie. At EOF
/// the cookie is the position reached while walking to the end.
enum Directory<'a> {
    Snapshot(&'a [DirEntry]),
    Proc(DescriptorDirectory, ProcFdSlots),
}

impl<'a> Directory<'a> {
    fn open(c: &Ctx<'_>, state: &'a FileState) -> Result<(Self, u64), Errno> {
        if let Some(directory) = &state.proc_dir {
            let tid = directory.entry.tid;
            if directory.pid == c.p.pid {
                if !c.is_own_tid(tid) {
                    return Err(Errno(ENOENT));
                }
            } else if c.p.config.host_services {
                // A host-backed fork has a separate address space. Its copied
                // table must never stand in for the original owner's table.
                return Err(Errno(ENOENT));
            }
            Ok((
                Self::Proc(directory.entry, directory.slots()?),
                state.synth_pos,
            ))
        } else {
            let (entries, cursor) = state.dir.as_ref().expect("directory initialized");
            Ok((Self::Snapshot(entries), *cursor as u64))
        }
    }

    fn next(&self, pos: u64) -> (u64, Option<Cow<'a, DirEntry>>) {
        match self {
            Self::Snapshot(entries) => (pos, entries.get(pos as usize).map(Cow::Borrowed)),
            Self::Proc(directory, _) if pos < 2 => (pos, Some(Cow::Owned(directory.entry(pos)))),
            Self::Proc(directory, slots) => {
                // proc_readfd_common converts the requested slot to unsigned int.
                let (fd, open) = slots.next((pos - 2) as u32 as usize);
                let pos = fd as u64 + 2;
                (pos, open.then(|| Cow::Owned(directory.entry(pos))))
            }
        }
    }
}

fn set_cookie(st: &mut FileState, pos: u64) {
    match &mut st.dir {
        Some((_, cursor)) => *cursor = pos as usize,
        None => st.synth_pos = pos,
    }
}

/// `getdents64` and `getdents`: as many entries as fit in `count` bytes.
/// Each `d_off` is the cookie of the next entry or the end of the scan.
pub fn getdents(c: &mut Ctx<'_>, fd: i32, buf: u64, count: u64, layout: Dirent) -> SysResult {
    let file = directory(c, fd)?;
    let result = (|| {
        let mut st = file.state.lock().unwrap();
        let (dir, mut pos) = Directory::open(c, &st)?;
        let mut out = Vec::new();
        let mut previous = None;
        let stop = loop {
            let (cookie, entry) = dir.next(pos);
            pos = cookie;
            if let Some(start) = previous {
                layout.set_offset(&mut out[start..], cookie);
            }
            let Some(entry) = entry else { break None };
            if (out.len() + layout.reclen(&entry)) as u64 > count {
                break Some(Errno(EINVAL));
            }
            match layout.record(&entry) {
                Ok(record) => {
                    previous = Some(out.len());
                    out.extend_from_slice(&record);
                    pos += 1;
                }
                Err(error) => break Some(error),
            }
        };
        if out.is_empty()
            && let Some(error) = stop
        {
            set_cookie(&mut st, pos);
            return Err(error);
        }
        c.write_mem(buf, &out)?;
        set_cookie(&mut st, pos);
        Ok(out.len() as u64)
    })();
    super::notify::listed(&file);
    result
}

/// `compat_sys_old_readdir`: the next entry as a `struct
/// compat_old_linux_dirent` (`d_ino`, `d_offset`, `d_namlen`, then the
/// name and a NUL), 1 for an entry or 0 at the end. `d_offset` is the
/// entry's own offset (`compat_fillonedir`). The count is ignored.
pub fn old_readdir(c: &mut Ctx<'_>, fd: i32, dirent: u64) -> SysResult {
    let file = directory(c, fd)?;
    let result = (|| {
        let mut st = file.state.lock().unwrap();
        let (dir, pos) = Directory::open(c, &st)?;
        let (pos, entry) = dir.next(pos);
        let Some(entry) = entry else {
            set_cookie(&mut st, pos);
            return Ok(0);
        };
        let ino = u32::try_from(entry.ino).map_err(|_| Errno(EOVERFLOW))?;
        let mut rec = Vec::new();
        rec.extend_from_slice(&ino.to_le_bytes());
        rec.extend_from_slice(&(pos as u32).to_le_bytes());
        rec.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        rec.extend_from_slice(&entry.name);
        rec.push(0);
        let (next, _) = dir.next(pos + 1);
        c.write_mem(dirent, &rec)?;
        set_cookie(&mut st, next);
        Ok(1)
    })();
    super::notify::listed(&file);
    result
}
