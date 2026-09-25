//! The file-system events the calls here report to the emulated
//! notification backend (`include/linux/fsnotify.h`), in the order the
//! kernel's helpers report them. With the host's inotify (or nothing
//! watched), they do nothing: the host kernel reports what the calls do to
//! host files itself.

use std::path::Path;
use std::sync::Arc;

use super::super::fs::fd::{FileType, OpenFile};
use super::super::fsnotify::bits::*;
use super::super::fsnotify::hub::Hub;
use super::super::fsnotify::{Hook, Key, Obj};
use super::Ctx;

/// The namespace, when something in it is watched.
fn active<'a>(c: &'a Ctx<'_>) -> Option<&'a Arc<Hub>> {
    c.p.fsnotify.as_ref().filter(|h| h.active())
}

/// The inode of host file `path`.
pub fn obj_of(path: &Path, follow: bool) -> Option<Obj> {
    super::inotify::host_obj(path, follow).ok()
}

/// The inode of the metadata of an open file.
fn obj_from(m: &std::fs::Metadata) -> Obj {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let t = m.file_type();
    Obj {
        key: Key {
            dev: m.dev(),
            ino: m.ino(),
        },
        dir: t.is_dir(),
        special: t.is_fifo() || t.is_socket() || t.is_char_device() || t.is_block_device(),
    }
}

/// Entry `path`'s directory and name.
fn entry(path: &Path) -> Option<(Key, Vec<u8>)> {
    use std::os::unix::ffi::OsStrExt;
    let name = path.file_name()?.as_bytes().to_vec();
    let dir = obj_of(path.parent().filter(|p| !p.as_os_str().is_empty())?, true)?;
    Some((dir.key, name))
}

/// `fsnotify_name`: a change to entry `path`.
fn name(hub: &Hub, path: &Path, mask: u32, cookie: u32) {
    if let Some((dir, name)) = entry(path) {
        hub.notify(&Hook::Name {
            dir,
            name: &name,
            mask,
            cookie,
        });
    }
}

/// `fsnotify_inode`.
fn inode(hub: &Hub, obj: Obj, mask: u32) {
    hub.notify(&Hook::Inode { obj, mask });
}

/// `fsnotify_open` (after `fsnotify_create` for an open that made the
/// file, before the truncation of `O_TRUNC`): gives `file` its token.
pub fn opened(
    c: &Ctx<'_>,
    file: &OpenFile,
    host: &Path,
    meta: &std::fs::Metadata,
    created: bool,
    truncated: bool,
    exec: bool,
) {
    let Some(hub) = &c.p.fsnotify else {
        return;
    };
    if created && hub.active() {
        name(hub, host, IN_CREATE, 0);
    }
    let token = hub.open_file(obj_from(meta), host.to_path_buf(), file.writable(), exec);
    if truncated {
        token.change(IN_MODIFY);
    }
    let _ = file.notify.set(token);
}

/// `open_exec`'s `fsnotify_open` with `FS_OPEN_EXEC`: a token for a file
/// opened for execution.
pub fn exec_open(c: &Ctx<'_>, host: &Path) -> Option<Arc<super::super::fsnotify::hub::Token>> {
    let hub = c.p.fsnotify.as_ref()?;
    let obj = obj_of(host, true)?;
    Some(hub.open_file(obj, host.to_path_buf(), false, true))
}

/// `fsnotify_access`: a read of `n` bytes (reported when `n` is not zero
/// unless `always`, as `vfs_read` and the vectored reads differ).
pub fn access(file: &OpenFile, n: u64, always: bool) {
    if (n > 0 || always)
        && let Some(t) = file.notify.get()
    {
        t.event(IN_ACCESS);
    }
}

/// A vectored read that moved nothing: `vfs_readv` still reports an
/// access. The emulated backend is told; with the host's inotify, a
/// zero-length host `readv` of the description makes the host report it
/// (the host read found nothing, and reports nothing).
pub fn vectored_nothing(c: &Ctx<'_>, file: &OpenFile) {
    use super::super::fs::fd::FileObject;
    if c.p.fsnotify.is_some() {
        access(file, 0, true);
        return;
    }
    if let FileObject::Host(f) = &file.object {
        use std::os::fd::AsRawFd;
        let iov = libc::iovec {
            iov_base: std::ptr::NonNull::<u8>::dangling().as_ptr().cast(),
            iov_len: 0,
        };
        // SAFETY: one zero-length vector: nothing is written.
        unsafe {
            libc::readv(f.as_raw_fd(), &iov, 1);
        }
    }
}

/// `fsnotify_modify`: a write of `n` bytes (when not zero).
pub fn modify(file: &OpenFile, n: u64) {
    if n > 0
        && let Some(t) = file.notify.get()
    {
        t.event(IN_MODIFY);
    }
}

/// `fsnotify_modify` for `fallocate`, reported on success whatever it
/// changed.
pub fn allocated(file: &OpenFile) {
    if let Some(t) = file.notify.get() {
        t.event(IN_MODIFY);
    }
}

/// `fsnotify_change` through an open file (`fchmod`, `fchown`,
/// `ftruncate`, `futimens`, `fsetxattr`).
pub fn changed_file(file: &OpenFile, mask: u32) {
    if mask != 0
        && let Some(t) = file.notify.get()
    {
        t.change(mask);
    }
}

/// `fsnotify_change` (and `fsnotify_xattr`) on host file `path`.
pub fn changed(c: &Ctx<'_>, path: &Path, follow: bool, mask: u32) {
    let Some(hub) = active(c) else {
        return;
    };
    if mask == 0 {
        return;
    }
    let Some(obj) = obj_of(path, follow) else {
        return;
    };
    let parent = entry(path);
    hub.notify(&Hook::Parent {
        obj,
        parent: parent.as_ref().map(|(k, n)| (*k, n.as_slice())),
        mask,
        path: false,
        unlinked: false,
    });
}

/// `fsnotify_change`'s mask for new times: both (or now) are an attribute
/// change, the access time alone an access, the modification time alone
/// a modification.
pub fn times_mask(atime: bool, mtime: bool) -> u32 {
    match (atime, mtime) {
        (true, true) => IN_ATTRIB,
        (true, false) => IN_ACCESS,
        (false, true) => IN_MODIFY,
        (false, false) => 0,
    }
}

/// `fsnotify_create`/`fsnotify_mkdir`: entry `path` was made.
pub fn created(c: &Ctx<'_>, path: &Path, dir: bool) {
    if let Some(hub) = active(c) {
        name(hub, path, IN_CREATE | if dir { IN_ISDIR } else { 0 }, 0);
    }
}

/// `unix_bind_bsd` for a socket already bound: the node it made, then
/// removed again.
pub fn made_and_unmade(c: &Ctx<'_>, path: &Path) {
    if let Some(hub) = active(c) {
        name(hub, path, IN_CREATE, 0);
        name(hub, path, IN_DELETE, 0);
    }
}

/// The inode an entry about to be removed or replaced names, and its
/// links: looked up only when something is watched.
pub fn before(c: &Ctx<'_>, path: &Path) -> Option<(Obj, u64)> {
    active(c)?;
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((obj_from(&m), m.nlink()))
}

/// The inode an entry about to be renamed names: looked up whenever the
/// namespace exists, since this process's open files by that entry follow
/// it even when nothing is watched.
pub fn moving(c: &Ctx<'_>, path: &Path) -> Option<(Obj, u64)> {
    c.p.fsnotify.as_ref()?;
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((obj_from(&m), m.nlink()))
}

/// `vfs_unlink` and `vfs_rmdir` removed entry `path` of inode `was`: the
/// link count's change (a file), the inode's end when it has no links left
/// (`d_delete`), then the directory's `IN_DELETE`.
pub fn removed(c: &Ctx<'_>, path: &Path, was: Option<(Obj, u64)>) {
    let (Some(hub), Some((obj, nlink))) = (active(c), was) else {
        return;
    };
    let left = if obj.dir { 0 } else { nlink.saturating_sub(1) };
    if !obj.dir {
        inode(hub, obj, IN_ATTRIB);
    }
    hub.unlinked(obj, path, left);
    name(hub, path, IN_DELETE | if obj.dir { IN_ISDIR } else { 0 }, 0);
}

/// `fsnotify_link`: a new entry `path` for an inode.
pub fn linked(c: &Ctx<'_>, path: &Path) {
    let Some(hub) = active(c) else {
        return;
    };
    if let Some(obj) = obj_of(path, false) {
        inode(hub, obj, IN_ATTRIB);
        name(hub, path, IN_CREATE, 0);
    }
}

/// `fsnotify_move`: entry `from` (inode `moved`) became `to`, replacing
/// `target` if there was one.
pub fn renamed(
    c: &Ctx<'_>,
    from: &Path,
    to: &Path,
    moved: Option<(Obj, u64)>,
    target: Option<(Obj, u64)>,
) {
    let Some(hub) = c.p.fsnotify.as_ref() else {
        return;
    };
    let Some((obj, _)) = moved else {
        return;
    };
    // This process's open files by the old name follow it.
    hub.moved(obj.key, from, to);
    if !hub.active() {
        return;
    }
    let isdir = if obj.dir { IN_ISDIR } else { 0 };
    let cookie = hub.cookie();
    name(hub, from, IN_MOVED_FROM | isdir, cookie);
    name(hub, to, IN_MOVED_TO | isdir, cookie);
    if let Some((t, _)) = target {
        inode(hub, t, IN_ATTRIB);
    }
    inode(hub, obj, IN_MOVE_SELF);
    if let Some((t, nlink)) = target {
        let left = if t.dir { 0 } else { nlink.saturating_sub(1) };
        hub.unlinked(t, to, left);
    }
}

/// `iterate_dir`'s `fsnotify_access` (unless the directory is removed).
pub fn listed(file: &OpenFile) {
    if file.ftype == FileType::Directory
        && let Some(t) = file.notify.get()
        && !t.removed()
    {
        t.event(IN_ACCESS);
    }
}
