//! File-system notification (`fs/notify/`): the events file-system calls
//! generate, and how inotify instances receive them.
//!
//! | Module | Contents |
//! |---|---|
//! | this one | the event bits, what one `fsnotify` call delivers to one instance |
//! | [`queue`] | an instance's event queue: merging, overflow, and `read`'s records |
//! | [`hub`] | the emulated backend: instances and watches every process shares |
//! | [`sys`] | the host calls: shared mappings, FIFOs, locks, the host's inotify |
//!
//! A file-system call reports what it did as one or more [`Hook`]s, the
//! `fsnotify_*` helpers of `include/linux/fsnotify.h`: an event on a file
//! that its parent directory may hear of too (`fsnotify_parent`: opens,
//! reads, writes, closes, attribute changes), an event on an inode alone
//! (`fsnotify_inode`: link-count changes, deletion, moves), or a change to
//! a directory entry (`fsnotify_name`: creation, deletion, moves). Each
//! instance with a watch (a *mark*) on the inode or its parent then
//! receives what `send_to_group` and `fsnotify_handle_event` give it
//! ([`deliver`]).

pub mod hub;
pub mod queue;
pub mod sys;

/// Where inotify instances come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The host's inotify (Linux hosts): what any process does to a file
    /// is reported, as the host kernel sees it.
    Host,
    /// The emulated namespace in this directory (`None`: the host user's
    /// default): what `rax-user` processes do is reported.
    Emulated(Option<std::path::PathBuf>),
}

impl Default for Backend {
    fn default() -> Self {
        if cfg!(target_os = "linux") {
            Backend::Host
        } else {
            Backend::Emulated(None)
        }
    }
}

/// An inotify instance.
#[derive(Debug)]
pub enum Instance {
    /// An instance of the emulated namespace.
    Emulated(hub::Handle),
    /// A host instance (non-blocking), and the stand-in files it watches
    /// for synthesized entries, by guest path.
    Host {
        fd: std::os::fd::OwnedFd,
        stand_ins: std::sync::Mutex<Vec<(String, tempfile_path::TempPath)>>,
    },
}

/// A temporary file removed when dropped.
pub mod tempfile_path {
    /// A path removed when dropped.
    #[derive(Debug)]
    pub struct TempPath(pub std::path::PathBuf);

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// The event bits (`uapi/linux/inotify.h`, `include/linux/fsnotify_backend.h`).
pub mod bits {
    pub const IN_ACCESS: u32 = 0x0000_0001;
    pub const IN_MODIFY: u32 = 0x0000_0002;
    pub const IN_ATTRIB: u32 = 0x0000_0004;
    pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
    pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
    pub const IN_OPEN: u32 = 0x0000_0020;
    pub const IN_MOVED_FROM: u32 = 0x0000_0040;
    pub const IN_MOVED_TO: u32 = 0x0000_0080;
    pub const IN_CREATE: u32 = 0x0000_0100;
    pub const IN_DELETE: u32 = 0x0000_0200;
    pub const IN_DELETE_SELF: u32 = 0x0000_0400;
    pub const IN_MOVE_SELF: u32 = 0x0000_0800;
    /// `FS_OPEN_EXEC`: an open for execution (no inotify bit of its own).
    pub const FS_OPEN_EXEC: u32 = 0x0000_1000;
    pub const IN_UNMOUNT: u32 = 0x0000_2000;
    pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
    pub const IN_IGNORED: u32 = 0x0000_8000;
    pub const IN_ONLYDIR: u32 = 0x0100_0000;
    pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
    pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
    /// `FS_EVENT_ON_CHILD`: a watch on a directory hears of its children;
    /// an event reported to one.
    pub const FS_EVENT_ON_CHILD: u32 = 0x0800_0000;
    pub const IN_MASK_CREATE: u32 = 0x1000_0000;
    pub const IN_MASK_ADD: u32 = 0x2000_0000;
    pub const IN_ISDIR: u32 = 0x4000_0000;
    pub const IN_ONESHOT: u32 = 0x8000_0000;
    pub const IN_ALL_EVENTS: u32 = 0x0000_0FFF;
    pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
    /// `ALL_INOTIFY_BITS`: every bit `inotify_add_watch` takes.
    pub const ALL_INOTIFY_BITS: u32 = IN_ALL_EVENTS
        | IN_UNMOUNT
        | IN_Q_OVERFLOW
        | IN_IGNORED
        | IN_ONLYDIR
        | IN_DONT_FOLLOW
        | IN_EXCL_UNLINK
        | IN_MASK_CREATE
        | IN_MASK_ADD
        | IN_ISDIR
        | IN_ONESHOT;
    /// `ALL_FSNOTIFY_EVENTS` as inotify can see them: the event bits, less
    /// the flags.
    pub const EVENTS: u32 = IN_ALL_EVENTS | FS_OPEN_EXEC | IN_UNMOUNT | IN_Q_OVERFLOW;
    /// `ALL_FSNOTIFY_DIRENT_EVENTS`: the events that name a directory
    /// entry.
    pub const DIRENT: u32 = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    /// `FS_EVENTS_POSS_ON_CHILD`: the events a directory hears of its
    /// children.
    pub const ON_CHILD: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE | IN_OPEN | FS_OPEN_EXEC;
    /// `inotify_mask_to_arg`: the bits `read` reports.
    pub const REPORTED: u32 = IN_ALL_EVENTS | IN_ISDIR | IN_UNMOUNT | IN_IGNORED | IN_Q_OVERFLOW;
}

use bits::*;

/// An inode: its host device and inode numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Key {
    pub dev: u64,
    pub ino: u64,
}

/// The inode an event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Obj {
    pub key: Key,
    /// A directory (`IN_ISDIR`).
    pub dir: bool,
    /// A device, FIFO, or socket (`d_is_special`): its reads and writes
    /// are not its directory's business.
    pub special: bool,
}

/// One `fsnotify` call.
#[derive(Clone, Debug)]
pub enum Hook<'a> {
    /// `fsnotify_parent`: an event on `obj`, which its parent directory
    /// hears of with the entry's name (`None` for the root). `path` marks
    /// the events on an open file (`FSNOTIFY_EVENT_PATH`), `unlinked` one
    /// whose name is gone (`d_unlinked`).
    Parent {
        obj: Obj,
        parent: Option<(Key, &'a [u8])>,
        mask: u32,
        path: bool,
        unlinked: bool,
    },
    /// `fsnotify_inode`: an event on `obj` alone.
    Inode { obj: Obj, mask: u32 },
    /// `fsnotify_name`: a change to entry `name` of directory `dir`.
    Name {
        dir: Key,
        name: &'a [u8],
        mask: u32,
        cookie: u32,
    },
}

/// A watch: its descriptor, `fsnotify` mask (with `IN_UNMOUNT`, and
/// `FS_EVENT_ON_CHILD` on a directory), and flags (`IN_EXCL_UNLINK`,
/// `IN_ONESHOT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    pub wd: i32,
    pub mask: u32,
    pub flags: u32,
}

impl Mark {
    /// `inotify_arg_to_mask` and `inotify_arg_to_flags` for a new watch
    /// on an inode (a directory if `dir`).
    pub fn from_arg(wd: i32, arg: u32, dir: bool) -> Mark {
        Mark {
            wd,
            mask: arg_mask(arg, dir),
            flags: arg & (IN_EXCL_UNLINK | IN_ONESHOT),
        }
    }

    /// `inotify_update_existing_watch`: `arg` replaces the mask and flags,
    /// or with `IN_MASK_ADD` adds to them.
    pub fn update(&mut self, arg: u32, dir: bool) {
        if arg & IN_MASK_ADD == 0 {
            self.mask = 0;
            self.flags = 0;
        }
        self.mask |= arg_mask(arg, dir);
        self.flags |= arg & (IN_EXCL_UNLINK | IN_ONESHOT);
    }

    /// `inotify_mark_user_mask`: the mask `/proc/<pid>/fdinfo` shows.
    pub fn user_mask(&self) -> u32 {
        self.mask & IN_ALL_EVENTS | self.flags
    }
}

/// `inotify_arg_to_mask`.
fn arg_mask(arg: u32, dir: bool) -> u32 {
    IN_UNMOUNT | if dir { FS_EVENT_ON_CHILD } else { 0 } | arg & IN_ALL_EVENTS
}

/// An event for an instance's queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub wd: i32,
    /// The `fsnotify` mask (`FS_EVENT_ON_CHILD` included); `read` reports
    /// [`bits::REPORTED`] of it.
    pub mask: u32,
    pub cookie: u32,
    pub name: Vec<u8>,
}

impl Event {
    /// `IN_IGNORED` for watch `wd`.
    pub fn ignored(wd: i32) -> Event {
        Event {
            wd,
            mask: IN_IGNORED,
            cookie: 0,
            name: Vec::new(),
        }
    }
}

/// What an instance receives from one hook, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Queue this event.
    Queue(Event),
    /// A one-shot watch fired: remove it (queueing its `IN_IGNORED`).
    Remove(i32),
}

/// What [`deliver`] needs to know of every instance's watches: whether
/// any watches the parent directory, and the union of their masks
/// (`i_fsnotify_mask` of the parent).
#[derive(Clone, Copy, Debug, Default)]
pub struct Watched {
    pub parent_mask: u32,
    pub parent_marks: bool,
}

/// `fsnotify_parent`'s decision, the same for every instance: whether
/// the parent hears of the event (`parent_interested`), with the mask
/// `fsnotify` then passes on.
pub fn parent_interest(hook: &Hook<'_>, w: Watched) -> (u32, bool) {
    match *hook {
        Hook::Parent {
            obj,
            parent,
            mask,
            path,
            ..
        } => {
            let mask = if obj.dir { mask | IN_ISDIR } else { mask };
            if parent.is_none() || !w.parent_marks {
                return (mask, false);
            }
            // fsnotify_inode_watches_children.
            let p_mask = if w.parent_mask & FS_EVENT_ON_CHILD != 0 {
                w.parent_mask & ON_CHILD
            } else {
                0
            };
            let interested = mask & p_mask & EVENTS != 0
                && !(path && obj.special && mask & (IN_ACCESS | IN_MODIFY) != 0);
            if interested {
                (mask | FS_EVENT_ON_CHILD, true)
            } else {
                (mask, false)
            }
        }
        Hook::Inode { obj, mask } => (if obj.dir { mask | IN_ISDIR } else { mask }, false),
        Hook::Name { mask, .. } => (mask, false),
    }
}

/// `send_to_group`, `fsnotify_handle_event`, and
/// `inotify_handle_inode_event` for one instance: what it receives, given
/// its mark on the event's inode (for a [`Hook::Name`], the directory) and
/// on the parent directory. `mask` and `interested` are
/// [`parent_interest`]'s.
pub fn deliver(
    hook: &Hook<'_>,
    mask: u32,
    interested: bool,
    inode: Option<Mark>,
    parent: Option<Mark>,
) -> Vec<Action> {
    let parent = if interested { parent } else { None };
    let (unlinked, name, cookie) = match *hook {
        Hook::Parent {
            path,
            unlinked,
            parent,
            ..
        } => (path && unlinked, parent.map(|p| p.1), 0),
        Hook::Inode { .. } => (false, None, 0),
        Hook::Name { name, cookie, .. } => (false, Some(name), cookie),
    };
    let union = inode.map_or(0, |m| m.mask) | parent.map_or(0, |m| m.mask);
    let mut out = Vec::new();
    if mask & EVENTS & union == 0 {
        return out;
    }
    let mut handle = |m: Mark, mask: u32, name: Option<&[u8]>, cookie: u32| {
        if m.flags & IN_EXCL_UNLINK != 0 && unlinked {
            return;
        }
        if mask & m.mask & EVENTS == 0 {
            return;
        }
        let mask = if mask & (IN_MOVE_SELF | IN_DELETE_SELF) != 0 {
            mask & !IN_ISDIR
        } else {
            mask
        };
        out.push(Action::Queue(Event {
            wd: m.wd,
            mask,
            cookie,
            name: name.map(<[u8]>::to_vec).unwrap_or_default(),
        }));
        if m.flags & IN_ONESHOT != 0 {
            out.push(Action::Remove(m.wd));
        }
    };
    if let Some(p) = parent {
        handle(p, mask, name, 0);
    }
    if let Some(m) = inode {
        let mask = mask & !FS_EVENT_ON_CHILD;
        let name = if mask & DIRENT != 0 { name } else { None };
        handle(m, mask, name, cookie);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: Obj = Obj {
        key: Key { dev: 1, ino: 10 },
        dir: false,
        special: false,
    };
    const DIR: Key = Key { dev: 1, ino: 2 };

    fn run(hook: &Hook<'_>, inode: Option<Mark>, parent: Option<Mark>) -> Vec<Action> {
        let w = Watched {
            parent_mask: parent.map_or(0, |m| m.mask),
            parent_marks: parent.is_some(),
        };
        let (mask, interested) = parent_interest(hook, w);
        deliver(hook, mask, interested, inode, parent)
    }

    fn q(wd: i32, mask: u32, name: &[u8], cookie: u32) -> Action {
        Action::Queue(Event {
            wd,
            mask,
            cookie,
            name: name.to_vec(),
        })
    }

    #[test]
    fn marks_follow_inotify_arg_to_mask() {
        let mut m = Mark::from_arg(1, IN_MODIFY | IN_ONESHOT | IN_ISDIR, true);
        assert_eq!(m.mask, IN_UNMOUNT | FS_EVENT_ON_CHILD | IN_MODIFY);
        assert_eq!(m.user_mask(), IN_MODIFY | IN_ONESHOT);
        m.update(IN_OPEN | IN_MASK_ADD | IN_EXCL_UNLINK, true);
        assert_eq!(
            m.user_mask(),
            IN_MODIFY | IN_OPEN | IN_ONESHOT | IN_EXCL_UNLINK
        );
        m.update(IN_ACCESS, true);
        assert_eq!(m.user_mask(), IN_ACCESS);
        assert_eq!(
            Mark::from_arg(2, IN_ALL_EVENTS, false).mask,
            IN_UNMOUNT | IN_ALL_EVENTS
        );
    }

    #[test]
    fn a_parent_hears_of_its_children() {
        let dir = Mark::from_arg(1, IN_ALL_EVENTS, true);
        let file = Mark::from_arg(2, IN_ALL_EVENTS, false);
        let open = Hook::Parent {
            obj: FILE,
            parent: Some((DIR, b"f")),
            mask: IN_OPEN,
            path: true,
            unlinked: false,
        };
        // The directory with the name first, then the file itself.
        assert_eq!(
            run(&open, Some(file), Some(dir)),
            [
                q(1, IN_OPEN | FS_EVENT_ON_CHILD, b"f", 0),
                q(2, IN_OPEN, b"", 0)
            ]
        );
        assert_eq!(
            run(&open, None, Some(dir)),
            [q(1, IN_OPEN | FS_EVENT_ON_CHILD, b"f", 0)]
        );
        // A directory that does not want the event.
        let dir_attrib = Mark::from_arg(1, IN_ATTRIB, true);
        assert_eq!(
            run(&open, Some(file), Some(dir_attrib)),
            [q(2, IN_OPEN, b"", 0)]
        );
        // A subdirectory: IN_ISDIR for both.
        let sub = Hook::Parent {
            obj: Obj { dir: true, ..FILE },
            parent: Some((DIR, b"d")),
            mask: IN_OPEN,
            path: true,
            unlinked: false,
        };
        assert_eq!(
            run(&sub, Some(Mark::from_arg(2, IN_OPEN, true)), Some(dir)),
            [
                q(1, IN_OPEN | IN_ISDIR | FS_EVENT_ON_CHILD, b"d", 0),
                q(2, IN_OPEN | IN_ISDIR, b"", 0)
            ]
        );
    }

    #[test]
    fn special_files_keep_reads_and_writes_from_their_directory() {
        let dir = Mark::from_arg(1, IN_ALL_EVENTS, true);
        let fifo = Obj {
            special: true,
            ..FILE
        };
        let hook = |mask, path| Hook::Parent {
            obj: fifo,
            parent: Some((DIR, b"p")),
            mask,
            path,
            unlinked: false,
        };
        assert!(run(&hook(IN_MODIFY, true), None, Some(dir)).is_empty());
        assert!(run(&hook(IN_ACCESS, true), None, Some(dir)).is_empty());
        assert_eq!(run(&hook(IN_OPEN, true), None, Some(dir)).len(), 1);
        // A truncation reports a dentry, not a path.
        assert_eq!(run(&hook(IN_MODIFY, false), None, Some(dir)).len(), 1);
    }

    #[test]
    fn excl_unlink_skips_unlinked_files() {
        let dir = Mark::from_arg(1, IN_ALL_EVENTS | IN_EXCL_UNLINK, true);
        let file = Mark::from_arg(2, IN_ALL_EVENTS | IN_EXCL_UNLINK, false);
        let hook = |path| Hook::Parent {
            obj: FILE,
            parent: Some((DIR, b"f")),
            mask: IN_MODIFY,
            path,
            unlinked: true,
        };
        assert!(run(&hook(true), Some(file), Some(dir)).is_empty());
        assert_eq!(run(&hook(false), Some(file), Some(dir)).len(), 2);
        let plain = Mark::from_arg(2, IN_ALL_EVENTS, false);
        assert_eq!(
            run(&hook(true), Some(plain), Some(dir)),
            [q(2, IN_MODIFY, b"", 0)]
        );
    }

    #[test]
    fn names_self_events_and_one_shot_watches() {
        let dir = Mark::from_arg(1, IN_ALL_EVENTS, true);
        let create = Hook::Name {
            dir: DIR,
            name: b"n",
            mask: IN_MOVED_TO | IN_ISDIR,
            cookie: 7,
        };
        assert_eq!(
            run(&create, Some(dir), None),
            [q(1, IN_MOVED_TO | IN_ISDIR, b"n", 7)]
        );
        // DELETE_SELF and MOVE_SELF never carry IN_ISDIR.
        let gone = Hook::Inode {
            obj: Obj { dir: true, ..FILE },
            mask: IN_DELETE_SELF,
        };
        assert_eq!(
            run(&gone, Some(Mark::from_arg(3, IN_DELETE_SELF, true)), None),
            [q(3, IN_DELETE_SELF, b"", 0)]
        );
        // A one-shot watch goes after its event; one on the parent before
        // the child's event.
        let once_dir = Mark::from_arg(1, IN_CLOSE | IN_ONESHOT, true);
        let once_file = Mark::from_arg(2, IN_CLOSE | IN_ONESHOT, false);
        let close = Hook::Parent {
            obj: FILE,
            parent: Some((DIR, b"f")),
            mask: IN_CLOSE_WRITE,
            path: true,
            unlinked: false,
        };
        assert_eq!(
            run(&close, Some(once_file), Some(once_dir)),
            [
                q(1, IN_CLOSE_WRITE | FS_EVENT_ON_CHILD, b"f", 0),
                Action::Remove(1),
                q(2, IN_CLOSE_WRITE, b"", 0),
                Action::Remove(2),
            ]
        );
        // Link-count changes reach only the inode.
        let attrib = Hook::Inode {
            obj: FILE,
            mask: IN_ATTRIB,
        };
        assert!(run(&attrib, None, Some(dir)).is_empty());
    }
}
