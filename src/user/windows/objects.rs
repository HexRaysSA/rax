//! Kernel objects and the process handle table.
//!
//! Objects are reference-counted by the handles that name them (and by
//! internal references such as a thread's own object). Handle values are
//! multiples of 4 allocated lowest-first from 4, and the low two bits of a
//! handle are ignored on lookup (they are tag bits on Windows). The
//! pseudo-handles `GetCurrentProcess()` (-1) and `GetCurrentThread()` (-2)
//! are not table entries; callers resolve them.
//!
//! Named objects share one namespace per process; names compare
//! case-insensitively, and the `Global\`/`Local\` session prefixes are
//! accepted and ignored.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Instant;

/// An object identifier.
pub type ObjId = u32;

/// `GetCurrentProcess()`.
pub const CURRENT_PROCESS: u64 = u64::MAX;
/// `GetCurrentThread()`.
pub const CURRENT_THREAD: u64 = u64::MAX - 1;

/// Which host standard stream a console handle uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdStream {
    /// Standard input.
    In,
    /// Standard output.
    Out,
    /// Standard error.
    Err,
}

/// An open file.
#[derive(Debug)]
pub struct FileObj {
    /// The host file (`None` for a directory handle).
    pub host: Option<std::fs::File>,
    /// Host path.
    pub host_path: PathBuf,
    /// Windows path.
    pub path: String,
    /// Granted `GENERIC_*`/`FILE_*` access mask.
    pub access: u32,
    /// Opened with `FILE_APPEND_DATA` only: writes go to the end.
    pub append: bool,
    /// `FILE_FLAG_DELETE_ON_CLOSE`.
    pub delete_on_close: bool,
    /// A directory handle.
    pub directory: bool,
    /// `FILE_FLAG_OVERLAPPED`.
    pub overlapped: bool,
}

/// A kernel object.
#[derive(Debug)]
pub enum Object {
    /// A file or directory.
    File(FileObj),
    /// A console standard stream (the host's stdin, stdout, or stderr).
    Console(StdStream),
    /// The `NUL` device.
    Null,
    /// An event.
    Event {
        /// Manual-reset.
        manual: bool,
        /// Signaled.
        signaled: bool,
    },
    /// A mutex (mutant).
    Mutex {
        /// Owning thread.
        owner: Option<u32>,
        /// Recursion count.
        count: u32,
        /// The owner ended without releasing it.
        abandoned: bool,
    },
    /// A semaphore.
    Semaphore {
        /// Current count.
        count: i32,
        /// Maximum count.
        max: i32,
    },
    /// A thread.
    Thread {
        /// Thread id.
        tid: u32,
        /// Exit code once it has ended.
        exit_code: Option<u32>,
    },
    /// A process.
    Process {
        /// Process id.
        pid: u32,
        /// Exit code once it has ended.
        exit_code: Option<u32>,
    },
    /// A waitable timer.
    Timer {
        /// Manual-reset (notification) timer.
        manual: bool,
        /// Signaled.
        signaled: bool,
        /// When it next fires.
        due: Option<Instant>,
        /// Period in milliseconds (0 = one-shot).
        period_ms: u32,
    },
    /// A file mapping (section).
    Mapping {
        /// Backing file, if any.
        file: Option<ObjId>,
        /// Maximum size in bytes.
        size: u64,
        /// Page protection.
        protect: u32,
        /// Contents of a pagefile-backed mapping, shared by its views.
        shared: Option<std::sync::Arc<crate::user::mm::SharedObject>>,
    },
    /// An anonymous pipe end.
    Pipe {
        /// Shared buffer id.
        pipe: u32,
        /// The write end.
        write: bool,
    },
    /// An I/O completion port.
    CompletionPort {
        /// Queued packets: (bytes, key, overlapped).
        queue: std::collections::VecDeque<(u32, u64, u64)>,
    },
    /// An object this implementation only needs to name (tokens,
    /// registry keys, window stations).
    Opaque(&'static str),
}

impl Object {
    /// The object type name `NtQueryObject` reports.
    pub fn type_name(&self) -> &'static str {
        match self {
            Object::File(_) | Object::Console(_) | Object::Null => "File",
            Object::Event { .. } => "Event",
            Object::Mutex { .. } => "Mutant",
            Object::Semaphore { .. } => "Semaphore",
            Object::Thread { .. } => "Thread",
            Object::Process { .. } => "Process",
            Object::Timer { .. } => "Timer",
            Object::Mapping { .. } => "Section",
            Object::Pipe { .. } => "File",
            Object::CompletionPort { .. } => "IoCompletion",
            Object::Opaque(t) => t,
        }
    }
}

#[derive(Debug)]
struct Entry {
    obj: Object,
    refs: u32,
    name: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct HandleEntry {
    obj: ObjId,
    inherit: bool,
    protect_from_close: bool,
}

/// Objects and handles.
#[derive(Debug, Default)]
pub struct Objects {
    objs: HashMap<ObjId, Entry>,
    next: ObjId,
    handles: BTreeMap<u32, HandleEntry>,
    names: HashMap<String, ObjId>,
}

fn name_key(name: &str) -> String {
    let n = name
        .strip_prefix("Global\\")
        .or_else(|| name.strip_prefix("Local\\"))
        .unwrap_or(name);
    n.to_uppercase()
}

impl Objects {
    /// Creates an object with no references yet.
    pub fn create(&mut self, obj: Object) -> ObjId {
        self.next += 1;
        self.objs.insert(
            self.next,
            Entry {
                obj,
                refs: 0,
                name: None,
            },
        );
        self.next
    }

    /// Creates a named object, or finds the existing object of that name:
    /// `(id, existed)`.
    pub fn create_named(&mut self, name: &str, obj: Object) -> (ObjId, bool) {
        let key = name_key(name);
        if let Some(&id) = self.names.get(&key) {
            return (id, true);
        }
        let id = self.create(obj);
        self.objs.get_mut(&id).unwrap().name = Some(key.clone());
        self.names.insert(key, id);
        (id, false)
    }

    /// The object named `name`.
    pub fn by_name(&self, name: &str) -> Option<ObjId> {
        self.names.get(&name_key(name)).copied()
    }

    /// Adds an internal reference.
    pub fn retain(&mut self, id: ObjId) {
        if let Some(e) = self.objs.get_mut(&id) {
            e.refs += 1;
        }
    }

    /// Drops a reference; the object is destroyed at zero. Returns the
    /// destroyed object.
    pub fn release(&mut self, id: ObjId) -> Option<Object> {
        let e = self.objs.get_mut(&id)?;
        e.refs = e.refs.saturating_sub(1);
        if e.refs > 0 {
            return None;
        }
        let e = self.objs.remove(&id)?;
        if let Some(n) = &e.name {
            self.names.remove(n);
        }
        Some(e.obj)
    }

    /// Opens a handle to `id`.
    pub fn open(&mut self, id: ObjId, inherit: bool) -> u32 {
        let mut h = 4u32;
        for &k in self.handles.keys() {
            if k != h {
                break;
            }
            h += 4;
        }
        self.retain(id);
        self.handles.insert(
            h,
            HandleEntry {
                obj: id,
                inherit,
                protect_from_close: false,
            },
        );
        h
    }

    /// Creates an object and opens a handle to it.
    pub fn insert(&mut self, obj: Object) -> u32 {
        let id = self.create(obj);
        self.open(id, false)
    }

    fn key(handle: u64) -> Option<u32> {
        u32::try_from(handle & !3).ok().filter(|&h| h != 0)
    }

    /// The object a handle names.
    pub fn id(&self, handle: u64) -> Option<ObjId> {
        self.handles.get(&Self::key(handle)?).map(|e| e.obj)
    }

    /// The object behind a handle.
    pub fn get(&self, handle: u64) -> Option<&Object> {
        let id = self.id(handle)?;
        self.objs.get(&id).map(|e| &e.obj)
    }

    /// Mutable access to the object behind a handle.
    pub fn get_mut(&mut self, handle: u64) -> Option<&mut Object> {
        let id = self.id(handle)?;
        self.objs.get_mut(&id).map(|e| &mut e.obj)
    }

    /// An object by id.
    pub fn obj(&self, id: ObjId) -> Option<&Object> {
        self.objs.get(&id).map(|e| &e.obj)
    }

    /// Mutable access to an object by id.
    pub fn obj_mut(&mut self, id: ObjId) -> Option<&mut Object> {
        self.objs.get_mut(&id).map(|e| &mut e.obj)
    }

    /// Closes a handle. `Err(())` for an invalid or protected handle.
    /// Returns the object if this was its last reference.
    pub fn close(&mut self, handle: u64) -> Result<Option<Object>, ()> {
        let key = Self::key(handle).ok_or(())?;
        let e = *self.handles.get(&key).ok_or(())?;
        if e.protect_from_close {
            return Err(());
        }
        self.handles.remove(&key);
        Ok(self.release(e.obj))
    }

    /// Duplicates a handle within the process.
    pub fn duplicate(&mut self, handle: u64, inherit: bool) -> Option<u32> {
        let id = self.id(handle)?;
        Some(self.open(id, inherit))
    }

    /// `HANDLE_FLAG_INHERIT` and `HANDLE_FLAG_PROTECT_FROM_CLOSE` of a
    /// handle.
    pub fn flags(&self, handle: u64) -> Option<u32> {
        let e = self.handles.get(&Self::key(handle)?)?;
        Some(u32::from(e.inherit) | u32::from(e.protect_from_close) << 1)
    }

    /// Changes a handle's flags under `mask`.
    pub fn set_flags(&mut self, handle: u64, mask: u32, flags: u32) -> bool {
        let Some(key) = Self::key(handle) else {
            return false;
        };
        let Some(e) = self.handles.get_mut(&key) else {
            return false;
        };
        if mask & 1 != 0 {
            e.inherit = flags & 1 != 0;
        }
        if mask & 2 != 0 {
            e.protect_from_close = flags & 2 != 0;
        }
        true
    }

    /// Number of open handles (`GetProcessHandleCount`).
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// Every object id with its object (for the scheduler's timers).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (ObjId, &mut Object)> {
        self.objs.iter_mut().map(|(&k, e)| (k, &mut e.obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_lowest_free_multiples_of_four_and_ignore_tag_bits() {
        let mut o = Objects::default();
        let a = o.insert(Object::Null);
        let b = o.insert(Object::Null);
        assert_eq!((a, b), (4, 8));
        assert!(o.get(u64::from(a) | 3).is_some(), "tag bits ignored");
        o.close(u64::from(a)).unwrap();
        assert_eq!(o.insert(Object::Null), 4, "lowest free value reused");
        assert!(o.close(0x1000).is_err());
        assert!(o.get(0).is_none());
    }

    #[test]
    fn objects_live_until_their_last_handle_closes() {
        let mut o = Objects::default();
        let h = o.insert(Object::Event {
            manual: true,
            signaled: false,
        });
        let d = o.duplicate(u64::from(h), false).unwrap();
        assert!(o.close(u64::from(h)).unwrap().is_none());
        assert!(matches!(o.get(u64::from(d)), Some(Object::Event { .. })));
        assert!(o.close(u64::from(d)).unwrap().is_some());
    }

    #[test]
    fn named_objects_are_shared_case_insensitively() {
        let mut o = Objects::default();
        let (a, existed) = o.create_named("Local\\MyEvent", Object::Null);
        assert!(!existed);
        let (b, existed) = o.create_named("myevent", Object::Null);
        assert!(existed);
        assert_eq!(a, b);
        let h = o.open(a, false);
        o.close(u64::from(h)).unwrap();
        assert_eq!(o.by_name("MYEVENT"), None, "the name goes with the object");
    }

    #[test]
    fn protected_handles_cannot_be_closed() {
        let mut o = Objects::default();
        let h = o.insert(Object::Null);
        assert!(o.set_flags(u64::from(h), 2, 2));
        assert!(o.close(u64::from(h)).is_err());
        assert_eq!(o.flags(u64::from(h)), Some(2));
    }
}
