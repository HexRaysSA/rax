//! Kernel objects and the process handle table.
//!
//! Objects are reference-counted by the handles that name them (and by
//! internal references such as a thread's own object). Handle values are
//! multiples of 4 allocated lowest-first from 4, and the low two bits of a
//! handle are ignored on lookup (they are tag bits on Windows). The
//! pseudo-handles `GetCurrentProcess()` (-1) and `GetCurrentThread()` (-2)
//! are not table entries; callers resolve them.
//!
//! Named objects share a process-local model of session/global namespaces.
//! Names are case-sensitive; Local aliases the default session namespace,
//! while Global is distinct. Cross-process/private namespaces are unsupported.

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
    /// Granted file sharing mask.
    pub share: u32,
    /// Shared file identity and deferred-deletion lifetime.
    pub lifetime: std::sync::Arc<crate::user::windows::fs::FileLifetime>,
    /// A CreateFile handle to the NUL device.
    pub null: bool,
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
        /// Native signal state (LONG): zero is nonsignaled. NtCreateEvent
        /// retains the low BOOLEAN byte, including noncanonical 2..=255.
        signaled: i32,
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
    access: u32,
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
    if let Some(n) = name.strip_prefix("Global\\") {
        format!("Global\\{n}")
    } else {
        format!("Local\\{}", name.strip_prefix("Local\\").unwrap_or(name))
    }
}

impl Objects {
    /// Creates an object with no references yet.
    pub fn create(&mut self, obj: Object) -> ObjId {
        self.try_create(obj)
            .expect("internal object capacity exhausted")
    }

    /// Creates an unreferenced object, rejecting identifier exhaustion.
    pub fn try_create(&mut self, obj: Object) -> Option<ObjId> {
        let next = self.next.checked_add(1)?;
        self.objs.insert(
            next,
            Entry {
                obj,
                refs: 0,
                name: None,
            },
        );
        self.next = next;
        Some(next)
    }

    /// Creates a named object, or finds the existing object of that name:
    /// `(id, existed)`.
    pub fn create_named(&mut self, name: &str, obj: Object) -> (ObjId, bool) {
        self.try_create_named(name, obj)
            .expect("internal object capacity exhausted")
    }

    /// Fallible named creation. The caller must independently check the
    /// existing object's type and the requested access grant.
    pub fn try_create_named(&mut self, name: &str, obj: Object) -> Option<(ObjId, bool)> {
        let key = name_key(name);
        if let Some(&id) = self.names.get(&key) {
            return Some((id, true));
        }
        let id = self.try_create(obj)?;
        self.objs.get_mut(&id).unwrap().name = Some(key.clone());
        self.names.insert(key, id);
        Some((id, false))
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

    /// Pins a complete wait set transactionally. Multiplicities are counted
    /// before publishing references: O(N) expected time and O(U) space for N
    /// identifiers and U distinct objects.
    pub fn retain_many(&mut self, ids: &[ObjId]) -> Result<(), &'static str> {
        let mut counts = HashMap::<ObjId, u32>::new();
        for &id in ids {
            let n = counts.entry(id).or_default();
            *n = n
                .checked_add(1)
                .ok_or("wait reference multiplicity overflow")?;
        }
        for (&id, &count) in &counts {
            self.objs
                .get(&id)
                .ok_or("wait object disappeared")?
                .refs
                .checked_add(count)
                .ok_or("wait object reference overflow")?;
        }
        for (id, count) in counts {
            self.objs.get_mut(&id).expect("validated wait object").refs += count;
        }
        Ok(())
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
        self.open_access(id, inherit, u32::MAX)
            .expect("internal object handle capacity exhausted")
    }

    /// Opens a handle with an explicit grant. Invalid objects, reference
    /// overflow and handle exhaustion leave the table unchanged. O(H) time
    /// and O(1) extra space for H open handles.
    pub fn open_access(&mut self, id: ObjId, inherit: bool, access: u32) -> Option<u32> {
        let refs = self.objs.get(&id)?.refs.checked_add(1)?;
        let mut h = 4u32;
        for &k in self.handles.keys() {
            if k != h {
                break;
            }
            h = h.checked_add(4)?;
        }
        self.objs.get_mut(&id)?.refs = refs;
        self.handles.insert(
            h,
            HandleEntry {
                obj: id,
                access,
                inherit,
                protect_from_close: false,
            },
        );
        Some(h)
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

    /// The access mask granted to this particular handle.
    pub fn access(&self, handle: u64) -> Option<u32> {
        self.handles.get(&Self::key(handle)?).map(|e| e.access)
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
        self.open_access(id, inherit, self.access(handle)?)
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

    /// Every live object, including internally pinned objects with no handle.
    pub fn iter(&self) -> impl Iterator<Item = (ObjId, &Object)> {
        self.objs.iter().map(|(&k, e)| (k, &e.obj))
    }

    /// Process termination destroys the entire local table, including protected
    /// handles and internally referenced objects. Returned objects let the
    /// caller report final file cleanup failures rather than hiding them.
    pub fn drain(&mut self) -> impl Iterator<Item = Object> + '_ {
        self.handles.clear();
        self.names.clear();
        self.objs.drain().map(|(_, entry)| entry.obj)
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
            signaled: 0,
        });
        let d = o.duplicate(u64::from(h), false).unwrap();
        assert!(o.close(u64::from(h)).unwrap().is_none());
        assert!(matches!(o.get(u64::from(d)), Some(Object::Event { .. })));
        assert!(o.close(u64::from(d)).unwrap().is_some());
    }

    #[test]
    fn names_are_exact_case_and_global_namespace_is_distinct() {
        let mut o = Objects::default();
        let (a, existed) = o.create_named("Local\\MyEvent", Object::Null);
        assert!(!existed);
        let (b, existed) = o.create_named("MyEvent", Object::Null);
        assert!(existed);
        assert_eq!(a, b);
        assert_eq!(o.by_name("myevent"), None);
        let (global, existed) = o.create_named("Global\\MyEvent", Object::Null);
        assert!(!existed);
        assert_ne!(global, a);
        assert_eq!(o.by_name("Global\\MyEvent"), Some(global));
        let h = o.open(a, false);
        o.close(u64::from(h)).unwrap();
        assert_eq!(o.by_name("MyEvent"), None, "the name goes with the object");
        assert_eq!(o.by_name("Global\\MyEvent"), Some(global));
    }

    #[test]
    fn explicit_handle_grants_are_preserved_without_escalation() {
        let mut o = Objects::default();
        assert_eq!(o.open_access(42, false, 0), None);
        let id = o.create(Object::Null);
        let a = o.open_access(id, false, 0x0010_0000).unwrap();
        let b = o.duplicate(u64::from(a), true).unwrap();
        assert_eq!(o.access(u64::from(a) | 3), Some(0x0010_0000));
        assert_eq!(o.access(u64::from(b)), Some(0x0010_0000));
        assert_eq!(o.flags(u64::from(b)), Some(1));
        let c = o.open_access(id, false, 2).unwrap();
        assert_eq!(o.access(u64::from(c)), Some(2));
        assert_eq!(o.access(u64::from(a)), Some(0x0010_0000));
        o.objs.get_mut(&id).unwrap().refs = u32::MAX;
        let before = o.handle_count();
        assert_eq!(o.open_access(id, false, 0), None);
        assert_eq!(o.handle_count(), before);
    }

    #[test]
    fn wait_pins_validate_all_objects_and_multiplicities_before_commit() {
        let mut o = Objects::default();
        let a = o.create(Object::Null);
        let b = o.create(Object::Null);
        o.retain_many(&[a, b, a]).unwrap();
        assert_eq!(o.objs[&a].refs, 2);
        assert_eq!(o.objs[&b].refs, 1);
        assert!(o.retain_many(&[a, 99]).is_err());
        assert_eq!(o.objs[&a].refs, 2);
        o.objs.get_mut(&b).unwrap().refs = u32::MAX;
        assert!(o.retain_many(&[a, b]).is_err());
        assert_eq!(o.objs[&a].refs, 2);
        o.next = u32::MAX;
        assert_eq!(o.try_create(Object::Null), None);
        assert_eq!(o.try_create_named("capacity", Object::Null), None);
        assert_eq!(o.by_name("capacity"), None);
    }

    #[test]
    fn protected_handles_cannot_be_closed() {
        let mut o = Objects::default();
        let h = o.insert(Object::Null);
        assert!(o.set_flags(u64::from(h), 2, 2));
        assert!(o.close(u64::from(h)).is_err());
        assert_eq!(o.flags(u64::from(h)), Some(2));
    }

    #[test]
    fn process_table_drain_removes_protected_handles_names_and_internal_refs() {
        let mut o = Objects::default();
        let (id, _) = o.create_named("drain", Object::Null);
        let handle = o.open(id, false);
        o.retain(id);
        o.set_flags(u64::from(handle), 2, 2);
        assert_eq!(o.drain().count(), 1);
        assert_eq!(o.handle_count(), 0);
        assert!(o.by_name("drain").is_none());
        assert!(o.obj(id).is_none());
    }
}
