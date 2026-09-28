//! Mach ports, rights, and a task's port name space.
//!
//! A [`Port`] is a kernel message queue; a task holds rights to ports under
//! names in its [`IpcSpace`]. The rules are XNU's (`osfmk/ipc/`):
//!
//! - A name is `(index << 8) | generation`. A fresh space hands out indices
//!   in ascending order with generation byte `0x03` (`IE_BITS_GEN_INIT`
//!   rolled over by `ipc_entry_next_gen`); a freed entry goes to the head of
//!   the free list and its next name's generation byte grows by 4.
//! - Send and receive rights to one port share one name in a space (with a
//!   user-reference count for the send right); each send-once right has a
//!   name of its own.
//! - When a port's receive right is destroyed, the port dies and every send
//!   right to it becomes a dead name.
//!
//! Every task of the emulator lives in its own host process, so a space
//! only ever names ports of its own process.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::kr::{self, KernReturn};
use super::msg::Message;

/// A port name.
pub type PortName = u32;

/// `MACH_PORT_NULL`.
pub const MACH_PORT_NULL: PortName = 0;
/// `MACH_PORT_DEAD`.
pub const MACH_PORT_DEAD: PortName = !0;

/// `MACH_PORT_RIGHT_*`.
pub mod right {
    /// `MACH_PORT_RIGHT_SEND`.
    pub const SEND: u32 = 0;
    /// `MACH_PORT_RIGHT_RECEIVE`.
    pub const RECEIVE: u32 = 1;
    /// `MACH_PORT_RIGHT_SEND_ONCE`.
    pub const SEND_ONCE: u32 = 2;
    /// `MACH_PORT_RIGHT_PORT_SET`.
    pub const PORT_SET: u32 = 3;
    /// `MACH_PORT_RIGHT_DEAD_NAME`.
    pub const DEAD_NAME: u32 = 4;
}

/// `MACH_PORT_TYPE_*` bits (`MACH_PORT_TYPE(right) = 1 << (right + 16)`).
pub mod ptype {
    /// `MACH_PORT_TYPE_SEND`.
    pub const SEND: u32 = 1 << 16;
    /// `MACH_PORT_TYPE_RECEIVE`.
    pub const RECEIVE: u32 = 1 << 17;
    /// `MACH_PORT_TYPE_SEND_ONCE`.
    pub const SEND_ONCE: u32 = 1 << 18;
    /// `MACH_PORT_TYPE_PORT_SET`.
    pub const PORT_SET: u32 = 1 << 19;
    /// `MACH_PORT_TYPE_DEAD_NAME`.
    pub const DEAD_NAME: u32 = 1 << 20;
    /// `MACH_PORT_TYPE_DNREQUEST`: a dead-name request is registered.
    pub const DNREQUEST: u32 = 0x8000_0000;
}

/// `MACH_MSG_TYPE_*` dispositions: how a right is copied in from a space.
pub mod disp {
    /// `MACH_MSG_TYPE_MOVE_RECEIVE`.
    pub const MOVE_RECEIVE: u32 = 16;
    /// `MACH_MSG_TYPE_MOVE_SEND`.
    pub const MOVE_SEND: u32 = 17;
    /// `MACH_MSG_TYPE_MOVE_SEND_ONCE`.
    pub const MOVE_SEND_ONCE: u32 = 18;
    /// `MACH_MSG_TYPE_COPY_SEND`.
    pub const COPY_SEND: u32 = 19;
    /// `MACH_MSG_TYPE_MAKE_SEND`.
    pub const MAKE_SEND: u32 = 20;
    /// `MACH_MSG_TYPE_MAKE_SEND_ONCE`.
    pub const MAKE_SEND_ONCE: u32 = 21;

    /// `MACH_MSG_TYPE_PORT_ANY_RIGHT`.
    pub fn is_port_right(d: u32) -> bool {
        (MOVE_RECEIVE..=MAKE_SEND_ONCE).contains(&d)
    }

    /// `ipc_object_copyin_type`: the right a disposition yields
    /// (`MACH_MSG_TYPE_PORT_*`, numerically the `MOVE_*` values).
    pub fn copyin_type(d: u32) -> u32 {
        match d {
            MOVE_RECEIVE => MOVE_RECEIVE,
            MOVE_SEND | COPY_SEND | MAKE_SEND => MOVE_SEND,
            MOVE_SEND_ONCE | MAKE_SEND_ONCE => MOVE_SEND_ONCE,
            _ => 0,
        }
    }
}

/// `MACH_PORT_UREFS_MAX`.
pub const UREFS_MAX: u32 = 0xffff;

/// The kernel object a port stands for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KObject {
    /// An ordinary port whose receive right a task holds.
    None,
    /// The task (its control port).
    Task,
    /// The task's name port (`TASK_NAME_PORT`).
    TaskName,
    /// The task's read port (`TASK_READ_PORT`).
    TaskRead,
    /// The task's inspect port (`TASK_INSPECT_PORT`).
    TaskInspect,
    /// A thread (its control port), by thread ID.
    Thread(u64),
    /// The host name port.
    Host,
    /// The host privileged port.
    HostPriv,
    /// A semaphore.
    Semaphore(Arc<super::sync::Semaphore>),
    /// A Mach timer (`mk_timer_create`), by timer number. A timer's port
    /// is a labelled user port, not a kernel object's: messages to it
    /// queue like any others.
    Timer(u64),
    /// A clock (`host_get_clock_service`).
    Clock(u32),
    /// A voucher, by its attribute values.
    Voucher(Arc<super::voucher::Attrs>),
    /// A task identity token (`task_create_identity_token`), by the
    /// identity of its task's control port.
    TaskIdToken(u64),
    /// A proxy of a host send or send-once right: messages to it are sent
    /// on the host ([`crate::user::darwin::bridge`]). It is a message
    /// queue's, not a kernel object's, as the guest sees it.
    Proxy(Arc<crate::user::darwin::bridge::HostRight>),
}

static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(1);

/// A port's mutable state.
#[derive(Debug, Default)]
pub struct PortState {
    /// Whether the port is dead (its receive right was destroyed).
    pub dead: bool,
    /// Queued messages.
    pub queue: VecDeque<Message>,
    /// The queue limit (`mach_port_limits.mpl_qlimit`).
    pub qlimit: u32,
    /// The receive sequence number.
    pub seqno: u32,
    /// The make-send count.
    pub mscount: u32,
    /// Send rights outstanding (held in spaces or in transit).
    pub srights: u32,
    /// Send-once rights outstanding.
    pub sorights: u32,
    /// The receive right's context (`ip_context`), which is also the guard
    /// of a guarded port.
    pub context: u64,
    /// The port set the receive right belongs to (by set identity).
    pub pset: Option<u64>,
    /// `MACH_NOTIFY_NO_SENDERS` request: the send-once notify port.
    pub no_senders: Option<Arc<Port>>,
    /// `MACH_NOTIFY_PORT_DESTROYED` request: the send-once notify port.
    pub pd_request: Option<Arc<Port>>,
    /// Armed `MACH_NOTIFY_SEND_POSSIBLE` requests: the requesting name
    /// and its send-once notify port.
    pub sp_requests: Vec<(PortName, Arc<Port>)>,
    /// Status flags (`MACH_PORT_STATUS_FLAG_*`, see [`status`]).
    pub flags: u32,
    /// The host port the receive right moved to (sent to a host service):
    /// messages to the port go there
    /// ([`crate::user::darwin::bridge`]).
    pub host: Option<Arc<crate::user::darwin::bridge::HostRight>>,
}

impl PortState {
    /// Whether the receive right is guarded (`ip_guarded`).
    pub fn guarded(&self) -> bool {
        self.flags & status::GUARDED != 0
    }

    /// Whether the guard is strict (`ip_strict_guard`).
    pub fn strict_guard(&self) -> bool {
        self.flags & status::STRICT_GUARD != 0
    }

    /// Whether the receive right may not move (`IO_STATE_IN_SPACE_IMMOVABLE`).
    pub fn immovable_receive(&self) -> bool {
        self.flags & status::GUARD_IMMOVABLE_RECEIVE != 0
    }

    /// Removes the guard (`ipc_port_mark_in_limbo`, `mach_port_unguard`).
    pub fn unguard(&mut self) {
        self.context = 0;
        self.flags &= !(status::GUARDED | status::STRICT_GUARD | status::GUARD_IMMOVABLE_RECEIVE);
    }
}

/// `MACH_PORT_STATUS_FLAG_*`: port status bits `mach_port_get_attributes`
/// reports.
pub mod status {
    /// `MACH_PORT_STATUS_FLAG_GUARDED`.
    pub const GUARDED: u32 = 0x02;
    /// `MACH_PORT_STATUS_FLAG_STRICT_GUARD`.
    pub const STRICT_GUARD: u32 = 0x04;
    /// `MACH_PORT_STATUS_FLAG_IMP_DONATION`.
    pub const IMP_DONATION: u32 = 0x08;
    /// `MACH_PORT_STATUS_FLAG_TEMPOWNER`.
    pub const TEMPOWNER: u32 = 0x20;
    /// `MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE`.
    pub const GUARD_IMMOVABLE_RECEIVE: u32 = 0x40;
}

/// `MACH_PORT_QLIMIT_DEFAULT`.
pub const QLIMIT_DEFAULT: u32 = 5;
/// `MACH_PORT_QLIMIT_KERNEL`.
pub const QLIMIT_KERNEL: u32 = 65_534;

/// A port.
#[derive(Debug)]
pub struct Port {
    /// A process-unique identity (never reused).
    pub id: u64,
    /// The kernel object.
    pub kobject: KObject,
    /// Mutable state.
    pub state: Mutex<PortState>,
}

impl Port {
    /// A new port for `kobject`.
    pub fn new(kobject: KObject) -> Arc<Self> {
        let qlimit = if matches!(kobject, KObject::None | KObject::Timer(_)) {
            QLIMIT_DEFAULT
        } else {
            QLIMIT_KERNEL
        };
        Arc::new(Port {
            id: NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed),
            kobject,
            state: Mutex::new(PortState {
                qlimit,
                ..Default::default()
            }),
        })
    }

    /// Whether the kernel receives this port's messages.
    pub fn is_kernel(&self) -> bool {
        !matches!(
            self.kobject,
            KObject::None | KObject::Timer(_) | KObject::Proxy(_)
        )
    }

    /// Whether the port is dead.
    pub fn is_dead(&self) -> bool {
        self.state.lock().unwrap().dead
    }

    /// Whether its send rights may move (`ipc_should_mark_immovable_send`
    /// for the caller's own ports): the task read and inspect ports' may
    /// not (their kernel objects lack `iko_op_movable_send`), nor may they
    /// be stashed where another task could get them
    /// (`ipc_can_stash_naked_send`).
    pub fn movable_send(&self) -> bool {
        !matches!(self.kobject, KObject::TaskRead | KObject::TaskInspect)
    }
}

/// A port set.
#[derive(Debug)]
pub struct PortSet {
    /// A process-unique identity.
    pub id: u64,
    /// Member ports.
    pub members: Mutex<Vec<Arc<Port>>>,
}

impl PortSet {
    /// A new, empty set.
    pub fn new() -> Arc<Self> {
        Arc::new(PortSet {
            id: NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed),
            members: Mutex::new(Vec::new()),
        })
    }
}

/// What an entry names.
#[derive(Clone, Debug)]
pub enum Object {
    /// A port.
    Port(Arc<Port>),
    /// A port set.
    Set(Arc<PortSet>),
}

/// One name's rights.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The generation byte of the entry's current name.
    pub generation: u8,
    /// The object, `None` when the entry is free.
    pub object: Option<Object>,
    /// Send right user references.
    pub send: u32,
    /// Whether the entry holds the receive right.
    pub receive: bool,
    /// Whether the entry is a send-once right.
    pub send_once: bool,
    /// Dead-name user references.
    pub dead: u32,
    /// A dead-name (or send-possible) request on the name: the send-once
    /// right to notify (`ie_request`).
    pub request: Option<Arc<Port>>,
}

impl Entry {
    fn free(generation: u8) -> Self {
        Entry {
            generation,
            object: None,
            send: 0,
            receive: false,
            send_once: false,
            dead: 0,
            request: None,
        }
    }

    /// `MACH_PORT_TYPE_*` of the entry.
    pub fn port_type(&self) -> u32 {
        let mut t = 0;
        if self.send > 0 {
            t |= ptype::SEND;
        }
        if self.receive {
            t |= ptype::RECEIVE;
        }
        if self.send_once {
            t |= ptype::SEND_ONCE;
        }
        if self.dead > 0 {
            t |= ptype::DEAD_NAME;
        }
        if matches!(self.object, Some(Object::Set(_))) {
            t |= ptype::PORT_SET;
        }
        if self.request.is_some() {
            t |= ptype::DNREQUEST;
        }
        t
    }

    /// The port, if the entry names one.
    pub fn port(&self) -> Option<&Arc<Port>> {
        match &self.object {
            Some(Object::Port(p)) => Some(p),
            _ => None,
        }
    }
}

/// A right in transit (in a message or being inserted).
#[derive(Clone, Debug)]
pub enum Right {
    /// A send right.
    Send(Arc<Port>),
    /// A send-once right.
    SendOnce(Arc<Port>),
    /// A receive right.
    Receive(Arc<Port>),
    /// A dead right (`IP_DEAD`): copied in from a dead name.
    Dead,
}

impl Right {
    /// The port the right names (`None` for a dead right).
    pub fn port(&self) -> Option<&Arc<Port>> {
        match self {
            Right::Send(p) | Right::SendOnce(p) | Right::Receive(p) => Some(p),
            Right::Dead => None,
        }
    }
}

/// A task's port name space.
#[derive(Debug, Default)]
pub struct IpcSpace {
    /// Entries by index (index 0 is never used).
    entries: Vec<Entry>,
    /// Free indices; the last is the next to be claimed.
    free: Vec<u32>,
    /// The index naming each port the space holds send or receive rights
    /// to.
    by_port: HashMap<u64, u32>,
    /// Notifications owed by changes to the space, for the caller to send.
    pub notices: Vec<Notice>,
}

/// A notification a space change owes (sent by the IPC layer, which can
/// deliver messages).
#[derive(Debug)]
pub enum Notice {
    /// `MACH_NOTIFY_DEAD_NAME`: the port `name` named died.
    DeadName(PortName, Arc<Port>),
    /// `MACH_NOTIFY_PORT_DELETED`: `name` went away with a request on it.
    PortDeleted(PortName, Arc<Port>),
}

/// Indices a fresh table has before it grows.
const INITIAL_ENTRIES: u32 = 64;

impl IpcSpace {
    /// An empty space.
    pub fn new() -> Self {
        let mut s = IpcSpace::default();
        s.entries.push(Entry::free(0));
        s.grow(INITIAL_ENTRIES);
        s
    }

    fn grow(&mut self, to: u32) {
        let from = self.entries.len() as u32;
        for _ in from..to {
            // IE_BITS_GEN_INIT: the first claim rolls over to 0x03.
            self.entries.push(Entry::free(0xff));
        }
        // Ascending claim order: the lowest new index on top.
        let mut new: Vec<u32> = (from..to).rev().collect();
        new.extend(std::mem::take(&mut self.free));
        self.free = new;
    }

    fn name(index: u32, generation: u8) -> PortName {
        (index << 8) | u32::from(generation)
    }

    fn index(name: PortName) -> u32 {
        name >> 8
    }

    /// `ipc_entry_claim`: a new entry and its name.
    fn claim(&mut self) -> Result<u32, KernReturn> {
        if self.free.is_empty() {
            let len = self.entries.len() as u32;
            if len >= 0x00ff_ffff {
                return Err(kr::KERN_NO_SPACE);
            }
            self.grow((len * 2).min(0x00ff_ffff));
        }
        let i = self.free.pop().expect("a grown table has free entries");
        let e = &mut self.entries[i as usize];
        // Generation byte: IE_BITS_GEN_INIT (0xff) rolls over to 0x03, and
        // every later claim adds IE_BITS_GEN_ONE (4 in the name byte).
        e.generation = if e.generation == 0xff {
            0x03
        } else {
            e.generation.wrapping_add(4) | 0x03
        };
        Ok(i)
    }

    fn release(&mut self, index: u32) {
        let e = &mut self.entries[index as usize];
        if let Some(n) = e.request.take() {
            // ipc_right_request_cancel: the request's right reports the
            // name's deletion.
            let name = Self::name(index, e.generation);
            self.notices.push(Notice::PortDeleted(name, n));
        }
        let e = &mut self.entries[index as usize];
        if let Some(Object::Port(p)) = &e.object
            && self.by_port.get(&p.id) == Some(&index)
        {
            self.by_port.remove(&p.id);
        }
        let generation = e.generation;
        *e = Entry::free(generation);
        self.free.push(index);
    }

    /// The entry a name selects: `KERN_INVALID_NAME` when free or stale.
    pub fn lookup(&self, name: PortName) -> Result<&Entry, KernReturn> {
        let i = Self::index(name) as usize;
        if i == 0 {
            return Err(kr::KERN_INVALID_NAME);
        }
        let e = self.entries.get(i).ok_or(kr::KERN_INVALID_NAME)?;
        if (e.object.is_none() && e.dead == 0) || Self::name(i as u32, e.generation) != name {
            return Err(kr::KERN_INVALID_NAME);
        }
        Ok(e)
    }

    fn lookup_index(&self, name: PortName) -> Result<u32, KernReturn> {
        self.lookup(name)?;
        Ok(Self::index(name))
    }

    /// The name of this space's send or receive entry for `port`.
    pub fn name_of(&self, port: &Arc<Port>) -> Option<PortName> {
        self.by_port
            .get(&port.id)
            .map(|&i| Self::name(i, self.entries[i as usize].generation))
    }

    /// Allocates a new port and a receive right to it
    /// (`mach_port_allocate(MACH_PORT_RIGHT_RECEIVE)`).
    pub fn alloc_receive(&mut self) -> Result<(PortName, Arc<Port>), KernReturn> {
        let port = Port::new(KObject::None);
        let name = self.insert(Right::Receive(port.clone()))?;
        Ok((name, port))
    }

    /// Allocates a dead name (`mach_port_allocate(MACH_PORT_RIGHT_DEAD_NAME)`).
    pub fn alloc_dead_name(&mut self) -> Result<PortName, KernReturn> {
        let i = self.claim()?;
        let e = &mut self.entries[i as usize];
        e.dead = 1;
        Ok(Self::name(i, e.generation))
    }

    /// Allocates an empty port set.
    pub fn alloc_set(&mut self) -> Result<(PortName, Arc<PortSet>), KernReturn> {
        let set = PortSet::new();
        let i = self.claim()?;
        let e = &mut self.entries[i as usize];
        e.object = Some(Object::Set(set.clone()));
        Ok((Self::name(i, e.generation), set))
    }

    /// Inserts a right (`ipc_object_copyout`): a send or receive right
    /// joins the space's entry for its port when there is one; a
    /// send-once right always gets a new name. A right to a dead port
    /// becomes a dead name.
    pub fn insert(&mut self, right: Right) -> Result<PortName, KernReturn> {
        match right {
            Right::Dead => self.alloc_dead_name(),
            Right::Send(port) => {
                if port.is_dead() {
                    return self.alloc_dead_name();
                }
                if let Some(&i) = self.by_port.get(&port.id) {
                    let e = &mut self.entries[i as usize];
                    if e.send >= UREFS_MAX {
                        return Err(kr::KERN_UREFS_OVERFLOW);
                    }
                    if e.send > 0 {
                        // The in-flight right merges into the held one.
                        port.state.lock().unwrap().srights -= 1;
                    }
                    e.send += 1;
                    return Ok(Self::name(i, e.generation));
                }
                let i = self.claim()?;
                let e = &mut self.entries[i as usize];
                e.object = Some(Object::Port(port.clone()));
                e.send = 1;
                self.by_port.insert(port.id, i);
                Ok(Self::name(i, e.generation))
            }
            Right::SendOnce(port) => {
                if port.is_dead() {
                    return self.alloc_dead_name();
                }
                let i = self.claim()?;
                let e = &mut self.entries[i as usize];
                e.object = Some(Object::Port(port));
                e.send_once = true;
                Ok(Self::name(i, e.generation))
            }
            Right::Receive(port) => {
                if let Some(&i) = self.by_port.get(&port.id) {
                    let e = &mut self.entries[i as usize];
                    e.receive = true;
                    return Ok(Self::name(i, e.generation));
                }
                let i = self.claim()?;
                let e = &mut self.entries[i as usize];
                e.object = Some(Object::Port(port.clone()));
                e.receive = true;
                self.by_port.insert(port.id, i);
                Ok(Self::name(i, e.generation))
            }
        }
    }

    /// Claims the free entry `name` names (`ipc_entry_alloc_name` for a
    /// new object): `KERN_NAME_EXISTS` when the name is in use.
    fn claim_name(&mut self, name: PortName) -> Result<u32, KernReturn> {
        let i = Self::index(name);
        if i == 0 || name == MACH_PORT_DEAD {
            return Err(kr::KERN_INVALID_VALUE);
        }
        while self.entries.len() <= i as usize {
            if self.entries.len() as u32 >= 0x00ff_ffff {
                return Err(kr::KERN_NO_SPACE);
            }
            let len = self.entries.len() as u32;
            self.grow((len * 2).max(i + 1).min(0x00ff_ffff));
        }
        let e = &self.entries[i as usize];
        if e.object.is_some() || e.dead > 0 {
            return Err(kr::KERN_NAME_EXISTS);
        }
        self.free.retain(|&f| f != i);
        self.entries[i as usize].generation = (name & 0xff) as u8;
        Ok(i)
    }

    /// Allocates an empty port set named `name` (`ipc_pset_alloc_name`).
    pub fn alloc_set_named(&mut self, name: PortName) -> Result<Arc<PortSet>, KernReturn> {
        let i = self.claim_name(name)?;
        let set = PortSet::new();
        self.entries[i as usize].object = Some(Object::Set(set.clone()));
        Ok(set)
    }

    /// Inserts a right under the caller-chosen `name`
    /// (`ipc_object_copyout_name`, as `mach_port_insert_right` uses it). A
    /// send or receive right must go to the name that already names its
    /// port in this space (`KERN_RIGHT_EXISTS` otherwise) or to a free name
    /// (`KERN_NAME_EXISTS` when it is in use); a send-once right always
    /// needs a free name. Kernel-object and dead ports cannot be named by
    /// the caller (`KERN_INVALID_CAPABILITY`). On failure the right is
    /// returned so the caller can destroy it.
    pub fn copyout_name(
        &mut self,
        name: PortName,
        right: Right,
    ) -> Result<(), (KernReturn, Right)> {
        let i = Self::index(name);
        if i == 0 || name == MACH_PORT_DEAD {
            return Err((kr::KERN_INVALID_VALUE, right));
        }
        let Some(port) = right.port().cloned() else {
            return Err((kr::KERN_INVALID_CAPABILITY, right));
        };
        if port.is_dead() || port.is_kernel() {
            return Err((kr::KERN_INVALID_CAPABILITY, right));
        }
        // ipc_entry_alloc_name: the index must be free or carry `name`'s
        // generation.
        while self.entries.len() <= i as usize {
            if self.entries.len() as u32 >= 0x00ff_ffff {
                return Err((kr::KERN_NO_SPACE, right));
            }
            let len = self.entries.len() as u32;
            self.grow((len * 2).max(i + 1).min(0x00ff_ffff));
        }
        let e = &self.entries[i as usize];
        let in_use = e.object.is_some() || e.dead > 0;
        if in_use && e.generation != (name & 0xff) as u8 {
            return Err((kr::KERN_NAME_EXISTS, right));
        }
        let reverse = match right {
            Right::SendOnce(_) => None,
            _ => self.by_port.get(&port.id).copied(),
        };
        if let Some(o) = reverse {
            if o != i {
                return Err((kr::KERN_RIGHT_EXISTS, right));
            }
        } else if in_use {
            return Err((kr::KERN_NAME_EXISTS, right));
        } else {
            self.free.retain(|&f| f != i);
            let e = &mut self.entries[i as usize];
            e.generation = (name & 0xff) as u8;
            e.object = Some(Object::Port(port.clone()));
        }
        let e = &mut self.entries[i as usize];
        match right {
            Right::Send(_) => {
                if e.send > 0 {
                    // The in-flight right merges into the held one; urefs
                    // stay pegged at the maximum.
                    port.state.lock().unwrap().srights -= 1;
                    e.send = (e.send + 1).min(UREFS_MAX);
                } else {
                    e.send = 1;
                }
                self.by_port.insert(port.id, i);
            }
            Right::Receive(_) => {
                e.receive = true;
                self.by_port.insert(port.id, i);
            }
            Right::SendOnce(_) => e.send_once = true,
            Right::Dead => unreachable!("dead rights were rejected above"),
        }
        Ok(())
    }

    /// Copies a right in from `name` with disposition `d`
    /// (`ipc_right_copyin` with `IPC_OBJECT_COPYIN_FLAGS_DEADOK`): the
    /// in-flight right, which the caller must insert somewhere or release.
    pub fn copyin(&mut self, name: PortName, d: u32) -> Result<Right, KernReturn> {
        let i = self.lookup_index(name)?;
        let e = &mut self.entries[i as usize];
        let port = e.port().cloned();
        match d {
            disp::MAKE_SEND | disp::MAKE_SEND_ONCE => {
                if !e.receive {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                let port = port.expect("receive entries name ports");
                let mut st = port.state.lock().unwrap();
                if d == disp::MAKE_SEND {
                    st.mscount += 1;
                    st.srights += 1;
                    drop(st);
                    Ok(Right::Send(port))
                } else {
                    st.sorights += 1;
                    drop(st);
                    Ok(Right::SendOnce(port))
                }
            }
            disp::MOVE_RECEIVE => {
                if !e.receive {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                let port = port.expect("receive entries name ports");
                e.receive = false;
                if e.send == 0 {
                    self.release(i);
                }
                Ok(Right::Receive(port))
            }
            disp::COPY_SEND | disp::MOVE_SEND | disp::MOVE_SEND_ONCE if e.dead > 0 => {
                if d != disp::COPY_SEND {
                    if e.dead < UREFS_MAX {
                        e.dead -= 1;
                    }
                    if e.dead == 0 {
                        self.release(i);
                    }
                }
                Ok(Right::Dead)
            }
            disp::COPY_SEND => {
                if e.send == 0 {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                let port = port.expect("send entries name ports");
                port.state.lock().unwrap().srights += 1;
                Ok(Right::Send(port))
            }
            disp::MOVE_SEND => {
                if e.send == 0 {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                let port = port.expect("send entries name ports");
                if e.send == 1 {
                    // The entry's own send right leaves with the message.
                    e.send = 0;
                    if e.receive {
                        // The receive right keeps the name.
                    } else {
                        self.release(i);
                    }
                } else {
                    if e.send < UREFS_MAX {
                        e.send -= 1;
                    }
                    port.state.lock().unwrap().srights += 1;
                }
                Ok(Right::Send(port))
            }
            disp::MOVE_SEND_ONCE => {
                if !e.send_once {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                let port = port.expect("send-once entries name ports");
                self.release(i);
                Ok(Right::SendOnce(port))
            }
            _ => Err(kr::KERN_INVALID_RIGHT),
        }
    }

    /// Removes `delta` user references of `right` from `name`
    /// (`mach_port_mod_refs` with a negative delta, `mach_port_deallocate`
    /// with -1). Returns the rights the space no longer holds.
    pub fn drop_refs(
        &mut self,
        name: PortName,
        right_kind: u32,
        delta: u32,
    ) -> Result<Vec<Right>, KernReturn> {
        let i = self.lookup_index(name)?;
        let e = &mut self.entries[i as usize];
        let mut released = Vec::new();
        match right_kind {
            right::SEND => {
                if e.send == 0 {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                if delta > e.send {
                    return Err(kr::KERN_INVALID_VALUE);
                }
                e.send -= delta;
                if e.send == 0 {
                    let port = e.port().cloned().expect("send entries name ports");
                    released.push(Right::Send(port));
                    if !e.receive {
                        self.release(i);
                    }
                }
            }
            right::SEND_ONCE => {
                if !e.send_once {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                if delta > 1 {
                    return Err(kr::KERN_INVALID_VALUE);
                }
                if delta == 1 {
                    let port = e.port().cloned().expect("send-once entries name ports");
                    released.push(Right::SendOnce(port));
                    self.release(i);
                }
            }
            right::DEAD_NAME => {
                if e.dead == 0 {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                if delta > e.dead {
                    return Err(kr::KERN_INVALID_VALUE);
                }
                e.dead -= delta;
                if e.dead == 0 {
                    self.release(i);
                }
            }
            right::RECEIVE => {
                if !e.receive {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                if delta > 1 {
                    return Err(kr::KERN_INVALID_VALUE);
                }
                if delta == 1 {
                    let port = e.port().cloned().expect("receive entries name ports");
                    released.push(Right::Receive(port));
                    e.receive = false;
                    if e.send == 0 {
                        self.release(i);
                    }
                }
            }
            right::PORT_SET => {
                if !matches!(e.object, Some(Object::Set(_))) {
                    return Err(kr::KERN_INVALID_RIGHT);
                }
                if delta > 1 {
                    return Err(kr::KERN_INVALID_VALUE);
                }
                if delta == 1 {
                    self.release(i);
                }
            }
            _ => return Err(kr::KERN_INVALID_VALUE),
        }
        Ok(released)
    }

    /// Adds `delta` user references of `right` to `name`.
    pub fn add_refs(
        &mut self,
        name: PortName,
        right_kind: u32,
        delta: u32,
    ) -> Result<(), KernReturn> {
        let i = self.lookup_index(name)?;
        let e = &mut self.entries[i as usize];
        let refs = match right_kind {
            right::SEND if e.send > 0 => &mut e.send,
            right::DEAD_NAME if e.dead > 0 => &mut e.dead,
            right::SEND | right::DEAD_NAME => return Err(kr::KERN_INVALID_RIGHT),
            right::RECEIVE | right::SEND_ONCE | right::PORT_SET => {
                return if delta == 0 {
                    Ok(())
                } else {
                    Err(kr::KERN_INVALID_VALUE)
                };
            }
            _ => return Err(kr::KERN_INVALID_VALUE),
        };
        if *refs + delta > UREFS_MAX {
            return Err(kr::KERN_UREFS_OVERFLOW);
        }
        *refs += delta;
        Ok(())
    }

    /// Turns every right this space holds to `port` into a dead name (the
    /// port died).
    pub fn port_died(&mut self, port: &Arc<Port>) {
        let ids: Vec<u32> = (1..self.entries.len() as u32)
            .filter(|&i| {
                self.entries[i as usize]
                    .port()
                    .is_some_and(|p| Arc::ptr_eq(p, port))
            })
            .collect();
        for i in ids {
            let e = &mut self.entries[i as usize];
            let refs = e.send + u32::from(e.send_once);
            if refs == 0 {
                continue;
            }
            e.object = None;
            e.send = 0;
            e.send_once = false;
            e.receive = false;
            e.dead += refs;
            if let Some(n) = e.request.take() {
                // The notification carries a user reference of the dead
                // name (ipc_right_check).
                e.dead = (e.dead + 1).min(UREFS_MAX);
                let name = Self::name(i, e.generation);
                self.notices.push(Notice::DeadName(name, n));
            }
            self.by_port.remove(&port.id);
        }
    }

    /// Registers a dead-name request on `name` (`ipc_right_request_alloc`
    /// without send-possible options), returning the previous request's
    /// right. A null `notify` cancels.
    pub fn request_dead_name(
        &mut self,
        name: PortName,
        notify: Option<Arc<Port>>,
    ) -> Result<Option<Arc<Port>>, KernReturn> {
        let i = self.lookup_index(name)?;
        let e = &mut self.entries[i as usize];
        if notify.is_none() && e.request.is_none() {
            return Ok(None);
        }
        if e.port().is_some() && (e.send > 0 || e.receive || e.send_once) {
            let previous = e.request.take();
            e.request = notify;
            return Ok(previous);
        }
        Err(if e.dead > 0 || e.port().is_some() {
            kr::KERN_INVALID_ARGUMENT
        } else {
            kr::KERN_INVALID_RIGHT
        })
    }

    /// The entry table's size (`is_table_size`).
    pub fn table_size(&self) -> u32 {
        self.entries.len() as u32
    }

    /// The names in use with their types (`mach_port_names`).
    pub fn names(&self) -> Vec<(PortName, u32)> {
        (1..self.entries.len() as u32)
            .filter_map(|i| {
                let e = &self.entries[i as usize];
                (e.object.is_some() || e.dead > 0)
                    .then(|| (Self::name(i, e.generation), e.port_type()))
            })
            .collect()
    }

    /// Mutable access to an entry by name.
    pub fn entry_mut(&mut self, name: PortName) -> Result<&mut Entry, KernReturn> {
        let i = self.lookup_index(name)?;
        Ok(&mut self.entries[i as usize])
    }

    /// Removes a name entirely (`mach_port_destroy`), returning its rights.
    pub fn remove(&mut self, name: PortName) -> Result<Vec<Right>, KernReturn> {
        let i = self.lookup_index(name)?;
        let e = self.entries[i as usize].clone();
        let mut out = Vec::new();
        if let Some(Object::Port(p)) = &e.object {
            if e.send > 0 {
                out.push(Right::Send(p.clone()));
            }
            if e.send_once {
                out.push(Right::SendOnce(p.clone()));
            }
            if e.receive {
                out.push(Right::Receive(p.clone()));
            }
        }
        self.release(i);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_xnu_allocation_order() {
        let mut s = IpcSpace::new();
        let thread = s
            .insert(Right::Send(Port::new(KObject::Thread(1))))
            .unwrap();
        let task = s.insert(Right::Send(Port::new(KObject::Task))).unwrap();
        assert_eq!((thread, task), (0x103, 0x203));
        let (r, _) = s.alloc_receive().unwrap();
        assert_eq!(r, 0x303);
        // A freed entry is reused first, with the next generation.
        s.drop_refs(r, right::RECEIVE, 1).unwrap();
        assert_eq!(s.lookup(r).unwrap_err(), kr::KERN_INVALID_NAME);
        let (r2, _) = s.alloc_receive().unwrap();
        assert_eq!(r2, 0x307);
        let (r3, _) = s.alloc_receive().unwrap();
        assert_eq!(r3, 0x403);
    }

    #[test]
    fn send_rights_to_one_port_share_a_name() {
        let mut s = IpcSpace::new();
        let (name, port) = s.alloc_receive().unwrap();
        port.state.lock().unwrap().srights += 2;
        assert_eq!(s.insert(Right::Send(port.clone())).unwrap(), name);
        assert_eq!(s.insert(Right::Send(port.clone())).unwrap(), name);
        let e = s.lookup(name).unwrap();
        assert_eq!(e.send, 2);
        assert!(e.receive);
        assert_eq!(e.port_type(), ptype::SEND | ptype::RECEIVE);
        // Send-once rights get names of their own.
        let so = s.insert(Right::SendOnce(port.clone())).unwrap();
        assert_ne!(so, name);
        assert_eq!(s.lookup(so).unwrap().port_type(), ptype::SEND_ONCE);
        // Dropping the send refs keeps the receive right under the name.
        s.drop_refs(name, right::SEND, 2).unwrap();
        assert_eq!(s.lookup(name).unwrap().port_type(), ptype::RECEIVE);
        assert_eq!(
            s.drop_refs(name, right::SEND, 1).unwrap_err(),
            kr::KERN_INVALID_RIGHT
        );
    }

    #[test]
    fn a_dead_port_leaves_dead_names() {
        let mut s = IpcSpace::new();
        let port = Port::new(KObject::None);
        port.state.lock().unwrap().srights += 1;
        let name = s.insert(Right::Send(port.clone())).unwrap();
        port.state.lock().unwrap().dead = true;
        s.port_died(&port);
        let e = s.lookup(name).unwrap();
        assert_eq!(e.port_type(), ptype::DEAD_NAME);
        assert_eq!(e.dead, 1);
        s.drop_refs(name, right::DEAD_NAME, 1).unwrap();
        assert!(s.lookup(name).is_err());
        // Inserting a right to a dead port yields a dead name.
        let dn = s.insert(Right::Send(port)).unwrap();
        assert_eq!(s.lookup(dn).unwrap().port_type(), ptype::DEAD_NAME);
    }

    #[test]
    fn stale_and_null_names_are_invalid() {
        let s = IpcSpace::new();
        assert_eq!(s.lookup(0).unwrap_err(), kr::KERN_INVALID_NAME);
        assert_eq!(s.lookup(0x107).unwrap_err(), kr::KERN_INVALID_NAME);
        assert_eq!(s.lookup(MACH_PORT_DEAD).unwrap_err(), kr::KERN_INVALID_NAME);
    }

    #[test]
    fn caller_chosen_names() {
        let mut s = IpcSpace::new();
        let port = Port::new(KObject::None);
        port.state.lock().unwrap().srights += 1;
        s.copyout_name(0x1203, Right::Send(port.clone())).unwrap();
        assert_eq!(s.lookup(0x1203).unwrap().send, 1);
        assert_eq!(s.name_of(&port), Some(0x1203));
        // Another port may not take a used name, nor this port another name.
        let other = Port::new(KObject::None);
        let (k, _) = s
            .copyout_name(0x1203, Right::Send(other.clone()))
            .unwrap_err();
        assert_eq!(k, kr::KERN_NAME_EXISTS);
        port.state.lock().unwrap().srights += 1;
        let (k, _) = s
            .copyout_name(0x1303, Right::Send(port.clone()))
            .unwrap_err();
        assert_eq!(k, kr::KERN_RIGHT_EXISTS);
        // A send-once right needs a free name.
        let (k, _) = s
            .copyout_name(0x1203, Right::SendOnce(port.clone()))
            .unwrap_err();
        assert_eq!(k, kr::KERN_NAME_EXISTS);
        s.copyout_name(0x1403, Right::SendOnce(port.clone()))
            .unwrap();
        assert_eq!(s.lookup(0x1403).unwrap().port_type(), ptype::SEND_ONCE);
        // The generation byte must match an index in use.
        let (k, _) = s
            .copyout_name(0x1207, Right::Send(port.clone()))
            .unwrap_err();
        assert_eq!(k, kr::KERN_NAME_EXISTS);
        let (k, _) = s.copyout_name(0, Right::Send(port.clone())).unwrap_err();
        assert_eq!(k, kr::KERN_INVALID_VALUE);
        let task = Port::new(KObject::Task);
        let (k, _) = s.copyout_name(0x1503, Right::Send(task)).unwrap_err();
        assert_eq!(k, kr::KERN_INVALID_CAPABILITY);
        // A caller-chosen index is not handed out again.
        let names: Vec<PortName> = (0..0x20).map(|_| s.alloc_dead_name().unwrap()).collect();
        assert!(!names.iter().any(|&n| n >> 8 == 0x12 || n >> 8 == 0x14));
    }

    #[test]
    fn copyin_follows_dispositions() {
        let mut s = IpcSpace::new();
        let (name, port) = s.alloc_receive().unwrap();
        // MAKE_SEND bumps the make-send count and the send rights.
        let r = s.copyin(name, disp::MAKE_SEND).unwrap();
        assert!(matches!(r, Right::Send(_)));
        assert_eq!(port.state.lock().unwrap().mscount, 1);
        assert_eq!(port.state.lock().unwrap().srights, 1);
        s.copyout_name(name, r).unwrap();
        assert_eq!(s.lookup(name).unwrap().send, 1);
        // COPY_SEND leaves the entry alone; MOVE_SEND of the last
        // reference keeps the name for the receive right.
        let r = s.copyin(name, disp::COPY_SEND).unwrap();
        assert_eq!(port.state.lock().unwrap().srights, 2);
        s.copyout_name(name, r).unwrap();
        assert_eq!(s.lookup(name).unwrap().send, 2);
        assert_eq!(port.state.lock().unwrap().srights, 1);
        let _moved = s.copyin(name, disp::MOVE_SEND).unwrap();
        assert_eq!(s.lookup(name).unwrap().send, 1);
        let _moved2 = s.copyin(name, disp::MOVE_SEND).unwrap();
        assert_eq!(s.lookup(name).unwrap().port_type(), ptype::RECEIVE);
        assert_eq!(
            s.copyin(name, disp::MOVE_SEND).unwrap_err(),
            kr::KERN_INVALID_RIGHT
        );
        // MOVE_RECEIVE of a bare receive right frees the name.
        let r = s.copyin(name, disp::MOVE_RECEIVE).unwrap();
        assert!(matches!(r, Right::Receive(_)));
        assert!(s.lookup(name).is_err());
        // Dead names copy in as dead rights; moving consumes a reference.
        let dn = s.alloc_dead_name().unwrap();
        assert!(matches!(
            s.copyin(dn, disp::COPY_SEND).unwrap(),
            Right::Dead
        ));
        assert!(s.lookup(dn).is_ok());
        assert!(matches!(
            s.copyin(dn, disp::MOVE_SEND).unwrap(),
            Right::Dead
        ));
        assert!(s.lookup(dn).is_err());
        assert_eq!(
            s.copyin(dn, disp::COPY_SEND).unwrap_err(),
            kr::KERN_INVALID_NAME
        );
    }
}
