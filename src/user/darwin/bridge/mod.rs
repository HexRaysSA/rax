//! The bridge between the guest's Mach ports and the host's services.
//!
//! The emulated process is a host process: the system's services (launchd,
//! and the directory, preference, and notification services it names)
//! know it by its pid, credentials, and audit token, as they would know
//! the native program. The bridge lets the guest reach them. A host send
//! or send-once right the emulator holds appears in the guest as a proxy
//! port ([`KObject::Proxy`]); a message the guest sends to a proxy is sent
//! on the host ([`translate::forward`]), its rights translated. A guest
//! port the guest gives a host service a right to is exported: the host
//! sees a receive right of the emulator's, whose messages [`pump`] receives
//! and queues on the guest port ([`translate::to_guest`]).
//!
//! The process's bootstrap port is the host's (the task's bootstrap special
//! port, and its first registered port, as launchd registers it). The
//! bridge keeps the host's death of a proxied port (a dead-name
//! notification: the proxy dies and the guest's rights to it become dead
//! names) and the end of the host's rights to an exported port (a
//! no-senders notification: the guest port loses the send right that
//! stood for them). A receive right the guest would move to the host is
//! refused (`MACH_SEND_INVALID_RIGHT`).
//!
//! Host rights belong to the host process that holds them: a forked or
//! spawned child (a host fork) starts over, with the host's bootstrap port
//! again and no other proxy alive. Without a macOS host, or with
//! `RAX_DARWIN_NO_HOST_SERVICES` set, there is no bridge and no bootstrap
//! port.

#[cfg(target_os = "macos")]
pub mod host;
#[cfg(target_os = "macos")]
pub mod kernel;
#[cfg(target_os = "macos")]
pub mod mirror;
#[cfg(target_os = "macos")]
pub mod translate;

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use super::mach::exception::Handler;
use super::mach::ipc::{KObject, Port};
use super::mach::task::{TaskState, special};
use super::process::Proc;

/// Bumped in every host child: host rights of earlier processes are not
/// this process's to release.
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Called in a host child right after the host fork.
pub fn forked() {
    EPOCH.fetch_add(1, Ordering::SeqCst);
}

fn epoch() -> u64 {
    EPOCH.load(Ordering::SeqCst)
}

/// A host send or send-once right the emulator holds for a proxy port; it
/// is released with the proxy, unless it was consumed (a send-once right
/// sent on) or belongs to an earlier process.
#[derive(Debug)]
pub struct HostRight {
    name: AtomicU32,
    /// A send-once right.
    pub once: bool,
    epoch: u64,
}

impl HostRight {
    fn new(name: u32, once: bool) -> Self {
        HostRight {
            name: AtomicU32::new(name),
            once,
            epoch: epoch(),
        }
    }

    /// The host name, while the right is this process's and not consumed.
    pub fn name(&self) -> Option<u32> {
        let n = self.name.load(Ordering::SeqCst);
        (n != 0 && self.epoch == epoch()).then_some(n)
    }

    /// Takes the right (a send-once right about to be sent on).
    pub fn take(&self) -> Option<u32> {
        let n = self.name()?;
        self.name.store(0, Ordering::SeqCst);
        Some(n)
    }
}

impl Drop for HostRight {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(n) = self.name() {
            host::deallocate(n);
        }
    }
}

impl PartialEq for HostRight {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for HostRight {}

/// What a host receive right in the bridge's port set stands for.
#[derive(Debug)]
enum Import {
    /// Messages go to this guest port.
    Port(Arc<Port>),
    /// No-senders notifications for the export of the guest port with this
    /// identity.
    NoSenders(u64),
    /// Dead-name and other notifications about proxied rights.
    Control,
}

/// A guest port exported to the host.
#[derive(Debug)]
struct Export {
    /// The host receive right.
    recv: u32,
    /// Where its no-senders notification arrives.
    notify: u32,
    /// A host reply port whose send-once rights stand for the guest's in
    /// a message's reply field (0 until one is needed).
    reply: u32,
    /// Whether the host holds send rights to it: the guest port then keeps
    /// one send right that stands for them all.
    held: bool,
}

/// The bridge's state in a process.
#[derive(Debug, Default)]
pub struct Bridge {
    epoch: u64,
    /// The host port set of every host receive right the bridge serves
    /// (0 until first used).
    set: u32,
    /// A kqueue readable while the set holds a message.
    kq: Option<OwnedFd>,
    /// The receive right dead-name notifications arrive on.
    control: u32,
    /// Proxies by the host name of their send right.
    proxies: HashMap<u32, Weak<Port>>,
    imports: HashMap<u32, Import>,
    /// Exports by guest port identity.
    exports: HashMap<u64, Export>,
    /// Guest ports whose receive rights moved to the host, by the host
    /// name of the receive right that stands for theirs.
    moved: HashMap<u32, Weak<Port>>,
    /// The memory entries the bridge made, by their proxies' identity.
    entries: HashMap<u64, (Weak<Port>, super::syscall::mach::entry::Entry)>,
    /// Memory host services map into the task.
    #[cfg(target_os = "macos")]
    mirror: mirror::Mirror,
    /// The receive buffer.
    buf: Vec<u8>,
}

impl Bridge {
    /// A descriptor readable when the host has a message for the guest.
    pub fn fd(&self) -> Option<i32> {
        if self.epoch != epoch() {
            return None;
        }
        self.kq.as_ref().map(|k| k.as_raw_fd())
    }

    /// Forgets everything an earlier process held (its kqueue is not this
    /// process's descriptor: kqueues are not inherited).
    fn reset(&mut self) {
        if let Some(kq) = self.kq.take() {
            std::mem::forget(kq);
        }
        *self = Bridge {
            epoch: epoch(),
            ..Default::default()
        };
    }

    /// Makes the bridge this process's, creating the port set on first use.
    #[cfg(target_os = "macos")]
    fn ensure(&mut self) -> bool {
        if self.epoch != epoch() {
            self.reset();
        }
        if self.set != 0 {
            return true;
        }
        let (Some(set), Some(control)) = (
            host::allocate(host::right::PORT_SET),
            host::allocate(host::right::RECEIVE),
        ) else {
            return false;
        };
        host::join(control, set);
        self.kq = host::watch(set);
        self.set = set;
        self.control = control;
        self.imports.insert(control, Import::Control);
        true
    }

    /// The proxy for host send right `name`, which the caller holds one
    /// reference to: an existing proxy takes it over (the reference is
    /// dropped), a new one keeps it and arms a dead-name notification.
    #[cfg(target_os = "macos")]
    fn proxy(&mut self, name: u32) -> Arc<Port> {
        if let Some(p) = self.proxies.get(&name).and_then(Weak::upgrade) {
            host::deallocate(name);
            return p;
        }
        let p = Port::new(KObject::Proxy(Arc::new(HostRight::new(name, false))));
        if self.ensure() {
            host::request(name, host::notify::DEAD_NAME, 1, self.control);
        }
        self.proxies.insert(name, Arc::downgrade(&p));
        p
    }

    /// The host receive right standing for guest port `port`, exporting it
    /// on first use.
    #[cfg(target_os = "macos")]
    fn export(&mut self, port: &Arc<Port>) -> Option<u32> {
        if let Some(e) = self.exports.get(&port.id) {
            return Some(e.recv);
        }
        if !self.ensure() {
            return None;
        }
        let recv = host::allocate(host::right::RECEIVE)?;
        let notify = host::allocate(host::right::RECEIVE)?;
        host::join(recv, self.set);
        host::join(notify, self.set);
        self.imports.insert(recv, Import::Port(port.clone()));
        self.imports.insert(notify, Import::NoSenders(port.id));
        self.exports.insert(
            port.id,
            Export {
                recv,
                notify,
                reply: 0,
                held: false,
            },
        );
        Some(recv)
    }

    /// The host reply port standing for guest port `port` in a message's
    /// reply field.
    #[cfg(target_os = "macos")]
    fn reply_export(&mut self, port: &Arc<Port>) -> Option<u32> {
        self.export(port)?;
        let set = self.set;
        let e = self.exports.get_mut(&port.id)?;
        if e.reply == 0 {
            let r = host::reply_port()?;
            host::join(r, set);
            e.reply = r;
            self.imports.insert(r, Import::Port(port.clone()));
        }
        Some(self.exports[&port.id].reply)
    }

    /// The host receive right of guest port `port`'s export, taken out of
    /// the bridge to move to the host (host rights to it stay rights to the
    /// port); its notification and reply ports end.
    #[cfg(target_os = "macos")]
    fn take_export(&mut self, port: &Port) -> Option<u32> {
        let e = self.exports.remove(&port.id)?;
        self.imports.remove(&e.recv);
        host::join(e.recv, host::NULL);
        let recv = e.recv;
        self.end(Export { recv: 0, ..e });
        Some(recv)
    }

    /// Ends the export of guest port `port` (its receive right is gone):
    /// the host's rights to it die.
    pub fn unexport(&mut self, port: &Port) {
        if let Some(e) = self.exports.remove(&port.id) {
            self.end(e);
        }
    }

    /// Destroys an export's host receive rights.
    fn end(&mut self, e: Export) {
        for r in [e.recv, e.notify, e.reply] {
            if r == 0 {
                continue;
            }
            self.imports.remove(&r);
            #[cfg(target_os = "macos")]
            if self.epoch == epoch() {
                host::mod_refs(r, host::right::RECEIVE, -1);
            }
        }
    }

    /// Before a new image replaces the guest: its ports' exports end, and
    /// the new task has handed itself to no service.
    pub fn exec(&mut self) {
        let ids: Vec<u64> = self.exports.keys().copied().collect();
        for id in ids {
            let e = self.exports.remove(&id).expect("listed");
            self.end(e);
        }
        #[cfg(target_os = "macos")]
        {
            self.mirror = mirror::Mirror::default();
        }
    }
}

/// Whether the process may reach the host's services.
fn enabled() -> bool {
    cfg!(target_os = "macos") && std::env::var_os("RAX_DARWIN_NO_HOST_SERVICES").is_none()
}

/// The proxy of the host's bootstrap port for a new process, if any.
fn bootstrap(bridge: &mut Bridge) -> Option<Arc<Port>> {
    if !enabled() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let name = host::special_port(special::BOOTSTRAP);
        if name == host::NULL || name == host::DEAD {
            return None;
        }
        Some(bridge.proxy(name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bridge;
        None
    }
}

/// The first process's task ports: the bootstrap port is the host's, and
/// is registered first (as launchd registers it).
pub fn start(bridge: &mut Bridge, task: &mut TaskState) {
    bridge.reset();
    if let Some(p) = bootstrap(bridge) {
        p.state.lock().unwrap().srights += 2;
        task.special[special::BOOTSTRAP as usize] = Some(p.clone());
        task.registered[0] = Handler::Port(p);
    }
}

/// A host child's task ports (after a fork, or a spawn's): the bootstrap
/// port is the host's again, wherever the parent's stood; any other proxy
/// the task holds is dead.
pub fn rebind(bridge: &mut Bridge, task: &mut TaskState) {
    let stale = |p: &Arc<Port>| matches!(&p.kobject, KObject::Proxy(h) if h.name().is_none());
    let old = task.special[special::BOOTSTRAP as usize].clone();
    bridge.reset();
    let fresh = bootstrap(bridge);
    let is_old = |p: &Arc<Port>| old.as_ref().is_some_and(|o| Arc::ptr_eq(o, p));
    for slot in task.special.iter_mut() {
        if slot.as_ref().is_some_and(stale) {
            *slot = match slot.take() {
                Some(p) if is_old(&p) => fresh
                    .clone()
                    .inspect(|f| f.state.lock().unwrap().srights += 1),
                _ => None,
            };
        }
    }
    for h in task.registered.iter_mut() {
        if let Handler::Port(p) = h
            && stale(p)
        {
            *h = match &fresh {
                Some(f) if is_old(p) => {
                    f.state.lock().unwrap().srights += 1;
                    Handler::Port(f.clone())
                }
                _ => Handler::Dead,
            };
        }
    }
    for a in task.exc.iter_mut() {
        if a.port.as_ref().is_some_and(stale) {
            a.port = None;
            a.dead = true;
        }
    }
}

/// `mach_port_kobject`'s type of the port behind a proxy, as the host
/// reports it.
pub fn kobject_type(h: &HostRight) -> u32 {
    #[cfg(target_os = "macos")]
    if let Some(n) = h.name() {
        return host::kobject(n);
    }
    let _ = h;
    0
}

/// The contents a `vm_map` of the host memory object behind proxy `h`
/// gives the guest: `size` bytes from `offset`, as the mapping reads them
/// now (a later change by another mapper is not seen), with the mapping's
/// protections (`cur`, `max` as the guest asked, `VM_PROT_IS_MASK`
/// included, as the host's entry allows).
pub fn map_object(
    h: &HostRight,
    size: u64,
    offset: u64,
    cur: u32,
    max: u32,
) -> Result<(Vec<u8>, u32, u32), i32> {
    #[cfg(target_os = "macos")]
    if let Some(n) = h.name() {
        return host::map_copy(n, size, offset, cur, max);
    }
    let _ = (h, size, offset, cur, max);
    Err(super::mach::kr::KERN_INVALID_OBJECT)
}

/// A shared mapping of the host memory object behind proxy `h` (a
/// service's memory entry): `size` bytes from `offset`, which stores on
/// either side reach, with the mapping's protections (`cur`, `max` as the
/// guest asked, `VM_PROT_IS_MASK` included, as the host's entry allows).
pub fn map_object_shared(
    proc: &mut Proc,
    h: &HostRight,
    size: u64,
    offset: u64,
    cur: u32,
    max: u32,
) -> Result<(Arc<crate::user::mm::SharedObject>, u32, u32), i32> {
    #[cfg(target_os = "macos")]
    if let Some(n) = h.name() {
        return mirror::map_service(proc, n, size, offset, cur, max);
    }
    let _ = (proc, h, size, offset, cur, max);
    Err(super::mach::kr::KERN_INVALID_OBJECT)
}

/// A host memory entry for `entry` with protection `prot`, as a proxy
/// holding one send right for the caller.
pub fn make_entry(
    proc: &mut Proc,
    entry: super::syscall::mach::entry::Entry,
    prot: u32,
) -> Result<Arc<Port>, super::mach::kr::KernReturn> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let name = match (entry.object.host_file(), entry.object.memory()) {
            (Some(f), _) => host::memory_entry(f.as_raw_fd(), entry.offset, entry.len, prot)?,
            // Host memory a service mapped: an entry of its entry.
            (None, Some(m)) => mirror::sub_entry(m, entry.offset, entry.len, prot)?,
            (None, None) => return Err(super::mach::kr::KERN_INVALID_ARGUMENT),
        };
        let b = &mut proc.bridge;
        b.entries.retain(|_, (w, _)| w.strong_count() > 0);
        let p = b.proxy(name);
        p.state.lock().unwrap().srights += 1;
        b.entries.insert(p.id, (Arc::downgrade(&p), entry));
        Ok(p)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (proc, entry, prot);
        Err(super::mach::kr::KERN_INVALID_ARGUMENT)
    }
}

/// The memory entry the bridge made behind proxy `port`, if it made one.
pub fn entry_of(proc: &Proc, port: &Port) -> Option<super::syscall::mach::entry::Entry> {
    proc.bridge.entries.get(&port.id).map(|(_, e)| e.clone())
}

/// A proxy of IOKit's main port (`host_get_io_main`), holding one send
/// right for the caller; `None` without the bridge.
pub fn io_main(proc: &mut Proc) -> Option<Arc<Port>> {
    if !enabled() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let name = host::io_main()?;
        let p = proc.bridge.proxy(name);
        p.state.lock().unwrap().srights += 1;
        Some(p)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = proc;
        None
    }
}

/// Releases a proxy's host right.
pub fn release(name: u32) {
    #[cfg(target_os = "macos")]
    host::deallocate(name);
    #[cfg(not(target_os = "macos"))]
    let _ = name;
}

/// Sends a message whose destination is a proxy on the host; a failure
/// destroys it (a kernel-sent message has no sender to tell).
pub fn forward(proc: &mut Proc, m: super::mach::msg::Message) {
    #[cfg(target_os = "macos")]
    let _ = translate::forward(proc, m, None, host::opt64::ANY);
    #[cfg(not(target_os = "macos"))]
    super::syscall::mach::kmsg::destroy(proc, m);
}

/// Sends `m`, a guest's message to a proxy, on the host, waiting
/// `timeout` milliseconds for queue space when given, in the guest's call
/// class (`MACH64_SEND_*_CALL` bits of its options; none for the legacy
/// trap, which is sent as `MACH64_SEND_ANY`).
pub fn send(
    proc: &mut Proc,
    m: super::mach::msg::Message,
    timeout: Option<u32>,
    class: u64,
) -> Result<(), super::mach::kr::KernReturn> {
    #[cfg(target_os = "macos")]
    {
        let class = if class == 0 { host::opt64::ANY } else { class };
        translate::forward(proc, m, timeout, class)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (timeout, class);
        super::syscall::mach::kmsg::destroy(proc, m);
        Err(super::mach::kr::MACH_SEND_INVALID_DEST)
    }
}

/// Receives what the host sent the guest's exported ports and the
/// bridge's notifications, without blocking.
pub fn pump(proc: &mut Proc) {
    #[cfg(target_os = "macos")]
    translate::pump(proc);
    #[cfg(not(target_os = "macos"))]
    let _ = proc;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rights_belong_to_the_process_that_holds_them() {
        // A name no right has: releasing it is harmless.
        let r = HostRight::new(0x7fff_fff3, false);
        assert_eq!(r.name(), Some(0x7fff_fff3));
        let once = HostRight::new(0x7fff_fff7, true);
        assert_eq!(once.take(), Some(0x7fff_fff7));
        assert_eq!(once.name(), None, "a taken right is gone");
        // In a host child, the parent's rights are not the child's.
        forked();
        assert_eq!(r.name(), None);
        assert_eq!(HostRight::new(5, false).name(), Some(5));
        let mut b = Bridge::default();
        assert_eq!(b.fd(), None);
        b.reset();
        assert_eq!(b.epoch, epoch());
    }
}
