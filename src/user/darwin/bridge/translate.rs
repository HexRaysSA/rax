//! Messages across the bridge: a guest message to a proxy sent on the host
//! ([`forward`]), and a host message to an exported port queued in the
//! guest ([`pump`]). Both keep the 64-bit user layout of the body, whose
//! descriptors name rights and memory in the side that holds them.

use std::sync::Arc;

use super::host::{self, Name};
use super::{Bridge, Import};
use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp as gdisp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{HEADER_SIZE, Item, Message, Sender, bits, desc};
use crate::user::darwin::mach::task::special;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// The first receive buffer (a larger message is received again into one
/// its size).
const RECEIVE_BUFFER: usize = 64 << 10;
/// The largest trailer (`MAX_TRAILER_SIZE`).
const MAX_TRAILER: usize = 68;

/// A host right the forwarded message moves, and what to do with the guest
/// right it stands for once the send is over.
struct Moved {
    name: Name,
    disp: u32,
    /// A guest send right to release after the send (a proxy's, or a kernel
    /// object's).
    release: Option<Arc<Port>>,
    /// A guest port whose export the host now holds a send right to.
    held: Option<Arc<Port>>,
    /// A guest port whose receive right the message moves to the host.
    receive: Option<Arc<Port>>,
}

/// The host right standing for guest right `right`, made for the send to
/// move; a right with none is handed back.
fn to_host(bridge: &mut Bridge, right: Right) -> Result<Moved, (KernReturn, Right)> {
    let moved = |name, disp| Moved {
        name,
        disp,
        release: None,
        held: None,
        receive: None,
    };
    let refuse = |r| Err((kr::MACH_SEND_INVALID_RIGHT, r));
    // A guest port whose receive right moved to the host: its host right.
    let moved_to = |p: &Port| {
        let st = p.state.lock().unwrap();
        st.host.as_ref().map(|h| h.name())
    };
    match right {
        Right::Dead => Ok(moved(host::DEAD, host::disp::MOVE_SEND)),
        Right::Send(p) if matches!(p.kobject, KObject::None) && moved_to(&p).is_some() => {
            let n = moved_to(&p)
                .flatten()
                .filter(|&n| host::mod_refs(n, host::right::SEND, 1));
            Ok(Moved {
                release: Some(p),
                ..moved(n.unwrap_or(host::DEAD), host::disp::MOVE_SEND)
            })
        }
        Right::SendOnce(p) if matches!(p.kobject, KObject::None) && moved_to(&p).is_some() => {
            // No send-once right can be made without the receive right: a
            // send right stands for it.
            let n = moved_to(&p)
                .flatten()
                .filter(|&n| host::mod_refs(n, host::right::SEND, 1));
            let mut st = p.state.lock().unwrap();
            st.sorights = st.sorights.saturating_sub(1);
            drop(st);
            Ok(moved(n.unwrap_or(host::DEAD), host::disp::MOVE_SEND))
        }
        Right::Receive(p) if matches!(p.kobject, KObject::None) && !p.is_dead() => {
            // A host receive right goes in its place (its export's, so that
            // the host's rights to the port stay its); the guest port keeps
            // a send right to it for what is sent to the port.
            let Some(r) = bridge
                .take_export(&p)
                .or_else(|| host::allocate(host::right::RECEIVE))
            else {
                return Err((kr::MACH_SEND_NO_BUFFER, Right::Receive(p)));
            };
            if !host::make_send(r) {
                host::mod_refs(r, host::right::RECEIVE, -1);
                return Err((kr::MACH_SEND_NO_BUFFER, Right::Receive(p)));
            }
            p.state.lock().unwrap().host = Some(Arc::new(super::HostRight::new(r, false)));
            Ok(Moved {
                receive: Some(p),
                ..moved(r, host::disp::MOVE_RECEIVE)
            })
        }
        Right::Send(p) => {
            let name = match &p.kobject {
                KObject::Proxy(h) if !h.once => {
                    // A reference of the proxy's host right; a right the
                    // host already lost is dead.
                    let n = h
                        .name()
                        .filter(|&n| host::mod_refs(n, host::right::SEND, 1));
                    Some(n.unwrap_or(host::DEAD))
                }
                KObject::None => {
                    let Some(recv) = bridge.export(&p).filter(|&r| host::make_send(r)) else {
                        return Err((kr::MACH_SEND_NO_BUFFER, Right::Send(p)));
                    };
                    return Ok(Moved {
                        held: Some(p),
                        ..moved(recv, host::disp::MOVE_SEND)
                    });
                }
                // Kernel objects the host has too: the emulator's task and
                // its flavors, and the host.
                KObject::Task => host::task_port(),
                KObject::Host => Some(host::host_port()),
                KObject::TaskName | KObject::TaskRead | KObject::TaskInspect => {
                    let which = match p.kobject {
                        KObject::TaskName => special::NAME,
                        KObject::TaskRead => special::READ,
                        _ => special::INSPECT,
                    };
                    Some(host::special_port(which)).filter(|&n| n != host::NULL)
                }
                _ => None,
            };
            match name {
                Some(n) => Ok(Moved {
                    release: Some(p),
                    ..moved(n, host::disp::MOVE_SEND)
                }),
                None => refuse(Right::Send(p)),
            }
        }
        Right::SendOnce(p) => match &p.kobject {
            KObject::Proxy(h) if h.once => {
                // The host right goes with the message.
                let name = h.take().unwrap_or(host::DEAD);
                let mut st = p.state.lock().unwrap();
                st.sorights = st.sorights.saturating_sub(1);
                drop(st);
                Ok(moved(name, host::disp::MOVE_SEND_ONCE))
            }
            KObject::None => {
                // The guest's send-once right stays counted: the host holds
                // it, and its use or destruction reaches the guest port.
                match bridge.export(&p).and_then(host::make_send_once) {
                    Some(name) => Ok(moved(name, host::disp::MOVE_SEND_ONCE)),
                    None => Err((kr::MACH_SEND_NO_BUFFER, Right::SendOnce(p))),
                }
            }
            _ => refuse(Right::SendOnce(p)),
        },
        // A kernel object's, or a dead port's.
        Right::Receive(p) => refuse(Right::Receive(p)),
    }
}

/// [`to_host`] for a right of the message being sent, recorded in
/// `moved`; a right it refuses is released.
fn convert(proc: &mut Proc, r: Right, moved: &mut Vec<Moved>) -> Result<(Name, u32), KernReturn> {
    match to_host(&mut proc.bridge, r) {
        Ok(m) => {
            let x = (m.name, m.disp);
            moved.push(m);
            Ok(x)
        }
        Err((e, r)) => {
            if proc.config.strace {
                let what = match &r {
                    Right::Send(p) => format!("send right to {:?}", p.kobject),
                    Right::SendOnce(p) => format!("send-once right to {:?}", p.kobject),
                    Right::Receive(_) => "receive right".into(),
                    Right::Dead => "dead name".into(),
                };
                eprintln!("rax-user: bridge: no host right for a {what} ({e:#x})");
            }
            kmsg::release(proc, [r]);
            Err(e)
        }
    }
}

/// The reply field's host right for guest right `r`: a guest port's
/// send-once right is a send-once right the message makes from the port's
/// host reply port; any other right is as [`convert`] makes it.
fn convert_reply(
    proc: &mut Proc,
    r: Right,
    moved: &mut Vec<Moved>,
) -> Result<(Name, u32), KernReturn> {
    match r {
        Right::SendOnce(p) if matches!(p.kobject, KObject::None) => {
            match proc.bridge.reply_export(&p) {
                // The guest's send-once right stays counted: the host holds
                // the one the message makes.
                Some(rp) => Ok((rp, host::disp::MAKE_SEND_ONCE)),
                None => {
                    kmsg::release(proc, [Right::SendOnce(p)]);
                    Err(kr::MACH_SEND_NO_BUFFER)
                }
            }
        }
        r => convert(proc, r, moved),
    }
}

/// Undoes the host rights made for a send that failed.
fn unmake(moved: &[Moved]) {
    for m in moved {
        if m.name != host::NULL && m.name != host::DEAD {
            if let Some(p) = &m.receive {
                host::mod_refs(m.name, host::right::RECEIVE, -1);
                p.state.lock().unwrap().host = None;
            } else if m.held.is_some() {
                host::mod_refs(m.name, host::right::SEND, -1);
            } else {
                host::deallocate(m.name);
            }
        }
    }
}

/// Sends guest message `m`, whose destination is a proxy, on the host
/// (waiting `timeout` milliseconds for queue space when given, else for
/// as long as it takes).
pub fn forward(proc: &mut Proc, mut m: Message, timeout: Option<u32>) -> Result<(), KernReturn> {
    // Notifications first: a proxy the host knows dead is dead here.
    pump(proc);
    let dest_port = m.dest.port().cloned();
    let mut moved: Vec<Moved> = Vec::new();
    match send(proc, &mut m, timeout, &mut moved) {
        Ok(()) => {
            for mv in moved {
                if let Some(p) = mv.release {
                    kmsg::release_send(proc, &p);
                }
                if let Some(p) = mv.held {
                    held(proc, &p);
                }
                if let Some(p) = mv.receive {
                    moved_away(proc, &p, mv.name);
                }
            }
            Ok(())
        }
        Err(e) => {
            unmake(&moved);
            for mv in moved {
                if let Some(p) = mv.release.or(mv.held) {
                    kmsg::release_send(proc, &p);
                }
                // The message's receive right is destroyed with it.
                if let Some(p) = mv.receive {
                    kmsg::destroy_receive(proc, &p);
                }
            }
            if e == kr::MACH_SEND_INVALID_DEST
                && let Some(p) = dest_port.filter(|p| matches!(p.kobject, KObject::Proxy(_)))
            {
                kmsg::destroy_receive(proc, &p);
                kmsg::flush(proc);
            }
            kmsg::destroy(proc, m);
            Err(e)
        }
    }
}

/// The host send of [`forward`]: the rights `m` carries are taken out of
/// it as they are translated (into `moved`).
fn send(
    proc: &mut Proc,
    m: &mut Message,
    timeout: Option<u32>,
    moved: &mut Vec<Moved>,
) -> Result<(), KernReturn> {
    if m.dest.port().is_none_or(|p| p.is_dead()) {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    let dest = std::mem::replace(&mut m.dest, Right::Dead);
    let (remote, remote_disp) = convert(proc, dest, moved)?;
    if remote == host::DEAD {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    let (local, local_disp) = match m.reply.take() {
        None => (host::NULL, 0),
        Some(r) => convert_reply(proc, r, moved)?,
    };
    // Vouchers stay in the guest.
    if let Some(v) = m.voucher.take() {
        kmsg::release(proc, [v]);
    }
    let mut buf = vec![0u8; HEADER_SIZE + m.body.len()];
    buf[HEADER_SIZE..].copy_from_slice(&m.body);
    let hb = bits::set(remote_disp, local_disp, 0, m.bits & bits::COMPLEX);
    buf[0..4].copy_from_slice(&hb.to_le_bytes());
    let size = buf.len() as u32;
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf[8..12].copy_from_slice(&remote.to_le_bytes());
    buf[12..16].copy_from_slice(&local.to_le_bytes());
    buf[20..24].copy_from_slice(&m.id.to_le_bytes());
    // Out-of-line data and port arrays live here until the send is over.
    let mut regions: Vec<Vec<u8>> = Vec::new();
    let mut arrays: Vec<Vec<u32>> = Vec::new();
    for (off, item) in std::mem::take(&mut m.items) {
        let at = HEADER_SIZE + off;
        match item {
            Item::Port { right, .. } => {
                let (name, d) = match right {
                    None => (host::NULL, host::disp::COPY_SEND),
                    Some(r) => convert(proc, r, moved)?,
                };
                buf[at..at + 4].copy_from_slice(&name.to_le_bytes());
                buf[at + 10] = d as u8;
            }
            Item::Guarded { right, .. } => {
                // A guarded descriptor carries a receive right.
                if let Some(r) = right {
                    kmsg::release(proc, [r]);
                }
                return Err(kr::MACH_SEND_INVALID_RIGHT);
            }
            Item::Ool { data, .. } => {
                buf[at..at + 8].copy_from_slice(&(data.as_ptr() as u64).to_le_bytes());
                buf[at + 8] = 0; // deallocate
                buf[at + 9] = desc::PHYSICAL_COPY;
                buf[at + 12..at + 16].copy_from_slice(&(data.len() as u32).to_le_bytes());
                regions.push(data);
            }
            Item::OolPorts { rights, .. } => {
                let mut names = Vec::with_capacity(rights.len());
                let mut d = host::disp::COPY_SEND;
                for r in rights {
                    match r {
                        None => names.push(host::NULL),
                        Some(r) => {
                            let (n, rd) = convert(proc, r, moved)?;
                            names.push(n);
                            d = rd;
                        }
                    }
                }
                buf[at..at + 8].copy_from_slice(&(names.as_ptr() as u64).to_le_bytes());
                buf[at + 8] = 0;
                buf[at + 9] = desc::PHYSICAL_COPY;
                buf[at + 10] = d as u8;
                buf[at + 12..at + 16].copy_from_slice(&(names.len() as u32).to_le_bytes());
                arrays.push(names);
            }
        }
    }
    let (option, t) = match timeout {
        Some(t) => (host::opt::SEND_MSG | host::opt::SEND_TIMEOUT, t),
        None => (host::opt::SEND_MSG, host::TIMEOUT_NONE),
    };
    // SAFETY: `buf` holds the message; `regions` and `arrays` hold the
    // memory its descriptors point at, alive until the call returns.
    let mr = unsafe { host::msg(buf.as_mut_ptr(), option, size, 0, host::NULL, t) };
    drop((regions, arrays));
    match mr {
        host::mr::SUCCESS => Ok(()),
        _ => Err(mr as KernReturn),
    }
}

/// Guest port `p`'s receive right moved to the host as host right `name`:
/// the host's death of it kills the port, and what was queued on it
/// follows it.
fn moved_away(proc: &mut Proc, p: &Arc<Port>, name: Name) {
    proc.bridge.moved.insert(name, Arc::downgrade(p));
    if proc.bridge.ensure() {
        host::request(name, host::notify::DEAD_NAME, 1, proc.bridge.control);
    }
    let queued = std::mem::take(&mut p.state.lock().unwrap().queue);
    for m in queued {
        let _ = forward(proc, m, Some(0));
    }
}

/// The host holds a send right to guest port `p`'s export: the first time,
/// the guest right it was made from stays to stand for the host's, and a
/// no-senders notification is armed; after, the guest right is released.
fn held(proc: &mut Proc, p: &Arc<Port>) {
    let Some(e) = proc.bridge.exports.get_mut(&p.id) else {
        kmsg::release_send(proc, p);
        return;
    };
    if e.held {
        kmsg::release_send(proc, p);
        return;
    }
    e.held = true;
    let (recv, notify) = (e.recv, e.notify);
    host::request(recv, host::notify::NO_SENDERS, host::mscount(recv), notify);
}

/// Receives, without blocking, every message the host has for the bridge.
pub fn pump(proc: &mut Proc) {
    if proc.bridge.set == 0 {
        return;
    }
    if proc.bridge.epoch != super::epoch() {
        proc.bridge.reset();
        return;
    }
    let set = proc.bridge.set;
    loop {
        if proc.bridge.buf.len() < RECEIVE_BUFFER {
            proc.bridge.buf.resize(RECEIVE_BUFFER, 0);
        }
        let mut buf = std::mem::take(&mut proc.bridge.buf);
        let option = host::opt::RCV_MSG
            | host::opt::RCV_TIMEOUT
            | host::opt::RCV_LARGE
            | host::opt::TRAILER_AUDIT;
        // SAFETY: `buf` holds `buf.len()` bytes for the message.
        let mr = unsafe { host::msg(buf.as_mut_ptr(), option, 0, buf.len() as u32, set, 0) };
        if mr == host::mr::RCV_TOO_LARGE {
            let need = u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes")) as usize;
            buf.resize(need + MAX_TRAILER, 0);
            proc.bridge.buf = buf;
            continue;
        }
        if mr != host::mr::SUCCESS {
            proc.bridge.buf = buf;
            break;
        }
        received(proc, &buf);
        proc.bridge.buf = buf;
    }
    kmsg::flush(proc);
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

/// Handles one received host message.
fn received(proc: &mut Proc, raw: &[u8]) {
    let local = u32_at(raw, 12);
    let id = u32_at(raw, 20) as i32;
    match proc.bridge.imports.get(&local) {
        Some(Import::Control) => {
            if id == host::notify::DEAD_NAME {
                // NDR, then the name that died.
                let name = u32_at(raw, HEADER_SIZE + 8);
                proxy_died(proc, name);
            }
        }
        Some(Import::NoSenders(pid)) => {
            let pid = *pid;
            let port = proc.bridge.imports.values().find_map(|i| match i {
                Import::Port(p) if p.id == pid => Some(p.clone()),
                _ => None,
            });
            if let Some(e) = proc.bridge.exports.get_mut(&pid)
                && e.held
            {
                e.held = false;
                if let Some(p) = port {
                    kmsg::release_send(proc, &p);
                }
            }
        }
        Some(Import::Port(p)) => {
            let p = p.clone();
            let m = to_guest(&mut proc.bridge, raw, p);
            kmsg::enqueue(proc, m);
        }
        None => destroy_host(raw),
    }
}

/// The host port behind proxy `name` died.
fn proxy_died(proc: &mut Proc, name: Name) {
    // The notification added a reference to the dead name.
    host::deallocate(name);
    if let Some(p) = proc.bridge.proxies.remove(&name).and_then(|w| w.upgrade()) {
        kmsg::destroy_receive(proc, &p);
    }
    // A moved receive right the host destroyed: the guest port dies.
    if let Some(p) = proc.bridge.moved.remove(&name).and_then(|w| w.upgrade()) {
        p.state.lock().unwrap().host = None;
        kmsg::destroy_receive(proc, &p);
    }
}

/// Releases the rights and memory of a host message the bridge drops.
fn destroy_host(raw: &[u8]) {
    unsafe extern "C" {
        fn mach_msg_destroy(msg: *mut u8);
    }
    let mut copy = raw.to_vec();
    // SAFETY: `copy` holds a received message whose rights and memory are
    // this process's.
    unsafe { mach_msg_destroy(copy.as_mut_ptr()) };
}

/// The guest right standing for host right `name` of type `d`
/// (`MACH_MSG_TYPE_PORT_*`) a message brought.
fn from_host(bridge: &mut Bridge, name: Name, d: u32) -> Option<Right> {
    if name == host::NULL {
        return None;
    }
    if name == host::DEAD {
        return Some(Right::Dead);
    }
    match d {
        host::disp::MOVE_RECEIVE => {
            // A receive right the guest moved to the host comes back to its
            // port.
            if let Some(p) = bridge.moved.remove(&name).and_then(|w| w.upgrade()) {
                // Dropping the port's host send right leaves the receive
                // right under the name.
                p.state.lock().unwrap().host = None;
                if bridge.ensure() {
                    host::join(name, bridge.set);
                    bridge.imports.insert(name, Import::Port(p.clone()));
                }
                return Some(Right::Receive(p));
            }
            // Else a new guest port that the host's messages to it reach.
            let p = Port::new(KObject::None);
            if bridge.ensure() {
                host::join(name, bridge.set);
                bridge.imports.insert(name, Import::Port(p.clone()));
            }
            Some(Right::Receive(p))
        }
        host::disp::MOVE_SEND_ONCE => {
            let p = Port::new(KObject::Proxy(Arc::new(super::HostRight::new(name, true))));
            p.state.lock().unwrap().sorights += 1;
            Some(Right::SendOnce(p))
        }
        _ => {
            // A send right to an export of the bridge's own is a right to
            // its guest port.
            if let Some(Import::Port(p)) = bridge.imports.get(&name) {
                let p = p.clone();
                host::mod_refs(name, host::right::SEND, -1);
                p.state.lock().unwrap().srights += 1;
                return Some(Right::Send(p));
            }
            let p = bridge.proxy(name);
            p.state.lock().unwrap().srights += 1;
            Some(Right::Send(p))
        }
    }
}

/// The guest message a host message to guest port `dest` becomes.
fn to_guest(bridge: &mut Bridge, raw: &[u8], dest: Arc<Port>) -> Message {
    let hbits = u32_at(raw, 0);
    let size = (u32_at(raw, 4) as usize).min(raw.len());
    let reply_name = u32_at(raw, 8);
    let voucher = u32_at(raw, 16);
    let id = u32_at(raw, 20) as i32;
    // On receipt the remote field is the reply right, the local field the
    // destination's.
    let reply_disp = bits::remote(hbits);
    let dest_disp = bits::local(hbits);
    if bits::voucher(hbits) != 0 && voucher != host::NULL {
        host::deallocate(voucher);
    }
    let dest_right = if dest_disp == gdisp::MOVE_SEND_ONCE {
        Right::SendOnce(dest)
    } else {
        dest.state.lock().unwrap().srights += 1;
        Right::Send(dest)
    };
    let reply = from_host(bridge, reply_name, reply_disp);
    let complex = hbits & bits::COMPLEX;
    let body = raw[HEADER_SIZE..size].to_vec();
    let mut items = Vec::new();
    if complex != 0 && body.len() >= 4 {
        let count = u32_at(&body, 0) as usize;
        let mut off = 4;
        for _ in 0..count {
            if off + 12 > body.len() {
                break;
            }
            let t = body[off + 11];
            let len = desc::size(t);
            if off + len > body.len() {
                break;
            }
            match t {
                desc::PORT => {
                    let d = u32::from(body[off + 10]);
                    let right = from_host(bridge, u32_at(&body, off), d);
                    items.push((off, Item::Port { right, disp: d }));
                }
                desc::OOL | desc::OOL_VOLATILE => {
                    let (addr, n) = (u64_at(&body, off), u64::from(u32_at(&body, off + 12)));
                    let data = host::read(addr, n);
                    host::free(addr, n);
                    items.push((
                        off,
                        Item::Ool {
                            data,
                            copy: body[off + 9],
                            page_offset: 0,
                        },
                    ));
                }
                desc::OOL_PORTS => {
                    let (addr, n) = (u64_at(&body, off), u64::from(u32_at(&body, off + 12)));
                    let d = u32::from(body[off + 10]);
                    let names = host::read(addr, n * 4);
                    host::free(addr, n * 4);
                    let rights = names
                        .chunks(4)
                        .map(|c| from_host(bridge, u32::from_le_bytes(c.try_into().unwrap()), d))
                        .collect();
                    items.push((off, Item::OolPorts { rights, disp: d }));
                }
                _ => {}
            }
            off += len;
        }
    }
    // The trailer (MACH_MSG_TRAILER_FORMAT_0 with the audit token) follows
    // the message.
    let t = (size + 3) & !3;
    let sender = if raw.len() >= t + 52 {
        let mut audit = [0u32; 8];
        for (i, w) in audit.iter_mut().enumerate() {
            *w = u32_at(raw, t + 20 + 4 * i);
        }
        Sender {
            sec: [u32_at(raw, t + 12), u32_at(raw, t + 16)],
            audit,
        }
    } else {
        Sender::KERNEL
    };
    Message {
        bits: bits::set(dest_disp, reply_disp, 0, complex),
        dest: dest_right,
        reply,
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items,
        sender,
        aux: Vec::new(),
    }
}
