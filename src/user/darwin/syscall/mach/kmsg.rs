//! Message copy-in, delivery, and copy-out (`osfmk/ipc/ipc_kmsg.c`,
//! `ipc_mqueue.c`, `ipc_right.c`, `ipc_notify.c`).
//!
//! [`copyin`] turns a user message into a [`Message`] that owns its
//! rights and out-of-line data; [`deliver`] hands it to the kernel server
//! of a kernel object's port or queues it on a user port; [`copyout`]
//! gives its rights and memory to the receiving space and lays it out in
//! the receiver's buffer. [`release`] destroys in-transit rights with the
//! notifications XNU sends when the last send right to a port or a
//! send-once right goes away.

use std::sync::Arc;

use crate::user::darwin::mach::ipc::{
    self, KObject, MACH_PORT_DEAD, MACH_PORT_NULL, Object, Port, PortName, Right, disp,
};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{self, HEADER_SIZE, Item, Message, Sender, bits, desc, opt};
use crate::user::darwin::mach::voucher;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::WaitKey;

/// `MACH_NOTIFY_NO_SENDERS`.
pub const MACH_NOTIFY_NO_SENDERS: i32 = 0o106;
/// `MACH_NOTIFY_SEND_ONCE`.
pub const MACH_NOTIFY_SEND_ONCE: i32 = 0o107;
/// `MACH_NOTIFY_DEAD_NAME`.
pub const MACH_NOTIFY_DEAD_NAME: i32 = 0o110;
/// `MACH_NOTIFY_PORT_DESTROYED`.
pub const MACH_NOTIFY_PORT_DESTROYED: i32 = 0o105;
/// `MACH_NOTIFY_PORT_DELETED`.
pub const MACH_NOTIFY_PORT_DELETED: i32 = 0o101;
/// `MACH_NOTIFY_SEND_POSSIBLE`.
pub const MACH_NOTIFY_SEND_POSSIBLE: i32 = 0o102;

/// The largest out-of-line region copied through a kernel buffer
/// (`msg_ool_size_small` = `KHEAP_MAX_SIZE`: 16 KiB on x86-64 kernels,
/// 32 KiB on arm64); larger regions keep their page offset.
fn ool_size_small(proc: &Proc) -> usize {
    match proc.abi {
        crate::user::darwin::abi::DarwinAbi::X86_64 => 16 << 10,
        crate::user::darwin::abi::DarwinAbi::Arm64 => 32 << 10,
    }
}

// ---------------------------------------------------------------------
// Rights in transit

/// Destroys in-transit rights (`ipc_object_destroy`).
pub fn release(proc: &mut Proc, rights: impl IntoIterator<Item = Right>) {
    for r in rights {
        match r {
            Right::Receive(p) => destroy_receive(proc, &p),
            Right::Send(p) => release_send(proc, &p),
            Right::SendOnce(p) => release_send_once(proc, p),
            Right::Dead => {}
        }
    }
}

/// Drops one send right to `port`; the last one fires the port's
/// no-senders request (`ipc_port_release_send`).
pub fn release_send(proc: &mut Proc, port: &Arc<Port>) {
    let fire = {
        let mut st = port.state.lock().unwrap();
        st.srights = st.srights.saturating_sub(1);
        if st.srights == 0 && !st.dead {
            st.no_senders.take().map(|n| (n, st.mscount))
        } else {
            None
        }
    };
    if let Some((notify, mscount)) = fire {
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&msg::NDR_RECORD);
        body.extend_from_slice(&mscount.to_le_bytes());
        notify_msg(proc, notify, MACH_NOTIFY_NO_SENDERS, body);
    }
}

/// Consumes a delivered message's destination right
/// (`ipc_object_copyout_dest`): a send right is released (possibly firing
/// no-senders); a send-once right is used up without a notification.
pub fn consume_dest(proc: &mut Proc, dest: Right) {
    match dest {
        Right::Send(p) => release_send(proc, &p),
        Right::SendOnce(p) => {
            let mut st = p.state.lock().unwrap();
            st.sorights = st.sorights.saturating_sub(1);
        }
        other => release(proc, [other]),
    }
}

/// Destroys a send-once right: a live port receives
/// `MACH_NOTIFY_SEND_ONCE` through it (`ipc_notify_send_once_and_unlock`).
pub fn release_send_once(proc: &mut Proc, port: Arc<Port>) {
    if port.is_dead() || port.is_kernel() {
        let mut st = port.state.lock().unwrap();
        st.sorights = st.sorights.saturating_sub(1);
        return;
    }
    notify_msg(proc, port, MACH_NOTIFY_SEND_ONCE, Vec::new());
}

/// Fires the send-possible requests armed on `port` once its queue has
/// room (`ipc_port_spnotify`): each requester gets
/// `MACH_NOTIFY_SEND_POSSIBLE` naming its right.
pub fn fire_send_possible(proc: &mut Proc, port: &Arc<Port>) {
    let armed = {
        let mut st = port.state.lock().unwrap();
        if st.sp_requests.is_empty() || (st.queue.len() as u32) >= st.qlimit {
            return;
        }
        std::mem::take(&mut st.sp_requests)
    };
    for (name, notify) in armed {
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&msg::NDR_RECORD);
        body.extend_from_slice(&name.to_le_bytes());
        notify_msg(proc, notify, MACH_NOTIFY_SEND_POSSIBLE, body);
    }
}

/// Sends a kernel notification with `id` and `body` through a send-once
/// right to `port` (the right is consumed).
pub fn notify_msg(proc: &mut Proc, port: Arc<Port>, id: i32, body: Vec<u8>) {
    let m = Message {
        bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, 0),
        dest: Right::SendOnce(port),
        reply: None,
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    enqueue(proc, m);
}

/// Destroys a receive right (`ipc_port_destroy`). A port with a
/// port-destroyed request instead travels to its requester in a
/// `MACH_NOTIFY_PORT_DESTROYED` notification. Otherwise the port dies: its
/// queued messages are destroyed, rights to it in the space become dead
/// names (with their dead-name notifications), and its no-senders request
/// goes away.
pub fn destroy_receive(proc: &mut Proc, port: &Arc<Port>) {
    let pd = port.state.lock().unwrap().pd_request.take();
    if let Some(notify) = pd {
        if port.state.lock().unwrap().pset.is_some() {
            leave_sets(proc, port);
        }
        let mut body = vec![0u8; 4 + 12];
        body[0..4].copy_from_slice(&1u32.to_le_bytes());
        body[4 + 10] = disp::MOVE_RECEIVE as u8;
        body[4 + 11] = desc::PORT;
        let m = Message {
            bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, bits::COMPLEX),
            dest: Right::SendOnce(notify),
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: MACH_NOTIFY_PORT_DESTROYED,
            body,
            items: vec![(
                4,
                Item::Port {
                    right: Some(Right::Receive(port.clone())),
                    disp: disp::MOVE_RECEIVE,
                },
            )],
            sender: Sender::KERNEL,
            aux: Vec::new(),
        };
        enqueue(proc, m);
        return;
    }
    let (queue, ns, pset, sp) = {
        let mut st = port.state.lock().unwrap();
        if st.dead {
            return;
        }
        st.dead = true;
        (
            std::mem::take(&mut st.queue),
            st.no_senders.take(),
            st.pset.take(),
            std::mem::take(&mut st.sp_requests),
        )
    };
    if pset.is_some() {
        leave_sets(proc, port);
    }
    proc.ipc.port_died(port);
    for m in queue {
        destroy(proc, m);
    }
    if let Some(n) = ns {
        release_send_once(proc, n);
    }
    // Armed send-possible requests turn into dead-name notifications.
    for (name, n) in sp {
        dead_name_notify(proc, n, name);
    }
    flush(proc);
    proc.post(WaitKey::Port(port.id));
    proc.post(WaitKey::PortSpace(port.id));
}

/// Sends `MACH_NOTIFY_DEAD_NAME` for `name` through `notify`.
fn dead_name_notify(proc: &mut Proc, notify: Arc<Port>, name: PortName) {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&msg::NDR_RECORD);
    body.extend_from_slice(&name.to_le_bytes());
    notify_msg(proc, notify, MACH_NOTIFY_DEAD_NAME, body);
}

/// Sends the notifications the space owes (dead names and deleted names
/// with requests on them).
pub fn flush(proc: &mut Proc) {
    while !proc.ipc.notices.is_empty() {
        let notices = std::mem::take(&mut proc.ipc.notices);
        for n in notices {
            match n {
                ipc::Notice::DeadName(name, notify) => dead_name_notify(proc, notify, name),
                ipc::Notice::PortDeleted(name, notify) => {
                    let mut body = Vec::with_capacity(12);
                    body.extend_from_slice(&msg::NDR_RECORD);
                    body.extend_from_slice(&name.to_le_bytes());
                    notify_msg(proc, notify, MACH_NOTIFY_PORT_DELETED, body);
                }
            }
        }
    }
}

/// Removes `port` from every port set of the space.
pub fn leave_sets(proc: &mut Proc, port: &Arc<Port>) {
    for (name, t) in proc.ipc.names() {
        if t & ipc::ptype::PORT_SET == 0 {
            continue;
        }
        if let Ok(e) = proc.ipc.lookup(name)
            && let Some(Object::Set(set)) = &e.object
        {
            set.members
                .lock()
                .unwrap()
                .retain(|p| !Arc::ptr_eq(p, port));
        }
    }
    port.state.lock().unwrap().pset = None;
}

/// Destroys a message and everything it carries (`ipc_kmsg_destroy`).
pub fn destroy(proc: &mut Proc, mut m: Message) {
    let rights = m.take_rights();
    release(proc, rights);
}

// ---------------------------------------------------------------------
// Delivery

/// Sends a copied-in message to its destination (`ipc_kmsg_send`): a
/// kernel object's server handles it at once and its reply is delivered
/// in turn; a user port queues it; a dead port destroys it.
pub fn deliver(ctx: &mut Ctx<'_>, m: Message) {
    let port = m
        .dest
        .port()
        .cloned()
        .expect("a message's destination is a port");
    if port.is_dead() {
        destroy(ctx.proc, m);
        return;
    }
    if port.is_kernel() {
        if let Some(reply) = crate::user::darwin::mig::serve(ctx, &port, m) {
            deliver(ctx, reply);
        }
        return;
    }
    let mut m = m;
    if let Some(v) = m.voucher.take() {
        m.voucher = Some(revoucher(ctx.proc, v, voucher::sent));
    }
    enqueue(ctx.proc, m);
}

/// The right to the voucher `change` makes of the voucher `v` a message
/// carries (the send right to the old one released), or `v` itself when
/// nothing changes.
fn revoucher(
    proc: &mut Proc,
    v: Right,
    change: impl Fn(&voucher::Attrs) -> Option<voucher::Attrs>,
) -> Right {
    let new = match v
        .port()
        .and_then(|p| voucher::attrs_of(p))
        .and_then(|a| change(a))
    {
        Some(a) => proc.vouchers.canonical(a),
        None => return v,
    };
    if v.port().is_some_and(|p| Arc::ptr_eq(p, &new)) {
        return v;
    }
    new.state.lock().unwrap().srights += 1;
    release(proc, [v]);
    Right::Send(new)
}

/// Queues `m` on its (user) destination port and wakes its receivers.
pub fn enqueue(proc: &mut Proc, m: Message) {
    let port = m
        .dest
        .port()
        .cloned()
        .expect("a message's destination is a port");
    let pset = {
        let mut st = port.state.lock().unwrap();
        if st.dead {
            drop(st);
            destroy(proc, m);
            return;
        }
        st.queue.push_back(m);
        st.pset
    };
    proc.post(WaitKey::Port(port.id));
    crate::user::darwin::kevent::filters::post_machport(proc, port.id);
    if let Some(set) = pset {
        proc.post(WaitKey::Port(set));
        crate::user::darwin::kevent::filters::post_machport(proc, set);
    }
}

/// Whether a send of a message with destination right type `dest_type` to
/// `port` would have to wait for queue space (`ipc_mqueue_send`: a full
/// queue blocks everything but send-once rights).
pub fn queue_full(port: &Port, dest_type: u32) -> bool {
    if port.is_kernel() || dest_type == disp::MOVE_SEND_ONCE {
        return false;
    }
    let st = port.state.lock().unwrap();
    !st.dead && st.queue.len() as u32 >= st.qlimit
}

// ---------------------------------------------------------------------
// Copy-in

/// A user message header (`mach_msg_user_header_t` less its size).
#[derive(Clone, Copy, Debug)]
pub struct UserHeader {
    /// `msgh_bits`.
    pub bits: u32,
    /// `msgh_remote_port`: the destination.
    pub remote: PortName,
    /// `msgh_local_port`: the reply port.
    pub local: PortName,
    /// `msgh_voucher_port`.
    pub voucher: PortName,
    /// `msgh_id`.
    pub id: i32,
}

/// `MACH_MSG_TYPE_PORT_ANY_SEND`.
fn any_send(d: u32) -> bool {
    (disp::MOVE_SEND..=disp::MAKE_SEND_ONCE).contains(&d)
}

fn valid(name: PortName) -> bool {
    name != MACH_PORT_NULL && name != MACH_PORT_DEAD
}

/// A descriptor as the sender wrote it.
#[derive(Clone, Copy, Debug)]
enum UserDesc {
    Port {
        name: PortName,
        disp: u32,
    },
    Ool {
        addr: u64,
        size: u32,
        dealloc: bool,
        copy: u8,
    },
    OolPorts {
        addr: u64,
        count: u32,
        dealloc: bool,
        disp: u32,
    },
    Guarded {
        name: PortName,
        disp: u32,
        flags: u16,
        context: u64,
    },
}

/// Parses and validates the descriptors of a complex message
/// (`ipc_kmsg_measure_descriptors_from_user`, `ipc_kmsg_inflate_*`):
/// returns them with their offsets in `raw`, and the size they take.
fn parse_descriptors(
    raw: &[u8],
    count: u32,
    options: u64,
) -> Result<(Vec<(usize, UserDesc)>, usize), KernReturn> {
    let mut out = Vec::with_capacity(count as usize);
    let mut pos = 0usize;
    for _ in 0..count {
        if pos + 12 > raw.len() {
            return Err(kr::MACH_SEND_MSG_TOO_SMALL);
        }
        let t = raw[pos + 11];
        match t {
            desc::PORT | desc::OOL | desc::OOL_PORTS => {}
            desc::OOL_VOLATILE | desc::GUARDED_PORT
                if options & (opt::SEND_KOBJECT_CALL | opt::SEND_DK_CALL) == 0 => {}
            _ => return Err(kr::MACH_SEND_INVALID_TYPE),
        }
        let size = desc::size(t);
        if pos + size > raw.len() {
            return Err(kr::MACH_SEND_MSG_TOO_SMALL);
        }
        let d = &raw[pos..pos + size];
        let u32_at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().expect("4 bytes"));
        let u64_at = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().expect("8 bytes"));
        let ud = match t {
            desc::PORT => UserDesc::Port {
                name: u32_at(0),
                disp: u32::from(d[10]),
            },
            desc::OOL | desc::OOL_VOLATILE => {
                let copy = d[9];
                if copy != desc::PHYSICAL_COPY && copy != desc::VIRTUAL_COPY {
                    return Err(kr::MACH_SEND_INVALID_TYPE);
                }
                UserDesc::Ool {
                    addr: u64_at(0),
                    size: u32_at(12),
                    dealloc: d[8] != 0,
                    copy,
                }
            }
            desc::OOL_PORTS => UserDesc::OolPorts {
                addr: u64_at(0),
                count: u32_at(12),
                dealloc: d[8] != 0,
                disp: u32::from(d[10]),
            },
            _ => {
                let flags = u16::from_le_bytes([d[8], d[9]]);
                let context = u64_at(0);
                // Only MOVE_RECEIVE, with a valid, consistent guard.
                if u32::from(d[10]) != disp::MOVE_RECEIVE
                    || flags == 0
                    || flags & !0x3 != 0
                    || (flags & 0x2 != 0 && context != 0)
                {
                    return Err(kr::MACH_SEND_INVALID_TYPE);
                }
                UserDesc::Guarded {
                    name: u32_at(12),
                    disp: disp::MOVE_RECEIVE,
                    flags,
                    context,
                }
            }
        };
        out.push((pos, ud));
        pos += size;
    }
    Ok((out, pos))
}

/// Copies a right in for a message (`ipc_object_copyin` with
/// `DEADOK`): `None` for a null name, `Right::Dead` for a dead one.
fn copyin_right(proc: &mut Proc, name: PortName, d: u32) -> Result<Option<Right>, KernReturn> {
    if name == MACH_PORT_NULL {
        return Ok(None);
    }
    if name == MACH_PORT_DEAD {
        return Ok(Some(Right::Dead));
    }
    if d == disp::MOVE_RECEIVE {
        // An immovable receive right does not move
        // (ipc_move_receive_allowed: a fatal kGUARD_EXC_IMMOVABLE).
        let immovable = proc
            .ipc
            .lookup(name)
            .ok()
            .filter(|e| e.receive)
            .and_then(|e| e.port().cloned())
            .is_some_and(|p| p.state.lock().unwrap().immovable_receive());
        if immovable {
            super::guard::raise(proc, name, super::guard::reason::IMMOVABLE, 0);
            return Err(kr::KERN_INVALID_CAPABILITY);
        }
    }
    let r = proc.ipc.copyin(name, d)?;
    if let Right::Receive(p) = &r {
        // In transit, the receive right leaves its port set and its guard
        // (ipc_port_mark_in_limbo).
        p.state.lock().unwrap().unguard();
        if p.state.lock().unwrap().pset.is_some() {
            leave_sets(proc, p);
        }
    }
    Ok(Some(r))
}

/// Copies a user message in (`ipc_kmsg_copyin_from_user`). `raw` is the
/// whole message as the sender laid it out (`send_size` bytes) and
/// `dsc_count` its descriptor count; on failure every right already taken
/// from the space is destroyed.
pub fn copyin(
    ctx: &mut Ctx<'_>,
    h: &UserHeader,
    raw: &[u8],
    dsc_count: u32,
    options: u64,
    sender: Sender,
) -> Result<Message, KernReturn> {
    let mbits = h.bits & bits::USER;
    let complex = mbits & bits::COMPLEX != 0;
    // Step 1: validate the descriptors' layout.
    let (descs, dsize) = if complex {
        parse_descriptors(&raw[HEADER_SIZE + 4..], dsc_count, options)?
    } else {
        (Vec::new(), 0)
    };

    // Step 2: the header (ipc_kmsg_copyin_header_validate / _rights).
    let reply_type = bits::local(mbits);
    let dest_type = bits::remote(mbits);
    let voucher_type = bits::voucher(mbits);
    if reply_type == 0 {
        if h.local != MACH_PORT_NULL {
            return Err(kr::MACH_SEND_INVALID_HEADER);
        }
    } else if !any_send(reply_type) {
        return Err(kr::MACH_SEND_INVALID_HEADER);
    }
    let voucher_name = match voucher_type {
        0 => MACH_PORT_NULL,
        disp::MOVE_SEND | disp::COPY_SEND if h.voucher != MACH_PORT_DEAD => h.voucher,
        _ => return Err(kr::MACH_SEND_INVALID_VOUCHER),
    };
    if !any_send(dest_type) {
        return Err(kr::MACH_SEND_INVALID_HEADER);
    }
    if !valid(h.remote) {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    if h.remote == voucher_name && dest_type != disp::MOVE_SEND && dest_type != disp::COPY_SEND {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    if h.remote == h.local
        && (dest_type == disp::MOVE_SEND_ONCE || reply_type == disp::MOVE_SEND_ONCE)
    {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    if valid(h.local) && h.local == voucher_name {
        return Err(kr::MACH_SEND_INVALID_REPLY);
    }
    let port_rights = ipc::ptype::SEND | ipc::ptype::RECEIVE | ipc::ptype::SEND_ONCE;
    if voucher_name != MACH_PORT_NULL {
        let ok = ctx.proc.ipc.lookup(voucher_name).is_ok_and(|e| {
            e.send > 0
                && e.port()
                    .is_some_and(|p| matches!(p.kobject, KObject::Voucher(_)))
        });
        if !ok {
            return Err(kr::MACH_SEND_INVALID_VOUCHER);
        }
    }
    if !ctx
        .proc
        .ipc
        .lookup(h.remote)
        .is_ok_and(|e| e.port_type() & port_rights != 0)
    {
        return Err(kr::MACH_SEND_INVALID_DEST);
    }
    if valid(h.local) {
        let ok = ctx.proc.ipc.lookup(h.local).is_ok_and(|e| {
            // ipc_right_copyin_check_reply
            match reply_type {
                disp::MAKE_SEND | disp::MAKE_SEND_ONCE => e.receive,
                disp::COPY_SEND | disp::MOVE_SEND => e.send > 0 || e.dead > 0,
                disp::MOVE_SEND_ONCE => e.send_once || e.dead > 0,
                _ => false,
            }
        });
        if !ok {
            return Err(kr::MACH_SEND_INVALID_REPLY);
        }
    }
    let dest = match ctx.proc.ipc.copyin(h.remote, dest_type) {
        Ok(Right::Dead) | Err(_) => return Err(kr::MACH_SEND_INVALID_DEST),
        Ok(r) => r,
    };
    let voucher = if voucher_name != MACH_PORT_NULL {
        match ctx.proc.ipc.copyin(voucher_name, voucher_type) {
            Ok(r) => Some(r),
            Err(_) => {
                release(ctx.proc, [dest]);
                return Err(kr::MACH_SEND_INVALID_VOUCHER);
            }
        }
    } else {
        None
    };
    let reply = match copyin_right(ctx.proc, h.local, reply_type) {
        Ok(r) => r,
        Err(_) => {
            release(ctx.proc, std::iter::once(dest).chain(voucher));
            return Err(kr::MACH_SEND_INVALID_REPLY);
        }
    };
    let kbits = bits::set(
        disp::copyin_type(dest_type),
        disp::copyin_type(reply_type),
        if voucher.is_some() {
            disp::MOVE_SEND
        } else {
            voucher_type
        },
        mbits,
    );
    let mut m = Message {
        bits: kbits,
        dest,
        reply,
        voucher,
        voucher_name: if voucher_type == 0 {
            h.voucher
        } else {
            MACH_PORT_NULL
        },
        id: h.id,
        body: raw[HEADER_SIZE..].to_vec(),
        items: Vec::new(),
        sender,
        aux: Vec::new(),
    };
    if !complex {
        return Ok(m);
    }
    m.body[..4].copy_from_slice(&dsc_count.to_le_bytes());

    // Step 3: the body's rights and memory (ipc_kmsg_copyin_body).
    let small = ool_size_small(ctx.proc);
    let page_mask = ctx.proc.vm.page - 1;
    for (pos, d) in descs {
        let r: Result<Item, KernReturn> = match d {
            UserDesc::Port { name, disp: ud } => {
                if valid(name) && !disp::is_port_right(ud) {
                    Err(kr::MACH_SEND_INVALID_RIGHT)
                } else {
                    copyin_right(ctx.proc, name, ud)
                        .map(|right| Item::Port {
                            right,
                            disp: disp::copyin_type(ud),
                        })
                        .map_err(|_| kr::MACH_SEND_INVALID_RIGHT)
                }
            }
            UserDesc::Ool {
                addr,
                size,
                dealloc,
                copy,
            } => {
                let mut data = vec![0u8; size as usize];
                match ctx.proc.space.read(addr, &mut data) {
                    Err(_) if size != 0 => Err(kr::MACH_SEND_INVALID_MEMORY),
                    _ => {
                        if dealloc && size != 0 {
                            let lo = addr & !page_mask;
                            let hi = (addr + u64::from(size) + page_mask) & !page_mask;
                            let _ = ctx.proc.space.unmap(lo, hi - lo);
                        }
                        let page_offset = if size as usize > small {
                            addr & page_mask
                        } else {
                            0
                        };
                        Ok(Item::Ool {
                            data,
                            copy,
                            page_offset,
                        })
                    }
                }
            }
            UserDesc::OolPorts {
                addr,
                count,
                dealloc,
                disp: ud,
            } => {
                let mut names = vec![0u8; count as usize * 4];
                if ctx.proc.space.read(addr, &mut names).is_err() && count != 0 {
                    Err(kr::MACH_SEND_INVALID_MEMORY)
                } else {
                    if dealloc && count != 0 {
                        let lo = addr & !page_mask;
                        let hi = (addr + u64::from(count) * 4 + page_mask) & !page_mask;
                        let _ = ctx.proc.space.unmap(lo, hi - lo);
                    }
                    let mut rights = Vec::with_capacity(count as usize);
                    let mut err = None;
                    for c in names.chunks(4) {
                        let n = u32::from_le_bytes(c.try_into().expect("4 bytes"));
                        match copyin_right(ctx.proc, n, ud) {
                            Ok(r) => rights.push(r),
                            Err(_) => {
                                err = Some(kr::MACH_SEND_INVALID_RIGHT);
                                break;
                            }
                        }
                    }
                    match err {
                        Some(e) => {
                            release(ctx.proc, rights.into_iter().flatten());
                            Err(e)
                        }
                        None => Ok(Item::OolPorts {
                            rights,
                            disp: disp::copyin_type(ud),
                        }),
                    }
                }
            }
            UserDesc::Guarded {
                name,
                disp: ud,
                flags,
                context,
            } => {
                // ipc_right_copyin_check_guard_locked: the descriptor names
                // the port's guard, or an unguarded port with
                // MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND and no context.
                let port = if valid(name) {
                    ctx.proc
                        .ipc
                        .lookup(name)
                        .ok()
                        .filter(|e| e.receive)
                        .and_then(|e| e.port().cloned())
                } else {
                    None
                };
                let guard_ok = port.as_ref().is_none_or(|p| {
                    let st = p.state.lock().unwrap();
                    (flags & 0x2 != 0 && !st.guarded() && context == 0)
                        || (st.guarded() && st.context == context)
                });
                if !guard_ok {
                    let context = port.as_ref().map_or(0, |p| p.state.lock().unwrap().context);
                    super::guard::raise(
                        ctx.proc,
                        name,
                        super::guard::reason::INCORRECT_GUARD,
                        context,
                    );
                    Err(kr::MACH_SEND_INVALID_RIGHT)
                } else {
                    if let Some(p) = &port {
                        p.state.lock().unwrap().flags &=
                            !crate::user::darwin::mach::ipc::status::GUARD_IMMOVABLE_RECEIVE;
                    }
                    copyin_right(ctx.proc, name, ud)
                        .map(|right| Item::Guarded {
                            right,
                            disp: disp::copyin_type(ud),
                            // Cleared again when the receiver guards the
                            // port.
                            flags: flags | 0x2,
                            context,
                        })
                        .map_err(|_| kr::MACH_SEND_INVALID_RIGHT)
                }
            }
        };
        match r {
            Ok(item) => m.items.push((4 + pos, item)),
            Err(e) => {
                destroy(ctx.proc, m);
                return Err(e);
            }
        }
    }
    let _ = dsize;
    Ok(m)
}

// ---------------------------------------------------------------------
// Copy-out

/// Gives a right to the receiving space (`ipc_kmsg_copyout_port`): its
/// name, `MACH_PORT_DEAD` for a dead right or a dead port.
fn copyout_right(proc: &mut Proc, right: Option<Right>) -> PortName {
    match right {
        None => MACH_PORT_NULL,
        Some(Right::Dead) => MACH_PORT_DEAD,
        Some(r) => {
            if r.port().is_some_and(|p| p.is_dead()) {
                release(proc, [r]);
                return MACH_PORT_DEAD;
            }
            match proc.ipc.insert(r.clone()) {
                Ok(n) => n,
                Err(_) => {
                    release(proc, [r]);
                    MACH_PORT_DEAD
                }
            }
        }
    }
}

/// Copies a received message out to the receiving space
/// (`ipc_kmsg_copyout` and `ipc_kmsg_deflate`): its rights get names,
/// its out-of-line data new memory. Returns the bytes of the message
/// (header and body; the caller appends the trailer) and the copy-out
/// status bits (`MACH_MSG_IPC_SPACE`, `MACH_MSG_VM_SPACE`, ...).
pub fn copyout(
    proc: &mut Proc,
    mut m: Message,
    options: u64,
    rcv_addr: u64,
) -> (Vec<u8>, KernReturn) {
    let mut status = kr::MACH_MSG_SUCCESS;
    let dest_type = bits::remote(m.bits);
    let reply_type = bits::local(m.bits);
    let mut voucher_type = bits::voucher(m.bits);

    // Header: reply right, voucher, then the destination.
    let reply_name = copyout_right(proc, m.reply.take());
    let voucher_name = match m.voucher.take() {
        Some(v) if options & opt::RCV_VOUCHER != 0 => {
            // ipc_importance_receive, ipc_voucher_receive_postprocessing.
            let v = revoucher(proc, v, |a| Some(voucher::received(a)));
            copyout_right(proc, Some(v))
        }
        Some(v) => {
            voucher_type = 0;
            release(proc, [v]);
            MACH_PORT_NULL
        }
        None if voucher_type != 0 => {
            if options & opt::RCV_VOUCHER == 0 {
                voucher_type = 0;
            }
            MACH_PORT_NULL
        }
        None => m.voucher_name,
    };
    let dest = std::mem::replace(&mut m.dest, Right::Dead);
    let dport = dest
        .port()
        .cloned()
        .expect("a message's destination is a port");
    let dest_name = if dport.is_dead() {
        MACH_PORT_DEAD
    } else {
        proc.ipc
            .name_of(&dport)
            .filter(|&n| proc.ipc.lookup(n).is_ok_and(|e| e.receive))
            .unwrap_or(MACH_PORT_NULL)
    };
    consume_dest(proc, dest);
    status |= copyout_body(proc, &mut m, options, rcv_addr);

    let hbits = bits::set(reply_type, dest_type, voucher_type, m.bits);
    (
        header_bytes(&m, hbits, reply_name, dest_name, voucher_name),
        status,
    )
}

fn header_bytes(
    m: &Message,
    hbits: u32,
    remote: PortName,
    local: PortName,
    voucher: PortName,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(m.size());
    out.extend_from_slice(&hbits.to_le_bytes());
    out.extend_from_slice(&(m.size() as u32).to_le_bytes());
    out.extend_from_slice(&remote.to_le_bytes());
    out.extend_from_slice(&local.to_le_bytes());
    out.extend_from_slice(&voucher.to_le_bytes());
    out.extend_from_slice(&m.id.to_le_bytes());
    out.extend_from_slice(&m.body);
    out
}

/// Gives a failed send's message back to the sender
/// (`ipc_kmsg_copyout_pseudo`): the destination and reply rights return
/// to the space as the rights the message held, the descriptors are copied
/// out as for a receive, and the header keeps the sender's orientation.
pub fn copyout_pseudo(proc: &mut Proc, mut m: Message, rcv_addr: u64) -> (Vec<u8>, KernReturn) {
    let dest = std::mem::replace(&mut m.dest, Right::Dead);
    let dest_name = copyout_right(proc, Some(dest));
    let reply_name = copyout_right(proc, m.reply.take());
    let voucher_name = match m.voucher.take() {
        Some(v) => copyout_right(proc, Some(v)),
        None => m.voucher_name,
    };
    let status = copyout_body(proc, &mut m, opt::RCV_GUARDED_DESC, rcv_addr);
    let hbits = m.bits & bits::USER;
    (
        header_bytes(&m, hbits, dest_name, reply_name, voucher_name),
        status,
    )
}

/// Copies a message's descriptors out (`ipc_kmsg_copyout_descriptors`),
/// rewriting them in `m.body`; returns the `MACH_MSG_*` status bits.
fn copyout_body(proc: &mut Proc, m: &mut Message, options: u64, rcv_addr: u64) -> KernReturn {
    let mut status = kr::MACH_MSG_SUCCESS;
    let small = ool_size_small(proc);
    for (pos, item) in std::mem::take(&mut m.items) {
        match item {
            Item::Port { right, disp: d } => {
                let name = copyout_right(proc, right);
                m.body[pos..pos + 4].copy_from_slice(&name.to_le_bytes());
                m.body[pos + 4..pos + 10].fill(0);
                m.body[pos + 10] = d as u8;
            }
            Item::Guarded {
                right,
                disp: d,
                flags,
                context,
            } => {
                // ipc_kmsg_copyout_guarded_port_descriptor: without
                // MACH_RCV_GUARDED_DESC the right is destroyed. With
                // MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE the receiver's
                // port is guarded by the receive buffer's address
                // (ipc_right_copyout_recv_and_unlock_space).
                let (name, ctxv, fl) = if options & opt::RCV_GUARDED_DESC == 0 {
                    release(proc, right);
                    (MACH_PORT_NULL, 0, flags)
                } else {
                    let port = right.as_ref().and_then(|r| r.port().cloned());
                    let name = copyout_right(proc, right);
                    match port {
                        Some(p) if flags & 0x1 != 0 && name != MACH_PORT_DEAD => {
                            let mut st = p.state.lock().unwrap();
                            st.context = rcv_addr;
                            st.flags |= crate::user::darwin::mach::ipc::status::GUARDED
                                | crate::user::darwin::mach::ipc::status::GUARD_IMMOVABLE_RECEIVE;
                            st.flags &= !crate::user::darwin::mach::ipc::status::STRICT_GUARD;
                            (name, rcv_addr, flags & !0x2)
                        }
                        _ => (name, context, flags),
                    }
                };
                m.body[pos..pos + 8].copy_from_slice(&ctxv.to_le_bytes());
                m.body[pos + 8..pos + 10].copy_from_slice(&fl.to_le_bytes());
                m.body[pos + 10] = d as u8;
                m.body[pos + 12..pos + 16].copy_from_slice(&name.to_le_bytes());
            }
            Item::Ool {
                data,
                copy,
                page_offset,
            } => {
                let size = data.len();
                let addr = if size == 0 {
                    0
                } else {
                    let off = if size > small { page_offset } else { 0 };
                    match super::vm::allocate_kernel(
                        proc,
                        off + size as u64,
                        super::vm::VM_MEMORY_MACH_MSG,
                    ) {
                        Ok(base) => {
                            let _ = proc.space.write(base + off, &data);
                            base + off
                        }
                        Err(k) => {
                            status |= if k == kr::KERN_RESOURCE_SHORTAGE {
                                kr::MACH_MSG_VM_KERNEL
                            } else {
                                kr::MACH_MSG_VM_SPACE
                            };
                            0
                        }
                    }
                };
                let size = if addr == 0 { 0 } else { size as u32 };
                m.body[pos..pos + 8].copy_from_slice(&addr.to_le_bytes());
                m.body[pos + 8] = u8::from(copy == desc::VIRTUAL_COPY);
                m.body[pos + 9] = copy;
                m.body[pos + 10] = 0;
                m.body[pos + 12..pos + 16].copy_from_slice(&size.to_le_bytes());
            }
            Item::OolPorts { rights, disp: d } => {
                let count = rights.len();
                let mut addr = 0u64;
                if count != 0 {
                    match super::vm::allocate_kernel(
                        proc,
                        count as u64 * 4,
                        super::vm::VM_MEMORY_MACH_MSG,
                    ) {
                        Ok(base) => {
                            let names: Vec<u8> = rights
                                .into_iter()
                                .flat_map(|r| copyout_right(proc, r).to_le_bytes())
                                .collect();
                            let _ = proc.space.write(base, &names);
                            addr = base;
                        }
                        Err(_) => {
                            release(proc, rights.into_iter().flatten());
                            status |= kr::MACH_MSG_VM_SPACE;
                        }
                    }
                }
                m.body[pos..pos + 8].copy_from_slice(&addr.to_le_bytes());
                m.body[pos + 8] = 1;
                m.body[pos + 9] = desc::VIRTUAL_COPY;
                m.body[pos + 10] = d as u8;
            }
        }
    }

    status
}

/// A received message reduced to its header (`ipc_kmsg_copyout_dest_to_user`,
/// used when it does not fit): the reply, voucher, and body are destroyed.
pub fn copyout_dest_only(proc: &mut Proc, mut m: Message) -> Vec<u8> {
    let dest_type = bits::remote(m.bits);
    let reply_type = bits::local(m.bits);
    let voucher_type = bits::voucher(m.bits);
    let voucher_name = if m.voucher.is_some() {
        MACH_PORT_NULL
    } else {
        m.voucher_name
    };
    let reply_name = match &m.reply {
        None => MACH_PORT_NULL,
        Some(Right::Dead) => MACH_PORT_DEAD,
        Some(_) => MACH_PORT_NULL,
    };
    let dest = std::mem::replace(&mut m.dest, Right::Dead);
    let dport = dest
        .port()
        .cloned()
        .expect("a message's destination is a port");
    let dest_name = if dport.is_dead() {
        MACH_PORT_DEAD
    } else {
        proc.ipc.name_of(&dport).unwrap_or(MACH_PORT_NULL)
    };
    consume_dest(proc, dest);
    let rest = m.take_rights();
    release(proc, rest);
    let hbits = bits::set(reply_type, dest_type, voucher_type, m.bits & !bits::COMPLEX);
    let mut out = Vec::with_capacity(HEADER_SIZE);
    out.extend_from_slice(&hbits.to_le_bytes());
    out.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&reply_name.to_le_bytes());
    out.extend_from_slice(&dest_name.to_le_bytes());
    out.extend_from_slice(&voucher_name.to_le_bytes());
    out.extend_from_slice(&m.id.to_le_bytes());
    out
}
