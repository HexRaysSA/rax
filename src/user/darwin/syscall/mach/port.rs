//! Mach port operations on the calling task's name space
//! (`osfmk/ipc/mach_port.c`), shared by the `_kernelrpc_mach_port_*` traps
//! (`mach_kernelrpc.c`) and the `mach_port` MIG subsystem.

use std::sync::Arc;

use super::guard::{self, reason};
use super::kmsg;
use crate::user::darwin::mach::ipc::{
    self, KObject, MACH_PORT_DEAD, MACH_PORT_NULL, Object, Port, PortName, Right, disp, right,
};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::process::Proc;

/// `MACH_PORT_QLIMIT_MAX`.
pub const QLIMIT_MAX: u32 = 1024;

pub use crate::user::darwin::mach::ipc::status;

/// `MACH_NOTIFY_*` ids accepted by `mach_port_request_notification`.
mod notify {
    pub const PORT_DESTROYED: i32 = 0o105;
    pub const NO_SENDERS: i32 = 0o106;
    pub const SEND_POSSIBLE: i32 = 0o102;
    pub const DEAD_NAME: i32 = 0o110;
}

fn valid(name: PortName) -> bool {
    name != MACH_PORT_NULL && name != MACH_PORT_DEAD
}

/// The port of the receive right `name` (`ipc_port_translate_receive`).
fn receive_port(proc: &Proc, name: PortName) -> Result<Arc<Port>, KernReturn> {
    let e = proc.ipc.lookup(name)?;
    match e.port() {
        Some(p) if e.receive => Ok(p.clone()),
        _ => Err(kr::KERN_INVALID_RIGHT),
    }
}

/// Whether `name` is a send right to the calling task's control port
/// (`port_name_to_current_task_noref`).
pub fn is_self_task(proc: &Proc, name: PortName) -> bool {
    proc.ipc
        .lookup(name)
        .ok()
        .filter(|e| e.send > 0)
        .and_then(|e| e.port().cloned())
        .is_some_and(|p| p.kobject == KObject::Task && Arc::ptr_eq(&p, &proc.task_port))
}

/// `mach_port_names`: every name in use with its type, in name order.
pub fn names(proc: &Proc) -> Vec<(PortName, u32)> {
    let mut v = proc.ipc.names();
    v.sort_by_key(|n| n.0);
    v
}

/// `mach_port_type`.
pub fn port_type(proc: &Proc, name: PortName) -> Result<u32, KernReturn> {
    if !valid(name) {
        return Err(kr::KERN_INVALID_NAME);
    }
    Ok(proc.ipc.lookup(name)?.port_type())
}

/// `mach_port_allocate`.
pub fn allocate(proc: &mut Proc, r: u32) -> Result<PortName, KernReturn> {
    match r {
        right::RECEIVE => proc.ipc.alloc_receive().map(|(n, _)| n),
        right::DEAD_NAME => proc.ipc.alloc_dead_name(),
        right::PORT_SET => proc.ipc.alloc_set().map(|(n, _)| n),
        _ => Err(kr::KERN_INVALID_VALUE),
    }
}

/// `mach_port_allocate_name` (`mach_port_allocate_full` with a name). A
/// dead name ignores the requested name, as `ipc_object_alloc_dead`
/// does.
pub fn allocate_name(proc: &mut Proc, r: u32, name: PortName) -> Result<PortName, KernReturn> {
    if !valid(name) {
        return Err(kr::KERN_INVALID_VALUE);
    }
    match r {
        right::RECEIVE => {
            let port = Port::new(KObject::None);
            proc.ipc
                .copyout_name(name, Right::Receive(port))
                .map_err(|(k, _)| k)?;
            Ok(name)
        }
        right::PORT_SET => proc.ipc.alloc_set_named(name).map(|_| name),
        right::DEAD_NAME => proc.ipc.alloc_dead_name(),
        _ => Err(kr::KERN_INVALID_VALUE),
    }
}

/// `mach_port_destroy`: every right under `name` goes away.
pub fn destroy(proc: &mut Proc, name: PortName) -> KernReturn {
    if !valid(name) {
        return kr::KERN_SUCCESS;
    }
    let set = match proc.ipc.lookup(name) {
        Ok(e) => {
            let guarded = e
                .port()
                .filter(|_| e.receive)
                .map(|p| p.state.lock().unwrap())
                .filter(|st| st.guarded())
                .map(|st| st.context);
            if let Some(context) = guarded {
                guard::raise(proc, name, reason::DESTROY, context);
                return kr::KERN_INVALID_RIGHT;
            }
            match &e.object {
                Some(Object::Set(s)) => Some(s.clone()),
                _ => None,
            }
        }
        Err(k) => {
            guard::raise(proc, name, reason::INVALID_NAME, 0);
            return k;
        }
    };
    match proc.ipc.remove(name) {
        Ok(rights) => {
            if let Some(set) = set {
                destroy_set(&set);
            }
            kmsg::release(proc, rights);
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

/// A destroyed port set's members leave it.
fn destroy_set(set: &Arc<ipc::PortSet>) {
    for p in set.members.lock().unwrap().drain(..) {
        p.state.lock().unwrap().pset = None;
    }
}

/// `mach_port_deallocate`: one user reference of a send, send-once, or
/// dead-name right.
pub fn deallocate(proc: &mut Proc, name: PortName) -> KernReturn {
    if !valid(name) {
        return kr::KERN_SUCCESS;
    }
    let kind = match proc.ipc.lookup(name) {
        Ok(e) if e.send > 0 => right::SEND,
        Ok(e) if e.send_once => right::SEND_ONCE,
        Ok(e) if e.dead > 0 => right::DEAD_NAME,
        Ok(_) => {
            let bits = guard::entry_bits(proc, name);
            guard::raise(
                proc,
                name,
                reason::INVALID_RIGHT,
                guard::payload(guard::FLAG_DEALLOC, 0, bits),
            );
            return kr::KERN_INVALID_RIGHT;
        }
        Err(k) => {
            guard::raise(proc, name, reason::INVALID_NAME, 0);
            return k;
        }
    };
    match proc.ipc.drop_refs(name, kind, 1) {
        Ok(rights) => {
            kmsg::release(proc, rights);
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

/// `mach_port_get_refs`.
pub fn get_refs(proc: &Proc, name: PortName, r: u32) -> Result<u32, KernReturn> {
    if r > right::DEAD_NAME {
        return Err(kr::KERN_INVALID_VALUE);
    }
    if !valid(name) {
        // A null or dead name "holds" one reference of a send or
        // send-once right.
        return if r == right::SEND || r == right::SEND_ONCE {
            Ok(1)
        } else {
            Err(kr::KERN_INVALID_NAME)
        };
    }
    let e = proc.ipc.lookup(name)?;
    Ok(match r {
        right::SEND => e.send,
        right::RECEIVE => u32::from(e.receive),
        right::SEND_ONCE => u32::from(e.send_once),
        right::PORT_SET => u32::from(matches!(e.object, Some(Object::Set(_)))),
        _ => e.dead,
    })
}

/// `mach_port_mod_refs`.
pub fn mod_refs(proc: &mut Proc, name: PortName, r: u32, delta: i32) -> KernReturn {
    if r > right::DEAD_NAME {
        return kr::KERN_INVALID_VALUE;
    }
    if !valid(name) {
        return if r == right::SEND || r == right::SEND_ONCE {
            kr::KERN_SUCCESS
        } else {
            kr::KERN_INVALID_NAME
        };
    }
    let bits = guard::entry_bits(proc, name);
    let set = match proc.ipc.lookup(name) {
        Ok(e) => {
            let guarded = e
                .port()
                .filter(|_| r == right::RECEIVE && delta < 0 && e.receive)
                .map(|p| p.state.lock().unwrap())
                .filter(|st| st.guarded())
                .map(|st| st.context);
            if let Some(context) = guarded {
                guard::raise(proc, name, reason::DESTROY, context);
                return kr::KERN_INVALID_RIGHT;
            }
            match &e.object {
                Some(Object::Set(s)) if r == right::PORT_SET => Some(s.clone()),
                _ => None,
            }
        }
        Err(k) => {
            guard::raise(proc, name, reason::INVALID_NAME, 0);
            return k;
        }
    };
    let result = if delta >= 0 {
        proc.ipc
            .add_refs(name, r, delta as u32)
            .err()
            .unwrap_or(kr::KERN_SUCCESS)
    } else {
        match proc.ipc.drop_refs(name, r, delta.unsigned_abs()) {
            Ok(rights) => {
                if let Some(set) = set.filter(|_| proc.ipc.lookup(name).is_err()) {
                    destroy_set(&set);
                }
                kmsg::release(proc, rights);
                kr::KERN_SUCCESS
            }
            Err(k) => k,
        }
    };
    match result {
        kr::KERN_INVALID_RIGHT => guard::raise(
            proc,
            name,
            reason::INVALID_RIGHT,
            guard::payload(guard::FLAG_DELTA, r, bits),
        ),
        kr::KERN_INVALID_VALUE => guard::raise(
            proc,
            name,
            reason::INVALID_VALUE,
            guard::payload3(guard::FLAG_DELTA, r, delta as u16, bits as u16),
        ),
        _ => {}
    }
    result
}

/// `mach_port_set_mscount`.
pub fn set_mscount(proc: &Proc, name: PortName, mscount: u32) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_RIGHT;
    }
    match receive_port(proc, name) {
        Ok(p) => {
            p.state.lock().unwrap().mscount = mscount;
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

/// `mach_port_set_seqno`.
pub fn set_seqno(proc: &Proc, name: PortName, seqno: u32) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_RIGHT;
    }
    match receive_port(proc, name) {
        Ok(p) => {
            p.state.lock().unwrap().seqno = seqno;
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

/// `mach_port_get_context`: a strictly guarded port hides its guard.
pub fn get_context(proc: &Proc, name: PortName) -> Result<u64, KernReturn> {
    if !valid(name) {
        return Err(kr::KERN_INVALID_RIGHT);
    }
    let p = receive_port(proc, name)?;
    let st = p.state.lock().unwrap();
    Ok(if st.strict_guard() { 0 } else { st.context })
}

/// `mach_port_set_context`: the context of a guarded port is its guard;
/// a strict guard may not change (a fatal `kGUARD_EXC_SET_CONTEXT`).
pub fn set_context(proc: &mut Proc, name: PortName, context: u64) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_RIGHT;
    }
    let p = match receive_port(proc, name) {
        Ok(p) => p,
        Err(k) => return k,
    };
    let (strict, portguard) = {
        let st = p.state.lock().unwrap();
        (st.strict_guard(), st.context)
    };
    if strict {
        guard::raise(proc, name, reason::SET_CONTEXT, portguard);
        return kr::KERN_INVALID_ARGUMENT;
    }
    p.state.lock().unwrap().context = context;
    kr::KERN_SUCCESS
}

/// `mach_port_get_set_status`: the member receive rights' names.
pub fn get_set_status(proc: &Proc, name: PortName) -> Result<Vec<PortName>, KernReturn> {
    if !valid(name) {
        return Err(kr::KERN_INVALID_RIGHT);
    }
    let set = set_of(proc, name)?;
    let mut names: Vec<PortName> = set
        .members
        .lock()
        .unwrap()
        .iter()
        .filter_map(|p| proc.ipc.name_of(p))
        .collect();
    names.sort_unstable();
    Ok(names)
}

fn set_of(proc: &Proc, name: PortName) -> Result<Arc<ipc::PortSet>, KernReturn> {
    match &proc.ipc.lookup(name)?.object {
        Some(Object::Set(s)) => Ok(s.clone()),
        _ => Err(kr::KERN_INVALID_RIGHT),
    }
}

/// `mach_port_insert_member`.
pub fn insert_member(proc: &Proc, name: PortName, pset: PortName) -> KernReturn {
    if !valid(name) || !valid(pset) {
        return kr::KERN_INVALID_RIGHT;
    }
    let port = match receive_port(proc, name) {
        Ok(p) => p,
        Err(k) => return k,
    };
    let set = match set_of(proc, pset) {
        Ok(s) => s,
        Err(k) => return k,
    };
    let mut members = set.members.lock().unwrap();
    if members.iter().any(|p| Arc::ptr_eq(p, &port)) {
        return kr::KERN_ALREADY_IN_SET;
    }
    members.push(port.clone());
    port.state.lock().unwrap().pset = Some(set.id);
    kr::KERN_SUCCESS
}

/// `mach_port_extract_member`.
pub fn extract_member(proc: &Proc, name: PortName, pset: PortName) -> KernReturn {
    if !valid(name) || !valid(pset) {
        return kr::KERN_INVALID_RIGHT;
    }
    let port = match receive_port(proc, name) {
        Ok(p) => p,
        Err(k) => return k,
    };
    let set = match set_of(proc, pset) {
        Ok(s) => s,
        Err(k) => return k,
    };
    let mut members = set.members.lock().unwrap();
    let Some(i) = members.iter().position(|p| Arc::ptr_eq(p, &port)) else {
        return kr::KERN_NOT_IN_SET;
    };
    members.remove(i);
    port.state.lock().unwrap().pset = None;
    kr::KERN_SUCCESS
}

/// `mach_port_move_member`: `member` leaves its sets and joins `after`
/// (none when `after` is null).
pub fn move_member(proc: &mut Proc, member: PortName, after: PortName) -> KernReturn {
    if !valid(member) {
        return kr::KERN_INVALID_RIGHT;
    }
    let port = match receive_port(proc, member) {
        Ok(p) => p,
        Err(k) => return k,
    };
    if after != MACH_PORT_NULL
        && let Err(k) = set_of(proc, after)
    {
        return k;
    }
    kmsg::leave_sets(proc, &port);
    if after == MACH_PORT_NULL {
        return kr::KERN_SUCCESS;
    }
    insert_member(proc, member, after)
}

/// `mach_port_request_notification`: registers `notify` (a send-once
/// right, or none to cancel) for `id` on `name`; returns the previous
/// request's right.
pub fn request_notification(
    proc: &mut Proc,
    name: PortName,
    id: i32,
    sync: u32,
    notify: Option<Right>,
) -> Result<Option<Right>, KernReturn> {
    let notify = match notify {
        None => None,
        Some(Right::SendOnce(p)) => Some(p),
        Some(Right::Dead) => return Err(kr::KERN_INVALID_CAPABILITY),
        Some(other) => {
            kmsg::release(proc, [other]);
            return Err(kr::KERN_INVALID_CAPABILITY);
        }
    };
    let give_back = |proc: &mut Proc, n: Option<Arc<Port>>| {
        if let Some(n) = n {
            kmsg::release_send_once(proc, n);
        }
    };
    if !valid(name) {
        give_back(proc, notify);
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let so = |p: Option<Arc<Port>>| p.map(Right::SendOnce);
    match id {
        notify::PORT_DESTROYED => {
            if sync != 0 {
                give_back(proc, notify);
                return Err(kr::KERN_INVALID_VALUE);
            }
            let port = match receive_port(proc, name) {
                Ok(p) => p,
                Err(k) => {
                    give_back(proc, notify);
                    return Err(k);
                }
            };
            // ipc_allow_register_pd_notification: a single request.
            let taken = port.state.lock().unwrap().pd_request.is_some();
            if taken {
                give_back(proc, notify);
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            port.state.lock().unwrap().pd_request = notify;
            Ok(None)
        }
        notify::NO_SENDERS => {
            let port = match receive_port(proc, name) {
                Ok(p) => p,
                Err(k) => {
                    give_back(proc, notify);
                    return Err(k);
                }
            };
            let (previous, fire) = {
                let mut st = port.state.lock().unwrap();
                let previous = st.no_senders.take();
                let mscount = st.mscount;
                if st.srights == 0 && sync <= mscount && notify.is_some() {
                    (previous, notify.map(|n| (n, mscount)))
                } else {
                    st.no_senders = notify;
                    (previous, None)
                }
            };
            if let Some((n, mscount)) = fire {
                let mut body = Vec::with_capacity(12);
                body.extend_from_slice(&crate::user::darwin::mach::msg::NDR_RECORD);
                body.extend_from_slice(&mscount.to_le_bytes());
                kmsg::notify_msg(proc, n, kmsg::MACH_NOTIFY_NO_SENDERS, body);
            }
            Ok(so(previous))
        }
        notify::DEAD_NAME => match proc.ipc.request_dead_name(name, notify.clone()) {
            Ok(previous) => Ok(so(previous)),
            Err(k) => {
                give_back(proc, notify);
                Err(k)
            }
        },
        notify::SEND_POSSIBLE => {
            let e = match proc.ipc.lookup(name) {
                Ok(e) => e.clone(),
                Err(k) => {
                    give_back(proc, notify);
                    return Err(k);
                }
            };
            let Some(port) = e
                .port()
                .cloned()
                .filter(|_| e.send > 0 || e.send_once || e.receive)
            else {
                give_back(proc, notify);
                return Err(if e.dead > 0 {
                    kr::KERN_INVALID_ARGUMENT
                } else {
                    kr::KERN_INVALID_RIGHT
                });
            };
            let Some(n) = notify else {
                return Ok(None);
            };
            // Send-once rights, kernel objects, and queues with room fire
            // at once when armed.
            let full = kmsg::queue_full(&port, disp::MOVE_SEND);
            if sync != 0 && (e.send_once || port.is_kernel() || !full) {
                let mut body = Vec::with_capacity(12);
                body.extend_from_slice(&crate::user::darwin::mach::msg::NDR_RECORD);
                body.extend_from_slice(&name.to_le_bytes());
                kmsg::notify_msg(proc, n, kmsg::MACH_NOTIFY_SEND_POSSIBLE, body);
            } else {
                port.state.lock().unwrap().sp_requests.push((name, n));
            }
            Ok(None)
        }
        _ => {
            give_back(proc, notify);
            Err(kr::KERN_INVALID_VALUE)
        }
    }
}

/// `mach_port_insert_right` from the trap: copies `poly` in with
/// disposition `d` and gives it the name `name`.
pub fn insert_right_trap(proc: &mut Proc, name: PortName, poly: PortName, d: u32) -> KernReturn {
    if name == poly && (d == disp::MAKE_SEND || d == disp::COPY_SEND) {
        // ipc_object_insert_send_right: the common fast path.
        let e = match proc.ipc.lookup(name) {
            Ok(e) => e.clone(),
            Err(k) => return k,
        };
        let Some(port) = e.port().cloned() else {
            return kr::KERN_INVALID_CAPABILITY;
        };
        if port.is_dead() {
            return kr::KERN_INVALID_CAPABILITY;
        }
        let ent = proc.ipc.entry_mut(name).expect("looked up");
        if d == disp::MAKE_SEND {
            if !ent.receive {
                return kr::KERN_INVALID_RIGHT;
            }
            let mut st = port.state.lock().unwrap();
            st.mscount += 1;
            if ent.send == 0 {
                st.srights += 1;
            }
        } else if ent.send == 0 {
            return kr::KERN_INVALID_RIGHT;
        }
        // User references stay pegged at the maximum.
        ent.send = (ent.send + 1).min(ipc::UREFS_MAX);
        return kr::KERN_SUCCESS;
    }
    let r = match proc.ipc.copyin(poly, d) {
        Ok(r) => r,
        Err(k) => return k,
    };
    insert_right(proc, name, d, r)
}

/// `mach_port_insert_right` with the right already copied in.
pub fn insert_right(proc: &mut Proc, name: PortName, d: u32, r: Right) -> KernReturn {
    if !valid(name) || !disp::is_port_right(d) {
        kmsg::release(proc, [r]);
        return kr::KERN_INVALID_VALUE;
    }
    match proc.ipc.copyout_name(name, r) {
        Ok(()) => kr::KERN_SUCCESS,
        Err((k, r)) => {
            kmsg::release(proc, [r]);
            k
        }
    }
}

/// `mach_port_extract_right`: takes a right out of the space as a message
/// would carry it.
pub fn extract_right(proc: &mut Proc, name: PortName, d: u32) -> Result<Right, KernReturn> {
    if !disp::is_port_right(d) {
        return Err(kr::KERN_INVALID_VALUE);
    }
    if !valid(name) {
        return Err(kr::KERN_INVALID_RIGHT);
    }
    proc.ipc.copyin(name, d)
}

/// `mach_port_get_attributes` flavors.
mod flavor {
    pub const LIMITS_INFO: i32 = 1;
    pub const RECEIVE_STATUS: i32 = 2;
    pub const DNREQUESTS_SIZE: i32 = 3;
    pub const TEMPOWNER: i32 = 4;
    pub const IMPORTANCE_RECEIVER: i32 = 5;
    pub const DENAP_RECEIVER: i32 = 6;
    pub const INFO_EXT: i32 = 7;
    pub const GUARD_INFO: i32 = 8;
    pub const SERVICE_THROTTLED: i32 = 9;
}

/// `mach_port_get_attributes` with the caller's `count`.
pub fn get_attributes(
    proc: &Proc,
    name: PortName,
    fl: i32,
    count: u32,
) -> Result<Vec<u32>, KernReturn> {
    let need = |n: u32| {
        if count < n {
            Err(kr::KERN_FAILURE)
        } else {
            Ok(())
        }
    };
    match fl {
        flavor::LIMITS_INFO => {
            need(1)?;
            if !valid(name) {
                return Err(kr::KERN_INVALID_RIGHT);
            }
            let p = receive_port(proc, name)?;
            Ok(vec![p.state.lock().unwrap().qlimit])
        }
        flavor::RECEIVE_STATUS | flavor::INFO_EXT => {
            need(if fl == flavor::RECEIVE_STATUS { 10 } else { 17 })?;
            if !valid(name) {
                return Err(kr::KERN_INVALID_RIGHT);
            }
            let p = receive_port(proc, name)?;
            let st = p.state.lock().unwrap();
            // mach_port_status: pset, seqno, mscount, qlimit, msgcount,
            // sorights, srights, pdrequest, nsrequest, flags.
            let mut v = vec![
                u32::from(st.pset.is_some()),
                st.seqno,
                st.mscount,
                st.qlimit,
                st.queue.len() as u32,
                st.sorights,
                u32::from(st.srights > 0),
                u32::from(st.pd_request.is_some()),
                u32::from(st.no_senders.is_some()),
                st.flags,
            ];
            if fl == flavor::INFO_EXT {
                // mpie_boost_cnt, then reserved[6].
                v.extend_from_slice(&[0; 7]);
            }
            Ok(v)
        }
        flavor::DNREQUESTS_SIZE => {
            need(1)?;
            if valid(name) {
                receive_port(proc, name)?;
            }
            Ok(vec![0])
        }
        flavor::GUARD_INFO => {
            need(2)?;
            if !valid(name) {
                return Err(kr::KERN_INVALID_RIGHT);
            }
            let p = receive_port(proc, name)?;
            let st = p.state.lock().unwrap();
            let g = if st.guarded() { st.context } else { 0 };
            Ok(vec![g as u32, (g >> 32) as u32])
        }
        flavor::SERVICE_THROTTLED => {
            need(1)?;
            if !valid(name) {
                return Err(kr::KERN_INVALID_RIGHT);
            }
            receive_port(proc, name)?;
            Err(kr::KERN_INVALID_CAPABILITY)
        }
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// `mach_port_set_attributes`.
pub fn set_attributes(proc: &Proc, name: PortName, fl: i32, info: &[u32]) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_RIGHT;
    }
    match fl {
        flavor::LIMITS_INFO => {
            if info.is_empty() {
                return kr::KERN_FAILURE;
            }
            if info[0] > QLIMIT_MAX {
                return kr::KERN_INVALID_VALUE;
            }
            match receive_port(proc, name) {
                Ok(p) => {
                    p.state.lock().unwrap().qlimit = info[0];
                    kr::KERN_SUCCESS
                }
                Err(k) => k,
            }
        }
        flavor::DNREQUESTS_SIZE => {
            if info.is_empty() {
                return kr::KERN_FAILURE;
            }
            receive_port(proc, name).err().unwrap_or(kr::KERN_SUCCESS)
        }
        flavor::TEMPOWNER | flavor::IMPORTANCE_RECEIVER | flavor::DENAP_RECEIVER => {
            match receive_port(proc, name) {
                Ok(p) => {
                    let mut st = p.state.lock().unwrap();
                    st.flags |= status::IMP_DONATION;
                    if fl == flavor::TEMPOWNER {
                        st.flags |= status::TEMPOWNER;
                    }
                    kr::KERN_SUCCESS
                }
                Err(k) => k,
            }
        }
        _ => kr::KERN_INVALID_ARGUMENT,
    }
}

/// `mach_port_options_t` flags.
mod mpo {
    pub const CONTEXT_AS_GUARD: u32 = 0x01;
    pub const QLIMIT: u32 = 0x02;
    pub const TEMPOWNER: u32 = 0x04;
    pub const IMPORTANCE_RECEIVER: u32 = 0x08;
    pub const INSERT_SEND_RIGHT: u32 = 0x10;
    pub const STRICT: u32 = 0x20;
    pub const DENAP_RECEIVER: u32 = 0x40;
    pub const IMMOVABLE_RECEIVE: u32 = 0x80;
    /// `MPO_OPTIONS_MASK | MPO_PORT_TYPE_MASK`.
    pub const KNOWN: u32 = 0x23ff | 0x1_dc00;
    pub const PORT_TYPE_MASK: u32 = 0x1_dc00;
    pub const CONNECTION_PORT: u32 = 0x800;
}

/// `sizeof(mach_port_options_t)`.
pub const OPTIONS_SIZE: usize = 24;

/// `mach_port_construct` with the caller's `mach_port_options_t`.
pub fn construct(proc: &mut Proc, options: &[u8], context: u64) -> Result<PortName, KernReturn> {
    let w = |o: usize| u32::from_le_bytes(options[o..o + 4].try_into().expect("4 bytes"));
    let (flags, qlimit, service_name) = (w(0), w(4), w(8));
    if flags & !mpo::KNOWN != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let kind = flags & mpo::PORT_TYPE_MASK;
    if !matches!(
        kind,
        0 | 0x400 | 0x800 | 0x1000 | 0x4000 | 0x4400 | 0x8000 | 0x1_0000
    ) {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    if kind == mpo::CONNECTION_PORT && service_name == 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    if flags & mpo::QLIMIT != 0 && qlimit > QLIMIT_MAX {
        return Err(kr::KERN_INVALID_VALUE);
    }
    let (name, port) = proc.ipc.alloc_receive()?;
    let mut st = port.state.lock().unwrap();
    if flags & mpo::QLIMIT != 0 {
        st.qlimit = qlimit;
    }
    if flags & (mpo::IMPORTANCE_RECEIVER | mpo::DENAP_RECEIVER | mpo::TEMPOWNER) != 0 {
        st.flags |= status::IMP_DONATION;
        if flags & mpo::TEMPOWNER != 0 {
            st.flags |= status::TEMPOWNER;
        }
    }
    st.context = context;
    if flags & mpo::CONTEXT_AS_GUARD != 0 {
        st.flags |= status::GUARDED;
        if flags & mpo::STRICT != 0 {
            st.flags |= status::STRICT_GUARD;
        }
    }
    if flags & mpo::IMMOVABLE_RECEIVE != 0 {
        st.flags |= status::GUARD_IMMOVABLE_RECEIVE;
    }
    if flags & mpo::INSERT_SEND_RIGHT != 0 {
        st.srights += 1;
        st.mscount += 1;
        drop(st);
        proc.ipc.entry_mut(name).expect("just allocated").send = 1;
    }
    Ok(name)
}

/// `mach_port_destruct` (`ipc_right_destruct`): drops `-srdelta` send
/// references and destroys the receive right; a guarded port needs its
/// guard (a fatal `kGUARD_EXC_DESTROY` otherwise).
pub fn destruct(proc: &mut Proc, name: PortName, srdelta: i32, g: u64) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_NAME;
    }
    let bits = guard::entry_bits(proc, name);
    let invalid_right = guard::payload(guard::FLAG_DESTRUCT, 0, bits);
    let (port, send) = match proc.ipc.lookup(name) {
        Ok(e) if e.receive => (
            e.port().cloned().expect("receive entries name ports"),
            e.send,
        ),
        Ok(_) => {
            guard::raise(proc, name, reason::INVALID_RIGHT, invalid_right);
            return kr::KERN_INVALID_RIGHT;
        }
        Err(k) => {
            guard::raise(proc, name, reason::INVALID_NAME, 0);
            return k;
        }
    };
    if srdelta != 0 && send == 0 {
        guard::raise(proc, name, reason::INVALID_RIGHT, invalid_right);
        return kr::KERN_INVALID_RIGHT;
    }
    if srdelta > 0 || (srdelta < 0 && srdelta.unsigned_abs() > send) {
        let p = guard::payload(guard::FLAG_DESTRUCT, srdelta as u32, bits & 0xffff);
        guard::raise(proc, name, reason::INVALID_VALUE, p);
        return kr::KERN_INVALID_VALUE;
    }
    let wrong_guard = {
        let st = port.state.lock().unwrap();
        (st.guarded() && st.context != g).then_some(st.context)
    };
    if let Some(context) = wrong_guard {
        guard::raise(proc, name, reason::DESTROY, context);
        return kr::KERN_INVALID_ARGUMENT;
    }
    if srdelta < 0 {
        match proc
            .ipc
            .drop_refs(name, right::SEND, srdelta.unsigned_abs())
        {
            Ok(r) => kmsg::release(proc, r),
            Err(k) => return k,
        }
    }
    port.state.lock().unwrap().unguard();
    match proc.ipc.drop_refs(name, right::RECEIVE, 1) {
        Ok(r) => {
            kmsg::release(proc, r);
            kr::KERN_SUCCESS
        }
        Err(k) => k,
    }
}

/// `mach_port_guard`: the guard becomes the port's context, which must be
/// unset (a non-fatal `kGUARD_EXC_INVALID_ARGUMENT` otherwise).
pub fn guard(proc: &mut Proc, name: PortName, g: u64, strict: bool) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_NAME;
    }
    let port = match receive_port(proc, name) {
        Ok(p) => p,
        Err(k) => {
            // ipc_port_translate_receive's failures.
            let (r, payload) = if k == kr::KERN_INVALID_NAME {
                (reason::INVALID_NAME, 0)
            } else {
                (reason::INVALID_RIGHT, guard::INVALID_RIGHT_RECV)
            };
            guard::raise(proc, name, r, payload);
            return k;
        }
    };
    let context = port.state.lock().unwrap().context;
    if context != 0 {
        guard::raise(proc, name, reason::INVALID_ARGUMENT, context);
        return kr::KERN_INVALID_ARGUMENT;
    }
    let mut st = port.state.lock().unwrap();
    st.context = g;
    st.flags |= status::GUARDED;
    if strict {
        st.flags |= status::STRICT_GUARD;
    }
    kr::KERN_SUCCESS
}

/// `mach_port_unguard`: an unguarded port or a wrong guard is a fatal
/// guard exception.
pub fn unguard(proc: &mut Proc, name: PortName, g: u64) -> KernReturn {
    if !valid(name) {
        return kr::KERN_INVALID_NAME;
    }
    let port = match receive_port(proc, name) {
        Ok(p) => p,
        Err(k) => {
            // ipc_port_translate_receive's failures.
            let (r, payload) = if k == kr::KERN_INVALID_NAME {
                (reason::INVALID_NAME, 0)
            } else {
                (reason::INVALID_RIGHT, guard::INVALID_RIGHT_RECV)
            };
            guard::raise(proc, name, r, payload);
            return k;
        }
    };
    let (guarded, context) = {
        let st = port.state.lock().unwrap();
        (st.guarded(), st.context)
    };
    if !guarded {
        guard::raise(proc, name, reason::UNGUARDED, 0);
        return kr::KERN_INVALID_ARGUMENT;
    }
    if context != g {
        guard::raise(proc, name, reason::INCORRECT_GUARD, context);
        return kr::KERN_INVALID_ARGUMENT;
    }
    port.state.lock().unwrap().unguard();
    kr::KERN_SUCCESS
}

/// `mach_port_get_srights`: the number of send rights to the receive
/// right's port.
pub fn get_srights(proc: &Proc, name: PortName) -> Result<u32, KernReturn> {
    if !valid(name) {
        return Err(kr::KERN_INVALID_RIGHT);
    }
    let p = receive_port(proc, name)?;
    Ok(p.state.lock().unwrap().srights)
}

/// `ipc_info_object_type_t` of a kernel object (`IPC_OTYPE_*`,
/// `osfmk/mach_debug/ipc_info.h`, as `mach_port_kobject_type` maps
/// them); the object address is not disclosed on release kernels.
pub fn kobject_type(k: &KObject) -> u32 {
    match k {
        KObject::None => 0,
        KObject::Thread(_) => 1,
        KObject::Task => 2,
        KObject::Host => 3,
        KObject::HostPriv => 4,
        KObject::Timer(_) => 8,
        KObject::TaskName => 20,
        KObject::Semaphore(_) => 23,
        KObject::Clock(_) => 25,
        KObject::Voucher(_) => 37,
        KObject::TaskIdToken(_) => 50,
        KObject::TaskInspect => 44,
        KObject::TaskRead => 45,
        // What the host says of the port behind it.
        KObject::Proxy(h) => crate::user::darwin::bridge::kobject_type(h),
    }
}

/// `mach_port_kobject`: the type of the object a send or receive right
/// names.
pub fn kobject(proc: &Proc, name: PortName) -> Result<u32, KernReturn> {
    let e = proc.ipc.lookup(name)?;
    match e.port() {
        Some(p) if e.send > 0 || e.receive => Ok(kobject_type(&p.kobject)),
        _ => Err(kr::KERN_INVALID_RIGHT),
    }
}
