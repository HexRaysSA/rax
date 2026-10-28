//! Bounded messages for a Mach kernel-object call across a process link.
//!
//! The port named by a request is resolved by the receiving process. Reply
//! rights remain in the caller until a response or a connection failure;
//! they never travel as raw port names or host addresses. Thread identities
//! in a reply name the receiving process's threads, not host threads.
//!
//! The initial message format carries simple requests and the out-of-line
//! thread-port array returned by `task_threads`. Other descriptor types need
//! their own capability-transfer representation before they can cross.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::sync::Arc;

use super::transport::{self, MAX_FRAME};
use crate::user::darwin::mach::ipc::{KObject, Port, Right};
use crate::user::darwin::process::Proc;

const MAX_BACKLOG: usize = 4 << 20;
const MAX_SERVER_FDS: usize = 128;
const TARGET_INSTANCE_BIT: u64 = 1 << 63;
/// Both endpoints issue handoff generations for a task export. Their
/// namespaces must be disjoint even when their sequence counters coincide.
const TARGET_GENERATION_BIT: u64 = 1 << 63;

/// Encodes a frame, moving large out-of-line memory to a nameless file.
pub(super) fn encode_frame(mut message: Message) -> io::Result<transport::Frame> {
    if let Ok(payload) = message.encode() {
        return Ok(transport::Frame { payload, fd: None });
    }
    let memory = match &mut message {
        Message::Request { memory, .. } | Message::Reply { memory, .. } => memory.as_mut(),
        _ => None,
    }
    .ok_or_else(too_large)?;
    let size = u32::try_from(memory.data.len()).map_err(|_| too_large())?;
    let fd = blob::create(&memory.data)?;
    memory.data.clear();
    let inner = message.encode()?;
    if inner.len() > MAX_FRAME - 5 {
        return Err(too_large());
    }
    let mut payload = Vec::with_capacity(5 + inner.len());
    payload.push(BLOB_TAG);
    payload.extend_from_slice(&size.to_le_bytes());
    payload.extend_from_slice(&inner);
    Ok(transport::Frame {
        payload,
        fd: Some(fd),
    })
}

/// Reconstitutes a snapshot; a host resource failure is reported separately
/// so a valid connection is not mistaken for a dead tracer.
pub(super) fn decode_frame(frame: transport::Frame) -> io::Result<(Message, bool)> {
    if frame.payload.first() != Some(&BLOB_TAG) {
        if frame.fd.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected remote descriptor",
            ));
        }
        return Message::decode(&frame.payload).map(|message| (message, false));
    }
    let fd = frame
        .fd
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing remote descriptor"))?;
    let size = u32::from_le_bytes(
        frame
            .payload
            .get(1..5)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short remote descriptor"))?
            .try_into()
            .expect("four bytes"),
    );
    let mut message = Message::decode(frame.payload.get(5..).unwrap_or_default())?;
    let memory = match &mut message {
        Message::Request { memory, .. } | Message::Reply { memory, .. } => memory.as_mut(),
        _ => None,
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "descriptor without memory"))?;
    if !memory.data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duplicate remote memory",
        ));
    }
    match blob::read(fd, size) {
        Ok(data) => {
            memory.data = data;
            Ok((message, false))
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Err(error),
        Err(_) => Ok((message, true)),
    }
}

#[cfg(test)]
#[path = "remote_mach_tests.rs"]
mod integration_tests;

#[path = "remote_mach_blob.rs"]
mod blob;
#[path = "remote_mach_callback.rs"]
pub(super) mod callback;
#[path = "remote_mach_callback_inherit.rs"]
pub(super) mod callback_inherit;
#[path = "remote_mach_callback_install.rs"]
mod callback_install;
#[path = "remote_mach_callback_return.rs"]
mod callback_return;
#[path = "remote_mach_callback_runtime.rs"]
pub(super) mod callback_runtime;
#[path = "remote_mach_callback_wire.rs"]
pub(super) mod callback_wire;
#[path = "remote_mach_exception.rs"]
mod exception;
#[path = "remote_mach_grant.rs"]
pub(super) mod grant;
#[path = "remote_mach_queue.rs"]
mod queue;
pub(super) use queue::{
    flush_responses, flush_responses_on, parent_died, queue_control, queue_control_on,
    queue_response, queue_response_on, try_flush_responses, try_flush_responses_on,
    try_queue_control, try_queue_control_on,
};
#[path = "remote_mach_serve.rs"]
pub(super) mod server;
#[path = "remote_mach_target.rs"]
pub(super) mod target;
pub(super) use server::{queue_served, serve};
#[path = "remote_mach_suspend.rs"]
pub(super) mod suspension;
#[path = "remote_mach_token.rs"]
pub(super) mod token;
#[path = "remote_mach_wire.rs"]
mod wire;
use wire::{Memory, ThreadArray, too_large};
pub(super) use wire::{Message, Object};

/// Tags are disjoint from the fixed tracing messages in `protocol`.
pub(super) const REQUEST_TAG: u8 = 0x80;
pub(super) const REPLY_TAG: u8 = 0x81;
pub(super) const ACQUIRE_TAG: u8 = 0x82;
pub(super) const RELEASE_TAG: u8 = 0x83;
pub(super) const DEAD_TAG: u8 = 0x84;
pub(super) const BLOB_TAG: u8 = 0x85;

/// State owned by the process link, rather than by a particular guest
/// thread. Port identities are local, and remain tied to one link instance.
#[derive(Debug, Default)]
pub(super) struct State {
    pub parent_server: ServerState,
    grants: grant::State,
    peers: BTreeMap<(i32, u64), Peer>,
    ports: HashMap<u64, RemotePort>,
    pending: BTreeMap<u64, Pending>,
    next_sequence: u64,
    /// Parent-created instances use the low half of the wire namespace;
    /// the other half is reserved for capabilities delivered by the target.
    next_instance: u64,
    pub(super) callbacks: callback::State,
    pub(super) suspension: suspension::State,
    pub(super) tokens: token::State,
    orphan_releases: BTreeMap<(i32, u64, Object), u64>,
}

/// Caller-owned target exports and ordered response backpressure. Client
/// proxies/pending requests stay in State; each server connection can own an
/// independent namespace without losing another caller's rights or queue.
#[derive(Debug, Default)]
pub(super) struct ServerState {
    pub(super) code_flags: Option<Option<u32>>,
    pub allowed: bool,
    pub(super) callbacks: callback::State,
    pub(super) tokens: token::State,
    pub(super) suspension: suspension::State,
    replies: VecDeque<transport::Frame>,
    queued_bytes: usize,
    queued_fds: usize,
    notices: VecDeque<Vec<u8>>,
    exports: BTreeMap<(u64, Object), Export>,
    pub failed: bool,
}

#[derive(Debug)]
struct Peer {
    task: Arc<Port>,
    threads: BTreeMap<u64, Arc<Port>>,
    epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct RemotePort {
    pid: i32,
    instance: u64,
    object: Object,
    generation: u64,
    pending_release: bool,
}

#[derive(Debug)]
struct Export {
    generation: u64,
    right: Right,
}

#[derive(Debug)]
struct Pending {
    pid: i32,
    instance: u64,
    reply: Right,
    reply_type: u32,
    request_id: i32,
    overwrite: Option<(u64, u64)>,
    canceled: bool,
}

/// Resolve a thread proxy belonging to the selected connected child.
pub(super) fn thread_instance(state: &State, port: &Port, pid: i32, tid: u64) -> Option<u64> {
    state.ports.get(&port.id).and_then(|remote| {
        (remote.pid == pid && remote.object == Object::Thread(tid)).then_some(remote.instance)
    })
}

pub(super) fn is_proxy(state: &State, port: &Port) -> bool {
    state.ports.contains_key(&port.id)
}

/// Check the target-side right before operating on a remote thread.
pub(super) fn has_thread_export(state: &State, instance: u64, tid: u64) -> bool {
    state
        .parent_server
        .exports
        .contains_key(&(instance, Object::Thread(tid)))
}

/// Leave enough room for a maximum-size response before accepting a request.
pub(super) fn can_receive_request(state: &State) -> bool {
    server_can_receive(&state.parent_server)
}

/// Whether all target-side replies and notices entered the transport.
pub(super) fn output_empty(state: &State) -> bool {
    server_output_empty(&state.parent_server)
}

pub(super) fn server_can_receive(state: &ServerState) -> bool {
    state.notices.is_empty()
        && state.queued_bytes <= MAX_BACKLOG - MAX_FRAME
        && state.queued_fds < MAX_SERVER_FDS
}

pub(super) fn server_output_empty(state: &ServerState) -> bool {
    state.replies.is_empty() && state.notices.is_empty()
}

/// Allocate an instance independently of the local port's identity. A pending
/// reply or release can outlive its peer entry and must not be aliased.
fn allocate_instance(state: &mut State, pid: i32) -> Option<u64> {
    const LAST: u64 = TARGET_INSTANCE_BIT - 1;
    let occupied = state
        .peers
        .len()
        .checked_add(state.pending.len())?
        .checked_add(state.grants.len())?
        .checked_add(state.orphan_releases.len())?;
    for _ in 0..=occupied {
        let candidate = if state.next_instance == 0 || state.next_instance > LAST {
            1
        } else {
            state.next_instance
        };
        state.next_instance = candidate + 1;
        let busy = state.peers.contains_key(&(pid, candidate))
            || state.grants.uses_instance(pid, candidate)
            || state
                .pending
                .values()
                .any(|p| p.pid == pid && p.instance == candidate)
            || state
                .orphan_releases
                .keys()
                .any(|(p, id, _)| *p == pid && *id == candidate);
        if !busy {
            return Some(candidate);
        }
    }
    None
}

/// Whether a local port is a proxy tied to a connected guest process.
pub(super) fn is_remote(proc: &Proc, port: &Port) -> bool {
    proc.tracing.family.mach.ports.contains_key(&port.id)
}

/// The guest PID named by a live task proxy.
pub(super) fn pid_for_task(proc: &Proc, port: &Port) -> Option<i32> {
    if port.is_dead() {
        return None;
    }
    let remote = proc.tracing.family.mach.ports.get(&port.id)?;
    matches!(remote.object, Object::Task).then_some(remote.pid)
}

/// Sends one frame, distinguishing backpressure from a dead connection.
fn send_to_child(
    proc: &mut Proc,
    pid: i32,
    bytes: &[u8],
    fd: Option<&std::os::fd::OwnedFd>,
) -> Result<(), bool> {
    if proc.tracing.family.mach.callbacks.has_outgoing(pid) {
        return Err(false);
    }
    proc.tracing
        .family
        .children
        .get_mut(&pid)
        .and_then(|child| child.link.as_mut())
        .map(|link| {
            match match fd {
                Some(fd) => link.queue_with_fd(bytes, fd),
                None => link.queue(bytes),
            } {
                Ok(()) => link.flush().map_err(|_| true),
                Err(error) => Err(error.kind() != io::ErrorKind::WouldBlock),
            }
        })
        .unwrap_or(Err(true))
}

fn child_link_failed(proc: &mut Proc, pid: i32) {
    peer_died(proc, pid);
    if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
        child.link = None;
    }
    for call in proc
        .tracing
        .pending
        .values_mut()
        .filter(|call| call.pid == pid && call.errno.is_none())
    {
        call.errno = Some(crate::user::darwin::abi::Errno::ESRCH.0);
    }
    proc.post(crate::user::darwin::wait::WaitKey::Child);
}

/// Builds a MIG error reply and consumes the original request and its rights.
fn reject(proc: &mut Proc, mut request: crate::user::darwin::mach::msg::Message, error: i32) {
    use crate::user::darwin::mach::msg::{self, Sender, bits};
    use crate::user::darwin::syscall::mach::kmsg;
    let reply_type = bits::local(request.bits);
    let id = request.id;
    let reply = request.reply.take();
    kmsg::destroy(proc, request);
    let Some(dest @ (Right::Send(_) | Right::SendOnce(_))) = reply else {
        kmsg::release(proc, reply);
        return;
    };
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&error.to_le_bytes());
    kmsg::enqueue(
        proc,
        msg::Message {
            bits: bits::set(reply_type, 0, 0, 0),
            dest,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: id.wrapping_add(100),
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
}

fn supports(object: Object, id: i32) -> bool {
    use crate::user::darwin::mig::ids;
    matches!(
        (object, id),
        (Object::Task, ids::task::TASK_THREADS)
            | (Object::Task, ids::task::TASK_SUSPEND)
            | (Object::Task, ids::task::TASK_RESUME)
            | (Object::Task, ids::task::TASK_SUSPEND2)
            | (Object::Task, ids::task::TASK_INFO)
            | (Object::Task, ids::task::TASK_SET_EXCEPTION_PORTS)
            | (Object::Task, ids::task::TASK_SWAP_EXCEPTION_PORTS)
            | (Object::Task, ids::task::TASK_GET_EXCEPTION_PORTS)
            | (Object::Task, ids::task::TASK_GET_EXCEPTION_PORTS_INFO)
            | (Object::Task, ids::mach_vm::KERNELRPC_MACH_VM_ALLOCATE)
            | (Object::Task, ids::mach_vm::KERNELRPC_MACH_VM_DEALLOCATE)
            | (Object::Task, ids::mach_vm::KERNELRPC_MACH_VM_PROTECT)
            | (Object::Task, ids::mach_vm::KERNELRPC_MACH_VM_READ)
            | (Object::Task, ids::mach_vm::MACH_VM_READ_OVERWRITE)
            | (Object::Task, ids::mach_vm::MACH_VM_WRITE)
            | (Object::Task, ids::mach_vm::MACH_VM_MACHINE_ATTRIBUTE)
            | (Object::Task, ids::mach_vm::MACH_VM_COPY)
            | (Object::Task, ids::mach_vm::MACH_VM_PAGE_QUERY)
            | (Object::Task, ids::mach_vm::MACH_VM_REGION_RECURSE)
            | (Object::Task, ids::mach_vm::MACH_VM_REGION)
            | (Object::Task, ids::vm_map::KERNELRPC_VM_READ)
            | (Object::Task, ids::vm_map::VM_READ_OVERWRITE)
            | (Object::Task, ids::vm_map::VM_WRITE)
            | (Object::Task, ids::vm_map::VM_MACHINE_ATTRIBUTE)
            | (Object::Task, ids::vm_map::VM_COPY)
            | (Object::Task, ids::vm_map::VM_MAP_PAGE_QUERY)
            | (Object::Task, ids::vm_map::VM_REGION_RECURSE_64)
            | (Object::Task, ids::vm_map::VM_REGION_64)
            | (Object::Thread(_), ids::thread_act::THREAD_GET_STATE)
            | (Object::Thread(_), ids::thread_act::THREAD_SET_STATE)
            | (Object::Thread(_), ids::thread_act::THREAD_INFO)
            | (Object::Thread(_), ids::thread_act::THREAD_SUSPEND)
            | (Object::Thread(_), ids::thread_act::THREAD_RESUME)
    )
}

/// Forwards a request to a remote task or thread. Only operations whose
/// input and output rights are represented by this transport are admitted.
pub(super) fn deliver(
    ctx: &mut crate::user::darwin::syscall::Ctx<'_>,
    mut request: crate::user::darwin::mach::msg::Message,
) {
    use crate::user::darwin::mach::{kr, msg::bits};
    use crate::user::darwin::mig::ids;
    use crate::user::darwin::syscall::mach::kmsg;
    let Some(port) = request.dest.port() else {
        kmsg::destroy(ctx.proc, request);
        return;
    };
    let Some(remote) = ctx.proc.tracing.family.mach.ports.get(&port.id).copied() else {
        reject(ctx.proc, request, kr::KERN_INVALID_CAPABILITY);
        return;
    };
    if !supports(remote.object, request.id) {
        reject(ctx.proc, request, kr::KERN_NOT_SUPPORTED);
        return;
    }
    if exception::is_update(request.id)
        && matches!(
            request.items.as_slice(),
            [(
                4,
                crate::user::darwin::mach::msg::Item::Port {
                    right: Some(Right::Send(_)),
                    ..
                }
            )]
        )
    {
        callback_install::deliver(ctx, request, remote);
        return;
    }
    let is_write = matches!(
        request.id,
        ids::mach_vm::MACH_VM_WRITE | ids::vm_map::VM_WRITE
    );
    // Null and dead handlers carry no live capability across the link.
    let unbacked_handler = exception::is_update(request.id)
        .then(|| exception::unbacked_handler(&request, request.id))
        .flatten();
    if exception::is_update(request.id) && unbacked_handler.is_none() {
        reject(ctx.proc, request, kr::KERN_NOT_SUPPORTED);
        return;
    }
    let memory = if is_write && request.bits & bits::COMPLEX != 0 && request.items.len() == 1 {
        match &mut request.items[0] {
            (
                offset,
                crate::user::darwin::mach::msg::Item::Ool {
                    data,
                    copy,
                    page_offset,
                },
            ) => u32::try_from(*offset).ok().map(|offset| Memory {
                offset,
                copy: *copy,
                page_offset: *page_offset,
                data: std::mem::take(data),
            }),
            _ => None,
        }
    } else {
        None
    };
    if (is_write && memory.is_none())
        || (!is_write
            && unbacked_handler.is_none()
            && (request.bits & bits::COMPLEX != 0 || !request.items.is_empty()))
    {
        reject(ctx.proc, request, kr::MIG_BAD_ARGUMENTS);
        return;
    }
    let is_overwrite = matches!(
        request.id,
        ids::mach_vm::MACH_VM_READ_OVERWRITE | ids::vm_map::VM_READ_OVERWRITE
    );
    let mut id = request.id;
    let mut body = request.body.clone();
    if let Some((disposition, dead)) = unbacked_handler {
        if let Some(field) = body.get_mut(14) {
            *field = disposition as u8;
        }
        if let Some(name) = body.get_mut(4..8) {
            let marker = if dead {
                crate::user::darwin::mach::ipc::MACH_PORT_DEAD
            } else {
                0
            };
            name.copy_from_slice(&marker.to_le_bytes());
        }
    }
    let overwrite = if is_overwrite {
        if body.len() != 32 {
            reject(ctx.proc, request, kr::MIG_BAD_ARGUMENTS);
            return;
        }
        let size = u64::from_le_bytes(body[16..24].try_into().expect("size field"));
        let dest = u64::from_le_bytes(body[24..32].try_into().expect("destination field"));
        body.truncate(24);
        id = if id == ids::mach_vm::MACH_VM_READ_OVERWRITE {
            ids::mach_vm::KERNELRPC_MACH_VM_READ
        } else {
            ids::vm_map::KERNELRPC_VM_READ
        };
        Some((dest, size))
    } else {
        None
    };
    if body.len() > MAX_FRAME - 40 {
        reject(ctx.proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    }
    let expects_reply = matches!(
        request.reply.as_ref(),
        Some(Right::Send(_) | Right::SendOnce(_))
    );
    // Legacy suspend/resume have caller IPC effects even without an RPC
    // reply right. Their acknowledgements still install/consume hidden urefs.
    let tracks_effect = crate::user::darwin::mig::suspension::is_legacy(request.id);
    let tracks_reply = expects_reply || tracks_effect;
    let state = &mut ctx.proc.tracing.family.mach;
    if tracks_reply && state.pending.len() >= 1024 {
        reject(ctx.proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    }
    let mut sequence = state.next_sequence;
    while state.pending.contains_key(&sequence) {
        sequence = sequence.wrapping_add(1);
    }
    state.next_sequence = sequence.wrapping_add(1);
    let packet = Message::Request {
        sequence,
        instance: remote.instance,
        object: remote.object,
        id,
        bits: request.bits,
        expects_reply: tracks_reply,
        body,
        memory,
    };
    let Ok(frame) = encode_frame(packet) else {
        reject(ctx.proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    };
    let queued = send_to_child(ctx.proc, remote.pid, &frame.payload, frame.fd.as_ref());
    if let Err(dead) = queued {
        if dead {
            child_link_failed(ctx.proc, remote.pid);
        }
        reject(
            ctx.proc,
            request,
            if dead {
                kr::KERN_TERMINATED
            } else {
                kr::KERN_RESOURCE_SHORTAGE
            },
        );
        return;
    }
    match request.reply.take() {
        reply if tracks_reply => {
            ctx.proc.tracing.family.mach.pending.insert(
                sequence,
                Pending {
                    pid: remote.pid,
                    instance: remote.instance,
                    reply: reply.unwrap_or(Right::Dead),
                    reply_type: bits::local(request.bits),
                    request_id: request.id,
                    overwrite,
                    canceled: false,
                },
            );
        }
        other => kmsg::release(ctx.proc, other),
    }
    kmsg::destroy(ctx.proc, request);
}

/// Delivers a synthetic kernel reply through the caller's saved right.
fn enqueue_reply(
    proc: &mut Proc,
    pending: Pending,
    bits: u32,
    body: Vec<u8>,
    items: Vec<(usize, crate::user::darwin::mach::msg::Item)>,
) {
    use crate::user::darwin::mach::msg::{self, Sender, bits as mbits};
    if !matches!(pending.reply, Right::Send(_) | Right::SendOnce(_)) {
        let message = msg::Message {
            bits,
            dest: pending.reply,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: pending.request_id.wrapping_add(100),
            body,
            items,
            sender: Sender::KERNEL,
            aux: Vec::new(),
        };
        crate::user::darwin::syscall::mach::kmsg::destroy(proc, message);
        return;
    }
    crate::user::darwin::syscall::mach::kmsg::enqueue(
        proc,
        msg::Message {
            bits: mbits::set(pending.reply_type, 0, 0, bits & mbits::COMPLEX),
            dest: pending.reply,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: pending.request_id.wrapping_add(100),
            body,
            items,
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
}

fn fail_pending(proc: &mut Proc, pending: Pending, error: i32) {
    if pending.canceled {
        crate::user::darwin::syscall::mach::kmsg::release(proc, [pending.reply]);
        return;
    }
    let mut body = crate::user::darwin::mach::msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&error.to_le_bytes());
    enqueue_reply(proc, pending, 0, body, Vec::new());
}

pub(super) fn failed_reply(proc: &mut Proc, pid: i32, sequence: u64) {
    let pending = &mut proc.tracing.family.mach.pending;
    if pending
        .get(&sequence)
        .is_some_and(|pending| pending.pid == pid)
    {
        let pending = pending.remove(&sequence).expect("matched pending reply");
        fail_pending(
            proc,
            pending,
            crate::user::darwin::mach::kr::KERN_RESOURCE_SHORTAGE,
        );
    }
}

pub(super) fn failed_request(proc: &mut Proc, sequence: u64, expects_reply: bool) -> bool {
    failed_request_on(
        proc,
        super::channels::ServerRoute::Parent,
        sequence,
        expects_reply,
    )
}

pub(super) fn failed_request_on(
    proc: &mut Proc,
    route: super::channels::ServerRoute,
    sequence: u64,
    expects_reply: bool,
) -> bool {
    if !expects_reply {
        return true;
    }
    let mut body = crate::user::darwin::mach::msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&crate::user::darwin::mach::kr::KERN_RESOURCE_SHORTAGE.to_le_bytes());
    queue_response_on(
        proc,
        route,
        Message::Reply {
            sequence,
            bits: 0,
            body,
            threads: None,
            memory: None,
        },
    )
}

/// Resolves the target's thread identities into local proxy send rights and
/// delivers the response to the original Mach reply right.
pub(super) fn receive_reply(proc: &mut Proc, pid: i32, message: Message) {
    receive_reply_with_handlers(proc, pid, message, None);
}

fn receive_reply_with_handlers(
    proc: &mut Proc,
    pid: i32,
    message: Message,
    handlers: Option<Vec<callback_wire::HandlerRef>>,
) {
    use crate::user::darwin::mach::{
        ipc::disp,
        kr,
        msg::{Item, bits, desc},
    };
    let Message::Reply {
        sequence,
        bits: reply_bits,
        body,
        threads,
        memory,
    } = message
    else {
        return;
    };
    let state = &mut proc.tracing.family.mach;
    if !state
        .pending
        .get(&sequence)
        .is_some_and(|pending| pending.pid == pid)
    {
        return;
    }
    let pending = state
        .pending
        .remove(&sequence)
        .expect("matched pending reply");
    if pending.canceled {
        if let Some(array) = threads {
            for tid in array.threads {
                if tid != 0 {
                    state
                        .orphan_releases
                        .insert((pid, pending.instance, Object::Thread(tid)), sequence);
                }
            }
        }
        crate::user::darwin::syscall::mach::kmsg::release(proc, [pending.reply]);
        flush_releases(proc);
        return;
    }
    if !state
        .peers
        .get(&(pid, pending.instance))
        .is_some_and(|peer| {
            state.ports.get(&peer.task.id).is_some_and(|port| {
                port.pid == pid && port.instance == pending.instance && port.object == Object::Task
            })
        })
    {
        fail_pending(proc, pending, kr::KERN_TERMINATED);
        return;
    }
    let mut items = Vec::new();
    if handlers.is_some()
        && (threads.is_some()
            || memory.is_some()
            || reply_bits & bits::COMPLEX == 0
            || !exception::has_port_reply(pending.request_id))
    {
        fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
        return;
    }
    if let Some(array) = threads {
        let offset = array.offset as usize;
        let Some(descriptor) = body.get(offset..offset.saturating_add(16)) else {
            fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            return;
        };
        if pending.request_id != crate::user::darwin::mig::ids::task::TASK_THREADS
            || offset != 4
            || body.len() != 32
            || u32::from_le_bytes(body[..4].try_into().expect("descriptor count")) != 1
            || body[20..28] != crate::user::darwin::mach::msg::NDR_RECORD
            || u32::from_le_bytes(body[28..32].try_into().expect("array count")) as usize
                != array.threads.len()
            || reply_bits & bits::COMPLEX == 0
            || descriptor[11] != desc::OOL_PORTS
            || descriptor[10] as u32 != array.disposition
            || array.disposition != disp::MOVE_SEND
            || u32::from_le_bytes(descriptor[12..16].try_into().expect("descriptor count")) as usize
                != array.threads.len()
            || array.threads.iter().any(|&tid| tid == 0)
        {
            fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            return;
        }
        let State { peers, ports, .. } = &mut proc.tracing.family.mach;
        let peer = peers
            .get_mut(&(pid, pending.instance))
            .expect("validated peer");
        let mut rights = Vec::with_capacity(array.threads.len());
        for tid in array.threads {
            let port = peer
                .threads
                .entry(tid)
                .or_insert_with(|| Port::new(KObject::Thread(tid)))
                .clone();
            ports.insert(
                port.id,
                RemotePort {
                    pid,
                    instance: pending.instance,
                    object: Object::Thread(tid),
                    generation: sequence,
                    pending_release: false,
                },
            );
            port.state.lock().unwrap().srights += 1;
            rights.push(Some(Right::Send(port)));
        }
        items.push((
            offset,
            Item::OolPorts {
                rights,
                disp: array.disposition,
            },
        ));
    } else if let Some(memory) = memory {
        let read = matches!(
            pending.request_id,
            crate::user::darwin::mig::ids::mach_vm::KERNELRPC_MACH_VM_READ
                | crate::user::darwin::mig::ids::mach_vm::MACH_VM_READ_OVERWRITE
                | crate::user::darwin::mig::ids::vm_map::KERNELRPC_VM_READ
                | crate::user::darwin::mig::ids::vm_map::VM_READ_OVERWRITE
        );
        if !read
            || memory.offset != 4
            || body.len() != 32
            || u32::from_le_bytes(body[..4].try_into().expect("descriptor count")) != 1
            || body[20..28] != crate::user::darwin::mach::msg::NDR_RECORD
            || reply_bits & bits::COMPLEX == 0
            || body[15] != desc::OOL
            || u32::from_le_bytes(body[16..20].try_into().expect("descriptor size")) as usize
                != memory.data.len()
            || u32::from_le_bytes(body[28..32].try_into().expect("data count")) as usize
                != memory.data.len()
            || memory.copy != desc::VIRTUAL_COPY
            || memory.page_offset != 0
        {
            fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            return;
        }
        if let Some((dest, size)) = pending.overwrite {
            if size != memory.data.len() as u64 {
                fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            } else if proc.space.write(dest, &memory.data).is_err() {
                fail_pending(proc, pending, kr::KERN_INVALID_ADDRESS);
            } else {
                let mut output = crate::user::darwin::mach::msg::NDR_RECORD.to_vec();
                output.extend_from_slice(&0i32.to_le_bytes());
                output.extend_from_slice(&size.to_le_bytes());
                enqueue_reply(proc, pending, 0, output, Vec::new());
            }
            return;
        }
        items.push((
            memory.offset as usize,
            Item::Ool {
                data: memory.data,
                copy: memory.copy,
                page_offset: memory.page_offset,
            },
        ));
    } else if reply_bits & bits::COMPLEX != 0 && exception::has_port_reply(pending.request_id) {
        let ports = match handlers {
            Some(handlers) => callback_return::restore(proc, pid, &body, &handlers),
            None => exception::reply(&body),
        };
        let Some(ports) = ports else {
            fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            return;
        };
        items = ports;
    } else if reply_bits & bits::COMPLEX != 0 {
        let region = matches!(
            pending.request_id,
            crate::user::darwin::mig::ids::mach_vm::MACH_VM_REGION
                | crate::user::darwin::mig::ids::vm_map::VM_REGION_64
        );
        let valid = region
            && body.len() >= 44
            && u32::from_le_bytes(body[..4].try_into().expect("descriptor count")) == 1
            && body[4..14] == [0; 10]
            && body[14] as u32 == disp::MOVE_SEND
            && body[15] == desc::PORT
            && body[16..24] == crate::user::darwin::mach::msg::NDR_RECORD
            && {
                let count =
                    u32::from_le_bytes(body[40..44].try_into().expect("region count")) as usize;
                count <= 10 && body.len() == 44 + count * 4
            };
        if !valid {
            fail_pending(proc, pending, kr::MIG_TYPE_ERROR);
            return;
        }
        items.push((
            4,
            Item::Port {
                right: None,
                disp: disp::MOVE_SEND,
            },
        ));
    }
    enqueue_reply(proc, pending, reply_bits, body, items);
}

/// Fails outstanding calls and kills proxy ports when a process link dies.
pub(super) fn peer_died(proc: &mut Proc, pid: i32) {
    token::peer_died(proc, pid);
    grant::peer_died(proc, pid);
    suspension::peer_died(proc, pid);
    callback_runtime::peer_died(proc, pid);
    end_instance(proc, pid, None);
}

fn end_instance(proc: &mut Proc, pid: i32, instance: Option<u64>) {
    use crate::user::darwin::mach::kr;
    use crate::user::darwin::syscall::mach::kmsg;
    let state = &mut proc.tracing.family.mach;
    let sequences: Vec<u64> = state
        .pending
        .iter()
        .filter_map(|(&sequence, pending)| {
            (pending.pid == pid && instance.is_none_or(|id| id == pending.instance))
                .then_some(sequence)
        })
        .collect();
    let pending: Vec<Pending> = sequences
        .into_iter()
        .filter_map(|sequence| state.pending.remove(&sequence))
        .collect();
    let peer_keys: Vec<_> = state
        .peers
        .keys()
        .filter(|(peer, id)| *peer == pid && instance.is_none_or(|want| want == *id))
        .copied()
        .collect();
    state
        .orphan_releases
        .retain(|(peer, id, _), _| *peer != pid || instance.is_some_and(|want| want != *id));
    let mut ports = Vec::new();
    for key in peer_keys {
        if let Some(peer) = state.peers.remove(&key) {
            ports.push(peer.task);
            ports.extend(peer.threads.into_values());
        }
    }
    for port in &ports {
        state.ports.remove(&port.id);
    }
    for pending in pending {
        fail_pending(proc, pending, kr::KERN_TERMINATED);
    }
    for port in ports {
        kmsg::destroy_receive(proc, &port);
    }
}

/// Holds a task export in the ancestral caller's namespace.
pub(super) fn acquire(proc: &mut Proc, generation: u64, instance: u64, epoch: u64, object: Object) {
    target::acquire(
        proc,
        super::channels::ServerRoute::Parent,
        generation,
        instance,
        epoch,
        object,
    );
}
pub(super) fn release(proc: &mut Proc, generation: u64, instance: u64, object: Object) {
    target::release(
        proc,
        super::channels::ServerRoute::Parent,
        generation,
        instance,
        object,
    );
}

/// Records the last local send right's release. A pending notice is retained
/// under backpressure and a newer handoff supersedes the old generation.
pub(super) fn local_last_send(proc: &mut Proc, port: &Port) {
    suspension::last_send(proc, port);
    callback_runtime::last_send(proc, port);
    let Some(remote) = proc.tracing.family.mach.ports.get_mut(&port.id) else {
        return;
    };
    remote.pending_release = true;
    flush_releases(proc);
}

pub(super) fn flush_releases(proc: &mut Proc) {
    callback_runtime::flush_pending(proc);
    let orphans: Vec<_> = proc
        .tracing
        .family
        .mach
        .orphan_releases
        .iter()
        .map(|(&(pid, instance, object), &generation)| (pid, instance, object, generation))
        .collect();
    for (pid, instance, object, generation) in orphans {
        let Ok(bytes) = (Message::Release {
            generation,
            instance,
            object,
        })
        .encode() else {
            continue;
        };
        match send_to_child(proc, pid, &bytes, None) {
            Ok(()) => {
                let releases = &mut proc.tracing.family.mach.orphan_releases;
                if releases.get(&(pid, instance, object)) == Some(&generation) {
                    releases.remove(&(pid, instance, object));
                }
            }
            Err(true) => child_link_failed(proc, pid),
            Err(false) => {}
        }
    }
    let pending: Vec<_> = proc
        .tracing
        .family
        .mach
        .ports
        .iter()
        .filter_map(|(&id, remote)| remote.pending_release.then_some((id, *remote)))
        .collect();
    for (id, remote) in pending {
        let Ok(bytes) = (Message::Release {
            generation: remote.generation,
            instance: remote.instance,
            object: remote.object,
        })
        .encode() else {
            continue;
        };
        match send_to_child(proc, remote.pid, &bytes, None) {
            Ok(()) => {
                if let Some(current) = proc.tracing.family.mach.ports.get_mut(&id)
                    && current.generation == remote.generation
                {
                    current.pending_release = false;
                }
            }
            Err(true) => child_link_failed(proc, remote.pid),
            Err(false) => {}
        }
    }
}

/// An exec destroys the old guest port space. Cancel its reply rights and
/// release its proxy exports; replies already in flight are drained and
/// their newly exported thread rights are released when they arrive.
pub(super) fn before_exec(proc: &mut Proc) {
    token::before_exec(proc);
    grant::before_exec(proc);
    callback_runtime::before_exec(proc);
    let state = &mut proc.tracing.family.mach;
    for remote in state.ports.values() {
        state.orphan_releases.insert(
            (remote.pid, remote.instance, remote.object),
            remote.generation,
        );
    }
    state.ports.clear();
    state.peers.clear();
    let mut rights = Vec::new();
    for pending in state.pending.values_mut() {
        if !pending.canceled {
            rights.push(std::mem::replace(&mut pending.reply, Right::Dead));
            pending.canceled = true;
        }
    }
    crate::user::darwin::syscall::mach::kmsg::release(proc, rights);
    suspension::before_exec(proc);
    flush_releases(proc);
}

/// Retires the old image's task and thread capabilities before the new
/// image can receive a request on this link. A shared epoch also rejects an
/// acquire that was queued before exec but arrives afterwards.
pub(super) fn target_will_exec(proc: &mut Proc) {
    token::target_will_exec(proc);
    suspension::target_will_exec(proc);
    if let Some(shared) = &proc.tracing.family.parent_status {
        shared.advance_image_epoch();
    }
    retire_target_rights(proc);
    super::peers::advance_image(proc);
}

/// Task/thread control rights die independently of zombie PID ownership.
/// Keep the connection alive for the subsequent BSD exit/reap exchange.
pub(super) fn retire_target_rights(proc: &mut Proc) {
    for route in super::channels::routes(proc) {
        target::retire(proc, route);
    }
}

/// Death also destroys the task's legacy resume and send-once token rights.
pub(super) fn target_exited(proc: &mut Proc) {
    token::target_will_exec(proc);
    suspension::target_will_exec(proc);
    retire_target_rights(proc);
}

/// Marks a thread proxy dead after its target thread's control port dies.
pub(super) fn remote_dead(
    proc: &mut Proc,
    pid: i32,
    instance: u64,
    generation: u64,
    object: Object,
) {
    if object == Object::Task {
        let matches = proc
            .tracing
            .family
            .mach
            .peers
            .get(&(pid, instance))
            .and_then(|peer| proc.tracing.family.mach.ports.get(&peer.task.id))
            .is_some_and(|remote| remote.generation == generation);
        if matches {
            end_instance(proc, pid, Some(instance));
        }
        return;
    }
    let Object::Thread(tid) = object else {
        return;
    };
    let state = &mut proc.tracing.family.mach;
    let Some(peer) = state.peers.get_mut(&(pid, instance)) else {
        return;
    };
    let Some(port) = peer.threads.get(&tid) else {
        return;
    };
    if !state
        .ports
        .get(&port.id)
        .is_some_and(|remote| remote.generation == generation)
    {
        return;
    }
    let port = peer.threads.remove(&tid).expect("matched thread proxy");
    state.ports.remove(&port.id);
    crate::user::darwin::syscall::mach::kmsg::destroy_receive(proc, &port);
}

/// Notifies the tracer and drops its exported right when a target thread exits.
pub(super) fn local_thread_died(proc: &mut Proc, tid: u64) {
    for route in super::channels::routes(proc) {
        target::thread_died(proc, route, tid);
    }
}
