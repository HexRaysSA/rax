//! Target-side MIG execution and serialization of represented results.

use super::super::channels::ServerRoute;
use super::*;

/// A represented reply keeps its transferred rights until its frame is queued.
#[derive(Debug)]
pub(in super::super) enum Response {
    Mach(Message),
    Legacy(super::suspension::Packet),
    Token(super::token::Packet),
    Ports {
        packet: super::callback_wire::Message,
        held: crate::user::darwin::mach::msg::Message,
    },
}

pub(in super::super) fn queue_served(
    proc: &mut Proc,
    expects_reply: bool,
    response: Response,
) -> bool {
    queue_served_on(proc, ServerRoute::Parent, expects_reply, response)
}

pub(in super::super) fn queue_served_on(
    proc: &mut Proc,
    route: ServerRoute,
    expects_reply: bool,
    response: Response,
) -> bool {
    match response {
        Response::Token(packet) => {
            let queued = super::queue_control_on(proc, route, packet.encode());
            if queued {
                proc.tracing.output_barrier = true;
            }
            queued
        }
        Response::Legacy(packet) => {
            // Hidden caller-space effects are acknowledged even when the
            // original message carried no reply right.
            let queued = super::queue_control_on(proc, route, packet.encode());
            if queued {
                proc.tracing.output_barrier = true;
            }
            queued
        }
        Response::Mach(reply) => !expects_reply || super::queue_response_on(proc, route, reply),
        Response::Ports { packet, mut held } => {
            let queued = !expects_reply
                || packet
                    .encode()
                    .is_ok_and(|bytes| super::queue_control_on(proc, route, bytes));
            if expects_reply && queued {
                proc.tracing.output_barrier = true;
            }
            let dest = std::mem::replace(&mut held.dest, Right::Dead);
            crate::user::darwin::syscall::mach::kmsg::consume_dest(proc, dest);
            crate::user::darwin::syscall::mach::kmsg::destroy(proc, held);
            queued
        }
    }
}

/// Runs a supported request against the target process's own MIG server.
/// The selected thread is borrowed from the scheduler only while this call
/// executes; no guest instruction runs as a result of servicing the request.
pub(in super::super) fn serve(
    proc: &mut Proc,
    running: Option<&mut crate::user::darwin::process::Thread>,
    message: Message,
) -> Response {
    serve_on(proc, ServerRoute::Parent, running, message)
}

pub(in super::super) fn serve_on(
    proc: &mut Proc,
    route: ServerRoute,
    running: Option<&mut crate::user::darwin::process::Thread>,
    message: Message,
) -> Response {
    serve_inner(proc, route, running, message, &mut None, true)
}

pub(super) fn serve_with_handler(
    proc: &mut Proc,
    running: Option<&mut crate::user::darwin::process::Thread>,
    message: Message,
    right: Right,
    plain: bool,
) -> Response {
    serve_with_handler_on(proc, ServerRoute::Parent, running, message, right, plain)
}

pub(super) fn serve_with_handler_on(
    proc: &mut Proc,
    route: ServerRoute,
    running: Option<&mut crate::user::darwin::process::Thread>,
    message: Message,
    right: Right,
    plain: bool,
) -> Response {
    let mut handler = Some(right);
    let reply = serve_inner(proc, route, running, message, &mut handler, plain);
    crate::user::darwin::syscall::mach::kmsg::release(proc, handler);
    reply
}

fn serve_inner(
    proc: &mut Proc,
    route: ServerRoute,
    running: Option<&mut crate::user::darwin::process::Thread>,
    message: Message,
    handler: &mut Option<Right>,
    plain: bool,
) -> Response {
    use crate::user::darwin::mach::{
        ipc::disp,
        kr,
        msg::{Sender, bits},
    };
    use crate::user::darwin::mig::ids;
    use crate::user::darwin::syscall::{Ctx, mach::kmsg};

    let (sequence, instance, object, id, request_bits, expects_reply, body, memory) = match message
    {
        Message::Request {
            sequence,
            instance,
            object,
            id,
            bits,
            expects_reply,
            body,
            memory,
        } => (
            sequence,
            instance,
            object,
            id,
            bits,
            expects_reply,
            body,
            memory,
        ),
        other => return Response::Mach(other),
    };
    let error_reply = |error: i32| {
        let mut body = crate::user::darwin::mach::msg::NDR_RECORD.to_vec();
        body.extend_from_slice(&error.to_le_bytes());
        Response::Mach(Message::Reply {
            sequence,
            bits: disp::MOVE_SEND_ONCE,
            body,
            threads: None,
            memory: None,
        })
    };
    if !route.server(proc).is_some_and(|server| server.allowed) {
        return error_reply(kr::KERN_NO_ACCESS);
    }
    if !route
        .server(proc)
        .is_some_and(|server| server.exports.contains_key(&(instance, object)))
    {
        return error_reply(kr::KERN_INVALID_CAPABILITY);
    }
    if !supports(object, id)
        || matches!(
            id,
            ids::mach_vm::MACH_VM_READ_OVERWRITE | ids::vm_map::VM_READ_OVERWRITE
        )
    {
        return error_reply(kr::KERN_NOT_SUPPORTED);
    }
    let is_write = matches!(id, ids::mach_vm::MACH_VM_WRITE | ids::vm_map::VM_WRITE);
    if let Some(right) = handler.as_ref() {
        if !exception::is_update(id) {
            return error_reply(kr::KERN_NOT_SUPPORTED);
        }
        // Validate before gating represented layouts or mutating actions.
        // The proxy itself is plain; preserve the supplied handler's kind
        // so a kernel-object input receives XNU's KERN_INVALID_RIGHT.
        if request_bits & bits::COMPLEX != 0
            && body.len() == 36
            && body[..4] == 1u32.to_le_bytes()
            && body[14] == disp::MOVE_SEND as u8
            && body[15] == crate::user::darwin::mach::msg::desc::PORT
        {
            use crate::user::darwin::mach::exception::{self as exc, Handler};
            let port = if plain {
                right.port().expect("supplied handler send").clone()
            } else {
                Port::new(KObject::Task)
            };
            let word = |offset| {
                u32::from_le_bytes(body[offset..offset + 4].try_into().expect("validated body"))
            };
            let behavior = word(28) as i32;
            if let Err(error) = exc::validate(
                proc.abi,
                word(24),
                &Handler::Port(port),
                behavior,
                word(32) as i32,
            ) {
                return error_reply(error);
            }
            if exc::behavior::base(behavior) >= exc::behavior::IDENTITY_PROTECTED {
                return error_reply(kr::KERN_NOT_SUPPORTED);
            }
        }
    }
    let mut items = match memory {
        Some(memory)
            if is_write
                && memory.offset == 4
                && body.len() >= 20
                && request_bits & bits::COMPLEX != 0
                && body[15] == crate::user::darwin::mach::msg::desc::OOL
                && u32::from_le_bytes(body[16..20].try_into().expect("descriptor size"))
                    as usize
                    == memory.data.len() =>
        {
            vec![(
                memory.offset as usize,
                crate::user::darwin::mach::msg::Item::Ool {
                    data: memory.data,
                    copy: memory.copy,
                    page_offset: memory.page_offset,
                },
            )]
        }
        None if exception::is_update(id) && request_bits & bits::COMPLEX != 0 => {
            if body.len() < 16 || body[15] != crate::user::darwin::mach::msg::desc::PORT {
                return error_reply(kr::MIG_TYPE_ERROR);
            }
            if handler.is_some() {
                vec![(
                    4,
                    crate::user::darwin::mach::msg::Item::Port {
                        right: None,
                        disp: u32::from(body[14]),
                    },
                )]
            } else {
                let Some(items) = exception::request(&body, request_bits) else {
                    return error_reply(kr::MIG_TYPE_ERROR);
                };
                items
            }
        }
        None if !is_write && request_bits & bits::COMPLEX == 0 => Vec::new(),
        _ => return error_reply(kr::MIG_TYPE_ERROR),
    };
    if id == ids::task::TASK_SWAP_EXCEPTION_PORTS
        && exception::swap_exports_live_on(proc, route, &body)
    {
        return error_reply(kr::KERN_NOT_SUPPORTED);
    }
    let running = running.filter(|thread| !thread.exited);
    let target = match object {
        Object::Task => Some(proc.task_port.clone()),
        Object::Thread(tid) => running
            .as_ref()
            .filter(|thread| thread.tid == tid)
            .map(|thread| thread.kport.clone())
            .or_else(|| {
                proc.threads
                    .get(&tid)
                    .filter(|thread| !thread.exited)
                    .map(|thread| thread.kport.clone())
            }),
    };
    let Some(target) = target else {
        return error_reply(kr::KERN_INVALID_ARGUMENT);
    };
    let detached_tid = if running.is_none() {
        let Some(tid) = proc
            .threads
            .iter()
            .find_map(|(&tid, thread)| (!thread.exited).then_some(tid))
        else {
            return error_reply(kr::KERN_TERMINATED);
        };
        Some(tid)
    } else {
        None
    };
    if let [(4, crate::user::darwin::mach::msg::Item::Port { right, .. })] = items.as_mut_slice()
        && handler.is_some()
    {
        *right = handler.take();
    }
    let reply_port = Port::new(KObject::None);
    reply_port.state.lock().unwrap().sorights += 1;
    target.state.lock().unwrap().srights += 1;
    let request = crate::user::darwin::mach::msg::Message {
        bits: bits::set(
            disp::MOVE_SEND,
            disp::MOVE_SEND_ONCE,
            0,
            request_bits & bits::COMPLEX,
        ),
        dest: Right::Send(target.clone()),
        reply: Some(Right::SendOnce(reply_port)),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items,
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let reply = if let Some(thread) = running {
        let pc = thread.cpu.pc();
        let mut ctx = Ctx {
            proc: &mut *proc,
            thread,
            nr: -1,
            pc,
        };
        crate::user::darwin::mig::serve_remote(&mut ctx, &target, request)
    } else {
        let tid = detached_tid.expect("a live thread was selected");
        let mut thread = proc.threads.remove(&tid).expect("listed live thread");
        let pc = thread.cpu.pc();
        let reply = {
            let mut ctx = Ctx {
                proc: &mut *proc,
                thread: &mut thread,
                nr: -1,
                pc,
            };
            crate::user::darwin::mig::serve_remote(&mut ctx, &target, request)
        };
        proc.threads.insert(tid, thread);
        reply
    };
    let legacy = reply.legacy;
    let Some(mut reply) = reply.message else {
        return error_reply(kr::MIG_NO_REPLY);
    };
    if let Some(effect) = legacy {
        let packet = super::suspension::response_on(proc, route, sequence, effect);
        let dest = std::mem::replace(&mut reply.dest, Right::Dead);
        kmsg::consume_dest(proc, dest);
        kmsg::destroy(proc, reply);
        return Response::Legacy(packet);
    }
    if id == ids::task::TASK_SUSPEND2
        && let Some(packet) = super::token::capture_on(proc, route, sequence, instance, &mut reply)
    {
        let dest = std::mem::replace(&mut reply.dest, Right::Dead);
        kmsg::consume_dest(proc, dest);
        kmsg::destroy(proc, reply);
        if expects_reply {
            return Response::Token(packet);
        }
        super::token::discard_offer_on(proc, route, packet);
        return error_reply(kr::KERN_SUCCESS);
    }
    let mut threads = None;
    let mut memory = None;
    let mut valid = true;
    let unbacked_reply = exception::has_port_reply(id) && exception::normalize_reply(&mut reply);
    if exception::has_port_reply(id) && !unbacked_reply {
        if let Some(packet) = super::callback_return::encode_on(proc, route, sequence, &reply) {
            return Response::Ports {
                packet,
                held: reply,
            };
        }
    }
    if !reply.items.is_empty() && !unbacked_reply {
        if reply.items.len() != 1 {
            valid = false;
        }
        if let Some((offset, crate::user::darwin::mach::msg::Item::OolPorts { rights, disp })) =
            reply.items.first()
        {
            let mut ids = Vec::with_capacity(rights.len());
            for right in rights {
                match right {
                    Some(Right::Send(port)) => match port.kobject {
                        KObject::Thread(tid) => ids.push(tid),
                        _ => valid = false,
                    },
                    _ => valid = false,
                }
            }
            if let Ok(offset) = u32::try_from(*offset) {
                threads = Some(ThreadArray {
                    offset,
                    disposition: *disp,
                    threads: ids,
                });
            } else {
                valid = false;
            }
        } else if let Some((
            offset,
            crate::user::darwin::mach::msg::Item::Ool {
                data,
                copy,
                page_offset,
            },
        )) = reply.items.first_mut()
        {
            if let Ok(offset) = u32::try_from(*offset) {
                memory = Some(Memory {
                    offset,
                    copy: *copy,
                    page_offset: *page_offset,
                    data: std::mem::take(data),
                });
            } else {
                valid = false;
            }
        } else if let Some((
            offset,
            crate::user::darwin::mach::msg::Item::Port { right: None, disp },
        )) = reply.items.first()
        {
            valid &= *offset == 4
                && *disp == disp::MOVE_SEND
                && matches!(id, ids::mach_vm::MACH_VM_REGION | ids::vm_map::VM_REGION_64);
        } else {
            valid = false;
        }
    }
    if valid && let Some(array) = &threads {
        let size = 30usize.checked_add(reply.body.len()).and_then(|n| {
            array
                .threads
                .len()
                .checked_mul(8)
                .and_then(|v| n.checked_add(v))
        });
        if size.is_none_or(|size| size > MAX_FRAME) {
            valid = false;
        }
    }
    if valid
        && expects_reply
        && let Some(array) = &threads
        && let Some((_, crate::user::darwin::mach::msg::Item::OolPorts { rights, .. })) =
            reply.items.first_mut()
    {
        for (tid, right) in array.threads.iter().copied().zip(rights.iter_mut()) {
            let object = Object::Thread(tid);
            if let Some(export) = route
                .server_mut(proc)
                .expect("connected server")
                .exports
                .get_mut(&(instance, object))
            {
                export.generation = sequence;
            } else if let Some(right) = right.take() {
                route
                    .server_mut(proc)
                    .expect("connected server")
                    .exports
                    .insert(
                        (instance, object),
                        Export {
                            generation: sequence,
                            right,
                        },
                    );
            }
        }
    }
    let body = std::mem::take(&mut reply.body);
    let bits = reply.bits;
    let dest = std::mem::replace(&mut reply.dest, Right::Dead);
    kmsg::consume_dest(proc, dest);
    kmsg::destroy(proc, reply);
    if valid {
        Response::Mach(Message::Reply {
            sequence,
            bits,
            body,
            threads,
            memory,
        })
    } else {
        error_reply(kr::KERN_NOT_SUPPORTED)
    }
}
