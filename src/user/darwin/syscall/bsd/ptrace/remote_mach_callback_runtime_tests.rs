//! Callback lifetime hooks exercised through the Mach right implementation.

use super::*;

#[test]
fn queued_last_send_cannot_consume_a_new_callback_export() {
    let (mut tracer, mut tracee, tid, instance, _handler) = callback_pair();
    let port = tracer.proc.tracing.family.mach.peers[&(1002, instance)]
        .task
        .clone();
    let name = tracer
        .proc
        .ipc
        .names()
        .into_iter()
        .find_map(|(name, _)| {
            tracer
                .proc
                .ipc
                .lookup(name)
                .ok()
                .and_then(|entry| entry.port().filter(|p| p.id == port.id).map(|_| name))
        })
        .unwrap();
    // The last-send notice is already in flight when the target transfers
    // another send for the same task in an exception request.
    crate::user::darwin::syscall::mach::port::deallocate(&mut tracer.proc, name);
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    assert!(crate::user::darwin::exception::raise_bsd_signal(
        &mut tracee.proc,
        &mut thread,
        30,
    ));
    ptrace::pump(&mut tracee.proc, Some(&mut thread));
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
    tracee.proc.threads.insert(tid, thread);
}

#[test]
fn exec_destroys_owned_kernel_receivers_without_destroying_borrowed_kernel_sends() {
    let (mut tracer, _tracee, _) = pair();
    let owned = Port::new(KObject::Timer(1));
    tracer
        .proc
        .ipc
        .insert(Right::Receive(owned.clone()))
        .unwrap();
    let borrowed = Port::new(KObject::TaskResume(None));
    for port in [&owned, &borrowed] {
        port.state.lock().unwrap().srights += 1;
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .retain_handler(1002, port.id, 1, Right::Send(port.clone()))
            .unwrap();
    }
    before_exec(&mut tracer.proc);
    assert!(owned.is_dead());
    assert!(!borrowed.is_dead());
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(1002, owned.id)
            .is_none()
    );
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(1002, borrowed.id)
            .is_some()
    );
}

fn parent_frames(tracer: &mut DarwinProcess) -> Vec<Vec<u8>> {
    tracer
        .proc
        .tracing
        .family
        .children
        .get_mut(&1002)
        .unwrap()
        .link
        .as_mut()
        .unwrap()
        .receive()
        .unwrap()
        .0
}

fn child_frames(tracee: &mut DarwinProcess) -> Vec<Vec<u8>> {
    tracee
        .proc
        .tracing
        .family
        .parent
        .as_mut()
        .unwrap()
        .receive()
        .unwrap()
        .0
}

pub(super) fn callback_pair() -> (DarwinProcess, DarwinProcess, u64, u64, Arc<Port>) {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    ptrace::pump(&mut tracee.proc, None);
    let handler = Port::new(KObject::None);
    handler.state.lock().unwrap().srights = 1;
    tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_handler(1002, handler.id, 7, Right::Send(handler.clone()))
        .unwrap();
    let proxy = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .acquire_proxy(handler.id, 7, instance);
    tracee.proc.task.exc[5].port = Some(proxy);
    tracee.proc.task.exc[5].behavior = 1;
    tracee.proc.task.exc[5].flavor = 5;
    (tracer, tracee, tid, instance, handler)
}

#[test]
fn abandoned_callback_and_dead_handler_return_only_unheld_capabilities() {
    for handler_dies in [false, true] {
        let (mut tracer, mut tracee, tid, instance, handler) = callback_pair();
        let mut thread = tracee.proc.threads.remove(&tid).unwrap();
        assert!(crate::user::darwin::exception::raise_bsd_signal(
            &mut tracee.proc,
            &mut thread,
            30
        ));
        let reply = thread.mach.exception.as_ref().unwrap().reply.clone();
        if handler_dies {
            // The request is already in flight when its handler disappears.
            kmsg::destroy_receive(&mut tracer.proc, &handler);
        }
        ptrace::pump(&mut tracer.proc, None);
        if !handler_dies {
            let request = take_reply(&mut tracer.proc, &handler);
            kmsg::destroy(&mut tracer.proc, request);
        }
        ptrace::pump(&mut tracee.proc, Some(&mut thread));
        assert_eq!(
            reply.state.lock().unwrap().queue.front().unwrap().id,
            kmsg::MACH_NOTIFY_SEND_ONCE
        );
        assert!(
            tracee
                .proc
                .tracing
                .family
                .mach
                .parent_server
                .exports
                .contains_key(&(instance, Object::Task))
        );
        assert!(
            !tracee
                .proc
                .tracing
                .family
                .mach
                .parent_server
                .exports
                .contains_key(&(instance, Object::Thread(tid)))
        );
        assert!(tracee.proc.tracing.family.parent.is_some());
        let remote_task = &tracer.proc.tracing.family.mach.peers[&(1002, instance)].task;
        let target_generation = tracee.proc.tracing.family.mach.parent_server.exports
            [&(instance, Object::Task)]
            .generation;
        assert_eq!(
            tracer.proc.tracing.family.mach.ports[&remote_task.id].generation,
            target_generation
        );
        tracee.proc.threads.insert(tid, thread);
    }
}

#[test]
fn exec_retires_callback_replies_while_target_handler_actions_survive() {
    for target_exec in [false, true] {
        let (mut tracer, mut tracee, tid, _, handler) = callback_pair();
        let proxy = tracee.proc.task.exc[5].port.clone().unwrap();
        let mut thread = tracee.proc.threads.remove(&tid).unwrap();
        assert!(crate::user::darwin::exception::raise_bsd_signal(
            &mut tracee.proc,
            &mut thread,
            30
        ));
        let target_reply = thread.mach.exception.as_ref().unwrap().reply.clone();
        ptrace::pump(&mut tracer.proc, None);
        let mut request = take_reply(&mut tracer.proc, &handler);
        let reply = request.reply.take().unwrap();
        let local_reply = reply.port().unwrap().clone();
        kmsg::destroy(&mut tracer.proc, request);
        if target_exec {
            let _old_image_name = tracee.proc.insert_send(&proxy);
            assert_eq!(proxy.state.lock().unwrap().srights, 2);
            before_exec(&mut tracee.proc);
            target_will_exec(&mut tracee.proc);
            ptrace::pump(&mut tracer.proc, None);
            assert!(target_reply.is_dead());
            assert!(!proxy.is_dead());
            assert_eq!(proxy.state.lock().unwrap().srights, 1);
            assert!(
                tracee
                    .proc
                    .tracing
                    .family
                    .mach
                    .callbacks
                    .proxy_identity(&proxy)
                    .is_some()
            );
        } else {
            before_exec(&mut tracer.proc);
            ptrace::pump(&mut tracee.proc, Some(&mut thread));
            assert!(handler.is_dead());
            assert!(proxy.is_dead());
            assert_eq!(
                target_reply.state.lock().unwrap().queue.front().unwrap().id,
                kmsg::MACH_NOTIFY_SEND_ONCE
            );
        }
        assert!(local_reply.is_dead());
        assert!(
            tracer
                .proc
                .tracing
                .family
                .mach
                .callbacks
                .proxy_reply_identity(&local_reply)
                .is_none()
        );
        kmsg::release(&mut tracer.proc, [reply]);
        tracee.proc.threads.insert(tid, thread);
    }
}

#[test]
fn ptrace_and_signal_controls_cannot_overtake_a_deferred_callback_reply() {
    let (mut tracer, mut tracee, _) = pair();
    let packet = callback_wire::Message::Cancel { reply: 456 }
        .encode()
        .unwrap();
    tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .defer_to_child(1002, packet.clone());
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let mut ctx = Ctx {
        proc: &mut tracer.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert_eq!(
        ptrace::ptrace(&mut ctx, 7, 1002, 1, 0),
        Err(crate::user::darwin::abi::Errno::EAGAIN)
    );
    assert!(ctx.proc.tracing.pending.is_empty());
    assert!(ctx.proc.tracing.family.children[&1002].stop.is_some());
    let origin = crate::user::darwin::signal::Origin::own(ctx.proc);
    assert_eq!(
        ptrace::send_traced_signal(&mut ctx.proc.tracing, 1002, 30, origin),
        Err(crate::user::darwin::abi::Errno::EAGAIN)
    );
    assert!(child_frames(&mut tracee).is_empty());
    assert!(callback_runtime::flush_child(ctx.proc, 1002));
    assert_eq!(child_frames(&mut tracee), vec![packet]);
    tracer.proc.threads.insert(tid, thread);
}

#[test]
fn last_handler_send_and_abandoned_reply_produce_remote_notices() {
    let (mut tracer, mut tracee, _) = pair();
    let proxy = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .acquire_proxy(123, 4, 1);
    kmsg::release_send(&mut tracee.proc, &proxy);
    let frames = parent_frames(&mut tracer);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        callback_wire::Message::decode(&frames[0]).unwrap(),
        callback_wire::Message::Release {
            handler: 123,
            generation: 4
        }
    );
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .proxy_identity(&proxy)
            .is_none()
    );

    let reply = tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .proxy_reply(1002, 456)
        .unwrap();
    let local = reply.port().unwrap().clone();
    kmsg::release(&mut tracer.proc, [reply]);
    assert_eq!(local.state.lock().unwrap().sorights, 0);
    assert!(local.state.lock().unwrap().queue.is_empty());
    let frames = child_frames(&mut tracee);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        callback_wire::Message::decode(&frames[0]).unwrap(),
        callback_wire::Message::Cancel { reply: 456 }
    );
}

#[test]
fn destroying_exported_handler_notifies_target_and_releases_held_right() {
    let (mut tracer, mut tracee, _) = pair();
    let handler = Port::new(KObject::None);
    handler.state.lock().unwrap().srights = 1;
    tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_handler(1002, handler.id, 7, Right::Send(handler.clone()))
        .unwrap();
    kmsg::destroy_receive(&mut tracer.proc, &handler);
    assert!(handler.is_dead());
    assert_eq!(handler.state.lock().unwrap().srights, 0);
    let frames = child_frames(&mut tracee);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        callback_wire::Message::decode(&frames[0]).unwrap(),
        callback_wire::Message::Dead {
            handler: handler.id,
            generation: 7
        }
    );
    kmsg::destroy_receive(&mut tracer.proc, &handler);
    assert!(child_frames(&mut tracee).is_empty());
}

#[test]
fn disconnected_parent_retires_handler_proxies_and_notifies_waiting_reply() {
    let (_, mut tracee, _) = pair();
    let proxy = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .acquire_proxy(123, 4, 1);
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights = 1;
    tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_reply(Right::SendOnce(reply.clone()))
        .unwrap();
    tracee.proc.tracing.family.parent = None;
    parent_died(&mut tracee.proc);
    assert!(proxy.is_dead());
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .proxy_identity(&proxy)
            .is_none()
    );
    assert_eq!(
        reply.state.lock().unwrap().queue.front().unwrap().id,
        kmsg::MACH_NOTIFY_SEND_ONCE
    );
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .take_reply(reply.id)
            .is_none()
    );
}

#[test]
fn peer_exit_releases_export_and_invalidates_reply_proxy() {
    let (mut tracer, _, _) = pair();
    let handler = Port::new(KObject::None);
    handler.state.lock().unwrap().srights = 1;
    tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_handler(1002, handler.id, 7, Right::Send(handler.clone()))
        .unwrap();
    let reply = tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .proxy_reply(1002, 456)
        .unwrap();
    let port = reply.port().unwrap().clone();
    peer_died(&mut tracer.proc, 1002);
    assert_eq!(handler.state.lock().unwrap().srights, 0);
    assert!(port.is_dead());
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .proxy_reply_identity(&port)
            .is_none()
    );
}

#[test]
fn abandoned_reply_waits_for_socket_capacity_without_losing_its_notice() {
    let (mut tracer, mut tracee, _) = pair();
    let link = tracer
        .proc
        .tracing
        .family
        .children
        .get_mut(&1002)
        .unwrap()
        .link
        .as_mut()
        .unwrap();
    let capacity: libc::c_int = 4096;
    // SAFETY: the link owns the socket and capacity is an initialized integer.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                link.fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const capacity).cast(),
                std::mem::size_of_val(&capacity) as _,
            )
        },
        0
    );
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 16]).unwrap();
    link.flush().unwrap();
    while link.queue(&[]).is_ok() {}
    let right = tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .proxy_reply(1002, 456)
        .unwrap();
    kmsg::release(&mut tracer.proc, [right]);
    assert!(tracer.proc.tracing.family.mach.callbacks.has_outgoing(1002));
    assert!(ptrace::wait_fds(&tracer.proc.tracing).iter().any(|fd| fd.2));
    let expected = callback_wire::Message::Cancel { reply: 456 }
        .encode()
        .unwrap();
    let mut seen = 0;
    for _ in 0..10000 {
        let frames = child_frames(&mut tracee);
        seen += frames.iter().filter(|frame| **frame == expected).count();
        assert!(callback_runtime::flush_child(&mut tracer.proc, 1002));
        if seen != 0 {
            break;
        }
    }
    assert_eq!(seen, 1);
    assert!(!tracer.proc.tracing.family.mach.callbacks.has_outgoing(1002));
    assert!(child_frames(&mut tracee).is_empty());
}

#[test]
fn mach_delivery_and_family_pump_route_exception_and_reply() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    ptrace::pump(&mut tracee.proc, None);
    let handler = Port::new(KObject::None);
    handler.state.lock().unwrap().srights = 1;
    tracer
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_handler(1002, handler.id, 7, Right::Send(handler.clone()))
        .unwrap();
    let proxy = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .acquire_proxy(handler.id, 7, instance);
    tracee.proc.task.exc[5].port = Some(proxy.clone());
    tracee.proc.task.exc[5].behavior = 1;
    tracee.proc.task.exc[5].flavor = 5;
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    assert!(crate::user::darwin::exception::raise_bsd_signal(
        &mut tracee.proc,
        &mut thread,
        30
    ));
    let target_reply = thread.mach.exception.as_ref().unwrap().reply.clone();
    ptrace::pump(&mut tracer.proc, None);
    assert!(
        !handler.state.lock().unwrap().queue.is_empty(),
        "exception did not reach its handler"
    );
    let mut received = take_reply(&mut tracer.proc, &handler);
    let reply = received.reply.take().unwrap();
    let id = received.id + 100;
    kmsg::destroy(&mut tracer.proc, received);
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&0i32.to_le_bytes());
    kmsg::enqueue(
        &mut tracer.proc,
        msg::Message {
            bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, 0),
            dest: reply,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id,
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
    ptrace::pump(&mut tracee.proc, Some(&mut thread));
    assert_eq!(target_reply.state.lock().unwrap().queue.len(), 1);
    crate::user::darwin::exception::resume(&mut tracee.proc, &mut thread);
    assert!(thread.mach.exception.is_none());
    assert!(target_reply.is_dead());
    tracee.proc.threads.insert(tid, thread);
}

#[test]
fn destroying_target_reply_receive_right_cancels_the_remote_token() {
    let (mut tracer, mut tracee, _) = pair();
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights = 1;
    tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_reply(Right::SendOnce(reply.clone()))
        .unwrap();
    kmsg::destroy_receive(&mut tracee.proc, &reply);
    assert!(reply.is_dead());
    assert_eq!(reply.state.lock().unwrap().sorights, 0);
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .take_reply(reply.id)
            .is_none()
    );
    let frames = parent_frames(&mut tracer);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        callback_wire::Message::decode(&frames[0]).unwrap(),
        callback_wire::Message::Cancel { reply: reply.id }
    );
    callback::target::complete(
        &mut tracee.proc,
        callback_wire::Message::Reply {
            reply: reply.id,
            id: 2501,
            bits: 0,
            body: msg::NDR_RECORD.to_vec(),
        },
    );
    assert!(reply.state.lock().unwrap().queue.is_empty());
}

#[test]
fn registered_exception_callbacks_use_the_advertised_image_epoch_without_shared_memory() {
    use crate::user::darwin::syscall::bsd::ptrace::{channels::ServerRoute, peers, registry};
    for matching_epoch in [true, false] {
        let (mut tracer, mut tracee, tid, _instance, handler) = callback_pair();
        let child = tracer.proc.tracing.family.children.get_mut(&1002).unwrap();
        child.shared_status = None;
        child.registry_instance = Some([2; 16]);
        child.registry_epoch = if matching_epoch { 1 } else { 2 };
        let link = tracee.proc.tracing.family.parent.take().unwrap();
        let id = link.identity();
        tracee.proc.tracing.family.parent_status = None;
        tracee.proc.tracing.family.parent_pid = None;
        let mut server = std::mem::take(&mut tracee.proc.tracing.family.mach.parent_server);
        server.callbacks = std::mem::take(&mut tracee.proc.tracing.family.mach.callbacks);
        tracee.proc.tracing.family.peers.incoming.insert(
            id,
            peers::Incoming {
                record: registry::Record {
                    pid: 1001,
                    uid: 501,
                    instance: [1; 16],
                },
                link,
                server,
            },
        );
        let route = ServerRoute::Registered(id);
        tracee.proc.tracing.tracer_route = Some(route);
        let mut thread = tracee.proc.threads.remove(&tid).unwrap();
        assert!(crate::user::darwin::exception::raise_bsd_signal(
            &mut tracee.proc,
            &mut thread,
            17
        ));
        ptrace::pump(&mut tracer.proc, None);
        assert_eq!(
            !handler.state.lock().unwrap().queue.is_empty(),
            matching_epoch,
            "callback admission must use the registered image epoch"
        );
        tracee.proc.threads.insert(tid, thread);
    }
}
