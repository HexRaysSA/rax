//! End-to-end tests of remote kernel-object messages over a tracing link.

#[path = "remote_mach_attribute_tests.rs"]
mod attributes;
#[path = "remote_mach_exit_tests.rs"]
mod guest_exit;

#[path = "remote_mach_suspend_tests.rs"]
mod suspension_tests;
#[path = "remote_mach_token_tests.rs"]
mod token_tests;

use super::*;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp};
use crate::user::darwin::mach::msg::{self, Item, Sender, bits};
use crate::user::darwin::mig::ids;
use crate::user::darwin::process::{DarwinProcess, bounded_tests::process};
use crate::user::darwin::syscall::bsd::ptrace::{self, Child, ChildStop, SharedStatus};
use crate::user::darwin::syscall::{Ctx, mach::kmsg};

/// Sets up an already authorized capability for the remote RPC tests.
/// The guest trap's policy and grant ownership are tested in `grant::tests`.
fn task_port(proc: &mut Proc, pid: i32) -> Option<Arc<Port>> {
    let child = proc.tracing.family.children.get(&pid)?;
    child.link.as_ref()?;
    let shared = child.shared_status.as_ref()?;
    let epoch = shared.image_epoch();
    if epoch == 0 {
        return None;
    }
    for ((peer_pid, _), peer) in &proc.tracing.family.mach.peers {
        if *peer_pid == pid
            && peer.epoch == epoch
            && !peer.task.is_dead()
            && peer.task.state.lock().unwrap().srights != 0
        {
            return Some(peer.task.clone());
        }
    }
    let port = Port::new(KObject::Task);
    let state = &mut proc.tracing.family.mach;
    let instance = allocate_instance(state, pid)?;
    let mut generation = state.next_sequence;
    while state.pending.contains_key(&generation) {
        generation = generation.wrapping_add(1);
    }
    state.next_sequence = generation.wrapping_add(1);
    let bytes = Message::Acquire {
        generation,
        instance,
        epoch,
        object: Object::Task,
    }
    .encode()
    .ok()?;
    if let Err(dead) = send_to_child(proc, pid, &bytes, None) {
        if dead {
            child_link_failed(proc, pid);
        }
        return None;
    }
    let state = &mut proc.tracing.family.mach;
    state.ports.insert(
        port.id,
        RemotePort {
            pid,
            instance,
            object: Object::Task,
            generation,
            pending_release: false,
        },
    );
    state.peers.entry((pid, instance)).or_insert_with(|| Peer {
        task: port.clone(),
        threads: BTreeMap::new(),
        epoch,
    });
    Some(port)
}

pub(super) fn pair() -> (DarwinProcess, DarwinProcess, u64) {
    let mut tracer = process(DarwinAbi::Arm64);
    let mut tracee = process(DarwinAbi::Arm64);
    tracer.proc.pid = 1001;
    tracer.proc.creds = (501, 501, 20, 20);
    tracee.proc.pid = 1002;
    tracee.proc.ppid = 1001;
    tracee.proc.creds = (501, 501, 20, 20);
    let target_tid = *tracee.proc.threads.keys().next().unwrap();
    let (parent, child) = super::super::transport::Link::pair().unwrap();
    let shared = Arc::new(SharedStatus::new().unwrap());
    shared.set_parent_credentials((501, 501));
    shared.set_target_credentials((501, 501));
    shared.set_trace(1001, true);
    shared.set_codesign(Some(crate::user::darwin::codesign::cs::GET_TASK_ALLOW));
    let mut record = Child::new(parent, tracer.proc.pid);
    record.shared_status = Some(shared.clone());
    record.traced = true;
    record.mach_attached = true;
    record.stop = Some(ChildStop {
        thread: target_tid,
        signal: 17,
        waited: true,
    });
    tracer.proc.tracing.family.children.insert(1002, record);
    tracee.proc.tracing.family.parent = Some(child);
    tracee.proc.tracing.family.parent_status = Some(shared);
    tracee.proc.tracing.family.mach.parent_server.allowed = true;
    (tracer, tracee, target_tid)
}

#[test]
fn capability_instances_do_not_alias_local_port_ids_or_pending_releases() {
    let (mut tracer, mut tracee, _) = pair();
    tracer.proc.tracing.family.mach.next_instance = 1 << 62;
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    assert_eq!(instance, 1 << 62);
    assert_ne!(instance, task.id);
    let _task_name = tracer.proc.insert_send(&task);
    let reply = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
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
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &reply);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    kmsg::destroy(&mut tracer.proc, message);

    let epoch = tracee
        .proc
        .tracing
        .family
        .parent_status
        .as_ref()
        .unwrap()
        .image_epoch();
    acquire(&mut tracee.proc, 9, 1 << 63, epoch, Object::Task);
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(1 << 63, Object::Task))
    );

    let mut state = State::default();
    state.next_instance = (1 << 63) - 1;
    state.orphan_releases.insert((1002, 1, Object::Task), 9);
    assert_eq!(allocate_instance(&mut state, 1002), Some((1 << 63) - 1));
    assert_eq!(allocate_instance(&mut state, 1002), Some(2));
}

fn send(tracer: &mut DarwinProcess, port: &Arc<Port>, id: i32, body: Vec<u8>) -> Arc<Port> {
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    port.state.lock().unwrap().srights += 1;
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, 0),
        dest: Right::Send(port.clone()),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    let mut ctx = Ctx {
        proc: &mut tracer.proc,
        thread: &mut thread,
        nr: -1,
        pc,
    };
    kmsg::deliver(&mut ctx, request);
    tracer.proc.threads.insert(tid, thread);
    reply
}

fn take_reply(proc: &mut Proc, port: &Arc<Port>) -> msg::Message {
    let mut message = port
        .state
        .lock()
        .unwrap()
        .queue
        .pop_front()
        .expect("reply delivered");
    let dest = std::mem::replace(&mut message.dest, Right::Dead);
    kmsg::consume_dest(proc, dest);
    message
}

fn swap_unbacked(tracer: &mut DarwinProcess, task: &Arc<Port>, flavor: i32) -> Arc<Port> {
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    task.state.lock().unwrap().srights += 1;
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 12]);
    body[14] = disp::MOVE_SEND as u8;
    body.extend_from_slice(&msg::NDR_RECORD);
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes());
    body.extend_from_slice(&flavor.to_le_bytes());
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, bits::COMPLEX),
        dest: Right::Send(task.clone()),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id: ids::task::TASK_SWAP_EXCEPTION_PORTS,
        body,
        items: vec![(
            4,
            Item::Port {
                right: None,
                disp: disp::MOVE_SEND,
            },
        )],
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    kmsg::deliver(
        &mut Ctx {
            proc: &mut tracer.proc,
            thread: &mut thread,
            nr: -1,
            pc,
        },
        request,
    );
    tracer.proc.threads.insert(tid, thread);
    reply
}

#[test]
fn kernel_exception_request_exports_identity_and_retains_its_reply_right() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    ptrace::pump(&mut tracee.proc, None);
    let proxy = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .acquire_proxy(900, 7, instance);
    // Capture a real kernel request before registering its remote destination.
    let capture = Port::new(KObject::None);
    capture.state.lock().unwrap().srights = 1;
    tracee.proc.task.exc[5].port = Some(capture.clone());
    tracee.proc.task.exc[5].behavior = 1;
    tracee.proc.task.exc[5].flavor = 5;
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    assert!(crate::user::darwin::exception::raise_bsd_signal(
        &mut tracee.proc,
        &mut thread,
        crate::user::darwin::signal::SIGUSR1
    ));
    let reply = thread.mach.exception.as_ref().unwrap().reply.clone();
    let mut request = capture.state.lock().unwrap().queue.pop_front().unwrap();
    proxy.state.lock().unwrap().srights += 1;
    let old = std::mem::replace(&mut request.dest, Right::Send(proxy.clone()));
    kmsg::release(&mut tracee.proc, [old]);
    request.body[15] = 0xff;
    let mut request = callback::target::forward(&mut tracee.proc, request).unwrap_err();
    assert!(request.reply.is_some());
    assert!(request.items.iter().all(|(_, item)| matches!(
        item,
        Item::Port {
            right: Some(Right::Send(_)),
            ..
        }
    )));
    request.body[15] = msg::desc::PORT;
    callback::target::forward(&mut tracee.proc, request).unwrap();
    tracee.proc.threads.insert(tid, thread);
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
    let (frames, closed) = link.receive().unwrap();
    assert!(!closed);
    assert_eq!(frames.len(), 1);
    let packet = callback_wire::Message::decode(&frames[0]).unwrap();
    let callback_wire::Message::Deliver {
        instance: transferred,
        handler,
        generation,
        reply: token,
        descriptors,
        ..
    } = packet
    else {
        panic!("expected exception delivery")
    };
    assert_eq!(
        (transferred, handler, generation, token),
        (instance, 900, 7, reply.id)
    );
    assert_eq!(descriptors.len(), 2);
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Thread(tid)))
    );
    assert_eq!(reply.state.lock().unwrap().sorights, 1);
    let held = tracee
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .take_reply(token)
        .unwrap();
    kmsg::release(&mut tracee.proc, [held]);
    assert_eq!(reply.state.lock().unwrap().sorights, 1);
    let mut notification = reply.state.lock().unwrap().queue.pop_front().unwrap();
    assert_eq!(notification.id, kmsg::MACH_NOTIFY_SEND_ONCE);
    let destination = std::mem::replace(&mut notification.dest, Right::Dead);
    kmsg::consume_dest(&mut tracee.proc, destination);
    kmsg::destroy(&mut tracee.proc, notification);
    assert_eq!(reply.state.lock().unwrap().sorights, 0);
}

#[test]
fn exception_callback_round_trip_delivers_to_tracer_and_resumes_target() {
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
    // Capture a real kernel request before registering its remote destination.
    let capture = Port::new(KObject::None);
    capture.state.lock().unwrap().srights = 1;
    tracee.proc.task.exc[5].port = Some(capture.clone());
    tracee.proc.task.exc[5].behavior = 1;
    tracee.proc.task.exc[5].flavor = 5;
    let mut thread = tracee.proc.threads.remove(&tid).unwrap();
    assert!(crate::user::darwin::exception::raise_bsd_signal(
        &mut tracee.proc,
        &mut thread,
        30
    ));
    let target_reply = thread.mach.exception.as_ref().unwrap().reply.clone();
    let mut request = capture.state.lock().unwrap().queue.pop_front().unwrap();
    proxy.state.lock().unwrap().srights += 1;
    let old = std::mem::replace(&mut request.dest, Right::Send(proxy.clone()));
    kmsg::release(&mut tracee.proc, [old]);
    callback::target::forward(&mut tracee.proc, request).unwrap();
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
    let (frames, _) = link.receive().unwrap();
    let packet = callback_wire::Message::decode(&frames[0]).unwrap();
    let mut stale = packet.clone();
    if let callback_wire::Message::Deliver { epoch, .. } = &mut stale {
        *epoch += 1;
    }
    assert!(callback::receive::deliver(&mut tracer.proc, 1002, stale).is_err());
    assert!(handler.state.lock().unwrap().queue.is_empty());
    callback::receive::deliver(&mut tracer.proc, 1002, packet).unwrap();
    let mut received = take_reply(&mut tracer.proc, &handler);
    assert_eq!(received.items.len(), 2);
    let thread_port = match &received.items[0].1 {
        Item::Port {
            right: Some(Right::Send(port)),
            ..
        } => port,
        _ => panic!("expected thread right"),
    };
    assert_eq!(
        thread_instance(&tracer.proc.tracing.family.mach, thread_port, 1002, tid),
        Some(instance)
    );
    let reply_right = received.reply.take().unwrap();
    let reply_port = reply_right.port().unwrap().clone();
    let response_id = received.id + 100;
    kmsg::destroy(&mut tracer.proc, received);
    let mut response = msg::Message {
        bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, 0),
        dest: reply_right,
        reply: None,
        voucher: None,
        voucher_name: 0,
        id: response_id,
        body: vec![0; MAX_FRAME],
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    response = callback::receive::reply_packet(&mut tracer.proc, response).unwrap_err();
    assert_eq!(reply_port.state.lock().unwrap().sorights, 1);
    response.body = msg::NDR_RECORD.to_vec();
    response.body.extend_from_slice(&0i32.to_le_bytes());
    let (pid, reply) = callback::receive::reply_packet(&mut tracer.proc, response).unwrap();
    assert_eq!(pid, 1002);
    assert_eq!(reply_port.state.lock().unwrap().sorights, 0);
    callback::target::complete(&mut tracee.proc, reply.clone());
    callback::target::complete(&mut tracee.proc, reply);
    assert_eq!(target_reply.state.lock().unwrap().queue.len(), 1);
    crate::user::darwin::exception::resume(&mut tracee.proc, &mut thread);
    assert!(thread.mach.exception.is_none());
    assert!(target_reply.is_dead());
    assert_eq!(target_reply.state.lock().unwrap().sorights, 0);
    tracee.proc.threads.insert(tid, thread);
}

#[test]
fn remote_swap_returns_dead_handler_and_preserves_live_action_on_rejection() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    tracee.proc.task.exc[5].dead = true;
    let response = swap_unbacked(&mut tracer, &task, 5);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let result = take_reply(&mut tracer.proc, &response);
    assert!(matches!(
        result.items[0].1,
        Item::Port {
            right: Some(Right::Dead),
            ..
        }
    ));
    assert!(!tracee.proc.task.exc[5].dead);
    kmsg::destroy(&mut tracer.proc, result);

    let live = Port::new(KObject::None);
    live.state.lock().unwrap().srights = 1;
    tracee.proc.task.exc[5].port = Some(live.clone());
    for (flavor, expected) in [
        (5, crate::user::darwin::mach::kr::KERN_NOT_SUPPORTED),
        (
            i32::MAX,
            crate::user::darwin::mach::kr::KERN_INVALID_ARGUMENT,
        ),
    ] {
        let response = swap_unbacked(&mut tracer, &task, flavor);
        ptrace::pump(&mut tracee.proc, None);
        ptrace::pump(&mut tracer.proc, None);
        let result = take_reply(&mut tracer.proc, &response);
        assert_eq!(
            i32::from_le_bytes(result.body[8..12].try_into().unwrap()),
            expected
        );
        assert!(Arc::ptr_eq(
            tracee.proc.task.exc[5].port.as_ref().unwrap(),
            &live
        ));
        assert_eq!(live.state.lock().unwrap().srights, 1);
        kmsg::destroy(&mut tracer.proc, result);
    }
}

#[test]
fn task_info_uses_target_audit_token_and_validates_count() {
    let (mut tracer, mut tracee, _) = pair();
    tracer.proc.audit[5] = 1001;
    tracee.proc.audit[5] = 1002;
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    for (count, expected) in [(8u32, 0i32), (1, 4)] {
        let mut body = msg::NDR_RECORD.to_vec();
        body.extend_from_slice(&15i32.to_le_bytes()); // TASK_AUDIT_TOKEN
        body.extend_from_slice(&count.to_le_bytes());
        let response = send(&mut tracer, &task, ids::task::TASK_INFO, body);
        ptrace::pump(&mut tracee.proc, None);
        ptrace::pump(&mut tracer.proc, None);
        let message = take_reply(&mut tracer.proc, &response);
        assert_eq!(
            i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
            expected
        );
        if count == 8 {
            assert_eq!(
                u32::from_le_bytes(message.body[12..16].try_into().unwrap()),
                8
            );
            assert_eq!(
                u32::from_le_bytes(message.body[36..40].try_into().unwrap()),
                1002
            );
        }
        kmsg::destroy(&mut tracer.proc, message);
    }
}

#[test]
fn suspended_kill_requires_every_live_thread_to_be_suspended() {
    let (mut tracer, mut tracee, tid) = pair();
    let target = tracee.proc.threads.get_mut(&tid).unwrap();
    target.mach.suspend_count = 1;
    let pc = target.cpu.pc();
    assert_eq!(
        super::super::job_control::all_suspended_pc(&tracee.proc, None),
        Some(pc)
    );
    let tracer_tid = *tracer.proc.threads.keys().next().unwrap();
    let mut running = tracer.proc.threads.remove(&tracer_tid).unwrap();
    running.tid = tid.wrapping_add(1);
    assert_eq!(
        super::super::job_control::all_suspended_pc(&tracee.proc, Some(&running)),
        None
    );
    running.mach.suspend_count = 1;
    assert_eq!(
        super::super::job_control::all_suspended_pc(&tracee.proc, Some(&running)),
        Some(running.cpu.pc())
    );
    running.exited = true;
    assert_eq!(
        super::super::job_control::all_suspended_pc(&tracee.proc, Some(&running)),
        Some(pc)
    );
    tracee.proc.threads.get_mut(&tid).unwrap().exited = true;
    assert_eq!(
        super::super::job_control::all_suspended_pc(&tracee.proc, Some(&running)),
        None
    );
}

#[test]
fn dead_exception_handler_round_trips_without_a_live_capability() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    task.state.lock().unwrap().srights += 1;
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 12]);
    body[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
    body[14] = disp::COPY_SEND as u8;
    body.extend_from_slice(&msg::NDR_RECORD);
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes());
    body.extend_from_slice(&5i32.to_le_bytes());
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, bits::COMPLEX),
        dest: Right::Send(task.clone()),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id: ids::task::TASK_SET_EXCEPTION_PORTS,
        body,
        items: vec![(
            4,
            Item::Port {
                right: Some(Right::Dead),
                disp: disp::MOVE_SEND,
            },
        )],
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    kmsg::deliver(
        &mut Ctx {
            proc: &mut tracer.proc,
            thread: &mut thread,
            nr: -1,
            pc,
        },
        request,
    );
    tracer.proc.threads.insert(tid, thread);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let result = take_reply(&mut tracer.proc, &reply);
    assert_eq!(
        i32::from_le_bytes(result.body[8..12].try_into().unwrap()),
        0
    );
    assert!(tracee.proc.task.exc[5].dead);
    assert!(tracee.proc.task.exc[5].port.is_none());
    kmsg::destroy(&mut tracer.proc, result);

    let mut query = msg::NDR_RECORD.to_vec();
    query.extend_from_slice(&((1u32 << 1) | (1u32 << 5)).to_le_bytes());
    let reply = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS,
        query,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let result = take_reply(&mut tracer.proc, &reply);
    assert!(matches!(result.items[0].1, Item::Port { right: None, .. }));
    assert!(matches!(
        result.items[1].1,
        Item::Port {
            right: Some(Right::Dead),
            ..
        }
    ));
    kmsg::destroy(&mut tracer.proc, result);
}

#[test]
fn null_exception_handler_clears_the_targets_action() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    let old = Port::new(KObject::None);
    old.state.lock().unwrap().srights += 1;
    tracee.proc.task.exc[5].port = Some(old.clone());
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    task.state.lock().unwrap().srights += 1;
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 12]);
    body[14] = disp::COPY_SEND as u8;
    body.extend_from_slice(&msg::NDR_RECORD);
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    body.extend_from_slice(&1i32.to_le_bytes()); // EXCEPTION_DEFAULT
    body.extend_from_slice(&0i32.to_le_bytes()); // THREAD_STATE_NONE
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, bits::COMPLEX),
        dest: Right::Send(task.clone()),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id: ids::task::TASK_SET_EXCEPTION_PORTS,
        body,
        items: vec![(
            4,
            Item::Port {
                right: None,
                disp: disp::MOVE_SEND,
            },
        )],
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    kmsg::deliver(
        &mut Ctx {
            proc: &mut tracer.proc,
            thread: &mut thread,
            nr: -1,
            pc,
        },
        request,
    );
    tracer.proc.threads.insert(tid, thread);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &reply);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    assert!(tracee.proc.task.exc[5].port.is_none());
    assert_eq!(old.state.lock().unwrap().srights, 0);
    kmsg::destroy(&mut tracer.proc, message);

    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    let response = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS,
        body.clone(),
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    assert_ne!(message.bits & bits::COMPLEX, 0);
    assert_eq!(message.items.len(), 32);
    assert!(
        message
            .items
            .iter()
            .all(|(_, item)| matches!(item, Item::Port { right: None, .. }))
    );
    kmsg::destroy(&mut tracer.proc, message);

    let handler = Port::new(KObject::None);
    handler.state.lock().unwrap().srights += 1;
    tracee.proc.task.exc[5].port = Some(handler.clone());
    let response = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS_INFO,
        body.clone(),
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    assert_eq!(
        u32::from_le_bytes(message.body[12..16].try_into().unwrap()),
        1
    );
    assert_ne!(
        u32::from_le_bytes(message.body[20..24].try_into().unwrap()),
        0
    );
    assert_ne!(
        u32::from_le_bytes(message.body[24..28].try_into().unwrap()),
        0
    );
    kmsg::destroy(&mut tracer.proc, message);
    let response = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS,
        body,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        crate::user::darwin::mach::kr::KERN_NOT_SUPPORTED
    );
    assert_eq!(handler.state.lock().unwrap().srights, 1);
    kmsg::destroy(&mut tracer.proc, message);
}

#[test]
fn task_threads_and_thread_state_use_the_target_process() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    assert!(response.state.lock().unwrap().queue.is_empty());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let mut message = take_reply(&mut tracer.proc, &response);
    assert_ne!(message.bits & bits::COMPLEX, 0);
    assert_eq!(message.items.len(), 1);
    let thread = match &message.items[0].1 {
        Item::OolPorts { rights, .. } => {
            assert_eq!(rights.len(), 1);
            let port = rights[0].as_ref().unwrap().port().unwrap().clone();
            assert_eq!(port.kobject, KObject::Thread(tid));
            port
        }
        other => panic!("unexpected descriptor {other:?}"),
    };
    let _thread_name = tracer.proc.insert_send(&thread);
    kmsg::destroy(&mut tracer.proc, message);
    tracee.proc.threads.get_mut(&tid).unwrap().wait =
        Some(crate::user::darwin::wait::Wait::until(None));
    let mut info = msg::NDR_RECORD.to_vec();
    info.extend_from_slice(&3i32.to_le_bytes()); // THREAD_BASIC_INFO
    info.extend_from_slice(&10u32.to_le_bytes());
    let response = send(&mut tracer, &thread, ids::thread_act::THREAD_INFO, info);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    assert_eq!(
        u32::from_le_bytes(message.body[40..44].try_into().unwrap()),
        3
    ); // TH_STATE_WAITING
    kmsg::destroy(&mut tracer.proc, message);
    tracee.proc.threads.get_mut(&tid).unwrap().wait = None;
    for (id, result, count) in [
        (ids::thread_act::THREAD_RESUME, 5i32, 0u32),
        (ids::thread_act::THREAD_SUSPEND, 0, 1),
        (ids::thread_act::THREAD_SUSPEND, 0, 2),
        (ids::thread_act::THREAD_RESUME, 0, 1),
        (ids::thread_act::THREAD_RESUME, 0, 0),
    ] {
        let response = send(&mut tracer, &thread, id, Vec::new());
        ptrace::pump(&mut tracee.proc, None);
        ptrace::pump(&mut tracer.proc, None);
        message = take_reply(&mut tracer.proc, &response);
        assert_eq!(
            i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
            result
        );
        let target = &tracee.proc.threads[&tid];
        assert_eq!(target.mach.suspend_count, count);
        assert_eq!(target.runnable(), count == 0);
        kmsg::destroy(&mut tracer.proc, message);
        if id == ids::thread_act::THREAD_SUSPEND && count == 2 {
            tracee.proc.threads.get_mut(&tid).unwrap().wait =
                Some(crate::user::darwin::wait::Wait::until(None));
            let mut info = msg::NDR_RECORD.to_vec();
            info.extend_from_slice(&3i32.to_le_bytes()); // THREAD_BASIC_INFO
            info.extend_from_slice(&10u32.to_le_bytes());
            let response = send(&mut tracer, &thread, ids::thread_act::THREAD_INFO, info);
            ptrace::pump(&mut tracee.proc, None);
            ptrace::pump(&mut tracer.proc, None);
            message = take_reply(&mut tracer.proc, &response);
            assert_eq!(
                u32::from_le_bytes(message.body[40..44].try_into().unwrap()),
                3
            );
            assert_eq!(
                u32::from_le_bytes(message.body[48..52].try_into().unwrap()),
                2
            );
            kmsg::destroy(&mut tracer.proc, message);
            tracee.proc.threads.get_mut(&tid).unwrap().wait = None;
        }
    }
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&crate::user::darwin::thread_status::arm::THREAD_STATE64.to_le_bytes());
    body.extend_from_slice(
        &crate::user::darwin::thread_status::arm::THREAD_STATE64_COUNT.to_le_bytes(),
    );
    let response = send(
        &mut tracer,
        &thread,
        ids::thread_act::THREAD_GET_STATE,
        body,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    assert_eq!(
        u32::from_le_bytes(message.body[12..16].try_into().unwrap()),
        crate::user::darwin::thread_status::arm::THREAD_STATE64_COUNT
    );
    let pc = u64::from_le_bytes(message.body[16 + 32 * 8..16 + 33 * 8].try_into().unwrap());
    assert_eq!(pc, tracee.proc.threads[&tid].cpu.pc());
    let mut set_body = msg::NDR_RECORD.to_vec();
    set_body
        .extend_from_slice(&crate::user::darwin::thread_status::arm::THREAD_STATE64.to_le_bytes());
    set_body.extend_from_slice(
        &crate::user::darwin::thread_status::arm::THREAD_STATE64_COUNT.to_le_bytes(),
    );
    set_body.extend_from_slice(&message.body[16..]);
    let value = 0x1122_3344_5566_7788u64;
    set_body[16 + 19 * 8..16 + 20 * 8].copy_from_slice(&value.to_le_bytes());
    kmsg::destroy(&mut tracer.proc, message);
    let response = send(
        &mut tracer,
        &thread,
        ids::thread_act::THREAD_SET_STATE,
        set_body,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    assert_eq!(tracee.proc.threads[&tid].cpu.reg(19), value);
    kmsg::destroy(&mut tracer.proc, message);
}

#[test]
fn target_exec_retires_old_image_capabilities_and_rejects_stale_acquires() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _task_name = tracer.proc.insert_send(&task);
    let epoch = tracee
        .proc
        .tracing
        .family
        .parent_status
        .as_ref()
        .unwrap()
        .image_epoch();
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    let thread = match &message.items[0].1 {
        Item::OolPorts { rights, .. } => rights[0].as_ref().unwrap().port().unwrap().clone(),
        other => panic!("unexpected descriptor {other:?}"),
    };
    let _thread_name = tracer.proc.insert_send(&thread);
    kmsg::destroy(&mut tracer.proc, message);

    target_will_exec(&mut tracee.proc);
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
    let stale = serve(
        &mut tracee.proc,
        None,
        Message::Request {
            sequence: 900,
            instance: instance,
            object: Object::Thread(tid),
            id: ids::thread_act::THREAD_SET_STATE,
            bits: 0,
            expects_reply: true,
            body: Vec::new(),
            memory: None,
        },
    );
    match stale {
        server::Response::Mach(Message::Reply { body, .. }) => assert_eq!(
            i32::from_le_bytes(body[8..12].try_into().unwrap()),
            crate::user::darwin::mach::kr::KERN_INVALID_CAPABILITY
        ),
        other => panic!("unexpected response {other:?}"),
    }
    acquire(&mut tracee.proc, 901, instance, epoch, Object::Task);
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
    ptrace::pump(&mut tracer.proc, None);
    assert!(task.is_dead());
    assert!(thread.is_dead());
    let fresh = task_port(&mut tracer.proc, 1002).unwrap();
    assert_ne!(fresh.id, task.id);
}

#[test]
fn remote_thread_update_sets_signal_before_changing_tracee_state() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _task_name = tracer.proc.insert_send(&task);
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    let thread = match &message.items[0].1 {
        Item::OolPorts { rights, .. } => rights[0].as_ref().unwrap().port().unwrap().clone(),
        other => panic!("unexpected descriptor {other:?}"),
    };
    let _thread_name = tracer.proc.insert_send(&thread);
    kmsg::destroy(&mut tracer.proc, message);
    tracee.proc.tracing.tracer = Some(1001);
    let stop = ptrace::TraceStop {
        thread: tid,
        signal: 17,
    };
    tracee.proc.tracing.stopped = Some(stop);
    tracee.proc.tracing.reserved_update = Some(ptrace::ReservedUpdate {
        id: 70,
        signal: 30,
        stop,
    });
    assert_eq!(
        ptrace::commit_update(&mut tracee.proc, None, 70, Some((instance + 1, tid))),
        crate::user::darwin::abi::Errno::ESRCH.0
    );
    assert_eq!(tracee.proc.threads[&tid].sig.pending & (1u32 << 29), 0);
    assert!(tracee.proc.tracing.trace_update.is_none());

    tracee.proc.tracing.reserved_update = Some(ptrace::ReservedUpdate {
        id: 71,
        signal: 30,
        stop,
    });
    assert_eq!(
        ptrace::commit_update(&mut tracee.proc, None, 71, Some((instance, tid))),
        0
    );
    assert_ne!(tracee.proc.threads[&tid].sig.pending & (1u32 << 29), 0);
    assert_eq!(tracee.proc.tracing.trace_update, Some(30));
}

#[test]
fn malformed_thread_array_returns_mig_error_without_creating_rights() {
    let (mut tracer, _tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    let sequence = *tracer
        .proc
        .tracing
        .family
        .mach
        .pending
        .keys()
        .next()
        .unwrap();
    let mut body = vec![0u8; 32];
    body[..4].copy_from_slice(&1u32.to_le_bytes());
    body[14] = disp::MOVE_SEND as u8;
    body[15] = msg::desc::OOL_PORTS;
    body[16..20].copy_from_slice(&2u32.to_le_bytes()); // claims two; carries one
    body[20..28].copy_from_slice(&msg::NDR_RECORD);
    body[28..32].copy_from_slice(&1u32.to_le_bytes());
    receive_reply(
        &mut tracer.proc,
        1002,
        Message::Reply {
            sequence,
            bits: bits::COMPLEX,
            body,
            threads: Some(ThreadArray {
                offset: 4,
                disposition: disp::MOVE_SEND,
                threads: vec![123],
            }),
            memory: None,
        },
    );
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        crate::user::darwin::mach::kr::MIG_TYPE_ERROR
    );
    assert!(
        tracer.proc.tracing.family.mach.peers[&(1002, instance)]
            .threads
            .is_empty()
    );
    kmsg::destroy(&mut tracer.proc, message);
}

#[test]
fn remote_read_rejects_malformed_memory_replies() {
    let (mut tracer, _tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    let mut request = msg::NDR_RECORD.to_vec();
    request.extend_from_slice(&0x1000u64.to_le_bytes());
    request.extend_from_slice(&8u64.to_le_bytes());
    let response = send(
        &mut tracer,
        &task,
        ids::mach_vm::KERNELRPC_MACH_VM_READ,
        request,
    );
    let sequence = *tracer
        .proc
        .tracing
        .family
        .mach
        .pending
        .keys()
        .next()
        .unwrap();
    let mut body = vec![0u8; 32];
    body[..4].copy_from_slice(&1u32.to_le_bytes());
    body[15] = msg::desc::OOL;
    body[16..20].copy_from_slice(&8u32.to_le_bytes());
    body[20..28].copy_from_slice(&msg::NDR_RECORD);
    body[28..32].copy_from_slice(&8u32.to_le_bytes());
    receive_reply(
        &mut tracer.proc,
        1002,
        Message::Reply {
            sequence,
            bits: bits::COMPLEX,
            body,
            threads: None,
            memory: Some(Memory {
                offset: 4,
                copy: msg::desc::VIRTUAL_COPY,
                page_offset: 0,
                data: vec![0; 7],
            }),
        },
    );
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        crate::user::darwin::mach::kr::MIG_TYPE_ERROR
    );
    assert!(message.items.is_empty());
    kmsg::destroy(&mut tracer.proc, message);
}

#[test]
fn region_reply_accepts_only_a_null_object_descriptor() {
    let (mut tracer, _tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _task_name = tracer.proc.insert_send(&task);
    for malformed in [true, false] {
        let mut request = msg::NDR_RECORD.to_vec();
        request.extend_from_slice(&0x1000u64.to_le_bytes());
        request.extend_from_slice(&9i32.to_le_bytes());
        request.extend_from_slice(&10u32.to_le_bytes());
        let response = send(&mut tracer, &task, ids::mach_vm::MACH_VM_REGION, request);
        let sequence = *tracer
            .proc
            .tracing
            .family
            .mach
            .pending
            .keys()
            .next()
            .unwrap();
        let mut body = vec![0u8; 44];
        body[..4].copy_from_slice(&1u32.to_le_bytes());
        body[4] = u8::from(malformed);
        body[14] = disp::MOVE_SEND as u8;
        body[15] = msg::desc::PORT;
        body[16..24].copy_from_slice(&msg::NDR_RECORD);
        receive_reply(
            &mut tracer.proc,
            1002,
            Message::Reply {
                sequence,
                bits: bits::COMPLEX,
                body,
                threads: None,
                memory: None,
            },
        );
        let message = take_reply(&mut tracer.proc, &response);
        if malformed {
            assert_eq!(
                i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
                crate::user::darwin::mach::kr::MIG_TYPE_ERROR
            );
            assert!(message.items.is_empty());
        } else {
            assert!(matches!(
                message.items.as_slice(),
                [(
                    4,
                    Item::Port {
                        right: None,
                        disp: disp::MOVE_SEND
                    }
                )]
            ));
        }
        kmsg::destroy(&mut tracer.proc, message);
    }
}

#[test]
fn large_memory_frames_validate_their_snapshot_descriptor() {
    let message = Message::Request {
        sequence: 51,
        instance: 20,
        object: Object::Task,
        id: ids::mach_vm::MACH_VM_WRITE,
        bits: bits::COMPLEX,
        expects_reply: true,
        body: vec![0; 40],
        memory: Some(Memory {
            offset: 4,
            copy: msg::desc::VIRTUAL_COPY,
            page_offset: 0,
            data: vec![0x5a; MAX_FRAME + 7],
        }),
    };
    let frame = encode_frame(message.clone()).unwrap();
    assert!(frame.fd.is_some());
    let (decoded, failed) = decode_frame(frame).unwrap();
    assert!(!failed);
    assert_eq!(decoded, message);

    let mut frame = encode_frame(message.clone()).unwrap();
    frame.fd = None;
    assert_eq!(
        decode_frame(frame).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    let mut frame = encode_frame(message).unwrap();
    frame.payload[1..5].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_frame(frame).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn peer_exit_fails_pending_calls_and_kills_proxy_rights() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    tracee.proc.tracing.family.parent = None;
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        crate::user::darwin::mach::kr::KERN_TERMINATED
    );
    assert!(task.is_dead());
    kmsg::destroy(&mut tracer.proc, message);
}

#[test]
fn task_export_lives_until_the_last_local_send_right_is_released() {
    let (mut tracer, mut tracee, _) = pair();
    let target = tracee.proc.task_port.clone();
    let before = target.state.lock().unwrap().srights;
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let name = tracer.proc.insert_send(&task);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(target.state.lock().unwrap().srights, before + 1);
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
    assert_eq!(
        crate::user::darwin::syscall::mach::port::deallocate(&mut tracer.proc, name),
        0
    );
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(target.state.lock().unwrap().srights, before);
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
}

#[test]
fn stale_thread_release_does_not_drop_a_newer_export() {
    let (mut tracer, mut tracee, tid) = pair();
    let target = tracee.proc.threads[&tid].kport.clone();
    let before = target.state.lock().unwrap().srights;
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _name = tracer.proc.insert_send(&task);
    let first = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let first = take_reply(&mut tracer.proc, &first);
    assert_eq!(target.state.lock().unwrap().srights, before + 1);
    let second = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    let newer = tracee.proc.tracing.family.mach.parent_server.exports
        [&(instance, Object::Thread(tid))]
        .generation;
    kmsg::destroy(&mut tracer.proc, first);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(
        tracee.proc.tracing.family.mach.parent_server.exports[&(instance, Object::Thread(tid))]
            .generation,
        newer
    );
    assert_eq!(target.state.lock().unwrap().srights, before + 1);
    ptrace::pump(&mut tracer.proc, None);
    let second = take_reply(&mut tracer.proc, &second);
    kmsg::destroy(&mut tracer.proc, second);
    ptrace::pump(&mut tracee.proc, None);
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
    assert_eq!(target.state.lock().unwrap().srights, before);
}

#[test]
fn target_thread_death_kills_the_remote_thread_port() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let response = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    let remote = match &message.items[0].1 {
        Item::OolPorts { rights, .. } => rights[0].as_ref().unwrap().port().unwrap().clone(),
        other => panic!("unexpected descriptor {other:?}"),
    };
    let _thread_name = tracer.proc.insert_send(&remote);
    kmsg::destroy(&mut tracer.proc, message);
    let target = tracee.proc.threads[&tid].kport.clone();
    kmsg::destroy_receive(&mut tracee.proc, &target);
    local_thread_died(&mut tracee.proc, tid);
    ptrace::pump(&mut tracer.proc, None);
    assert!(remote.is_dead());
    assert!(
        !tracer
            .proc
            .tracing
            .family
            .mach
            .ports
            .contains_key(&remote.id)
    );
}

#[test]
fn exec_cancels_pending_reply_and_releases_late_thread_exports() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _name = tracer.proc.insert_send(&task);
    let _reply = send(&mut tracer, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
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
        tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Thread(tid)))
    );
    before_exec(&mut tracer.proc);
    assert!(tracer.proc.tracing.family.mach.peers.is_empty());
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .pending
            .values()
            .all(|pending| pending.canceled)
    );
    ptrace::pump(&mut tracee.proc, None);
    assert!(
        !tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(instance, Object::Task))
    );
    ptrace::pump(&mut tracer.proc, None);
    ptrace::pump(&mut tracee.proc, None);
    assert!(
        tracee
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
    assert!(tracer.proc.tracing.family.mach.pending.is_empty());
}

#[test]
fn a_one_way_enumeration_does_not_export_thread_rights() {
    let (mut tracer, mut tracee, tid) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let instance = tracer.proc.tracing.family.mach.ports[&task.id].instance;
    let _name = tracer.proc.insert_send(&task);
    let baseline = tracee.proc.threads[&tid]
        .kport
        .state
        .lock()
        .unwrap()
        .srights;
    let packet = Message::Request {
        sequence: 500,
        instance: instance,
        object: Object::Task,
        id: ids::task::TASK_THREADS,
        bits: 0,
        expects_reply: false,
        body: Vec::new(),
        memory: None,
    };
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
    link.queue(&packet.encode().unwrap()).unwrap();
    link.flush().unwrap();
    ptrace::pump(&mut tracee.proc, None);
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
    assert_eq!(
        tracee.proc.threads[&tid]
            .kport
            .state
            .lock()
            .unwrap()
            .srights,
        baseline
    );
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
    let (frames, closed) = link.receive().unwrap();
    assert!(!closed);
    assert!(frames.is_empty());
}

#[path = "remote_mach_backpressure_tests.rs"]
mod backpressure;
#[path = "remote_mach_callback_inherit_tests.rs"]
mod callback_inheritance;
#[path = "remote_mach_callback_install_tests.rs"]
mod callback_installation;
#[path = "remote_mach_callback_runtime_tests.rs"]
mod callback_lifecycle;
