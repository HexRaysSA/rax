//! Tokens traverse real transport, MIG dispatch, IPC copyout and destruction.

use super::*;
use crate::user::darwin::mach::kr;
use crate::user::darwin::syscall::mach::port;

fn legacy_name(tracer: &Proc) -> u32 {
    tracer
        .ipc
        .names()
        .into_iter()
        .find_map(|(name, _)| {
            let entry = tracer.ipc.lookup(name).ok()?;
            (entry.send > 0
                && entry
                    .port()
                    .is_some_and(|p| p.kobject == KObject::TaskResume(None)))
            .then_some(name)
        })
        .unwrap()
}

#[test]
fn raw_resume2_accepts_legacy_sends_and_runs_before_last_send_release() {
    for disposition in [disp::COPY_SEND, disp::MOVE_SEND] {
        let (mut tracer, mut tracee, task, _) = setup();
        let reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
        assert_eq!(complete(&mut tracer, &mut tracee, &reply), 0);
        let name = legacy_name(&tracer.proc);
        let destination = tracer.proc.ipc.copyin(name, disposition).unwrap();
        let response = request(
            &mut tracer,
            destination,
            ids::task::TASK_RESUME2,
            Vec::new(),
            true,
        );
        assert_eq!(complete(&mut tracer, &mut tracee, &response), 0);
        assert_eq!(tracee.proc.task.suspension.count(), 0);
        if disposition == disp::COPY_SEND {
            port::deallocate(&mut tracer.proc, name);
        }
        ptrace::pump(&mut tracee.proc, None);
    }
}

#[test]
fn final_send_call_stays_before_no_senders_under_output_backpressure() {
    let (mut tracer, mut tracee, task, _) = setup();
    let reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
    assert_eq!(complete(&mut tracer, &mut tracee, &reply), 0);
    let name = legacy_name(&tracer.proc);
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
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 32]).unwrap();
    let destination = tracer.proc.ipc.copyin(name, disp::MOVE_SEND).unwrap();
    let response = request(
        &mut tracer,
        destination,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    let mut observed = Vec::new();
    for _ in 0..10_000 {
        let (frames, closed) = tracee
            .proc
            .tracing
            .family
            .parent
            .as_mut()
            .unwrap()
            .receive()
            .unwrap();
        assert!(!closed);
        for bytes in frames {
            if let Ok(packet) = super::super::token::Packet::decode(&bytes) {
                observed.push("call");
                super::super::token::from_parent(&mut tracee.proc, None, packet);
            } else if let Ok(packet) = super::super::suspension::Packet::decode(&bytes) {
                observed.push("release");
                super::super::suspension::from_parent(&mut tracee.proc, packet);
            }
        }
        ptrace::pump(&mut tracer.proc, None);
        if observed.len() == 2 {
            break;
        }
    }
    assert_eq!(observed, ["call", "release"]);
    assert_eq!(complete(&mut tracer, &mut tracee, &response), 0);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn shared_resume_send_preserves_stale_legacy_credits_and_coalesced_urefs() {
    let (mut tracer, mut tracee, task, _) = setup();
    for _ in 0..2 {
        let reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
        assert_eq!(complete(&mut tracer, &mut tracee, &reply), 0);
    }
    let name = legacy_name(&tracer.proc);
    let destination = tracer.proc.ipc.copyin(name, disp::COPY_SEND).unwrap();
    let response = request(
        &mut tracer,
        destination,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    assert_eq!(complete(&mut tracer, &mut tracee, &response), 0);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    assert_eq!(tracer.proc.ipc.lookup(name).unwrap().send, 2);
    port::deallocate(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    port::deallocate(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn token_call_with_no_live_target_thread_consumes_the_destination() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    let resume = tracee.proc.task.suspension.resume.clone().unwrap();
    let response = request(
        &mut tracer,
        token,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    for thread in tracee.proc.threads.values_mut() {
        thread.exited = true;
    }
    assert_eq!(
        complete(&mut tracer, &mut tracee, &response),
        kr::KERN_TERMINATED
    );
    assert_eq!(resume.state.lock().unwrap().sorights, 0);
}

fn setup() -> (DarwinProcess, DarwinProcess, Arc<Port>, u32) {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let name = tracer.proc.insert_send(&task);
    ptrace::pump(&mut tracee.proc, None);
    (tracer, tracee, task, name)
}

fn suspend(tracer: &mut DarwinProcess, tracee: &mut DarwinProcess, task: &Arc<Port>) -> Right {
    let reply = send(tracer, task, ids::task::TASK_SUSPEND2, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let mut message = take_reply(&mut tracer.proc, &reply);
    let (
        offset,
        Item::Port {
            right: Some(token),
            disp,
        },
    ) = message.items.remove(0)
    else {
        panic!()
    };
    assert_eq!((offset, disp), (4, disp::MOVE_SEND_ONCE));
    assert!(matches!(token, Right::SendOnce(_)));
    kmsg::destroy(&mut tracer.proc, message);
    token
}

fn request(
    tracer: &mut DarwinProcess,
    destination: Right,
    id: i32,
    body: Vec<u8>,
    reply: bool,
) -> Arc<Port> {
    let response = Port::new(KObject::None);
    response.state.lock().unwrap().sorights = u32::from(reply);
    let remote = if matches!(destination, Right::SendOnce(_)) {
        disp::MOVE_SEND_ONCE
    } else {
        disp::MOVE_SEND
    };
    let message = msg::Message {
        bits: bits::set(remote, if reply { disp::MOVE_SEND_ONCE } else { 0 }, 0, 0),
        dest: destination,
        reply: reply.then(|| Right::SendOnce(response.clone())),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    deliver_message(tracer, message);
    response
}

fn deliver_message(tracer: &mut DarwinProcess, message: msg::Message) {
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
        message,
    );
    tracer.proc.threads.insert(tid, thread);
}

#[test]
fn a_kernel_reply_uses_its_token_destination_without_abandoning_it() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    let port = token.port().unwrap().clone();
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&20i32.to_le_bytes());
    body.extend_from_slice(&12u32.to_le_bytes());
    task.state.lock().unwrap().srights += 1;
    deliver_message(
        &mut tracer,
        msg::Message {
            bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, 0),
            dest: Right::Send(task),
            reply: Some(token),
            voucher: None,
            voucher_name: 0,
            id: ids::task::TASK_INFO,
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(port.state.lock().unwrap().sorights, 0);
    // The reply's id is not task_resume2. Like an unknown client RPC it
    // consumes the destination without releasing the normal hold.
    assert_eq!(tracee.proc.task.suspension.count(), 1);
}

#[test]
fn a_token_offer_survives_output_backpressure_until_it_is_abandoned() {
    let (mut tracer, mut tracee, task, _) = setup();
    let response = send(&mut tracer, &task, ids::task::TASK_SUSPEND2, Vec::new());
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    for _ in 0..3 {
        link.queue(&vec![0; MAX_FRAME]).unwrap();
    }
    link.queue(&vec![0; MAX_FRAME - 32]).unwrap();
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    let mut offered = false;
    for _ in 0..10_000 {
        let (frames, closed) = tracer
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
            .unwrap();
        assert!(!closed);
        for bytes in frames {
            if let Ok(packet) = super::super::token::Packet::decode(&bytes) {
                super::super::token::from_child(&mut tracer.proc, 1002, packet);
                offered = true;
            }
        }
        ptrace::pump(&mut tracee.proc, None);
        if offered {
            break;
        }
    }
    assert!(offered);
    let message = take_reply(&mut tracer.proc, &response);
    kmsg::destroy(&mut tracer.proc, message);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn target_disconnect_completes_a_pending_resume() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    let response = request(
        &mut tracer,
        token,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    drop(tracee);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &response);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        kr::KERN_TERMINATED
    );
    kmsg::destroy(&mut tracer.proc, message);
}

fn complete(tracer: &mut DarwinProcess, tracee: &mut DarwinProcess, response: &Arc<Port>) -> i32 {
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, response);
    let result = i32::from_le_bytes(message.body[8..12].try_into().unwrap());
    kmsg::destroy(&mut tracer.proc, message);
    result
}

#[test]
fn tokens_are_independent_of_each_other_and_the_task_control_name() {
    let (mut tracer, mut tracee, task, task_name) = setup();
    let a = suspend(&mut tracer, &mut tracee, &task);
    let b = suspend(&mut tracer, &mut tracee, &task);
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    let a = tracer.proc.ipc.insert(a).unwrap();
    let b = tracer.proc.ipc.insert(b).unwrap();
    assert_ne!(a, b);
    port::deallocate(&mut tracer.proc, task_name);
    port::deallocate(&mut tracer.proc, a);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    let destination = tracer.proc.ipc.copyin(b, disp::MOVE_SEND_ONCE).unwrap();
    let response = request(
        &mut tracer,
        destination,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    assert_eq!(complete(&mut tracer, &mut tracee, &response), 0);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn malformed_calls_use_up_the_remote_token_without_releasing_its_hold() {
    for (id, body, error) in [
        (0x7fff_fffe, Vec::new(), kr::MIG_BAD_ID),
        (ids::task::TASK_RESUME2, vec![0; 4], kr::MIG_BAD_ARGUMENTS),
        (
            ids::task::TASK_RESUME2,
            vec![0; 2 * MAX_FRAME],
            kr::MIG_BAD_ARGUMENTS,
        ),
        (0x7fff_fffe, vec![0; 2 * MAX_FRAME], kr::MIG_BAD_ID),
    ] {
        let (mut tracer, mut tracee, task, _) = setup();
        let token = suspend(&mut tracer, &mut tracee, &task);
        let port = token.port().unwrap().clone();
        let response = request(&mut tracer, token, id, body, true);
        assert_eq!(complete(&mut tracer, &mut tracee, &response), error);
        assert_eq!(tracee.proc.task.suspension.count(), 1);
        assert_eq!(port.state.lock().unwrap().sorights, 0);
    }
}

#[test]
fn out_of_band_resume_drains_the_hold_but_not_the_token() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    let reply = send(&mut tracer, &task, ids::task::TASK_RESUME, Vec::new());
    assert_eq!(complete(&mut tracer, &mut tracee, &reply), 0);
    let reply = request(
        &mut tracer,
        token,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    );
    assert_eq!(complete(&mut tracer, &mut tracee, &reply), kr::KERN_FAILURE);
}

#[test]
fn caller_exec_releases_both_delivered_and_late_tokens() {
    for late in [false, true] {
        let (mut tracer, mut tracee, task, _) = setup();
        if late {
            send(&mut tracer, &task, ids::task::TASK_SUSPEND2, Vec::new());
            ptrace::pump(&mut tracee.proc, None);
        } else {
            let token = suspend(&mut tracer, &mut tracee, &task);
            tracer.proc.ipc.insert(token).unwrap();
        }
        assert_eq!(tracee.proc.task.suspension.count(), 1);
        before_exec(&mut tracer.proc);
        ptrace::pump(&mut tracer.proc, None);
        ptrace::pump(&mut tracee.proc, None);
        assert_eq!(tracee.proc.task.suspension.count(), 0);
    }
}

#[test]
fn caller_disconnect_abandons_every_target_send_once() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    tracer.proc.ipc.insert(token).unwrap();
    drop(tracer);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn target_exec_invalidates_outstanding_token_names() {
    let (mut tracer, mut tracee, task, _) = setup();
    let token = suspend(&mut tracer, &mut tracee, &task);
    let name = tracer.proc.ipc.insert(token).unwrap();
    target_will_exec(&mut tracee.proc);
    ptrace::pump(&mut tracer.proc, None);
    assert_eq!(tracer.proc.ipc.lookup(name).unwrap().dead, 1);
}

#[test]
fn one_way_suspend_discards_its_token_and_one_way_resume_consumes_it() {
    let (mut tracer, mut tracee, task, _) = setup();
    task.state.lock().unwrap().srights += 1;
    request(
        &mut tracer,
        Right::Send(task.clone()),
        ids::task::TASK_SUSPEND2,
        Vec::new(),
        false,
    );
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
    let token = suspend(&mut tracer, &mut tracee, &task);
    request(
        &mut tracer,
        token,
        ids::task::TASK_RESUME2,
        Vec::new(),
        false,
    );
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn token_wire_validates_framing_and_boolean_fields() {
    use super::super::token::Packet;
    let packets = [
        Packet::Offer {
            sequence: 1,
            instance: 2,
            token: 3,
        },
        Packet::Drop { token: 3 },
        Packet::Dead { token: 3 },
        Packet::Call {
            once: true,
            sequence: 1,
            token: 3,
            id: 3437,
            bits: 18,
            reply: true,
            body: vec![0; 4],
        },
        Packet::Call {
            once: false,
            sequence: 1,
            token: 3,
            id: 3437,
            bits: 17,
            reply: false,
            body: Vec::new(),
        },
        Packet::Result {
            sequence: 1,
            result: -304,
        },
    ];
    for packet in packets {
        let mut bytes = packet.encode();
        assert_eq!(Packet::decode(&bytes).unwrap(), packet);
        for size in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..size]).is_err());
        }
        bytes.push(0);
        assert!(Packet::decode(&bytes).is_err());
        if let Packet::Call { .. } = packet {
            bytes.pop();
            bytes[25] = 2;
            assert!(Packet::decode(&bytes).is_err());
        }
    }
}
