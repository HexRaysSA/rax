//! Legacy holds traverse the actual tracing-link pump and caller namespace.

use super::*;
use crate::user::darwin::mach::kr;
use crate::user::darwin::syscall::mach::port;

fn setup() -> (DarwinProcess, DarwinProcess, Arc<Port>) {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    tracer.proc.insert_send(&task);
    ptrace::pump(&mut tracee.proc, None);
    (tracer, tracee, task)
}

fn call(tracer: &mut DarwinProcess, tracee: &mut DarwinProcess, task: &Arc<Port>, id: i32) -> i32 {
    let reply = send(tracer, task, id, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let message = take_reply(&mut tracer.proc, &reply);
    let result = i32::from_le_bytes(message.body[8..12].try_into().unwrap());
    kmsg::destroy(&mut tracer.proc, message);
    result
}

fn hidden(proc: &Proc) -> (u32, Arc<Port>) {
    proc.ipc
        .names()
        .into_iter()
        .find_map(|(name, _)| {
            let entry = proc.ipc.lookup(name).ok()?;
            let port = entry.port()?;
            (port.kobject == KObject::TaskResume(None) && entry.send > 0)
                .then(|| (name, port.clone()))
        })
        .expect("hidden caller resume right")
}

fn register(tracer: &mut DarwinProcess, port: Option<&Arc<Port>>) {
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    let task = tracer.proc.task_port.clone();
    task.state.lock().unwrap().srights += 1;
    let mut body = 3u32.to_le_bytes().to_vec();
    body.resize(40, 0);
    let mut items = Vec::new();
    for slot in 0..3 {
        let offset = 4 + slot * 12;
        body[offset + 10] = disp::MOVE_SEND as u8;
        body[offset + 11] = msg::desc::PORT;
        let right = if slot == 0 {
            port.map(|port| {
                port.state.lock().unwrap().srights += 1;
                Right::Send(port.clone())
            })
        } else {
            None
        };
        items.push((
            offset,
            Item::Port {
                right,
                disp: disp::MOVE_SEND,
            },
        ));
    }
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, bits::COMPLEX),
        dest: Right::Send(task),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id: ids::task::KERNELRPC_MACH_PORTS_REGISTER3,
        body,
        items,
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
    let message = take_reply(&mut tracer.proc, &reply);
    assert_eq!(
        i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
        0
    );
    kmsg::destroy(&mut tracer.proc, message);
}

fn exec_namespace(tracer: &mut DarwinProcess) {
    before_exec(&mut tracer.proc);
    tracer.proc.task = crate::user::darwin::exec::exec_task(&tracer.proc.task);
    tracer.proc.ipc = crate::user::darwin::mach::ipc::IpcSpace::new();
}

#[test]
fn registered_resume_send_survives_caller_exec_and_releases_on_clear() {
    let (mut tracer, mut tracee, task) = setup();
    for _ in 0..2 {
        assert_eq!(
            call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
            0
        );
    }
    let (_, proxy) = hidden(&tracer.proc);
    register(&mut tracer, Some(&proxy));
    assert_eq!(proxy.state.lock().unwrap().srights, 2);
    exec_namespace(&mut tracer);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    assert!(!proxy.is_dead());
    assert_eq!(proxy.state.lock().unwrap().srights, 1);
    register(&mut tracer, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn late_suspend_reply_preserves_registered_send_after_caller_exec() {
    let (mut tracer, mut tracee, task) = setup();
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let (_, proxy) = hidden(&tracer.proc);
    register(&mut tracer, Some(&proxy));
    let _reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    exec_namespace(&mut tracer);
    ptrace::pump(&mut tracer.proc, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    assert!(!proxy.is_dead());
    register(&mut tracer, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn pending_invalid_handler_does_not_destroy_registered_resume_send_on_exec() {
    let (mut tracer, mut tracee, task) = setup();
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let (_, proxy) = hidden(&tracer.proc);
    register(&mut tracer, Some(&proxy));
    // A kernel-object send is rejected as an exception handler. It remains
    // borrowed by the in-flight request until the target validates it.
    let _reply = super::callback_installation::install(&mut tracer, &task, &proxy, 1, 6);
    exec_namespace(&mut tracer);
    assert!(!proxy.is_dead());
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    assert_eq!(proxy.state.lock().unwrap().srights, 1);
    register(&mut tracer, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn remote_hidden_urefs_and_last_send_release_every_legacy_hold() {
    let (mut tracer, mut tracee, task) = setup();
    for count in [1, 2] {
        assert_eq!(
            call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
            0
        );
        assert_eq!(tracee.proc.task.suspension.count(), count);
    }
    assert!(
        tracee
            .proc
            .ipc
            .name_of(tracee.proc.task.suspension.resume.as_ref().unwrap())
            .is_none()
    );
    let (name, proxy) = hidden(&tracer.proc);
    assert_eq!(port::kobject_type(&proxy.kobject), 36);
    assert_eq!(tracer.proc.ipc.lookup(name).unwrap().send, 2);
    assert_eq!(proxy.state.lock().unwrap().srights, 1);
    let actual = tracee.proc.task.suspension.resume.clone().unwrap();
    assert_eq!(actual.state.lock().unwrap().srights, 1);
    assert_eq!(port::deallocate(&mut tracer.proc, name), 0);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    assert_eq!(port::deallocate(&mut tracer.proc, name), 0);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(actual.state.lock().unwrap().srights, 0);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_RESUME),
        kr::KERN_FAILURE
    );
}

#[test]
fn remote_resume_consumes_one_uref_and_failure_destroys_stale_urefs() {
    let (mut tracer, mut tracee, task) = setup();
    for _ in 0..2 {
        assert_eq!(
            call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
            0
        );
    }
    let (name, _) = hidden(&tracer.proc);
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_RESUME),
        0
    );
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    assert_eq!(tracer.proc.ipc.lookup(name).unwrap().send, 1);
    tracee
        .proc
        .task
        .suspension
        .release(crate::user::darwin::mach::suspend::Hold::Normal)
        .unwrap();
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_RESUME),
        kr::KERN_FAILURE
    );
    assert!(tracer.proc.ipc.lookup(name).is_err());
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(
        tracee
            .proc
            .task
            .suspension
            .resume
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .srights,
        0
    );
}

#[test]
fn caller_exec_and_disconnect_release_holds_and_target_exec_kills_hidden_rights() {
    for event in 0..3 {
        let (mut tracer, mut tracee, task) = setup();
        assert_eq!(
            call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
            0
        );
        let (_, proxy) = hidden(&tracer.proc);
        match event {
            0 => {
                before_exec(&mut tracer.proc);
                ptrace::pump(&mut tracee.proc, None);
            }
            1 => {
                parent_died(&mut tracee.proc);
            }
            _ => {
                target_will_exec(&mut tracee.proc);
                ptrace::pump(&mut tracer.proc, None);
            }
        }
        assert_eq!(tracee.proc.task.suspension.count(), 0);
        if event != 1 {
            assert!(proxy.is_dead());
        }
    }
}

#[test]
fn caller_exec_during_suspend_reply_does_not_strand_a_hold() {
    let (mut tracer, mut tracee, task) = setup();
    let reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    before_exec(&mut tracer.proc);
    ptrace::pump(&mut tracer.proc, None);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
    assert_eq!(reply.state.lock().unwrap().queue.len(), 1);
    // The notification carries the original destination send-once right
    // until receive consumes it; enqueue alone does not decrement sorights.
    let notification = take_reply(&mut tracer.proc, &reply);
    assert_eq!(notification.id, kmsg::MACH_NOTIFY_SEND_ONCE);
    assert_eq!(reply.state.lock().unwrap().sorights, 0);
    kmsg::destroy(&mut tracer.proc, notification);
}

#[test]
fn last_send_waits_for_connection_capacity_and_precedes_the_next_rpc() {
    let (mut tracer, mut tracee, task) = setup();
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let (name, _) = hidden(&tracer.proc);
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
    // SAFETY: the link owns a live socket; capacity is an initialized integer.
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
    port::deallocate(&mut tracer.proc, name);
    assert!(callback_runtime::wants_write(
        &tracer.proc.tracing.family.mach,
        1002
    ));
    let reply = send(&mut tracer, &task, ids::task::TASK_SUSPEND, Vec::new());
    let rejected = take_reply(&mut tracer.proc, &reply);
    assert_eq!(
        i32::from_le_bytes(rejected.body[8..12].try_into().unwrap()),
        kr::KERN_RESOURCE_SHORTAGE
    );
    kmsg::destroy(&mut tracer.proc, rejected);
    let token = tracee.proc.task.suspension.resume.as_ref().unwrap().id;
    let mut releases = 0;
    for _ in 0..10000 {
        let frames = tracee
            .proc
            .tracing
            .family
            .parent
            .as_mut()
            .unwrap()
            .receive()
            .unwrap()
            .0;
        for bytes in frames {
            if let Ok(packet @ suspension::Packet::Release { token: got, .. }) =
                suspension::Packet::decode(&bytes)
            {
                assert_eq!(got, token);
                releases += 1;
                suspension::from_parent(&mut tracee.proc, packet);
            }
        }
        assert!(callback_runtime::flush_child(&mut tracer.proc, 1002));
        if releases > 0 {
            break;
        }
    }
    assert_eq!(releases, 1);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
    assert!(!callback_runtime::wants_write(
        &tracer.proc.tracing.family.mach,
        1002
    ));
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    assert_eq!(tracee.proc.task.suspension.count(), 1);
}

#[test]
fn a_stale_last_send_cannot_release_a_reacquired_resume_right() {
    let (mut tracer, mut tracee, task) = setup();
    let old_generation = tracer.proc.tracing.family.mach.next_sequence;
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let (name, _) = hidden(&tracer.proc);
    port::deallocate(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let token = tracee.proc.task.suspension.resume.as_ref().unwrap().id;
    suspension::from_parent(
        &mut tracee.proc,
        suspension::Packet::Release {
            token,
            generation: old_generation,
        },
    );
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    let (name, _) = hidden(&tracer.proc);
    port::deallocate(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn a_message_without_a_reply_right_still_installs_the_hidden_send() {
    let (mut tracer, mut tracee, task) = setup();
    task.state.lock().unwrap().srights += 1;
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, 0, 0, 0),
        dest: Right::Send(task),
        reply: None,
        voucher: None,
        voucher_name: 0,
        id: ids::task::TASK_SUSPEND,
        body: Vec::new(),
        items: Vec::new(),
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
    assert!(tracer.proc.tracing.family.mach.pending.is_empty());
    let (name, _) = hidden(&tracer.proc);
    port::deallocate(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn hidden_uref_exhaustion_preserves_existing_send_and_its_holds() {
    let (mut tracer, mut tracee, task) = setup();
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    let (name, proxy) = hidden(&tracer.proc);
    tracer.proc.ipc.entry_mut(name).unwrap().send = crate::user::darwin::mach::ipc::UREFS_MAX;
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        kr::KERN_UREFS_OVERFLOW
    );
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    assert_eq!(proxy.state.lock().unwrap().srights, 1);
    port::destroy(&mut tracer.proc, name);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}

#[test]
fn suspension_frames_reject_truncation_trailing_bytes_and_invalid_flags() {
    use suspension::Packet;
    for packet in [
        Packet::TraceResume {
            id: 8,
            token: 0,
            result: 5,
        },
        Packet::Reply {
            sequence: 0,
            token: 7,
            generation: 0,
            result: 0,
            suspend: true,
        },
        Packet::Reply {
            sequence: 9,
            token: 0,
            generation: 0,
            result: 5,
            suspend: false,
        },
        Packet::Release {
            token: 7,
            generation: 3,
        },
        Packet::Dead {
            token: 7,
            generation: 3,
        },
    ] {
        let encoded = packet.encode();
        assert_eq!(Packet::decode(&encoded).unwrap(), packet);
        for n in 0..encoded.len() {
            assert!(Packet::decode(&encoded[..n]).is_err());
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(Packet::decode(&extended).is_err());
    }
    let mut encoded = Packet::Reply {
        sequence: 0,
        token: 7,
        generation: 0,
        result: 0,
        suspend: true,
    }
    .encode();
    encoded[29] = 2;
    assert!(Packet::decode(&encoded).is_err());
    encoded[29] = 1;
    encoded[9..17].fill(0);
    assert!(Packet::decode(&encoded).is_err());
}

#[test]
fn hard_ptrace_continue_consumes_a_legacy_uref_and_leaves_the_other_hold() {
    let (mut tracer, mut tracee, task) = setup();
    tracee.proc.tracing.tracer = Some(1001);
    let target_tid = *tracee.proc.threads.keys().next().unwrap();
    assert!(ptrace::stop_for_signal(
        &mut tracee.proc,
        target_tid,
        crate::user::darwin::signal::SIGSTOP,
        0x1234
    ));
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    ptrace::pump(&mut tracer.proc, None);
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_SUSPEND),
        0
    );
    assert_eq!(tracee.proc.task.suspension.count(), 2);
    let (name, _) = hidden(&tracer.proc);
    let tid = *tracer.proc.threads.keys().next().unwrap();
    let mut thread = tracer.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    let _ = ptrace::ptrace(
        &mut Ctx {
            proc: &mut tracer.proc,
            thread: &mut thread,
            nr: 26,
            pc,
        },
        ptrace::PT_CONTINUE,
        1002,
        1,
        0,
    );
    tracer.proc.threads.insert(tid, thread);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    assert_eq!(tracer.proc.tracing.pending[&tid].errno, Some(0));
    assert!(tracer.proc.ipc.lookup(name).is_err());
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    ptrace::pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.task.suspension.count(), 1);
    assert_eq!(
        call(&mut tracer, &mut tracee, &task, ids::task::TASK_RESUME),
        0
    );
    assert_eq!(tracee.proc.task.suspension.count(), 0);
}
