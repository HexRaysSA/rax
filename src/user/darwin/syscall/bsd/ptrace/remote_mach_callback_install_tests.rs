//! Install live exception-handler sends through the target's MIG server.

use super::*;

pub(super) fn install(
    tracer: &mut DarwinProcess,
    task: &Arc<Port>,
    handler: &Arc<Port>,
    behavior: i32,
    flavor: i32,
) -> Arc<Port> {
    update(
        tracer,
        task,
        handler,
        behavior,
        flavor,
        ids::task::TASK_SET_EXCEPTION_PORTS,
    )
}

fn update(
    tracer: &mut DarwinProcess,
    task: &Arc<Port>,
    handler: &Arc<Port>,
    behavior: i32,
    flavor: i32,
    id: i32,
) -> Arc<Port> {
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    task.state.lock().unwrap().srights += 1;
    handler.state.lock().unwrap().srights += 1;
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 12]);
    body[14] = disp::MOVE_SEND as u8;
    body[15] = msg::desc::PORT;
    body.extend_from_slice(&msg::NDR_RECORD);
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    body.extend_from_slice(&behavior.to_le_bytes());
    body.extend_from_slice(&flavor.to_le_bytes());
    let request = msg::Message {
        bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, bits::COMPLEX),
        dest: Right::Send(task.clone()),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: vec![(
            4,
            Item::Port {
                right: Some(Right::Send(handler.clone())),
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
fn live_handler_installation_uses_target_validation_and_releases_failed_inputs() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    for (behavior, flavor, expected) in [
        (1, 6, 0),
        (0, 6, 4),
        (1, -1, 4),
        ((0x8000_0000u32 | 4) as i32, 6, 46),
        ((0x8000_0000u32 | 5) as i32, 6, 46),
        (4, 6, 4),
    ] {
        let handler = Port::new(KObject::None);
        let reply = install(&mut tracer, &task, &handler, behavior, flavor);
        ptrace::pump(&mut tracee.proc, None);
        ptrace::pump(&mut tracer.proc, None);
        let message = take_reply(&mut tracer.proc, &reply);
        assert_eq!(
            i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
            expected,
            "behavior={behavior} flavor={flavor}"
        );
        kmsg::destroy(&mut tracer.proc, message);
        assert_eq!(
            tracer
                .proc
                .tracing
                .family
                .mach
                .callbacks
                .handler_port(1002, handler.id)
                .is_some(),
            expected == 0
        );
        assert_eq!(
            handler.state.lock().unwrap().srights,
            u32::from(expected == 0)
        );
        if expected == 0 {
            let installed = tracee.proc.task.exc[5].port.as_ref().unwrap();
            assert_eq!(
                tracee
                    .proc
                    .tracing
                    .family
                    .mach
                    .callbacks
                    .proxy_identity(installed)
                    .unwrap()
                    .0,
                handler.id
            );
        }
    }
}

#[test]
fn installed_handler_routes_default_and_state_replies_for_both_code_widths() {
    for base in 1..=3 {
        for codes64 in [false, true] {
            let (mut tracer, mut tracee, tid) = pair();
            let task = task_port(&mut tracer.proc, 1002).unwrap();
            let _name = tracer.proc.insert_send(&task);
            let handler = Port::new(KObject::None);
            let behavior = (base | if codes64 { 0x8000_0000u32 } else { 0 }) as i32;
            let result = install(&mut tracer, &task, &handler, behavior, 6);
            ptrace::pump(&mut tracee.proc, None);
            ptrace::pump(&mut tracer.proc, None);
            let result = take_reply(&mut tracer.proc, &result);
            assert_eq!(
                i32::from_le_bytes(result.body[8..12].try_into().unwrap()),
                0
            );
            kmsg::destroy(&mut tracer.proc, result);
            let mut thread = tracee.proc.threads.remove(&tid).unwrap();
            thread.cpu.set_reg(0, 0x1357_9bdf);
            assert!(crate::user::darwin::exception::raise_bsd_signal(
                &mut tracee.proc,
                &mut thread,
                30
            ));
            ptrace::pump(&mut tracer.proc, None);
            let mut request = take_reply(&mut tracer.proc, &handler);
            assert_eq!(request.items.len(), if base == 2 { 0 } else { 2 });
            let mut body = msg::NDR_RECORD.to_vec();
            body.extend_from_slice(&0i32.to_le_bytes());
            if base != 1 {
                // exc.defs / mach_exc.defs: descriptors, NDR, exception,
                // codeCnt, code[], flavor, old_stateCnt, old_state[].
                let header = if base == 2 { 0 } else { 28 };
                let count =
                    u32::from_le_bytes(request.body[header + 12..header + 16].try_into().unwrap())
                        as usize;
                let state = header + 16 + count * if codes64 { 8 } else { 4 };
                body.extend_from_slice(&request.body[state..]);
                // ARM_THREAD_STATE64's first two natural_t words are X0.
                body[20..28].copy_from_slice(&0x2468_ace0u64.to_le_bytes());
            }
            let reply = request.reply.take().unwrap();
            let id = request.id + 100;
            kmsg::destroy(&mut tracer.proc, request);
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
            crate::user::darwin::exception::resume(&mut tracee.proc, &mut thread);
            assert!(
                thread.mach.exception.is_none(),
                "base={base} codes64={codes64}"
            );
            assert_eq!(
                thread.cpu.reg(0),
                if base == 1 { 0x1357_9bdf } else { 0x2468_ace0 }
            );
            tracee.proc.threads.insert(tid, thread);
        }
    }
}

#[test]
fn get_and_swap_return_the_tracers_original_handler_right() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let handler = Port::new(KObject::None);
    let installed = install(&mut tracer, &task, &handler, 1, 6);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let installed = take_reply(&mut tracer.proc, &installed);
    kmsg::destroy(&mut tracer.proc, installed);
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    let got = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS,
        body,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let got = take_reply(&mut tracer.proc, &got);
    assert!(
        matches!(got.items.first(), Some((4, Item::Port { right: Some(Right::Send(port)), .. })) if port.id == handler.id),
        "get lost the original handler right: {got:?}"
    );
    let swapped = swap_unbacked(&mut tracer, &task, 5);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let swapped = take_reply(&mut tracer.proc, &swapped);
    assert!(
        matches!(swapped.items.first(), Some((4, Item::Port { right: Some(Right::Send(port)), .. })) if port.id == handler.id)
    );
    assert!(tracee.proc.task.exc[5].port.is_none());
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(1002, handler.id)
            .is_none()
    );
    assert_eq!(handler.state.lock().unwrap().srights, 2);
    kmsg::destroy(&mut tracer.proc, got);
    kmsg::destroy(&mut tracer.proc, swapped);
    assert_eq!(handler.state.lock().unwrap().srights, 0);
}

#[test]
fn live_swap_retains_old_handler_until_its_return_is_queued() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let first = Port::new(KObject::None);
    let second = Port::new(KObject::None);
    let reply = install(&mut tracer, &task, &first, 1, 6);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let reply = take_reply(&mut tracer.proc, &reply);
    kmsg::destroy(&mut tracer.proc, reply);
    let reply = update(
        &mut tracer,
        &task,
        &second,
        1,
        6,
        ids::task::TASK_SWAP_EXCEPTION_PORTS,
    );
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let reply = take_reply(&mut tracer.proc, &reply);
    assert!(
        matches!(reply.items.first(), Some((4, Item::Port { right: Some(Right::Send(port)), .. })) if port.id == first.id)
    );
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(1002, first.id)
            .is_none()
    );
    assert!(
        tracer
            .proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(1002, second.id)
            .is_some()
    );
    assert_eq!(first.state.lock().unwrap().srights, 1);
    assert_eq!(second.state.lock().unwrap().srights, 1);
    kmsg::destroy(&mut tracer.proc, reply);
    assert_eq!(first.state.lock().unwrap().srights, 0);
}

#[test]
fn returned_handler_that_dies_in_transit_becomes_a_dead_name() {
    let (mut tracer, mut tracee, _) = pair();
    let task = task_port(&mut tracer.proc, 1002).unwrap();
    let _name = tracer.proc.insert_send(&task);
    let handler = Port::new(KObject::None);
    let installed = install(&mut tracer, &task, &handler, 1, 6);
    ptrace::pump(&mut tracee.proc, None);
    ptrace::pump(&mut tracer.proc, None);
    let installed = take_reply(&mut tracer.proc, &installed);
    kmsg::destroy(&mut tracer.proc, installed);
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&(1u32 << 5).to_le_bytes());
    let got = send(
        &mut tracer,
        &task,
        ids::task::TASK_GET_EXCEPTION_PORTS,
        body,
    );
    ptrace::pump(&mut tracee.proc, None);
    kmsg::destroy_receive(&mut tracer.proc, &handler);
    ptrace::pump(&mut tracer.proc, None);
    let got = take_reply(&mut tracer.proc, &got);
    assert!(matches!(
        got.items.first(),
        Some((
            4,
            Item::Port {
                right: Some(Right::Dead),
                ..
            }
        ))
    ));
    assert_eq!(handler.state.lock().unwrap().srights, 0);
    kmsg::destroy(&mut tracer.proc, got);
    ptrace::pump(&mut tracee.proc, None);
    assert!(tracee.proc.task.exc[5].port.as_ref().unwrap().is_dead());
}
