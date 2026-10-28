//! Inherited state RPCs traverse both private family connections.

use super::*;

#[test]
fn inherited_state_handler_and_its_reply_relay_through_the_parent() {
    for parent_exec in [false, true] {
        let (mut tracer, mut parent, _, _, handler) = super::callback_lifecycle::callback_pair();
        parent.proc.task.exc[5].behavior = 2;
        parent.proc.task.exc[5].flavor = 6;
        let original = parent.proc.task.exc[5].port.clone().unwrap();
        let mut child = process(DarwinAbi::Arm64);
        child.proc.pid = 1003;
        child.proc.ppid = 1002;
        child.proc.task = crate::user::darwin::fork::inherited_task(&parent.proc.task);
        let inherited = ptrace::InheritedHandlers::capture(&parent.proc.tracing, &child.proc.task);
        let (a, b) = super::super::super::transport::Link::pair().unwrap();
        let shared = Arc::new(SharedStatus::new().unwrap());
        let mut record = Child::new(a, parent.proc.pid);
        record.shared_status = Some(shared.clone());
        parent.proc.tracing.family.children.insert(1003, record);
        child.proc.tracing.family.parent = Some(b);
        child.proc.tracing.family.parent_status = Some(shared);
        // In a real fork each branch owns a COW copy of this captured Arc map.
        let parent_copy =
            ptrace::InheritedHandlers::capture(&parent.proc.tracing, &child.proc.task);
        parent_copy.parent(&mut parent.proc, 1003);
        inherited.child(&mut child.proc);
        let tid = *child.proc.threads.keys().next().unwrap();
        let mut thread = child.proc.threads.remove(&tid).unwrap();
        assert!(crate::user::darwin::exception::raise_bsd_signal(
            &mut child.proc,
            &mut thread,
            30
        ));
        ptrace::pump(&mut parent.proc, None);
        if parent_exec {
            before_exec(&mut parent.proc);
            target_will_exec(&mut parent.proc);
            assert!(!original.is_dead(), "exec retired a relayed handler send");
        }
        ptrace::pump(&mut tracer.proc, None);
        let mut received = take_reply(&mut tracer.proc, &handler);
        assert!(received.items.is_empty());
        let reply = received.reply.take().unwrap();
        let mut body = msg::NDR_RECORD.to_vec();
        body.extend_from_slice(&0i32.to_le_bytes());
        // Two 32-bit codes follow NDR, exception, and codeCnt in exc.defs.
        body.extend_from_slice(&received.body[24..]);
        body[20..28].copy_from_slice(&0x1357_2468u64.to_le_bytes());
        let id = received.id + 100;
        kmsg::destroy(&mut tracer.proc, received);
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
        ptrace::pump(&mut parent.proc, None);
        ptrace::pump(&mut child.proc, Some(&mut thread));
        crate::user::darwin::exception::resume(&mut child.proc, &mut thread);
        assert!(thread.mach.exception.is_none());
        assert_eq!(thread.cpu.reg(0), 0x1357_2468);
        assert_eq!(original.state.lock().unwrap().srights, 2);
        peer_died(&mut parent.proc, 1003);
        assert_eq!(original.state.lock().unwrap().srights, 1);
        assert_eq!(handler.state.lock().unwrap().srights, 1);
        child.proc.threads.insert(tid, thread);
    }
}
