//! Token expectations come from XNU and the arm64/Rosetta native probe.

use super::*;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::{
    ipc::disp,
    msg::{self, Item, Sender, bits},
};
use crate::user::darwin::mig::ids;
use crate::user::darwin::process::{DarwinProcess, bounded_tests::process};
use crate::user::darwin::syscall::{
    Ctx,
    mach::{kmsg, port},
};

fn call(
    p: &mut DarwinProcess,
    destination: Right,
    id: i32,
    body: Vec<u8>,
    reply: bool,
) -> Option<msg::Message> {
    let target = destination.port().unwrap().clone();
    let remote = if matches!(destination, Right::SendOnce(_)) {
        disp::MOVE_SEND_ONCE
    } else {
        disp::MOVE_SEND
    };
    let response = Port::new(KObject::None);
    response.state.lock().unwrap().sorights = u32::from(reply);
    let message = msg::Message {
        bits: bits::set(remote, if reply { disp::MOVE_SEND_ONCE } else { 0 }, 0, 0),
        dest: destination,
        reply: reply.then(|| Right::SendOnce(response)),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let tid = *p.proc.threads.keys().next().unwrap();
    let mut thread = p.proc.threads.remove(&tid).unwrap();
    let pc = thread.cpu.pc();
    let mut result = crate::user::darwin::mig::serve(
        &mut Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: -1,
            pc,
        },
        &target,
        message,
    );
    if let Some(message) = result.as_mut() {
        let destination = std::mem::replace(&mut message.dest, Right::Dead);
        kmsg::consume_dest(&mut p.proc, destination);
    }
    p.proc.threads.insert(tid, thread);
    result
}

fn task(p: &mut DarwinProcess) -> Right {
    let task = p.proc.task_port.clone();
    task.state.lock().unwrap().srights += 1;
    Right::Send(task)
}

fn token(p: &mut DarwinProcess) -> Right {
    let destination = task(p);
    let mut reply = call(p, destination, ids::task::TASK_SUSPEND2, Vec::new(), true).unwrap();
    assert_eq!(reply.bits & bits::COMPLEX, bits::COMPLEX);
    let (
        offset,
        Item::Port {
            right: Some(right),
            disp,
        },
    ) = reply.items.remove(0)
    else {
        panic!()
    };
    assert_eq!((offset, disp), (4, disp::MOVE_SEND_ONCE));
    assert!(matches!(right, Right::SendOnce(_)));
    kmsg::destroy(&mut p.proc, reply);
    right
}

fn result(p: &mut DarwinProcess, reply: msg::Message) -> i32 {
    let result = i32::from_le_bytes(reply.body[8..12].try_into().unwrap());
    kmsg::destroy(&mut p.proc, reply);
    result
}

#[test]
fn independent_tokens_share_a_resume_port_but_have_distinct_names() {
    let mut p = process(DarwinAbi::Arm64);
    let first = token(&mut p);
    let second = token(&mut p);
    assert_eq!(first.port().unwrap().id, second.port().unwrap().id);
    assert_eq!(p.proc.task.suspension.count(), 2);
    let a = p.proc.ipc.insert(first).unwrap();
    let b = p.proc.ipc.insert(second).unwrap();
    assert_ne!(a, b);
    assert!(p.proc.ipc.lookup(a).unwrap().send_once);
    assert_eq!(port::deallocate(&mut p.proc, a), 0);
    assert_eq!(p.proc.task.suspension.count(), 1);
    let destination = p.proc.ipc.copyin(b, disp::MOVE_SEND_ONCE).unwrap();
    let reply = call(
        &mut p,
        destination,
        ids::task::TASK_RESUME2,
        Vec::new(),
        true,
    )
    .unwrap();
    assert_eq!(result(&mut p, reply), 0);
    assert_eq!(p.proc.task.suspension.count(), 0);
}

#[test]
fn out_of_band_resume_leaves_a_live_token_whose_resume_fails() {
    let mut p = process(DarwinAbi::Arm64);
    let token = token(&mut p);
    p.proc.task.suspension.release(Hold::Legacy).unwrap();
    let reply = call(&mut p, token, ids::task::TASK_RESUME2, Vec::new(), true).unwrap();
    assert_eq!(result(&mut p, reply), kr::KERN_FAILURE);
    assert_eq!(p.proc.task.suspension.count(), 0);
    assert_eq!(
        p.proc
            .task
            .suspension
            .resume
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .sorights,
        0
    );
}

#[test]
fn a_mig_error_uses_the_token_without_abandoning_its_hold() {
    for (id, body, error) in [
        (0x7fff_fffe, Vec::new(), kr::MIG_BAD_ID),
        (ids::task::TASK_RESUME2, vec![0; 4], kr::MIG_BAD_ARGUMENTS),
    ] {
        let mut p = process(DarwinAbi::Arm64);
        let token = token(&mut p);
        let resume = token.port().unwrap().clone();
        let reply = call(&mut p, token, id, body, true).unwrap();
        assert_eq!(result(&mut p, reply), error);
        assert_eq!(p.proc.task.suspension.count(), 1);
        assert_eq!(resume.state.lock().unwrap().sorights, 0);
    }
}

#[test]
fn no_reply_right_discards_the_new_token_and_its_hold() {
    let mut p = process(DarwinAbi::Arm64);
    let task = task(&mut p);
    assert!(call(&mut p, task, ids::task::TASK_SUSPEND2, Vec::new(), false).is_none());
    assert_eq!(p.proc.task.suspension.count(), 0);
}

#[test]
fn token_abandonment_preserves_unrelated_legacy_holds() {
    let mut p = process(DarwinAbi::Arm64);
    let legacy = legacy_send(&mut p.proc).unwrap();
    let token = token(&mut p);
    kmsg::release(&mut p.proc, [token]);
    assert_eq!(p.proc.task.suspension.count(), 1);
    kmsg::release(&mut p.proc, [legacy]);
    assert_eq!(p.proc.task.suspension.count(), 0);
}
