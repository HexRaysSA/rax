//! Equal wire identifiers from different controllers must remain disjoint.

use super::*;
use crate::user::darwin::{
    abi::DarwinAbi,
    mach::{ipc::KObject, kr},
    mig::ids,
    process::{DarwinProcess, bounded_tests::process},
    syscall::bsd::ptrace::{channels, peers, registry, transport},
};

fn controllers() -> (
    DarwinProcess,
    ServerRoute,
    ServerRoute,
    transport::Link,
    transport::Link,
) {
    let mut process = process(DarwinAbi::Arm64);
    process.proc.pid = 1002;
    let mut routes = Vec::new();
    let mut links = Vec::new();
    for pid in [1001, 1003] {
        let (incoming, outgoing) = transport::Link::pair().unwrap();
        let id = incoming.identity();
        process.proc.tracing.family.peers.incoming.insert(
            id,
            peers::Incoming {
                record: registry::Record {
                    pid,
                    uid: 501,
                    instance: [pid as u8; 16],
                },
                link: incoming,
                server: Default::default(),
            },
        );
        let route = ServerRoute::Registered(id);
        route.server_mut(&mut process.proc).unwrap().allowed = true;
        acquire(&mut process.proc, route, 8, 7, 1, Object::Task);
        routes.push(route);
        links.push(outgoing);
    }
    (
        process,
        routes[0],
        routes[1],
        links.remove(0),
        links.remove(0),
    )
}

#[test]
fn identical_task_instances_and_generations_do_not_share_exports() {
    let (mut process, a, b, _a, _b) = controllers();
    assert_eq!(a.server(&process.proc).unwrap().exports.len(), 1);
    assert_eq!(b.server(&process.proc).unwrap().exports.len(), 1);
    release(&mut process.proc, a, 8, 7, Object::Task);
    assert!(a.server(&process.proc).unwrap().exports.is_empty());
    assert_eq!(b.server(&process.proc).unwrap().exports.len(), 1);
    let request = || Message::Request {
        sequence: 9,
        instance: 7,
        object: Object::Task,
        id: ids::task::TASK_THREADS,
        bits: 0,
        expects_reply: true,
        body: Vec::new(),
        memory: None,
    };
    let denied = server::serve_on(&mut process.proc, a, None, request());
    let server::Response::Mach(Message::Reply { body, .. }) = denied else {
        panic!("MIG error reply")
    };
    assert_eq!(
        i32::from_le_bytes(body[8..12].try_into().unwrap()),
        kr::KERN_INVALID_CAPABILITY
    );
    let permitted = server::serve_on(&mut process.proc, b, None, request());
    assert!(matches!(
        permitted,
        server::Response::Mach(Message::Reply {
            threads: Some(_),
            ..
        })
    ));
}

#[test]
fn same_numbered_suspension_tokens_release_only_the_callers_hold() {
    let (mut process, a, b, _a, _b) = controllers();
    for route in [a, b] {
        let reply = server::serve_on(
            &mut process.proc,
            route,
            None,
            Message::Request {
                sequence: 9,
                instance: 7,
                object: Object::Task,
                id: ids::task::TASK_SUSPEND2,
                bits: 0,
                expects_reply: true,
                body: Vec::new(),
                memory: None,
            },
        );
        assert!(matches!(
            reply,
            server::Response::Token(token::Packet::Offer { token: 1, .. })
        ));
    }
    assert_eq!(process.proc.task.suspension.count(), 2);
    token::from_controller(&mut process.proc, a, None, token::Packet::Drop { token: 1 });
    assert_eq!(process.proc.task.suspension.count(), 1);
    token::from_controller(&mut process.proc, a, None, token::Packet::Drop { token: 1 });
    assert_eq!(process.proc.task.suspension.count(), 1);
    token::from_controller(&mut process.proc, b, None, token::Packet::Drop { token: 1 });
    assert_eq!(process.proc.task.suspension.count(), 0);
}

#[test]
fn equal_handler_names_and_reply_tokens_are_bound_to_their_origin() {
    let (mut process, a, b, _a, _b) = controllers();
    let first = a
        .callbacks_mut(&mut process.proc)
        .unwrap()
        .acquire_proxy(42, 3, 7);
    let second = b
        .callbacks_mut(&mut process.proc)
        .unwrap()
        .acquire_proxy(42, 3, 7);
    assert_ne!(first.id, second.id);
    assert_eq!(channels::callback_route(&process.proc, &first), Some(a));
    assert_eq!(channels::callback_route(&process.proc, &second), Some(b));
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights = 1;
    a.callbacks_mut(&mut process.proc)
        .unwrap()
        .retain_reply(Right::SendOnce(reply.clone()))
        .unwrap();
    callback::target::complete_on(
        &mut process.proc,
        b,
        callback_wire::Message::Cancel { reply: reply.id },
    );
    assert_eq!(reply.state.lock().unwrap().sorights, 1);
    callback::target::complete_on(
        &mut process.proc,
        a,
        callback_wire::Message::Cancel { reply: reply.id },
    );
    assert!(
        a.callbacks_mut(&mut process.proc)
            .unwrap()
            .take_reply(reply.id)
            .is_none()
    );
    assert_eq!(reply.state.lock().unwrap().queue.len(), 1);
    channels::disconnect(&mut process.proc, a);
    assert!(first.is_dead());
    assert!(!second.is_dead());
    assert_eq!(channels::callback_route(&process.proc, &second), Some(b));
    assert_eq!(b.server(&process.proc).unwrap().exports.len(), 1);
}
