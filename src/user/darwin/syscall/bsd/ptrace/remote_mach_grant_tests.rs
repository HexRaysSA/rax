//! Task grants exercise the transport, target policy, and owned send lifetime.

use super::*;
use crate::user::darwin::codesign::{self, cs};
use crate::user::darwin::process::DarwinProcess;
use crate::user::darwin::syscall::bsd::ptrace;
use crate::user::darwin::syscall::mach::port;

fn pair() -> (DarwinProcess, DarwinProcess, u64) {
    let (mut parent, mut child, _) = super::super::integration_tests::pair();
    let tid = *parent.proc.threads.keys().next().unwrap();
    let record = parent.proc.tracing.family.children.get_mut(&1002).unwrap();
    record.traced = false;
    record.mach_attached = false;
    record.stop = None;
    child.proc.tracing.family.mach.parent_server.allowed = false;
    codesign::prepare_traced_exec(&mut child.proc);
    child.proc.codesign.as_mut().unwrap().flags = cs::GET_TASK_ALLOW;
    (parent, child, tid)
}

fn call(parent: &mut DarwinProcess, tid: u64) -> (i32, u32) {
    let mut thread = parent.proc.threads.remove(&tid).unwrap();
    let output = thread.cpu.sp() - 16;
    let pc = thread.cpu.pc();
    let mut ctx = Ctx {
        proc: &mut parent.proc,
        thread: &mut thread,
        nr: -45,
        pc,
    };
    let result = task_for_pid(&mut ctx, 1002, output);
    let name = ctx.read_u32(output).unwrap();
    parent.proc.threads.insert(tid, thread);
    (result, name)
}

fn second_thread(parent: &mut DarwinProcess, first: u64) -> u64 {
    use crate::user::darwin::process::Thread;
    let tid = first + 1;
    let mut cpu = parent.proc.new_thread_cpu();
    cpu.set_sp(parent.proc.threads[&first].cpu.sp() - 64);
    let kport = Port::new(KObject::Thread(tid));
    parent.proc.threads.insert(
        tid,
        Thread {
            tid,
            port: 0,
            kport,
            cpu,
            sig: Default::default(),
            wait: None,
            resume: None,
            pthread: 0,
            exited: false,
            woken: false,
            wake_event: false,
            mach: Default::default(),
            name: Vec::new(),
            pw: Default::default(),
            assumed: None,
        },
    );
    tid
}

#[test]
fn concurrent_grants_hold_sends_until_each_waiter_copies_out() {
    let (mut parent, mut child, first) = pair();
    let second = second_thread(&mut parent, first);
    call(&mut parent, first);
    call(&mut parent, second);
    request(&mut child, true);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    let (_, name) = call(&mut parent, first);
    port::deallocate(&mut parent.proc, name);
    ptrace::pump(&mut child.proc, None);
    assert_eq!(
        child.proc.tracing.family.mach.parent_server.exports.len(),
        1
    );
    let (result, second_name) = call(&mut parent, second);
    assert_eq!(result, kr::KERN_SUCCESS);
    assert_ne!(second_name, MACH_PORT_NULL);
    port::deallocate(&mut parent.proc, second_name);
    ptrace::pump(&mut child.proc, None);
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

#[test]
fn target_exec_rejects_a_grant_for_the_previous_image() {
    let (mut parent, mut child, tid) = pair();
    call(&mut parent, tid);
    super::super::target_will_exec(&mut child.proc);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    assert_eq!(call(&mut parent, tid), (kr::KERN_FAILURE, MACH_PORT_NULL));
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

fn request(child: &mut DarwinProcess, observed: bool) -> Packet {
    let (mut bytes, closed) = child
        .proc
        .tracing
        .family
        .parent
        .as_mut()
        .unwrap()
        .receive_one()
        .unwrap();
    assert!(!closed);
    assert_eq!(bytes.len(), 1);
    let packet = Packet::decode(&bytes.remove(0)).unwrap();
    let Packet::Request {
        sequence,
        instance,
        epoch,
        creds,
    } = packet.clone()
    else {
        panic!()
    };
    serve(&mut child.proc, sequence, instance, epoch, creds, observed);
    packet
}

#[test]
fn pre_attach_grant_owns_export_and_coalesces_names() {
    let (mut parent, mut child, tid) = pair();
    let initial_sends = child.proc.task_port.state.lock().unwrap().srights;
    assert_eq!(call(&mut parent, tid).0, mach::RESTART);
    assert!(parent.proc.tracing.family.mach.peers.is_empty());
    request(&mut child, true);
    assert_eq!(
        child.proc.task_port.state.lock().unwrap().srights,
        initial_sends + 1
    );
    ptrace::pump(&mut parent.proc, None);
    let (result, name) = call(&mut parent, tid);
    assert_eq!(result, kr::KERN_SUCCESS);
    assert_ne!(name, MACH_PORT_NULL);
    assert_eq!(call(&mut parent, tid).0, mach::RESTART);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    assert_eq!(call(&mut parent, tid), (kr::KERN_SUCCESS, name));
    assert_eq!(parent.proc.ipc.lookup(name).unwrap().send, 2);
    assert_eq!(port::deallocate(&mut parent.proc, name), kr::KERN_SUCCESS);
    assert_eq!(port::deallocate(&mut parent.proc, name), kr::KERN_SUCCESS);
    ptrace::pump(&mut child.proc, None);
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

#[test]
fn grant_policy_rechecks_target_and_observed_signature() {
    for mode in 0..7 {
        let (mut parent, mut child, tid) = pair();
        assert_eq!(call(&mut parent, tid).0, mach::RESTART);
        match mode {
            0 => child.proc.creds.1 = 502,
            1 => child.proc.creds.3 = 21,
            2 => child.proc.codesign.as_mut().unwrap().flags = 0,
            3 => child.proc.codesign.as_mut().unwrap().flags |= cs::PLATFORM_BINARY,
            5 => child
                .proc
                .tracing
                .family
                .parent_status
                .as_ref()
                .unwrap()
                .set_parent_credentials((502, 502)),
            6 => child
                .proc
                .exit_with(crate::user::darwin::process::ExitStatus::Exited(0)),
            _ => {}
        }
        request(&mut child, mode != 4);
        ptrace::pump(&mut parent.proc, None);
        assert_eq!(call(&mut parent, tid), (kr::KERN_FAILURE, MACH_PORT_NULL));
        assert!(!child.proc.tracing.family.mach.parent_server.allowed);
        assert!(
            child
                .proc
                .tracing
                .family
                .mach
                .parent_server
                .exports
                .is_empty()
        );
    }
}

#[test]
fn caller_exec_releases_late_grant_without_reusing_instance() {
    let (mut parent, mut child, tid) = pair();
    assert_eq!(call(&mut parent, tid).0, mach::RESTART);
    super::super::before_exec(&mut parent.proc);
    assert_eq!(call(&mut parent, tid).0, mach::RESTART);
    let first = request(&mut child, true);
    let second = request(&mut child, true);
    let (Packet::Request { instance: a, .. }, Packet::Request { instance: b, .. }) =
        (first, second)
    else {
        panic!()
    };
    assert_ne!(a, b);
    ptrace::pump(&mut parent.proc, None);
    ptrace::pump(&mut child.proc, None);
    assert!(
        !child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(a, Object::Task))
    );
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .contains_key(&(b, Object::Task))
    );
    let (_, name) = call(&mut parent, tid);
    port::deallocate(&mut parent.proc, name);
    ptrace::pump(&mut child.proc, None);
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

#[test]
fn canceled_refresh_preserves_an_existing_send() {
    let (mut parent, mut child, tid) = pair();
    call(&mut parent, tid);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    let (_, name) = call(&mut parent, tid);
    call(&mut parent, tid);
    cancel(&mut parent.proc, tid);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    ptrace::pump(&mut child.proc, None);
    assert_eq!(
        child.proc.tracing.family.mach.parent_server.exports.len(),
        1
    );
    port::deallocate(&mut parent.proc, name);
    ptrace::pump(&mut child.proc, None);
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

#[test]
fn terminated_waiter_releases_received_grant() {
    let (mut parent, mut child, tid) = pair();
    call(&mut parent, tid);
    request(&mut child, true);
    ptrace::pump(&mut parent.proc, None);
    parent.proc.threads.get_mut(&tid).unwrap().exited = true;
    ptrace::pump(&mut parent.proc, None);
    ptrace::pump(&mut child.proc, None);
    assert!(
        child
            .proc
            .tracing
            .family
            .mach
            .parent_server
            .exports
            .is_empty()
    );
}

#[test]
fn disconnected_grant_wakes_failure_without_a_send() {
    let (mut parent, child, tid) = pair();
    call(&mut parent, tid);
    drop(child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let result = loop {
        ptrace::pump(&mut parent.proc, None);
        let result = call(&mut parent, tid);
        if result.0 != crate::user::darwin::syscall::mach::RESTART {
            break result;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "grant peer did not close"
        );
        // A host fork can briefly retain a close-on-exec socket. The
        // nonblocking transport promises eventual EOF, not one pump turn.
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    assert_eq!(result, (kr::KERN_FAILURE, MACH_PORT_NULL));
    assert!(parent.proc.tracing.family.mach.grants.pending.is_empty());
}

#[test]
fn grant_wire_rejects_truncation_trailing_data_and_reserved_instances() {
    for packet in [
        Packet::Request {
            sequence: 7,
            instance: 8,
            epoch: 9,
            creds: (501, 501, 20, 20),
        },
        Packet::Reply {
            sequence: 7,
            instance: 8,
            epoch: 9,
            result: kr::KERN_SUCCESS,
        },
    ] {
        let mut bytes = packet.encode();
        assert_eq!(Packet::decode(&bytes).unwrap(), packet);
        for len in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..len]).is_err());
        }
        bytes.push(0);
        assert!(Packet::decode(&bytes).is_err());
        bytes.pop();
        bytes[9..17].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert!(Packet::decode(&bytes).is_err());
    }
}
