//! A zombie retains its PID, not its live Mach task/thread rights.
use super::*;
use crate::user::darwin::process::ExitStatus;

#[test]
fn cooperative_zombie_retires_task_and_thread_rights_before_any_reap_ack() {
    let (mut caller, mut target, _) = pair();
    let task = task_port(&mut caller.proc, 1002).unwrap();
    let _task_name = caller.proc.insert_send(&task);
    let token_reply = send(&mut caller, &task, ids::task::TASK_SUSPEND2, Vec::new());
    ptrace::pump(&mut target.proc, None);
    ptrace::pump(&mut caller.proc, None);
    let mut message = take_reply(&mut caller.proc, &token_reply);
    let (
        _,
        Item::Port {
            right: Some(right), ..
        },
    ) = message.items.remove(0)
    else {
        panic!("suspension token descriptor")
    };
    let token = right.port().unwrap().clone();
    caller.proc.ipc.insert(right).unwrap();
    kmsg::destroy(&mut caller.proc, message);
    let reply = send(&mut caller, &task, ids::task::TASK_THREADS, Vec::new());
    ptrace::pump(&mut target.proc, None);
    ptrace::pump(&mut caller.proc, None);
    let message = take_reply(&mut caller.proc, &reply);
    let thread = match &message.items[0].1 {
        Item::OolPorts { rights, .. } => rights[0].as_ref().unwrap().port().unwrap().clone(),
        other => panic!("unexpected descriptor {other:?}"),
    };
    let _thread_name = caller.proc.insert_send(&thread);
    kmsg::destroy(&mut caller.proc, message);
    target.proc.tracing.tracer = Some(1001);
    target.proc.tracing.original_parent = Some(1001);
    target.proc.exit_with(ExitStatus::Exited(42));
    assert!(ptrace::exit_wait(&mut target.proc).is_some());
    ptrace::pump(&mut caller.proc, None);
    assert!(
        task.is_dead(),
        "task right survived guest exit until physical reap"
    );
    assert!(thread.is_dead());
    assert!(
        token.is_dead(),
        "resume token survived guest exit until physical reap"
    );
    let child = &caller.proc.tracing.family.children[&1002];
    assert_eq!(child.registered_exit.unwrap().status, 42 << 8);
    assert!(
        child.link.is_some(),
        "zombie transport must remain available for its reap"
    );
}

#[test]
fn cooperative_zombie_rejects_an_inflight_task_grant_without_waiting_for_reap() {
    let (mut caller, mut target, _) = pair();
    let (tid, mut thread) = caller.proc.threads.pop_first().unwrap();
    let output = thread.cpu.sp() - 16;
    let pc = thread.cpu.pc();
    let mut ctx = Ctx {
        proc: &mut caller.proc,
        thread: &mut thread,
        nr: -45,
        pc,
    };
    assert_eq!(
        super::super::grant::task_for_pid(&mut ctx, 1002, output),
        crate::user::darwin::syscall::mach::RESTART
    );
    drop(ctx);
    caller.proc.threads.insert(tid, thread);
    target.proc.tracing.tracer = Some(1001);
    target.proc.tracing.original_parent = Some(1001);
    target.proc.exit_with(ExitStatus::Exited(42));
    assert!(ptrace::exit_wait(&mut target.proc).is_some());
    ptrace::pump(&mut caller.proc, None);
    let mut thread = caller.proc.threads.remove(&tid).unwrap();
    let mut ctx = Ctx {
        proc: &mut caller.proc,
        thread: &mut thread,
        nr: -45,
        pc,
    };
    assert_eq!(
        super::super::grant::task_for_pid(&mut ctx, 1002, output),
        crate::user::darwin::mach::kr::KERN_FAILURE
    );
    assert_eq!(ctx.read_u32(output).unwrap(), 0);
    assert!(ctx.proc.tracing.family.children[&1002].link.is_some());
}
