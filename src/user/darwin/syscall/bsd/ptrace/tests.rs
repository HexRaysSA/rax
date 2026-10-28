use super::*;

fn assert_peer_closed(link: &mut transport::Link) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let (frames, closed) = link.receive().unwrap();
        assert!(frames.is_empty());
        if closed {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "peer did not close");
        // A concurrently spawned process can briefly inherit a socket
        // before its close-on-exec descriptor is released.
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn thread_update_pair() -> (
    crate::user::darwin::process::DarwinProcess,
    crate::user::darwin::process::DarwinProcess,
    u64,
) {
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::bounded_tests::process;

    let mut tracer = process(DarwinAbi::Arm64);
    let mut tracee = process(DarwinAbi::Arm64);
    tracer.proc.pid = 1001;
    tracee.proc.pid = 1002;
    tracee.proc.ppid = tracer.proc.pid;
    tracee.proc.tracing.tracer = Some(tracer.proc.pid);
    let tracer_tid = *tracer.proc.threads.keys().next().unwrap();
    let tracee_tid = *tracee.proc.threads.keys().next().unwrap();
    tracee.proc.tracing.stopped = Some(TraceStop {
        thread: tracee_tid,
        signal: signal::SIGTRAP,
    });
    let (mut tracer_link, tracee_link) = transport::Link::pair().unwrap();
    tracer_link
        .queue(
            &protocol::Message::Resume {
                id: 7,
                signal: signal::SIGUSR1,
                mode: protocol::ResumeMode::ThreadUpdate,
                uid: 0,
            }
            .encode(),
        )
        .unwrap();
    tracer_link.flush().unwrap();
    let mut child = Child::new(tracer_link, tracer.proc.pid);
    child.traced = true;
    child.stop = Some(ChildStop {
        thread: tracee_tid,
        signal: signal::SIGTRAP,
        waited: true,
    });
    tracer.proc.tracing.family.children.insert(1002, child);
    tracee.proc.tracing.family.parent = Some(tracee_link);
    tracer.proc.tracing.pending.insert(
        tracer_tid,
        PendingCall {
            id: 7,
            pid: 1002,
            errno: None,
            kind: CallKind::ThreadUpdate {
                thread: tracer_tid,
                remote_instance: None,
                signal: signal::SIGUSR1,
                phase: UpdatePhase::Preparing,
            },
            resume_effect: false,
        },
    );
    (tracer, tracee, tracer_tid)
}

#[test]
fn thread_update_records_signal_before_committing_tracee_state() {
    let (mut tracer, mut tracee, tracer_tid) = thread_update_pair();
    pump(&mut tracee.proc, None);
    assert!(tracee.proc.tracing.reserved_update.is_some());
    assert_eq!(tracee.proc.tracing.trace_update, None);
    assert_eq!(
        tracer.proc.threads[&tracer_tid].sig.pending & signal::bit(signal::SIGUSR1),
        0
    );
    pump(&mut tracer.proc, None);
    assert_ne!(
        tracer.proc.threads[&tracer_tid].sig.pending & signal::bit(signal::SIGUSR1),
        0
    );
    assert_eq!(tracee.proc.tracing.trace_update, None);
    pump(&mut tracee.proc, None);
    assert_eq!(tracee.proc.tracing.trace_update, Some(signal::SIGUSR1));
    assert!(tracee.proc.tracing.reserved_update.is_none());
    pump(&mut tracer.proc, None);
    assert_eq!(tracer.proc.tracing.pending[&tracer_tid].errno, Some(0));
    assert!(tracer.proc.tracing.family.children[&1002].stop.is_none());
}

#[test]
fn thread_update_does_not_publish_signal_when_commit_queue_is_full() {
    let (mut tracer, mut tracee, tracer_tid) = thread_update_pair();
    pump(&mut tracee.proc, None);
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
    let size: libc::c_int = 4096;
    // SAFETY: link owns a live socket, and size is an initialized option.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                link.fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const size).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    const FRAME: usize = 1 << 20;
    const QUEUE: usize = 4 << 20;
    for _ in 0..3 {
        link.queue(&vec![0; FRAME]).unwrap();
    }
    link.queue(&vec![0; QUEUE - 3 * (FRAME + 4) - 4]).unwrap();
    pump(&mut tracer.proc, None);
    assert_eq!(
        tracer.proc.threads[&tracer_tid].sig.pending & signal::bit(signal::SIGUSR1),
        0
    );
    assert!(matches!(
        tracer.proc.tracing.pending[&tracer_tid].kind,
        CallKind::ThreadUpdate {
            phase: UpdatePhase::Prepared,
            ..
        }
    ));
    assert_eq!(tracee.proc.tracing.trace_update, None);
    assert!(tracee.proc.tracing.reserved_update.is_some());
}

#[test]
fn reserved_thread_update_rejects_a_competing_resume() {
    let (mut tracer, mut tracee, _) = thread_update_pair();
    pump(&mut tracee.proc, None);
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
    link.queue(
        &protocol::Message::Resume {
            id: 8,
            signal: 0,
            mode: protocol::ResumeMode::Continue,
            uid: 0,
        }
        .encode(),
    )
    .unwrap();
    link.flush().unwrap();
    pump(&mut tracee.proc, None);
    let (frames, closed) = link.receive().unwrap();
    assert!(!closed);
    let replies: Vec<_> = frames
        .iter()
        .map(|frame| protocol::Message::decode(frame).unwrap())
        .collect();
    assert_eq!(
        replies,
        vec![
            protocol::Message::Reply { id: 7, errno: 0 },
            protocol::Message::Reply {
                id: 8,
                errno: Errno::EBUSY.0,
            },
        ]
    );
    assert!(tracee.proc.tracing.reserved_update.is_some());
    assert_eq!(tracee.proc.tracing.trace_update, None);
}

#[test]
fn trace_metadata_is_visible_even_when_control_output_is_blocked() {
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::arch::Rv;
    use crate::user::darwin::process::bounded_tests::process;
    use crate::user::darwin::syscall::Ctx;

    let mut parent = State::default();
    let mut tracee = process(DarwinAbi::Arm64);
    tracee.proc.pid = 1002;
    tracee.proc.ppid = 1001;
    let pair = ForkPair::prepare().unwrap();
    let child_copy = ForkPair {
        parent: pair.parent.duplicate_empty().unwrap(),
        child: pair.child.duplicate_empty().unwrap(),
        shared: pair.shared.clone(),
    };
    pair.parent(&mut parent, 1002, 1001);
    child_copy.child(&mut tracee.proc.tracing, 1001);
    let link = tracee.proc.tracing.family.parent.as_mut().unwrap();
    let size: libc::c_int = 4096;
    // SAFETY: link owns a live socket, and size is an initialized option.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                link.fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const size).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    link.queue(&vec![0; 1 << 20]).unwrap();
    link.flush().unwrap();
    assert!(link.wants_write());
    let (_, mut thread) = tracee.proc.threads.pop_first().unwrap();
    let mut ctx = Ctx {
        proc: &mut tracee.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert_eq!(ptrace(&mut ctx, PT_TRACE_ME, 0, 0, 0), Ok(Rv::one(0)));
    assert_eq!(known_trace_info(&parent, 1001, 1002), Some((true, 1001)));
    assert!(is_traced_child(&parent, 1002));
    assert!(stop_for_signal(
        ctx.proc,
        ctx.thread.tid,
        signal::SIGUSR1,
        0,
    ));
    assert_eq!(
        known_signal_status(&parent, 1001, 1002),
        Some((true, signal::SIGUSR1))
    );
    assert!(
        ctx.proc
            .tracing
            .family
            .parent
            .as_ref()
            .unwrap()
            .wants_write()
    );
    record_exit(&ctx.proc.tracing, &ExitStatus::Exited(42));
    assert_eq!(known_trace_info(&parent, 1001, 1002), Some((false, 1001)));
    assert!(!is_traced_child(&parent, 1002));
}

#[test]
fn child_signing_status_changes_and_exec_invalidates_the_old_image() {
    let mut parent = State::default();
    let mut child = State::default();
    let pair = ForkPair::prepare().unwrap();
    pair.set_parent_credentials((501, 501));
    let child_copy = ForkPair {
        parent: pair.parent.duplicate_empty().unwrap(),
        child: pair.child.duplicate_empty().unwrap(),
        shared: pair.shared.clone(),
    };
    pair.parent(&mut parent, 1002, 1001);
    child_copy.child(&mut child, 1001);
    assert_eq!(
        child
            .family
            .parent_status
            .as_ref()
            .unwrap()
            .parent_credentials(),
        Some((501, 501))
    );
    parent.update_children_parent_credentials((u32::MAX, 0));
    assert_eq!(
        child
            .family
            .parent_status
            .as_ref()
            .unwrap()
            .parent_credentials(),
        Some((u32::MAX, 0))
    );
    assert_eq!(known_child_codesign(&parent, 1002), None);
    publish_codesign(&child, 0);
    assert_eq!(known_child_codesign(&parent, 1002), Some(0));
    publish_codesign(&child, u32::MAX);
    assert_eq!(known_child_codesign(&parent, 1002), Some(u32::MAX));

    let mut image = child.for_exec();
    image.take_connections(&mut child);
    assert_eq!(known_child_codesign(&parent, 1002), None);
    publish_codesign(&image, 0x3202_0021);
    assert_eq!(known_child_codesign(&parent, 1002), Some(0x3202_0021));
    assert_eq!(
        image
            .family
            .parent_status
            .as_ref()
            .unwrap()
            .parent_credentials(),
        Some((u32::MAX, 0))
    );
}

#[test]
fn restricted_trace_me_rejects_without_publishing_a_relationship() {
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::bounded_tests::process;
    use crate::user::darwin::syscall::Ctx;

    let mut parent = State::default();
    let mut tracee = process(DarwinAbi::Arm64);
    tracee.proc.pid = 1002;
    tracee.proc.ppid = 1001;
    tracee.proc.creds.0 = 501;
    tracee.proc.creds.1 = 501;
    let pair = ForkPair::prepare().unwrap();
    pair.set_parent_credentials((501, 501));
    let child_copy = ForkPair {
        parent: pair.parent.duplicate_empty().unwrap(),
        child: pair.child.duplicate_empty().unwrap(),
        shared: pair.shared.clone(),
    };
    pair.parent(&mut parent, 1002, 1001);
    child_copy.child(&mut tracee.proc.tracing, 1001);
    let (_, mut thread) = tracee.proc.threads.pop_first().unwrap();
    let mut ctx = Ctx {
        proc: &mut tracee.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert!(crate::user::darwin::codesign::csops(&mut ctx, 0, 8, 0, 0, None).is_ok());
    assert_eq!(ptrace(&mut ctx, PT_TRACE_ME, 0, 0, 0), Err(Errno::EPERM));
    assert_eq!(known_trace_info(&parent, 1001, 1002), Some((false, 0)));
    assert_eq!(ctx.proc.tracing.tracer, None);
}

#[test]
fn failed_trace_me_does_not_publish_shared_trace_state() {
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::bounded_tests::process;
    use crate::user::darwin::syscall::Ctx;

    let mut tracee = process(DarwinAbi::Arm64);
    tracee.proc.ppid = 1001;
    let pair = ForkPair::prepare().unwrap();
    let shared = pair.shared.clone();
    let peer = pair.parent;
    let link = pair.child;
    // SAFETY: peer owns a live socket; shutdown affects its socket only.
    assert_eq!(unsafe { libc::shutdown(peer.fd(), libc::SHUT_RDWR) }, 0);
    drop(peer);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let byte = [0u8];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let flags = libc::MSG_NOSIGNAL;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let flags = 0;
        // SAFETY: link owns a live nonblocking socket, and byte is valid
        // for one byte. SO_NOSIGPIPE or MSG_NOSIGNAL suppresses SIGPIPE.
        let sent = unsafe { libc::send(link.fd(), byte.as_ptr().cast(), 1, flags) };
        if sent < 0 {
            let kind = std::io::Error::last_os_error().kind();
            if kind != std::io::ErrorKind::WouldBlock && kind != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "peer did not close");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    tracee.proc.tracing.family.parent = Some(link);
    tracee.proc.tracing.family.parent_status = Some(shared.clone());
    let (_, mut thread) = tracee.proc.threads.pop_first().unwrap();
    let mut ctx = Ctx {
        proc: &mut tracee.proc,
        thread: &mut thread,
        nr: 26,
        pc: 0,
    };
    assert!(ptrace(&mut ctx, PT_TRACE_ME, 0, 0, 0).is_err());
    assert_eq!(shared.trace(), (false, 0));
    assert!(ctx.proc.tracing.tracer.is_none());
    assert!(ctx.proc.tracing.family.parent.is_none());
}

#[test]
fn fork_pair_keeps_each_process_connected_to_the_other() {
    let mut parent = State::default();
    let pair = ForkPair::prepare().unwrap();
    // A host fork duplicates both descriptors before each process drops
    // the endpoint that belongs to the other side.
    let child_copy = ForkPair {
        parent: pair.parent.duplicate_empty().unwrap(),
        child: pair.child.duplicate_empty().unwrap(),
        shared: pair.shared.clone(),
    };
    let mut child = State::default();
    pair.parent(&mut parent, 42, 1);
    child_copy.child(&mut child, 1);
    assert!(parent.family.parent.is_none());
    assert!(child.family.children.is_empty());
    let link = child.family.parent.as_mut().unwrap();
    link.queue(b"fork").unwrap();
    link.flush().unwrap();
    assert_eq!(
        parent
            .family
            .children
            .get_mut(&42)
            .unwrap()
            .link
            .as_mut()
            .unwrap()
            .receive()
            .unwrap(),
        (vec![b"fork".to_vec()], false)
    );
    child_reaped(&mut parent, 42);
    assert_peer_closed(child.family.parent.as_mut().unwrap());
}

#[test]
fn connections_move_through_exec_and_close_on_reap() {
    let (parent, mut child) = transport::Link::pair().unwrap();
    let mut state = State::default();
    state.family.children.insert(42, Child::new(parent, 1));
    state.deny_attach = true;
    state.original_parent = Some(88);
    let mut image = state.for_exec();
    image.take_connections(&mut state);
    assert!(state.family.children.is_empty());
    assert!(image.deny_attach);
    assert_eq!(image.original_parent, Some(88));

    child.queue(&protocol::Message::TraceMe.encode()).unwrap();
    child.flush().unwrap();
    let parent = image
        .family
        .children
        .get_mut(&42)
        .unwrap()
        .link
        .as_mut()
        .unwrap();
    let (frames, closed) = parent.receive().unwrap();
    assert!(!closed);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        protocol::Message::decode(&frames[0]).unwrap(),
        protocol::Message::TraceMe
    );
    child_reaped(&mut image, 42);
    assert_peer_closed(&mut child);
}

#[test]
fn traced_stop_waits_are_observed_once_and_can_be_peeked() {
    let (link, _peer) = transport::Link::pair().unwrap();
    let mut state = State::default();
    let mut child = Child::new(link, 42);
    child.traced = true;
    child.stop = Some(ChildStop {
        thread: 7,
        signal: signal::SIGTRAP,
        waited: false,
    });
    state.family.children.insert(42, child);
    assert_eq!(peek_stop(&state, 1, 41, false), None);
    assert_eq!(peek_stop(&state, 1, 42, false), Some((42, signal::SIGTRAP)));
    assert_eq!(peek_stop(&state, 1, 42, false), Some((42, signal::SIGTRAP)));
    consume_stop(&mut state, 42);
    assert_eq!(peek_stop(&state, 1, 42, false), None);
    assert_eq!(wait_stop(&mut state, 42, false), None);
    state
        .family
        .children
        .get_mut(&42)
        .unwrap()
        .stop
        .as_mut()
        .unwrap()
        .waited = false;
    assert_eq!(
        wait_stop(&mut state, 42, false),
        Some((42, signal::SIGTRAP))
    );
    assert_eq!(wait_stop(&mut state, 42, false), None);
}

#[test]
fn an_external_tracer_is_observable_without_giving_its_controls_to_the_parent() {
    let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
    let (link, _peer) = transport::Link::pair().unwrap();
    let mut child = Child::new(link, 42);
    child.shared_status = Some(shared.clone());
    shared.set_tracer(42, Some(99));
    assert_eq!(shared.trace(), (true, 42));
    assert_eq!(shared.trace_owner(), (Some(99), 42));
    assert!(!child.is_traced(), "the original parent is not this tracer");
    let mut state = State::default();
    state.family.children.insert(1002, child);
    assert_eq!(known_trace_info(&state, 42, 1002), Some((true, 42)));
    // XNU PT_TRACE_ME can replace p_oppid with the current parent, which
    // may itself be an external tracer. That does not change link ownership.
    shared.set_tracer(99, Some(99));
    assert!(!state.family.children[&1002].is_traced());
    shared.set_tracer(42, Some(42));
    assert!(state.family.children[&1002].is_traced());
    shared.set_tracer(42, None);
    assert_eq!(shared.trace(), (false, 42));
    assert!(!state.family.children[&1002].is_traced());
}

#[test]
fn signal_exit_handoff_only_replaces_fallback_status() {
    let (link, _parent) = transport::Link::pair().unwrap();
    let mut child = State::default();
    child.family.parent = Some(link);
    let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
    child.family.parent_status = Some(shared.clone());
    shared.set_trace(42, true);
    let status = ExitStatus::Signaled {
        signo: signal::SIGCONT,
        core: false,
        pc: 0,
    };
    record_exit(&child, &status);
    assert_eq!(shared.load(), signal::SIGCONT);
    assert_eq!(shared.trace(), (false, 42));

    let (link, _peer) = transport::Link::pair().unwrap();
    let mut parent = State::default();
    let mut record = Child::new(link, 42);
    record.shared_status = Some(shared);
    parent.family.children.insert(42, record);
    assert_eq!(
        exit_status(&parent, 42, (128 + signal::SIGCONT) << 8),
        signal::SIGCONT
    );
    assert_eq!(exit_status(&parent, 42, 42 << 8), 42 << 8);
    assert_eq!(
        exit_status(&parent, 43, (128 + signal::SIGCONT) << 8),
        (128 + signal::SIGCONT) << 8
    );
}

#[test]
fn exit_mapping_survives_host_fork_without_socket_progress() {
    const CHILD: &str = "RAX_PTRACE_SHARED_EXIT_FORK_TEST";
    if std::env::var_os(CHILD).is_none() {
        // Forking directly in the parallel test process would briefly
        // retain sockets owned by unrelated tests. Isolate the fork in
        // a process that runs only this test.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "user::darwin::syscall::bsd::ptrace::tests::exit_mapping_survives_host_fork_without_socket_progress",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "isolated fork test failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let shared = SharedStatus::new().unwrap();
    // SAFETY: after fork the child performs only an atomic store and
    // _exit; it does not touch the test harness or allocate memory.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "host fork failed");
    if pid == 0 {
        shared.store(signal::SIGCONT);
        shared.set_trace(1001, true);
        shared.set_codesign(Some(0x3202_0021));
        // SAFETY: exits the child without running inherited destructors.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    let waited = loop {
        // SAFETY: status points to writable storage and pid is our child.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            break result;
        }
    };
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(shared.load(), signal::SIGCONT);
    assert_eq!(shared.trace(), (true, 1001));
    assert_eq!(shared.codesign(), Some(0x3202_0021));
    shared.clear_traced();
    assert_eq!(shared.trace(), (false, 1001));
}

#[test]
fn foreign_parentage_excludes_retained_job_stop_and_continue_events() {
    let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
    let (link, mut peer) = transport::Link::pair().unwrap();
    let mut child = Child::new(link, 1001);
    child.shared_status = Some(shared.clone());
    child.stop = Some(ChildStop {
        thread: 7,
        signal: signal::SIGSTOP,
        waited: false,
    });
    child.continued = true;
    let mut state = State::default();
    state.family.children.insert(1002, child);
    shared.set_tracer(1001, Some(1003));
    assert_eq!(wait_stop(&mut state, 1002, true), None);
    assert_eq!(peek_stop(&state, 1, 1002, true), None);
    assert_eq!(wait_continue(&mut state, 1002), None);
    assert_eq!(peek_continue(&state, 1, 1002), None);
    assert!(!is_traced_child(&state, 1002));
    assert!(is_signal_peer(&state, 1002));
    assert_eq!(
        send_traced_signal(
            &mut state,
            1002,
            signal::SIGUSR1,
            Origin::process(1001, 501)
        ),
        Ok(true)
    );
    assert!(matches!(
        protocol::Message::decode(&peer.receive().unwrap().0[0]).unwrap(),
        protocol::Message::Signal {
            signal: signal::SIGUSR1,
            sender: 1001,
            uid: 501
        }
    ));
    shared.set_parent(0, 1001, false);
    assert_eq!(
        wait_stop(&mut state, 1002, true),
        Some((1002, signal::SIGSTOP))
    );
    assert_eq!(wait_continue(&mut state, 1002), Some(1002));
}

#[test]
fn ordinary_child_exit_still_requires_its_host_sigchld() {
    let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
    shared.set_parent(0, 1001, false);
    shared.set_guest_exit(7 << 8);
    let (link, _peer) = transport::Link::pair().unwrap();
    let mut child = Child::new(link, 1001);
    child.shared_status = Some(shared);
    let mut state = State::default();
    state.family.children.insert(1002, child);
    assert!(!observation::suppress_host_child_event(&state, 1001, 1002));
    state
        .family
        .children
        .get_mut(&1002)
        .unwrap()
        .registered_exit = Some(lifecycle::Report {
        status: 7 << 8,
        rusage: [0; 144],
    });
    assert!(observation::suppress_host_child_event(&state, 1001, 1002));
}

#[test]
fn parent_fork_handoff_must_not_overwrite_an_already_published_child_tracer() {
    let pair = ForkPair::prepare().unwrap();
    let shared = pair.shared.clone();
    // The host may schedule the child through PT_TRACE_ME or a registry
    // attach before the parent installs its side of the fork connection.
    shared.set_tracer(1001, Some(1003));
    let mut parent = State::default();
    pair.parent(&mut parent, 1002, 1001);
    assert_eq!(shared.snapshot(), (true, 1001, 1003));
    assert!(!parent.family.children[&1002].is_traced());
}
