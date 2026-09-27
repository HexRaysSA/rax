//! Forced and normal process-exit scheduler boundaries.

use super::*;

#[test]
fn forced_process_exit_aborts_held_loader_without_guest_detach_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, index) = terminal_fixture(arch);
        let p = process.state_mut();
        let (stack, teb) = (t.stack_alloc, t.teb);
        assert_eq!(lifecycle::thread_exit(p, &mut t, 3), Outcome::Continue);
        assert!(!t.frames.is_empty());
        assert!(!p.loader.is_idle());
        let mut peer = thread(p, 12);
        let peer_stack = peer.stack_alloc;
        park(
            &mut peer,
            sync::Wait::Sleep {
                deadline: None,
                alertable: false,
            },
        );
        p.threads.insert(peer.tid, peer);
        let mut last = 0;
        apply_outcome(p, t, Outcome::ProcessTerminate(0xDEAD_BEEF), &mut last);
        assert_eq!(p.exit_code, Some(0xDEAD_BEEF));
        assert!(p.failure.is_none());
        assert!(p.loader.is_idle());
        assert!(p.threads.values().all(|t| t.frames.is_empty()));
        assert!(
            p.modules.list[index].initialized,
            "forced termination must not run detach or guest rollback"
        );
        assert_eq!(run(p), ExitStatus::Exited(0xDEAD_BEEF));
        assert!(p.threads.is_empty());
        assert_eq!(p.objects.handle_count(), 0);
        for address in [stack, peer_stack] {
            assert_eq!(p.vm.query(address).unwrap().state, mem::FREE);
        }
        assert!(p.space.probe(teb, 1, MemoryAccessKind::Read).is_err());
    }
}

#[test]
fn normal_process_exit_stops_before_detach_after_peer_teardown_failure_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, t, index) = terminal_fixture(arch);
        let p = process.state_mut();
        let caller_tid = t.tid;
        let mut peer = thread(p, 12);
        // This invalid fiber identity makes actual peer destruction fail
        // after the normal-exit wait-retirement phase.
        peer.current_fiber = Some(0xBAD0);
        p.threads.insert(peer.tid, peer);
        let mut last = 0;
        apply_outcome(p, t, Outcome::ProcessExit(7), &mut last);
        assert!(
            p.failure
                .as_deref()
                .is_some_and(|message| message.contains("fiber teardown failed"))
        );
        assert!(p.exit_code.is_none());
        assert!(p.loader.exiting_process);
        assert!(p.threads[&caller_tid].frames.is_empty());
        assert!(p.modules.list[index].initialized);
        assert_eq!(run(p), ExitStatus::Internal(p.failure.clone().unwrap()));
    }
}
