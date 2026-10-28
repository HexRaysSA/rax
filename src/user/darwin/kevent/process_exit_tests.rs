use super::*;
use crate::user::darwin::kevent::{Knote, KqKind, kn};
use crate::user::darwin::{abi::DarwinAbi, process::bounded_tests::process};

fn note(id: u64, pid: i32, interest: u32, disabled: bool) -> Knote {
    Knote {
        id,
        ident: pid as u64,
        filter: evfilt::PROC,
        flags: ev::ADD,
        qos: 0,
        udata: 0x1234,
        fflags: 0,
        sfflags: interest,
        sdata: 0,
        ext: [0; 4],
        status: if disabled { kn::DISABLED } else { 0 },
        is_fd: false,
        qos_index: 0,
        qos_override: 0,
        thread: None,
        state: State::Host(HostKnote {
            ident: pid as u64,
            ..Default::default()
        }),
    }
}

#[test]
fn guest_exit_activates_only_matching_process_knote_with_guest_wait_status() {
    let mut process = process(DarwinAbi::Arm64);
    let p = &mut process.proc;
    let q = p.kq.create(KqKind::File);
    let queue = p.kq.kqueues.get_mut(&q).unwrap();
    queue
        .knotes
        .insert(1, note(1, 1002, EXIT | EXITSTATUS, false));
    queue
        .knotes
        .insert(2, note(2, 1003, EXIT | EXITSTATUS, false));
    guest_exit(p, 1002, 42 << 8);
    assert_eq!(
        p.kq.kqueues[&q].queues[0]
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![1]
    );
    let (event, result) = super::super::host::process(p, q, 1);
    assert_eq!(result, super::super::fr::ACTIVE);
    assert_eq!(
        (event.ident, event.udata, event.fflags, event.data),
        (1002, 0x1234, EXIT | EXITSTATUS, 42 << 8)
    );
    assert_eq!(
        event.flags & (ev::EOF | ev::ONESHOT | ev::CLEAR),
        ev::EOF | ev::ONESHOT | ev::CLEAR
    );
    assert_eq!(p.kq.kqueues[&q].knotes[&2].status & kn::ACTIVE, 0);
}

#[test]
fn disabled_exit_is_retained_and_note_reap_keeps_knote_without_disclosing_status() {
    let mut process = process(DarwinAbi::Arm64);
    let p = &mut process.proc;
    let q = p.kq.create(KqKind::File);
    p.kq.kqueues
        .get_mut(&q)
        .unwrap()
        .knotes
        .insert(1, note(1, 1002, EXIT | REAP, true));
    guest_exit(p, 1002, 9);
    let k = &p.kq.kqueues[&q].knotes[&1];
    assert_ne!(k.status & kn::ACTIVE, 0);
    assert_eq!(k.status & kn::QUEUED, 0);
    assert_eq!(k.flags & (ev::ONESHOT | ev::EOF), 0);
    let (event, _) = super::super::host::process(p, q, 1);
    assert_eq!((event.fflags, event.data), (EXIT, 0));
    // XNU can re-fire NOTE_EXIT when p_oppid returns the zombie to the
    // same parent; suppressing the eventual host event must not lose this.
    guest_exit(p, 1002, 9);
    assert_eq!(super::super::host::process(p, q, 1).0.fflags, EXIT);
}

#[test]
fn physical_exit_is_suppressed_but_reap_and_other_process_events_survive() {
    let h = HostKnote {
        guest_exit: true,
        ..Default::default()
    };
    let event = HostEvent {
        flags: ev::EOF,
        fflags: EXIT | EXITSTATUS,
        data: 125 << 8,
    };
    assert_eq!(host_event(&h, event), None);
    assert_eq!(
        host_event(
            &h,
            HostEvent {
                fflags: event.fflags | REAP,
                ..event
            }
        ),
        Some(HostEvent {
            flags: ev::EOF,
            fflags: REAP,
            data: 0
        })
    );
    let exec = HostEvent {
        flags: 0,
        fflags: 0x2000_0000,
        data: 0,
    };
    assert_eq!(host_event(&h, exec), Some(exec));
    assert_eq!(host_event(&HostKnote::default(), event), Some(event));
}
