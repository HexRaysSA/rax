//! `filt_procevent`: a traced guest can exit while its host engine pins the
//! zombie PID. Publish NOTE_EXIT to its current guest parent before any reap.

use super::{
    ev, evfilt,
    filters::State,
    host::{HostEvent, HostKnote},
};
use crate::user::darwin::process::Proc;

const EXIT: u32 = 0x8000_0000;
const REAP: u32 = 0x1000_0000;
const EXITSTATUS: u32 = 0x0400_0000;
const EXIT_DETAIL: u32 = 0x0200_0000;

/// Called only after ptrace has established this observer's exit ownership.
/// The scan takes O(K) time and O(K) temporary space for K registered knotes.
pub(crate) fn guest_exit(proc: &mut Proc, pid: i32, status: i32) {
    let mut active = Vec::new();
    for (&kq, queue) in &mut proc.kq.kqueues {
        for (&id, k) in &mut queue.knotes {
            if k.filter != evfilt::PROC || k.ident as i32 != pid {
                continue;
            }
            let State::Host(h) = &mut k.state else {
                continue;
            };
            h.guest_exit = true;
            // XNU forces EV_CLEAR at attach; NOTE_REAP retains the knote
            // after exit, otherwise this is its final event.
            k.flags |= ev::CLEAR;
            if k.sfflags & REAP == 0 {
                k.flags |= ev::EOF | ev::ONESHOT;
            }
            let fflags = k.sfflags & (EXIT | EXITSTATUS | EXIT_DETAIL);
            if fflags == 0 {
                continue;
            }
            let pending = h.event.map_or(0, |e| e.fflags);
            h.event = Some(HostEvent {
                flags: k.flags & ev::EOF,
                fflags: pending | fflags,
                data: if k.sfflags & EXITSTATUS != 0 {
                    i64::from(status)
                } else {
                    0
                },
            });
            active.push((kq, id));
        }
    }
    for (kq, id) in active {
        super::activate(proc, kq, id);
    }
}

/// The physical exit is a transport event after its guest exit was reported.
/// Keep NOTE_REAP and unrelated host events, without reporting exit twice.
pub(super) fn host_event(h: &HostKnote, mut event: HostEvent) -> Option<HostEvent> {
    if h.guest_exit && event.fflags & EXIT != 0 {
        event.fflags &= !(EXIT | EXITSTATUS | EXIT_DETAIL);
        event.data = 0;
        if event.fflags & REAP == 0 {
            event.flags &= !ev::EOF;
        }
        if event.fflags == 0 {
            return None;
        }
    }
    Some(event)
}

#[cfg(test)]
#[path = "process_exit_tests.rs"]
mod tests;
