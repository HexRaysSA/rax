//! Task user holds (`task.c`: place_task_hold, release_task_hold).
//!
//! XNU 12377.121.6 `task.h` uses signed integer_t counters. Accounting
//! accepts nonnegative representable counts; exhausting that range returns
//! KERN_RESOURCE_SHORTAGE before changing either counter. Each operation
//! takes O(1) time and space. The resume port belongs to this task image.

use std::sync::Arc;

use super::ipc::{KObject, Port, Right};
use super::kr::{self, KernReturn};
use crate::user::darwin::process::Proc;

#[cfg(test)]
#[path = "suspend_token_tests.rs"]
mod token_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    Normal,
    Legacy,
}

/// Make the send which a legacy suspend copies into the caller's space.
pub(crate) fn legacy_send(proc: &mut Proc) -> Result<Right, KernReturn> {
    proc.task.suspension.place(Hold::Legacy)?;
    let port = resume_port(proc);
    {
        let mut state = port.state.lock().unwrap();
        state.srights += 1;
        state.mscount = state.mscount.wrapping_add(1);
    }
    Ok(Right::Send(port))
}

fn resume_port(proc: &mut Proc) -> Arc<Port> {
    let owner = proc.task_port.id;
    proc.task
        .suspension
        .resume
        .get_or_insert_with(|| Port::new(KObject::TaskResume(Some(owner))))
        .clone()
}

pub(crate) fn is_resume_port(proc: &Proc, port: &Port) -> bool {
    matches!(port.kobject, KObject::TaskResume(Some(owner)) if owner == proc.task_port.id)
        && proc
            .task
            .suspension
            .resume
            .as_ref()
            .is_some_and(|p| p.id == port.id)
}

/// A suspension token is an independent send-once right on the same
/// underlying port used by legacy send rights (`ipc_tt.c`).
pub(crate) fn token(proc: &mut Proc) -> Result<Right, KernReturn> {
    proc.task.suspension.place(Hold::Normal)?;
    let port = resume_port(proc);
    port.state.lock().unwrap().sorights += 1;
    Ok(Right::SendOnce(port))
}

/// Abandonment releases a normal hold; using a send-once destination does
/// not. A malformed RPC can consume the token without releasing the hold.
pub(crate) fn abandon_token(proc: &mut Proc, port: &Port) -> bool {
    if !is_resume_port(proc, port) {
        return false;
    }
    let release = {
        let mut state = port.state.lock().unwrap();
        let release = state.sorights != 0 && !state.dead;
        state.sorights = state.sorights.saturating_sub(1);
        release
    };
    if release {
        let _ = proc.task.suspension.release(Hold::Normal);
    }
    true
}

/// The kernel resume port's no-senders callback, after its lock is released.
pub(crate) fn last_send(proc: &mut Proc, port: &Port) {
    if is_resume_port(proc, port) {
        let _ = proc.task.suspension.release_all_legacy();
    }
}

#[derive(Debug, Default)]
pub struct Suspension {
    user_stop_count: i32,
    legacy_stop_count: i32,
    pub(crate) resume: Option<Arc<Port>>,
}

impl Suspension {
    pub fn count(&self) -> i32 {
        self.user_stop_count
    }

    pub fn is_stopped(&self) -> bool {
        self.user_stop_count != 0
    }

    pub(crate) fn place(&mut self, kind: Hold) -> Result<(), KernReturn> {
        let total = self
            .user_stop_count
            .checked_add(1)
            .ok_or(kr::KERN_RESOURCE_SHORTAGE)?;
        let legacy = if kind == Hold::Legacy {
            self.legacy_stop_count
                .checked_add(1)
                .ok_or(kr::KERN_RESOURCE_SHORTAGE)?
        } else {
            self.legacy_stop_count
        };
        self.user_stop_count = total;
        self.legacy_stop_count = legacy;
        Ok(())
    }

    pub(crate) fn release(&mut self, kind: Hold) -> Result<(), KernReturn> {
        if self.user_stop_count == 0 {
            return Err(kr::KERN_FAILURE);
        }
        if kind == Hold::Legacy && self.legacy_stop_count > 0 {
            self.legacy_stop_count -= 1;
        }
        self.user_stop_count -= 1;
        Ok(())
    }

    pub(crate) fn release_all_legacy(&mut self) -> Result<(), KernReturn> {
        if self.user_stop_count == 0 {
            return Err(kr::KERN_FAILURE);
        }
        self.user_stop_count = (self.user_stop_count - self.legacy_stop_count).max(0);
        self.legacy_stop_count = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_no_senders_releases_every_legacy_hold_and_keeps_normal_holds() {
        let mut holds = Suspension::default();
        holds.place(Hold::Normal).unwrap();
        holds.place(Hold::Legacy).unwrap();
        holds.place(Hold::Legacy).unwrap();
        assert_eq!(holds.count(), 3);
        assert!(holds.is_stopped());
        holds.release_all_legacy().unwrap();
        assert_eq!(holds.count(), 1);
        assert_eq!(holds.legacy_stop_count, 0);
        holds.release(Hold::Normal).unwrap();
        assert!(!holds.is_stopped());
        assert_eq!(holds.release(Hold::Legacy), Err(kr::KERN_FAILURE));
    }

    #[test]
    fn an_out_of_band_legacy_resume_can_consume_a_normal_hold() {
        let mut holds = Suspension::default();
        holds.place(Hold::Normal).unwrap();
        holds.release(Hold::Legacy).unwrap();
        assert_eq!(holds.count(), 0);
        // The old normal token still exists when a new legacy hold arrives.
        holds.place(Hold::Legacy).unwrap();
        holds.release(Hold::Normal).unwrap();
        assert_eq!((holds.count(), holds.legacy_stop_count), (0, 1));
        assert_eq!(holds.release_all_legacy(), Err(kr::KERN_FAILURE));
        holds.place(Hold::Legacy).unwrap();
        assert_eq!((holds.count(), holds.legacy_stop_count), (1, 2));
        holds.release_all_legacy().unwrap();
        assert_eq!((holds.count(), holds.legacy_stop_count), (0, 0));
    }

    #[test]
    fn counter_capacity_is_checked_before_either_counter_changes() {
        for (total, legacy) in [(i32::MAX, 1), (1, i32::MAX)] {
            let mut holds = Suspension {
                user_stop_count: total,
                legacy_stop_count: legacy,
                resume: None,
            };
            assert_eq!(holds.place(Hold::Legacy), Err(kr::KERN_RESOURCE_SHORTAGE));
            assert_eq!((holds.count(), holds.legacy_stop_count), (total, legacy));
        }
    }
}
