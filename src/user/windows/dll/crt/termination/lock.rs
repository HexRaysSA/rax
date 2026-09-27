//! Recursive per-runtime exit serialization with scheduler-owned wait parking.
//! No host borrow survives guest callbacks. Wait keys cannot alias guest
//! address/condition-variable keys (which use only the low 65 bits).

use std::cell::RefCell;
use std::rc::Rc;

use crate::user::windows::hle::{ApiErr, ApiResult, Cont, Ctx, Flow};
use crate::user::windows::process::Proc;
use crate::user::windows::sync::Wait;

use super::super::RuntimeKind;

#[derive(Default)]
struct State {
    owner: Option<(u32, u32)>,
    /// Capacity is reserved before issuing each guard. Drop never allocates.
    abandoned: Vec<u32>,
}

#[derive(Clone, Default)]
pub(in crate::user::windows::dll::crt) struct ExitLockState(Rc<RefCell<State>>);

struct Guard {
    state: ExitLockState,
    runtime: RuntimeKind,
    tid: u32,
    finished: bool,
}

fn key(runtime: RuntimeKind) -> u128 {
    (1u128 << 127) | runtime.index() as u128
}

fn invalid(message: &str) -> ApiErr {
    ApiErr::Internal(format!("CRT exit lock: {message}"))
}

impl ExitLockState {
    fn acquire(&self, runtime: RuntimeKind, tid: u32) -> Result<Option<Guard>, ApiErr> {
        let mut state = self.0.borrow_mut();
        let count = match state.owner {
            Some((owner, _)) if owner != tid => return Ok(None),
            Some((_, count)) => count
                .checked_add(1)
                .ok_or_else(|| invalid("recursion exhausted"))?,
            None => 1,
        };
        let reserve = usize::try_from(count).map_err(|_| invalid("receipt size exhausted"))?;
        state
            .abandoned
            .try_reserve(reserve)
            .map_err(|_| invalid("receipt capacity exhausted"))?;
        state.owner = Some((tid, count));
        Ok(Some(Guard {
            state: self.clone(),
            runtime,
            tid,
            finished: false,
        }))
    }
}

fn release(
    p: &mut Proc,
    state: &ExitLockState,
    runtime: RuntimeKind,
    tid: u32,
) -> Result<(), String> {
    let mut state = state.0.borrow_mut();
    let (owner, count) = state.owner.ok_or("CRT exit lock owner missing")?;
    if owner != tid || count == 0 {
        return Err("CRT exit lock receipt ownership mismatch".into());
    }
    if count == 1 {
        state.owner = None;
        p.sync.wake(key(runtime), usize::MAX);
    } else {
        state.owner = Some((owner, count - 1));
    }
    Ok(())
}

impl Guard {
    fn finish(mut self, p: &mut Proc) -> Result<(), ApiErr> {
        release(p, &self.state, self.runtime, self.tid).map_err(ApiErr::Internal)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.finished {
            self.state.0.borrow_mut().abandoned.push(self.tid);
        }
    }
}

pub(in crate::user::windows::dll::crt) fn with_lock(
    c: &mut Ctx,
    runtime: RuntimeKind,
    next: Cont,
) -> ApiResult {
    let state = c.p.crt.runtimes[runtime.index()].exit_lock.clone();
    match state.acquire(runtime, c.t.tid)? {
        Some(guard) => {
            let result = next(c, 0);
            hold(c, guard, result)
        }
        None => Flow::block(
            Wait::Address {
                key: key(runtime),
                deadline: None,
            },
            move |c, _| with_lock(c, runtime, next),
        ),
    }
}

fn hold(c: &mut Ctx, guard: Guard, result: ApiResult) -> ApiResult {
    match result {
        Ok(Flow::Protected {
            code,
            handler,
            then,
        }) => Ok(Flow::Protected {
            code,
            handler,
            then: Box::new(move |c, value| {
                let result = then(c, value);
                hold(c, guard, result)
            }),
        }),
        Ok(Flow::Call { target, args, then }) => Ok(Flow::Call {
            target,
            args,
            then: Box::new(move |c, value| {
                let result = then(c, value);
                hold(c, guard, result)
            }),
        }),
        Ok(Flow::CallChecked { target, args, then }) => Ok(Flow::CallChecked {
            target,
            args,
            then: Box::new(move |c, value| {
                let result = then(c, value);
                hold(c, guard, result)
            }),
        }),
        Ok(Flow::RetryFault { fault, retry }) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, value| {
                let result = retry(c, value);
                hold(c, guard, result)
            }),
        }),
        Ok(Flow::Block { wait, then }) => Ok(Flow::Block {
            wait,
            then: Box::new(move |c, value| {
                let result = then(c, value);
                hold(c, guard, result)
            }),
        }),
        other => {
            guard.finish(c.p)?;
            other
        }
    }
}

pub(super) fn cleanup_abandoned(
    p: &mut Proc,
    runtime: RuntimeKind,
    terminal_owner: Option<u32>,
    all_terminal: bool,
) -> Result<(), String> {
    let state = p.crt.runtimes[runtime.index()].exit_lock.clone();
    let mut failure = None;
    loop {
        let Some(tid) = state.0.borrow_mut().abandoned.pop() else {
            break;
        };
        if let Err(error) = release(p, &state, runtime, tid) {
            failure.get_or_insert(error);
        } else if !all_terminal && terminal_owner != Some(tid) {
            failure.get_or_insert_with(|| {
                format!("CRT exit lock continuation abandoned on thread {tid}")
            });
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn discard_process(p: &mut Proc, runtime: RuntimeKind) {
    let state = p.crt.runtimes[runtime.index()].exit_lock.clone();
    let mut state = state.0.borrow_mut();
    state.owner = None;
    state.abandoned.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::dll::crt::tests::{int, invoke, run};
    use crate::user::windows::hle::Value;

    #[test]
    fn receipt_reaping_preserves_capacity_for_still_live_guards_all_abis() {
        run(|c| {
            let runtime = RuntimeKind::Ucrt;
            let state = c.p.crt.runtimes[runtime.index()].exit_lock.clone();
            let a = state.acquire(runtime, c.t.tid).unwrap().unwrap();
            let b = state.acquire(runtime, c.t.tid).unwrap().unwrap();
            let capacity = state.0.borrow().abandoned.capacity();
            drop(a);
            cleanup_abandoned(c.p, runtime, Some(c.t.tid), false).unwrap();
            assert_eq!(state.0.borrow().owner, Some((c.t.tid, 1)));
            assert_eq!(state.0.borrow().abandoned.capacity(), capacity);
            drop(b);
            assert_eq!(state.0.borrow().abandoned.capacity(), capacity);
            cleanup_abandoned(c.p, runtime, Some(c.t.tid), false).unwrap();
            assert!(state.0.borrow().owner.is_none());
            assert!(state.0.borrow().abandoned.is_empty());
        });
    }

    #[test]
    fn recursion_exhaustion_does_not_publish_guard_or_run_operation_all_abis() {
        run(|c| {
            let runtime = RuntimeKind::Ucrt;
            let state = c.p.crt.runtimes[runtime.index()].exit_lock.clone();
            state.0.borrow_mut().owner = Some((c.t.tid, u32::MAX));
            let result = with_lock(c, runtime, Box::new(|_, _| panic!("must not enter")));
            assert!(
                matches!(result, Err(ApiErr::Internal(message)) if message.contains("recursion exhausted"))
            );
            assert_eq!(state.0.borrow().owner, Some((c.t.tid, u32::MAX)));
            assert!(state.0.borrow().abandoned.is_empty());
            state.0.borrow_mut().owner = None;
            assert!(matches!(
                with_lock(c, runtime, Box::new(|_, _| Flow::ret(7))).unwrap(),
                Flow::Ret(Value::Int(7))
            ));
        });
    }

    #[test]
    fn dropping_unacquired_waiter_does_not_release_owner_or_register_target_all_abis() {
        run(|c| {
            let runtime = RuntimeKind::Ucrt;
            let state = c.p.crt.runtimes[runtime.index()].exit_lock.clone();
            let guard = state.acquire(runtime, c.t.tid).unwrap().unwrap();
            let owner = c.t.tid;
            c.t.tid += 1;
            let result = invoke(c, runtime, "_crt_atexit", &[0x1110]).unwrap();
            c.t.tid = owner;
            assert!(matches!(result, Flow::Block { .. }));
            drop(result);
            cleanup_abandoned(c.p, runtime, None, false).unwrap();
            assert_eq!(state.0.borrow().owner, Some((owner, 1)));
            guard.finish(c.p).unwrap();
            let queues = c.p.crt.runtimes[runtime.index()].termination.clone();
            let mut drain = queues
                .begin(super::super::storage::Kind::Ordinary, owner)
                .unwrap();
            assert_eq!(drain.next(c.p).unwrap(), None);
            drain.finish(c.p).unwrap();
            assert_eq!(int(invoke(c, runtime, "_crt_atexit", &[0x2220])), 0);
        });
    }
}
