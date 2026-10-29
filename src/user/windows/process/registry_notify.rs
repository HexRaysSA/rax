//! Publishing registry cleanup is a guest-memory transition, never a host call.
use super::thread::UserApc;
use super::{Proc, Thread};
use crate::user::windows::memory::Mem;
use crate::user::windows::objects::{Object, RegistryCompletion};

pub(crate) const NOTIFY_CLEANUP: u32 = 0x10b;

pub(crate) fn publish(p: &mut Proc, completion: RegistryCompletion) {
    if let Some(io) = completion.io {
        let width = p.arch.ptr_size();
        let result = if width == 4 {
            // WoW64 publishes its complete eight-byte caller record in one
            // checked store. A second-page fault preserves both old fields.
            p.space.w64(io, NOTIFY_CLEANUP.into())
        } else {
            p.space
                .wptr(io, width, NOTIFY_CLEANUP.into())
                .and_then(|()| p.space.wptr(io + width, width, 0))
        };
        if let Err(fault) = result {
            // Native cleanup catches a late user-store fault, consumes a
            // reached guard, and still completes the retained event.
            p.vm.take_guard(fault.addr);
        }
    }
    if let Some(event) = completion.event {
        if let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(event) {
            *signaled = 1;
        }
        p.objects.release(event);
    }
}

fn queue(t: &mut Thread, completion: RegistryCompletion) -> Result<(), String> {
    let (routine, context) = completion.apc.expect("APC completion");
    t.apcs
        .try_reserve(1)
        .map_err(|_| "registry APC allocation failed")?;
    t.apcs.push_back(UserApc::Registry {
        routine,
        context,
        io: completion.io.expect("thread-owned IOSB"),
        event: completion.event,
    });
    Ok(())
}

fn complete(p: &mut Proc, t: &mut Thread, exiting: bool) -> Result<(), String> {
    for completion in p.objects.take_registry_completions() {
        let queued = if let Some(owner) = completion.owner.filter(|_| completion.apc.is_some()) {
            if owner == t.tid && !exiting {
                queue(t, completion)?;
                true
            } else if let Some(other) = p.threads.get_mut(&owner) {
                queue(other, completion)?;
                true
            } else {
                false
            }
        } else {
            false
        };
        if !queued {
            publish(p, completion);
        }
    }
    Ok(())
}

pub(crate) fn finish(p: &mut Proc, t: &mut Thread) -> Result<(), String> {
    complete(p, t, false)
}

pub(crate) fn retire_thread(p: &mut Proc, t: &mut Thread) -> Result<(), String> {
    for apc in t.apcs.drain(..) {
        if let UserApc::Registry { io, event, .. } = apc {
            publish(
                p,
                RegistryCompletion {
                    owner: Some(t.tid),
                    io: Some(io),
                    event,
                    apc: None,
                },
            );
        }
    }
    p.objects.retire_registry_thread(t.tid);
    complete(p, t, true)
}
