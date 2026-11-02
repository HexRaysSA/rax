//! Publishing registry cleanup is a guest-memory transition, never a host call.
use super::thread::UserApc;
use super::{Proc, Thread};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::objects::{Object, RegistryCompletion};

pub(crate) const NOTIFY_CLEANUP: u32 = 0x10b;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IoStores {
    PointerStatus,
    Status32,
}

pub(crate) fn io_stores(p: &Proc) -> Result<IoStores, &'static str> {
    let Some(native) = &p.native else {
        // Retain the built-in personality's original ARM64-derived recipe.
        return Ok(IoStores::PointerStatus);
    };
    match (
        native.version.major,
        native.version.minor,
        native.version.build,
        native.object_namespace.native_machine,
        p.arch,
    ) {
        (10, 0, 29695, Some(0xAA64), _) => Ok(IoStores::PointerStatus),
        (10, 0, 20348 | 26100, Some(0x8664), WinArch::X64 | WinArch::X86) => Ok(IoStores::Status32),
        _ => Err("registry notification kernel profile is not captured"),
    }
}

pub(crate) fn publish(p: &mut Proc, completion: RegistryCompletion) {
    if let Some(io) = completion.io {
        let width = p.arch.ptr_size();
        let stores = io_stores(p).expect("notification retains its admitted kernel identity");
        let result = if stores == IoStores::Status32 {
            // AMD64 controls preserve the native64 union padding. WoW64 also
            // publishes its status word before a later information-store fault.
            p.space
                .w32(io, NOTIFY_CLEANUP)
                .and_then(|()| p.space.wptr(io + width, width, 0))
        } else if width == 4 {
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
