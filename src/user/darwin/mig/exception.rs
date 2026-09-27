//! What the task, thread, and host exception-port routines share
//! (`osfmk/kern/ipc_tt.c`, `osfmk/kern/ipc_host.c`): the handler right a
//! `set` or `swap` request carries, installing an action, the merged view
//! `get` and `swap` return, and the reply layouts of `get` and `get_info`.

use std::sync::Arc;

use super::{Buf, Out, Req, copy_send, null_port};
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::mach::exception::{self, Handler};
use crate::user::darwin::mach::ipc::{Port, Right, disp};
use crate::user::darwin::mach::kr::KernReturn;
use crate::user::darwin::mach::task::ExcAction;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// The most entries a `get` reply holds (`EXC_TYPES_COUNT` rounded up:
/// the arrays' MIG bound).
const MAX_ENTRIES: usize = 32;

/// An entry of the merged view: the exceptions it covers and their
/// handler, behavior, and flavor.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The exception types this entry covers.
    pub mask: u32,
    /// The handler.
    pub handler: Handler,
    /// `exception_behavior_t`.
    pub behavior: i32,
    /// `thread_state_flavor_t`.
    pub flavor: i32,
}

/// The handler of a `set`/`swap` request (its `new_port` descriptor,
/// which MIG requires to carry a send right: `MIG_TYPE_ERROR` otherwise).
pub fn take_handler(req: &mut Req) -> Result<Handler, KernReturn> {
    Ok(match req.take_port(28, &[disp::MOVE_SEND])? {
        None => Handler::None,
        Some(Right::Dead) => Handler::Dead,
        Some(Right::Send(p)) => Handler::Port(p),
        Some(_) => unreachable!("a MOVE_SEND descriptor carries a send right"),
    })
}

/// Releases the send right a request's handler carried (MIG consumes it on
/// failure, and a successful `set` copies it into each action).
pub fn release(proc: &mut Proc, handler: &Handler) {
    if let Handler::Port(p) = handler {
        kmsg::release_send(proc, p);
    }
}

/// Checks a `set`/`swap` (`set_exception_ports_validation`).
pub fn validate(
    abi: DarwinAbi,
    mask: u32,
    handler: &Handler,
    behavior: i32,
    flavor: i32,
) -> Result<(), KernReturn> {
    exception::validate(abi, mask, handler, behavior, flavor)
}

/// Installs the action in every slot of `mask` (a send right copied into
/// each); returns the handlers it replaced, whose send rights the caller
/// releases.
pub fn install(
    exc: &mut [ExcAction],
    mask: u32,
    handler: &Handler,
    behavior: i32,
    flavor: i32,
) -> Vec<Arc<Port>> {
    let mut old = Vec::new();
    for (i, action) in exc.iter_mut().enumerate().skip(1) {
        if mask & (1 << i) == 0 {
            continue;
        }
        if let Handler::Port(p) = handler {
            p.state.lock().unwrap().srights += 1;
        }
        let a = std::mem::replace(
            action,
            ExcAction {
                port: handler.port().cloned(),
                dead: matches!(handler, Handler::Dead),
                behavior,
                flavor,
            },
        );
        old.extend(a.port);
    }
    old
}

/// The actions of `mask` merged as `get` reports them: in exception
/// order, an action equal (handler, behavior, and flavor) to an earlier
/// entry joins that entry's mask; at most 32 entries.
pub fn view(exc: &[ExcAction], mask: u32) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for (i, a) in exc.iter().enumerate().skip(1) {
        if mask & (1 << i) == 0 {
            continue;
        }
        let same = out.iter().position(|o| {
            o.behavior == a.behavior
                && o.flavor == a.flavor
                && match (&o.handler, &a.port) {
                    (Handler::Port(x), Some(y)) => Arc::ptr_eq(x, y),
                    (Handler::Dead, None) => a.dead,
                    (Handler::None, None) => !a.dead,
                    _ => false,
                }
        });
        match same {
            Some(o) => out[o].mask |= 1 << i,
            None if out.len() < MAX_ENTRIES => out.push(Entry {
                mask: 1 << i,
                handler: match (&a.port, a.dead) {
                    (Some(p), _) => Handler::Port(p.clone()),
                    (None, true) => Handler::Dead,
                    (None, false) => Handler::None,
                },
                behavior: a.behavior,
                flavor: a.flavor,
            }),
            None => {}
        }
    }
    out
}

/// The `get`/`swap` reply: 32 port descriptors (the handlers, then
/// nulls), then `masksCnt` and the masks, behaviors, and flavors.
pub fn ports_reply(entries: &[Entry]) -> Out {
    let mut descs = Vec::with_capacity(MAX_ENTRIES);
    for e in entries {
        descs.push(match &e.handler {
            Handler::Port(p) => copy_send(p),
            Handler::Dead => super::OutDesc::Port(Some(Right::Dead), disp::MOVE_SEND),
            Handler::None => null_port(),
        });
    }
    while descs.len() < MAX_ENTRIES {
        descs.push(null_port());
    }
    Out::Complex(descs, arrays(entries, None))
}

/// The `get_info` reply: `masksCnt`, the masks, each handler's port and
/// receiver identities (nonzero for a port; the kernel's are address
/// hashes), the behaviors, and the flavors.
pub fn info_reply(entries: &[Entry], task_id: u32) -> Out {
    Out::Simple(arrays(entries, Some(task_id)))
}

fn arrays(entries: &[Entry], info: Option<u32>) -> Vec<u8> {
    let mut b = Buf::new().u32(entries.len() as u32);
    for e in entries {
        b = b.u32(e.mask);
    }
    if let Some(task_id) = info {
        for e in entries {
            let (port, receiver) = match &e.handler {
                Handler::Port(p) if !p.is_dead() => {
                    ((p.id as u32).wrapping_mul(0x9e37_79b1) | 1, task_id)
                }
                _ => (0, 0),
            };
            b = b.u32(port).u32(receiver);
        }
    }
    for e in entries {
        b = b.i32(e.behavior);
    }
    for e in entries {
        b = b.i32(e.flavor);
    }
    b.done()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::mach::ipc::KObject;

    #[test]
    fn view_merges_equal_actions_in_exception_order() {
        let a = Port::new(KObject::None);
        let b = Port::new(KObject::None);
        let mut exc = vec![ExcAction::default(); exception::EXC_TYPES_COUNT];
        let codes = exception::behavior::CODES as i32;
        install(&mut exc, 0x42, &Handler::Port(a.clone()), 1 | codes, 0);
        install(&mut exc, 0x4, &Handler::Port(a.clone()), 2 | codes, 6);
        install(&mut exc, 0x8, &Handler::Port(b.clone()), 1 | codes, 0);
        install(&mut exc, 0x100, &Handler::Dead, 1, 0);
        let v = view(&exc, 0x3fe);
        let masks: Vec<u32> = v.iter().map(|e| e.mask).collect();
        // Bit 9 (no handler) joins the earlier entry without one, not only
        // an adjacent entry.
        assert_eq!(masks, [0x42, 0x4, 0x8, 0x2b0, 0x100]);
        assert!(matches!(v[3].handler, Handler::None));
        assert!(matches!(v[4].handler, Handler::Dead));
        assert!(view(&exc, 0).is_empty());
    }
}
