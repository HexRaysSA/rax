//! Preserve inherited task-handler capabilities across a host fork.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::mach::{
    ipc::{Port, Right},
    task::TaskState,
};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// Captured before fork; each process consumes its own copy afterwards.
pub(crate) struct InheritedHandlers {
    ports: BTreeMap<u64, Arc<Port>>,
}

impl InheritedHandlers {
    pub(crate) fn capture(state: &super::super::State, task: &TaskState) -> Self {
        let ports = task
            .exc
            .iter()
            .filter_map(|action| action.port.as_ref())
            .filter(|port| {
                state.family.mach.callbacks.proxy_identity(port).is_some()
                    || state
                        .family
                        .peers
                        .incoming
                        .values()
                        .any(|peer| peer.server.callbacks.proxy_identity(port).is_some())
            })
            .map(|port| (port.id, port.clone()))
            .collect();
        Self { ports }
    }

    pub(crate) fn parent(self, proc: &mut Proc, pid: i32) {
        for (handler, port) in self.ports {
            port.state.lock().unwrap().srights += 1;
            match proc.tracing.family.mach.callbacks.retain_handler(
                pid,
                handler,
                0,
                Right::Send(port),
            ) {
                Ok(spare) => kmsg::release(proc, spare),
                Err(right) => {
                    kmsg::release(proc, [right]);
                    super::child_link_failed(proc, pid);
                    return;
                }
            }
        }
    }

    pub(crate) fn child(self, proc: &mut Proc) {
        for action in &mut proc.task.exc {
            if let Some(port) = action.port.as_ref()
                && self.ports.contains_key(&port.id)
            {
                // These are child-local names for sends to its parent, not
                // the copied parent image's now-unreachable receive ports.
                action.port = Some(
                    proc.tracing
                        .family
                        .mach
                        .callbacks
                        .acquire_proxy(port.id, 0, 0),
                );
            }
        }
    }
}
