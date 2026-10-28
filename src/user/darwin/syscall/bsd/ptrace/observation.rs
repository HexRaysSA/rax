//! Process parentage and zombie state observed across connected engines.

use super::*;

pub(crate) fn known_process_info(
    state: &State,
    self_pid: i32,
    self_parent: i32,
    pid: i32,
) -> Option<(bool, i32, Option<i32>, Option<i32>)> {
    if pid == self_pid {
        return Some((
            state.tracer.is_some(),
            state.original_parent.unwrap_or(0),
            Some(self_parent),
            None,
        ));
    }
    let child = state.family.children.get(&pid)?;
    if let Some(shared) = &child.shared_status {
        let (traced, original, parent) = shared.snapshot();
        return Some((
            traced,
            original,
            (parent > 0).then_some(parent),
            shared.guest_exit(),
        ));
    }
    let parent = if child.traced || child.registered_exit.is_some() {
        Some(child.owner_pid)
    } else {
        child.original_parent
    };
    Some((
        child.traced,
        child.original_parent.unwrap_or(0),
        parent,
        child.registered_exit.map(|report| report.status),
    ))
}

/// A physical host child can temporarily belong to a different guest parent.
/// Host wait calls must not consume its status during that interval.
pub(crate) fn foreign_child(state: &State, self_pid: i32, pid: i32) -> bool {
    state
        .family
        .children
        .get(&pid)
        .and_then(|child| child.shared_status.as_ref())
        .is_some_and(|shared| {
            let parent = shared.snapshot().2;
            parent > 0 && parent != self_pid
        })
}

pub(crate) fn reaping_child(state: &State, pid: i32) -> bool {
    super::reap::owns(state, pid)
}

pub(crate) fn suppress_host_child_event(state: &State, self_pid: i32, pid: i32) -> bool {
    foreign_child(state, self_pid, pid)
        || reaping_child(state, pid)
        || state
            .family
            .children
            .get(&pid)
            .is_some_and(|child| child.registered_exit.is_some())
}

/// A physical child that is finally reaped by another guest parent must not
/// remain a host zombie in its ancestral engine. Its SIGCHLD is internal.
pub(crate) fn host_child_event(proc: &mut Proc, pid: i32, code: i32) -> bool {
    let foreign = foreign_child(&proc.tracing, proc.pid, pid);
    if foreign && matches!(code, 1 | 2 | 3) && proc.children.contains(&pid) {
        let mut status = 0;
        // SAFETY: pid is a tracked physical child and status is writable.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            proc.children.remove(&pid);
            remote_mach::peer_died(proc, pid);
            child_reaped(&mut proc.tracing, pid);
        }
    }
    foreign || suppress_host_child_event(&proc.tracing, proc.pid, pid)
}

/// Publish guest signing flags in the controller's ordered stream. A reply
/// following this publication cannot expose the engine image's stale flags.
pub(crate) fn sync_codesign(proc: &mut Proc) {
    let flags = proc.codesign.as_ref().map(|signing| signing.flags);
    let epoch = super::peers::image_epoch(proc);
    let routes: Vec<_> = proc
        .tracing
        .family
        .peers
        .incoming
        .keys()
        .copied()
        .map(channels::ServerRoute::Registered)
        .collect();
    for route in routes {
        if route
            .server(proc)
            .is_some_and(|server| server.code_flags == Some(flags))
        {
            continue;
        }
        if channels::queue_reply(
            proc,
            route,
            protocol::Message::CodeFlags { epoch, flags }.encode(),
        ) {
            if let Some(server) = route.server_mut(proc) {
                server.code_flags = Some(flags);
            }
        } else {
            channels::disconnect(proc, route);
        }
    }
}
