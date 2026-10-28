//! Target capability ownership is per authenticated controller connection.

use super::super::channels::ServerRoute;
use super::*;
use crate::user::darwin::syscall::mach::kmsg;

pub(in super::super) fn epoch(proc: &Proc, route: ServerRoute) -> Option<u64> {
    match route {
        ServerRoute::Parent => proc
            .tracing
            .family
            .parent_status
            .as_ref()
            .map(|shared| shared.image_epoch()),
        ServerRoute::Registered(_) => Some(super::super::peers::image_epoch(proc)),
    }
}

pub(in super::super) fn acquire(
    proc: &mut Proc,
    route: ServerRoute,
    generation: u64,
    instance: u64,
    requested_epoch: u64,
    object: Object,
) {
    if !route.server(proc).is_some_and(|server| server.allowed)
        || object != Object::Task
        || instance & TARGET_INSTANCE_BIT != 0
        || generation & TARGET_GENERATION_BIT != 0
    {
        return;
    }
    if epoch(proc, route) != Some(requested_epoch) {
        if !queue_response_on(
            proc,
            route,
            Message::Dead {
                generation,
                instance,
                object,
            },
        ) {
            fail(proc, route);
        }
        return;
    }
    let port = proc.task_port.clone();
    let Some(server) = route.server_mut(proc) else {
        return;
    };
    if let Some(export) = server.exports.get_mut(&(instance, object)) {
        export.generation = generation;
    } else {
        port.state.lock().unwrap().srights += 1;
        server.exports.insert(
            (instance, object),
            Export {
                generation,
                right: Right::Send(port),
            },
        );
    }
}

pub(in super::super) fn release(
    proc: &mut Proc,
    route: ServerRoute,
    generation: u64,
    instance: u64,
    object: Object,
) {
    let Some(server) = route.server_mut(proc) else {
        return;
    };
    if !server
        .exports
        .get(&(instance, object))
        .is_some_and(|export| export.generation == generation)
    {
        return;
    }
    let export = server
        .exports
        .remove(&(instance, object))
        .expect("matched export");
    kmsg::release(proc, [export.right]);
}

pub(in super::super) fn fail(proc: &mut Proc, route: ServerRoute) {
    if let Some(server) = route.server_mut(proc) {
        server.failed = true;
    }
}

pub(in super::super) fn retire(proc: &mut Proc, route: ServerRoute) {
    let Some(server) = route.server_mut(proc) else {
        return;
    };
    let exports = std::mem::take(&mut server.exports);
    for ((instance, object), export) in exports {
        if let Some(port) = export.right.port().cloned() {
            kmsg::destroy_receive(proc, &port);
        }
        kmsg::release(proc, [export.right]);
        if !queue_response_on(
            proc,
            route,
            Message::Dead {
                generation: export.generation,
                instance,
                object,
            },
        ) {
            fail(proc, route);
        }
    }
}

pub(in super::super) fn thread_died(proc: &mut Proc, route: ServerRoute, tid: u64) {
    let Some(server) = route.server(proc) else {
        return;
    };
    let object = Object::Thread(tid);
    let keys: Vec<_> = server
        .exports
        .keys()
        .filter(|(_, kind)| *kind == object)
        .copied()
        .collect();
    for (instance, object) in keys {
        let export = route
            .server_mut(proc)
            .unwrap()
            .exports
            .remove(&(instance, object))
            .expect("listed export");
        kmsg::release(proc, [export.right]);
        if !queue_response_on(
            proc,
            route,
            Message::Dead {
                generation: export.generation,
                instance,
                object,
            },
        ) {
            fail(proc, route);
        }
    }
}

pub(in super::super) fn disconnected(proc: &mut Proc, route: ServerRoute) {
    super::token::controller_died(proc, route);
    super::suspension::controller_died(proc, route);
    super::callback_runtime::controller_died(proc, route);
    let Some(server) = route.server_mut(proc) else {
        return;
    };
    let exports = std::mem::take(&mut server.exports);
    server.allowed = false;
    server.replies.clear();
    server.notices.clear();
    server.queued_bytes = 0;
    server.queued_fds = 0;
    server.failed = false;
    kmsg::release(proc, exports.into_values().map(|export| export.right));
}

pub(in super::super) fn callback_parts(
    proc: &mut Proc,
    route: ServerRoute,
) -> Option<(&mut BTreeMap<(u64, Object), Export>, &mut callback::State)> {
    match route {
        ServerRoute::Parent => {
            let state = &mut proc.tracing.family.mach;
            Some((&mut state.parent_server.exports, &mut state.callbacks))
        }
        _ => {
            let server = route.server_mut(proc)?;
            Some((&mut server.exports, &mut server.callbacks))
        }
    }
}

pub(in super::super) fn has_thread_export(
    proc: &Proc,
    route: ServerRoute,
    instance: u64,
    tid: u64,
) -> bool {
    route.server(proc).is_some_and(|server| {
        server
            .exports
            .contains_key(&(instance, Object::Thread(tid)))
    })
}

#[cfg(test)]
#[path = "remote_mach_controller_tests.rs"]
mod tests;
