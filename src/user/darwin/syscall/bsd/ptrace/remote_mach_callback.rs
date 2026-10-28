//! Lifetime tracking for tracer-owned exception-handler send rights.
//!
//! An export holds one real send right in the tracer. A target proxy holds
//! local send rights on behalf of its task's exception actions. Generations
//! keep delayed no-senders and dead-port notices from retiring a newer use.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use crate::user::darwin::mach::ipc::{IpcSpace, KObject, Port, Right};

#[path = "remote_mach_callback_receive.rs"]
pub(super) mod receive;
#[path = "remote_mach_callback_target.rs"]
pub(super) mod target;

#[derive(Debug, Default)]
pub(in super::super) struct State {
    exports: BTreeMap<(i32, u64), HandlerExport>,
    proxies: BTreeMap<u64, HandlerProxy>,
    proxy_ids: HashMap<u64, u64>,
    next_target_instance: u64,
    owned_replies: BTreeMap<u64, Right>,
    proxy_replies: HashMap<u64, ReplyProxy>,
    reply_tokens: BTreeMap<(i32, u64), u64>,
    outgoing: BTreeMap<i32, VecDeque<Vec<u8>>>,
}

#[derive(Debug)]
struct HandlerExport {
    generation: u64,
    right: Right,
}

#[derive(Debug)]
struct HandlerProxy {
    generation: u64,
    task_instance: u64,
    port: Arc<Port>,
}

#[derive(Debug)]
struct ReplyProxy {
    pid: i32,
    token: u64,
    port: Arc<Port>,
}

impl State {
    /// Allocate in the target-originated half of the connection namespace.
    /// `occupied` counts the target exports tested by `in_use`.
    pub(in super::super) fn target_instance(
        &mut self,
        occupied: usize,
        mut in_use: impl FnMut(u64) -> bool,
    ) -> Option<u64> {
        const TARGET_BIT: u64 = 1 << 63;
        for _ in 0..=occupied {
            let candidate = TARGET_BIT | self.next_target_instance;
            self.next_target_instance =
                self.next_target_instance.wrapping_add(1) & (TARGET_BIT - 1);
            if !in_use(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Retain a handler send right after its installation frame is queued.
    /// When already exported, the caller must release the returned extra right.
    pub(in super::super) fn retain_handler(
        &mut self,
        pid: i32,
        handler: u64,
        generation: u64,
        right: Right,
    ) -> Result<Option<Right>, Right> {
        if !matches!(&right, Right::Send(port) if port.id == handler && !port.is_dead()) {
            return Err(right);
        }
        if let Some(export) = self.exports.get_mut(&(pid, handler)) {
            export.generation = generation;
            return Ok(Some(right));
        }
        self.exports
            .insert((pid, handler), HandlerExport { generation, right });
        Ok(None)
    }

    /// Retire only the generation observed by the target's no-senders path.
    pub(in super::super) fn release_handler(
        &mut self,
        pid: i32,
        handler: u64,
        generation: u64,
    ) -> Option<Right> {
        let key = (pid, handler);
        if !self
            .exports
            .get(&key)
            .is_some_and(|e| e.generation == generation)
        {
            return None;
        }
        self.exports.remove(&key).map(|export| export.right)
    }

    /// A handler remains usable by already queued exception messages even if
    /// a newer generation of the same send right has been installed.
    pub(in super::super) fn handler_port(&self, pid: i32, handler: u64) -> Option<Arc<Port>> {
        let port = self.exports.get(&(pid, handler))?.right.port()?;
        (!port.is_dead()).then(|| port.clone())
    }

    /// Retire all exports to a dead receive right, one notice per child.
    pub(in super::super) fn dead_exports(&mut self, handler: u64) -> Vec<(i32, u64, Right)> {
        let keys: Vec<_> = self
            .exports
            .keys()
            .filter(|(_, id)| *id == handler)
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                self.exports
                    .remove(&key)
                    .map(|export| (key.0, export.generation, export.right))
            })
            .collect()
    }

    /// Release a child's exported rights when its connection is gone.
    pub(in super::super) fn drop_peer(&mut self, pid: i32) -> Vec<Right> {
        self.outgoing.remove(&pid);
        let keys: Vec<_> = self
            .exports
            .keys()
            .filter(|(p, _)| *p == pid)
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|key| self.exports.remove(&key).map(|e| e.right))
            .collect()
    }

    /// Obtain a target-side proxy with one newly owned send right.
    pub(in super::super) fn acquire_proxy(
        &mut self,
        handler: u64,
        generation: u64,
        task_instance: u64,
    ) -> Arc<Port> {
        let Self {
            proxies, proxy_ids, ..
        } = self;
        let entry = proxies.entry(handler).or_insert_with(|| {
            let port = Port::new(KObject::None);
            proxy_ids.insert(port.id, handler);
            HandlerProxy {
                generation,
                task_instance,
                port,
            }
        });
        entry.generation = generation;
        entry.task_instance = task_instance;
        entry.port.state.lock().unwrap().srights += 1;
        entry.port.clone()
    }

    /// Resolve a proxy without exposing a target-side port name on the wire.
    pub(in super::super) fn proxy_identity(&self, port: &Port) -> Option<(u64, u64, u64)> {
        let handler = *self.proxy_ids.get(&port.id)?;
        let proxy = self.proxies.get(&handler)?;
        (proxy.port.id == port.id).then_some((handler, proxy.generation, proxy.task_instance))
    }

    /// Return a proxy's handler and generation after its last send is gone.
    pub(in super::super) fn last_proxy_send(&mut self, port: &Port) -> Option<(u64, u64)> {
        let handler = *self.proxy_ids.get(&port.id)?;
        let proxy = self.proxies.get(&handler)?;
        if proxy.port.id != port.id || port.state.lock().unwrap().srights != 0 {
            return None;
        }
        let generation = proxy.generation;
        self.proxies.remove(&handler);
        self.proxy_ids.remove(&port.id);
        Some((handler, generation))
    }

    /// Detach the matching proxy when its real receive right dies.
    pub(in super::super) fn dead_proxy(
        &mut self,
        handler: u64,
        generation: u64,
    ) -> Option<Arc<Port>> {
        if !self
            .proxies
            .get(&handler)
            .is_some_and(|p| p.generation == generation)
        {
            return None;
        }
        let proxy = self.proxies.remove(&handler)?;
        self.proxy_ids.remove(&proxy.port.id);
        Some(proxy.port)
    }

    /// Own the target's send-once right while its exception travels.
    pub(in super::super) fn retain_reply(&mut self, right: Right) -> Result<u64, Right> {
        let token = match &right {
            Right::SendOnce(port) if !port.is_dead() => port.id,
            _ => return Err(right),
        };
        if self.owned_replies.contains_key(&token) {
            return Err(right);
        }
        self.owned_replies.insert(token, right);
        Ok(token)
    }

    /// Consume an outstanding reply exactly once, whether sent or abandoned.
    pub(in super::super) fn take_reply(&mut self, token: u64) -> Option<Right> {
        self.owned_replies.remove(&token)
    }

    /// Build a local send-once proxy for a target-owned reply right.
    pub(in super::super) fn proxy_reply(&mut self, pid: i32, token: u64) -> Option<Right> {
        if token == 0 || self.reply_tokens.contains_key(&(pid, token)) {
            return None;
        }
        let port = Port::new(KObject::None);
        port.state.lock().unwrap().sorights += 1;
        self.reply_tokens.insert((pid, token), port.id);
        self.proxy_replies.insert(
            port.id,
            ReplyProxy {
                pid,
                token,
                port: port.clone(),
            },
        );
        Some(Right::SendOnce(port))
    }

    /// Consume the routing record when the debugger sends or drops the right.
    pub(in super::super) fn proxy_reply_identity(&self, port: &Port) -> Option<(i32, u64)> {
        let proxy = self.proxy_replies.get(&port.id)?;
        Some((proxy.pid, proxy.token))
    }

    pub(in super::super) fn take_proxy_reply(&mut self, port: &Port) -> Option<(i32, u64)> {
        let proxy = self.proxy_replies.remove(&port.id)?;
        self.reply_tokens.remove(&(proxy.pid, proxy.token));
        Some((proxy.pid, proxy.token))
    }

    /// Retire a reply proxy after the target's receive right dies.
    pub(in super::super) fn cancel_proxy_reply(
        &mut self,
        pid: i32,
        token: u64,
    ) -> Option<Arc<Port>> {
        let id = self.reply_tokens.remove(&(pid, token))?;
        self.proxy_replies.remove(&id).map(|proxy| proxy.port)
    }

    pub(in super::super) fn drop_peer_replies(&mut self, pid: i32) -> Vec<Arc<Port>> {
        let tokens: Vec<_> = self
            .reply_tokens
            .keys()
            .filter(|(p, _)| *p == pid)
            .copied()
            .collect();
        tokens
            .into_iter()
            .filter_map(|(p, token)| self.cancel_proxy_reply(p, token))
            .collect()
    }

    pub(in super::super) fn take_owned_replies(&mut self) -> Vec<Right> {
        std::mem::take(&mut self.owned_replies)
            .into_values()
            .collect()
    }

    /// Replies waiting in this image's threads; relayed child RPCs survive.
    pub(in super::super) fn take_image_replies(&mut self) -> Vec<Right> {
        let tokens: Vec<_> = self
            .owned_replies
            .keys()
            .filter(|token| !self.proxy_replies.contains_key(token))
            .copied()
            .collect();
        tokens
            .into_iter()
            .filter_map(|token| self.owned_replies.remove(&token))
            .collect()
    }

    /// Exported receive ports of this image; relayed handler sends survive.
    pub(in super::super) fn local_handler_ports(&self, ipc: &IpcSpace) -> Vec<Arc<Port>> {
        self.exports
            .values()
            .filter_map(|export| export.right.port())
            .filter(|port| {
                !self.proxy_ids.contains_key(&port.id)
                    && (matches!(port.kobject, KObject::None)
                        || ipc
                            .name_of(port)
                            .and_then(|name| ipc.lookup(name).ok())
                            .is_some_and(|entry| entry.receive))
            })
            .map(|port| (port.id, port.clone()))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect()
    }

    /// Old image reply rights, excluding sends held by forwarded child RPCs.
    pub(in super::super) fn image_reply_proxy_ports(&self) -> Vec<Arc<Port>> {
        self.proxy_replies
            .values()
            .filter(|reply| !self.owned_replies.contains_key(&reply.port.id))
            .map(|reply| reply.port.clone())
            .collect()
    }

    /// One retained relay send per child connection and handler identity.
    pub(in super::super) fn relay_export_count(&self, port: u64) -> u32 {
        self.exports
            .values()
            .filter(|export| export.right.port().is_some_and(|p| p.id == port))
            .count() as u32
    }

    pub(in super::super) fn handler_proxy_ports(&self) -> Vec<Arc<Port>> {
        self.proxies
            .values()
            .map(|proxy| proxy.port.clone())
            .collect()
    }

    pub(in super::super) fn take_parent_proxies(&mut self) -> Vec<Arc<Port>> {
        self.proxy_ids.clear();
        std::mem::take(&mut self.proxies)
            .into_values()
            .map(|proxy| proxy.port)
            .collect()
    }

    /// Retain an already-consumed callback reply or lifecycle notice until
    /// the child's nonblocking link can accept it, preserving wire order.
    pub(in super::super) fn defer_to_child(&mut self, pid: i32, frame: Vec<u8>) {
        self.outgoing.entry(pid).or_default().push_back(frame);
    }

    pub(in super::super) fn has_outgoing(&self, pid: i32) -> bool {
        self.outgoing
            .get(&pid)
            .is_some_and(|queue| !queue.is_empty())
    }

    pub(in super::super) fn outgoing_peers(&self) -> Vec<i32> {
        self.outgoing.keys().copied().collect()
    }

    pub(in super::super) fn front_outgoing(&self, pid: i32) -> Option<&[u8]> {
        self.outgoing.get(&pid)?.front().map(Vec::as_slice)
    }

    pub(in super::super) fn sent_outgoing(&mut self, pid: i32) {
        if let Some(queue) = self.outgoing.get_mut(&pid) {
            queue.pop_front();
            if queue.is_empty() {
                self.outgoing.remove(&pid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_release_cannot_retire_a_new_handler_generation() {
        let mut state = State::default();
        let port = Port::new(KObject::None);
        port.state.lock().unwrap().srights = 2;
        assert!(
            state
                .retain_handler(10, port.id, 4, Right::Send(port.clone()))
                .unwrap()
                .is_none()
        );
        let spare = state
            .retain_handler(10, port.id, 5, Right::Send(port.clone()))
            .unwrap()
            .unwrap();
        assert!(matches!(spare, Right::Send(ref p) if Arc::ptr_eq(p, &port)));
        port.state.lock().unwrap().srights -= 1;
        assert!(state.release_handler(10, port.id, 4).is_none());
        let retained = state.release_handler(10, port.id, 5).unwrap();
        assert!(matches!(retained, Right::Send(ref p) if Arc::ptr_eq(p, &port)));
        port.state.lock().unwrap().srights -= 1;
        assert_eq!(port.state.lock().unwrap().srights, 0);
        assert!(state.release_handler(10, port.id, 5).is_none());
    }

    #[test]
    fn target_handler_proxy_tracks_last_send_and_stale_death() {
        let mut state = State::default();
        let first = state.acquire_proxy(30, 1, 10);
        let second = state.acquire_proxy(30, 2, 11);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(state.proxy_identity(&first), Some((30, 2, 11)));
        assert_eq!(first.state.lock().unwrap().srights, 2);
        assert!(state.dead_proxy(30, 1).is_none());
        first.state.lock().unwrap().srights -= 1;
        assert!(state.last_proxy_send(&first).is_none());
        second.state.lock().unwrap().srights -= 1;
        assert_eq!(state.last_proxy_send(&second), Some((30, 2)));
        assert!(state.last_proxy_send(&second).is_none());
        let replacement = state.acquire_proxy(30, 3, 12);
        assert_ne!(replacement.id, first.id);
        assert!(state.dead_proxy(30, 2).is_none());
        assert!(Arc::ptr_eq(&state.dead_proxy(30, 3).unwrap(), &replacement));
    }

    #[test]
    fn handler_death_and_peer_loss_retire_only_their_exports() {
        let mut state = State::default();
        let port = Port::new(KObject::None);
        let other = Port::new(KObject::None);
        port.state.lock().unwrap().srights = 2;
        other.state.lock().unwrap().srights = 1;
        for (pid, generation) in [(10, 1), (11, 2)] {
            assert!(
                state
                    .retain_handler(pid, port.id, generation, Right::Send(port.clone()))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            state
                .retain_handler(10, other.id, 3, Right::Send(other.clone()))
                .unwrap()
                .is_none()
        );
        assert!(Arc::ptr_eq(
            &state.handler_port(10, port.id).unwrap(),
            &port
        ));
        port.state.lock().unwrap().dead = true;
        assert!(state.handler_port(10, port.id).is_none());
        let dead = state.dead_exports(port.id);
        assert_eq!(
            dead.iter()
                .map(|(pid, generation, _)| (*pid, *generation))
                .collect::<Vec<_>>(),
            vec![(10, 1), (11, 2)]
        );
        assert_eq!(state.drop_peer(10).len(), 1);
        assert!(state.drop_peer(11).is_empty());
        assert!(state.dead_exports(port.id).is_empty());
    }

    #[test]
    fn target_instances_wrap_within_the_reserved_namespace() {
        let mut state = State::default();
        state.next_target_instance = (1 << 63) - 1;
        assert_eq!(state.target_instance(0, |_| false), Some(u64::MAX));
        assert_eq!(
            state.target_instance(1, |id| id == 1 << 63),
            Some((1 << 63) | 1)
        );
    }

    #[test]
    fn reply_tokens_are_single_use_and_scoped_to_the_connection() {
        let mut state = State::default();
        let target = Port::new(KObject::None);
        target.state.lock().unwrap().sorights = 2;
        let token = state.retain_reply(Right::SendOnce(target.clone())).unwrap();
        assert!(state.retain_reply(Right::SendOnce(target.clone())).is_err());
        target.state.lock().unwrap().sorights -= 1;
        assert!(
            matches!(state.take_reply(token), Some(Right::SendOnce(ref p)) if Arc::ptr_eq(p, &target))
        );
        target.state.lock().unwrap().sorights -= 1;
        assert!(state.take_reply(token).is_none());

        let first = state.proxy_reply(10, token).unwrap();
        let second = state.proxy_reply(11, token).unwrap();
        assert!(state.proxy_reply(10, token).is_none());
        assert!(state.proxy_reply(10, 0).is_none());
        let first_port = first.port().unwrap().clone();
        let second_port = second.port().unwrap().clone();
        assert_eq!(state.take_proxy_reply(&first_port), Some((10, token)));
        assert!(state.take_proxy_reply(&first_port).is_none());
        assert!(state.cancel_proxy_reply(10, token).is_none());
        let dead = state.drop_peer_replies(11);
        assert_eq!(dead.len(), 1);
        assert!(Arc::ptr_eq(&dead[0], &second_port));
        assert!(state.drop_peer_replies(11).is_empty());
    }

    #[test]
    fn deferred_lifecycle_frames_keep_child_order_and_drop_with_the_peer() {
        let mut state = State::default();
        state.defer_to_child(10, vec![1]);
        state.defer_to_child(11, vec![2]);
        state.defer_to_child(10, vec![3]);
        assert_eq!(state.front_outgoing(10), Some(&[1][..]));
        state.sent_outgoing(10);
        assert_eq!(state.front_outgoing(10), Some(&[3][..]));
        assert!(state.has_outgoing(11));
        assert!(state.drop_peer(10).is_empty());
        assert!(!state.has_outgoing(10));
        assert_eq!(state.front_outgoing(11), Some(&[2][..]));
        state.sent_outgoing(11);
        assert!(!state.has_outgoing(11));
    }
}
