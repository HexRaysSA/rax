//! Pending registry requests retain event objects, never caller handle values.
use super::{ObjId, Object, Objects};

#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistryCompletion {
    /// None denotes REG_NOTIFY_THREAD_AGNOSTIC, which does not use an IOSB.
    pub owner: Option<u32>,
    pub event: Option<ObjId>,
    pub io: Option<u64>,
    pub apc: Option<(u64, u64)>,
}

#[derive(Debug, Default)]
pub(super) struct Notifications {
    pending: Vec<(ObjId, RegistryCompletion)>,
    ready: Vec<RegistryCompletion>,
}

impl Objects {
    pub(crate) fn register_registry_notification(
        &mut self,
        key: ObjId,
        completion: RegistryCompletion,
    ) -> Result<(), &'static str> {
        if !matches!(self.obj(key), Some(Object::Key(_)))
            || completion
                .event
                .is_some_and(|id| !matches!(self.obj(id), Some(Object::Event { .. })))
        {
            return Err("invalid registry notification object");
        }
        let state = &mut self.registry_notifications;
        state
            .pending
            .try_reserve(1)
            .map_err(|_| "registry notification allocation failed")?;
        // Every pending request can retire without allocating during close.
        state
            .ready
            .try_reserve(state.pending.len() + 1)
            .map_err(|_| "registry completion allocation failed")?;
        if let Some(event) = completion.event {
            self.retain_many(&[event])?;
            let Some(Object::Event { signaled, .. }) = self.obj_mut(event) else {
                unreachable!("validated and retained event")
            };
            *signaled = 0;
        }
        self.registry_notifications.pending.push((key, completion));
        Ok(())
    }

    pub(super) fn retire_registry_key(&mut self, key: ObjId) {
        let Notifications { pending, ready } = &mut self.registry_notifications;
        pending.retain(|&(watched, completion)| {
            if watched == key {
                ready.push(completion);
                false
            } else {
                true
            }
        });
    }

    pub(crate) fn retire_registry_thread(&mut self, tid: u32) {
        let Notifications { pending, ready } = &mut self.registry_notifications;
        pending.retain(|&(_, completion)| {
            if completion.owner == Some(tid) {
                ready.push(completion);
                false
            } else {
                true
            }
        });
    }

    pub(crate) fn take_registry_completions(&mut self) -> Vec<RegistryCompletion> {
        // Drain retains the capacity reserved for still-pending requests.
        self.registry_notifications.ready.drain(..).collect()
    }
}
