//! Process notification ownership; delivery requires separate WNF state services.
use super::{ObjId, Object, Objects};
use crate::user::windows::wnf::{Catalog, Name, Permission};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subscription {
    pub(crate) id: u64,
    pub(crate) change_stamp: u32,
    pub(crate) event_mask: u32,
    /// Queued metadata survives an absent notification Event and manual reset.
    /// Delivery/acknowledgement is a separate, currently unsupported service.
    pub(crate) pending_mask: u32,
}
#[derive(Debug, Default)]
pub(super) struct Subscriptions {
    catalog: Option<Catalog>,
    pub(super) records: BTreeMap<u64, Subscription>,
    next: u64,
}
fn levels(mask: u32) -> u32 {
    8 | if mask & 1 != 0 {
        2
    } else if mask & 0x0E != 0 {
        4
    } else {
        0
    }
}

impl Objects {
    pub(crate) fn wnf_queries(&self) -> Option<std::sync::Arc<crate::user::windows::wnf::Queries>> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(Catalog::queries)
    }

    pub(crate) fn primary_token_subject(
        &self,
    ) -> Option<std::sync::Arc<crate::user::windows::security::Subject>> {
        self.primary_token_adjusted.clone().or_else(|| {
            self.wnf_subscriptions
                .catalog
                .as_ref()
                .and_then(Catalog::primary_subject)
        })
    }
    /// Primary subject captured with the selected immutable native catalog.
    /// An absent capture is distinct from a non-AppContainer subject.
    pub(crate) fn primary_token_app_container(&self) -> Option<bool> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(Catalog::primary_app_container)
    }
    pub(crate) fn primary_token_access(
        &self,
    ) -> Option<crate::user::windows::security::token::Access> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(Catalog::primary_token_access)
    }

    pub(crate) fn select_wnf_catalog(&mut self, catalog: Catalog) {
        self.primary_token_adjusted = None;
        self.wnf_subscriptions.catalog = Some(catalog);
    }

    pub(crate) fn primary_token_scalar(
        &self,
        class: u32,
    ) -> Option<crate::user::windows::security::token::scalars::CapturedScalar> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(|catalog| catalog.primary_token_scalar(class))
    }

    pub(crate) fn primary_token_bno(
        &self,
    ) -> Option<std::sync::Arc<crate::user::windows::security::token::bno::Isolation>> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(Catalog::primary_token_bno)
    }

    pub(crate) fn primary_token_session_id(&self) -> Option<u32> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .and_then(Catalog::primary_token_session_id)
    }
    pub(crate) fn wnf_permission(&self, name: u64, mask: u32) -> Option<Permission> {
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .map(|catalog| catalog.permission(name, mask))
    }
    pub(crate) fn wnf_subscription(&self, name: u64) -> Option<&Subscription> {
        self.wnf_subscriptions.records.get(&name)
    }
    pub(crate) fn wnf_subscription_stamp(
        &self,
        name: u64,
        mask: u32,
    ) -> Result<Option<u32>, &'static str> {
        if !Name::decode(name).is_some_and(|parsed| parsed.scope == 0) {
            return Ok(None);
        }
        if mask & 0x0E != 0 {
            return Err(
                "System WNF subscriber-level notifications require uncaptured shared state",
            );
        }
        if mask & 1 == 0 {
            return Ok(None);
        }
        self.wnf_subscriptions
            .catalog
            .as_ref()
            .ok_or("System WNF subscription metadata was not selected")?
            .subscription_stamp(name)
    }
    /// O(log N) time/O(N) retained subscriptions, bounded by selected names.
    /// IDs are opaque private generations; no host subscription is created.
    pub(crate) fn subscribe_wnf(
        &mut self,
        name: u64,
        stamp: u32,
        mask: u32,
    ) -> Result<u64, &'static str> {
        if self.wnf_permission(name, mask) != Some(Permission::Allowed) || mask & !0x1F != 0 {
            return Err("WNF subscription was not admitted");
        }
        let selected_stamp = self.wnf_subscription_stamp(name, mask)?;
        let previous = self.wnf_subscriptions.records.get(&name);
        let old_mask = previous.map_or(0, |sub| sub.event_mask);
        let old_levels = previous.map_or(0, |sub| levels(sub.event_mask));
        let retained = previous.map_or(0, |sub| sub.pending_mask & mask);
        let arrived = mask & levels(mask) & (!old_mask | !old_levels)
            | if selected_stamp.is_some_and(|selected| selected != stamp) && retained == 0 {
                1
            } else {
                0
            };
        let pending = retained | arrived;
        let id = if let Some(previous) = previous {
            previous.id
        } else {
            self.wnf_subscriptions
                .next
                .checked_add(1)
                .ok_or("WNF subscription generation exhausted")?
        };
        // A pinned registration must still designate an Event. Validate before
        // publishing a generation/record so a corrupted owner cannot half-commit.
        if let Some(event) = self.wnf_event
            && !matches!(self.obj(event), Some(Object::Event { .. }))
        {
            return Err("WNF notification Event ownership is inconsistent");
        }
        self.wnf_subscriptions.next = self.wnf_subscriptions.next.max(id);
        self.wnf_subscriptions.records.insert(
            name,
            Subscription {
                id,
                change_stamp: stamp,
                event_mask: mask,
                pending_mask: pending,
            },
        );
        if arrived != 0
            && let Some(event) = self.wnf_event
        {
            let Some(Object::Event { signaled, .. }) = self.obj_mut(event) else {
                unreachable!()
            };
            *signaled = 1;
        }
        Ok(id)
    }
    pub(crate) fn unsubscribe_wnf(&mut self, name: u64) -> bool {
        // Native unsubscribe discards its queued metadata but does not reset
        // the sticky notification Event; the completion service owns that step.
        self.wnf_subscriptions.records.remove(&name).is_some()
    }
    /// Atomically pins the first registration. The service checks type/grants
    /// before this busy check. Expected O(1) time and O(1) extra space.
    pub(crate) fn register_wnf_event(&mut self, id: ObjId) -> Result<bool, &'static str> {
        if self.wnf_event.is_some() {
            return Ok(false);
        }
        if !matches!(self.obj(id), Some(Object::Event { .. })) {
            return Err("WNF notification object is not an Event");
        }
        self.retain_many(&[id])?;
        self.wnf_event = Some(id);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_wnf_subscription_generation_exhaustion_and_owner_failure_are_transactional() {
        let name = 0x41911A28A3BC10B5;
        let mut objects = Objects::default();
        objects.select_wnf_catalog(crate::user::windows::wnf::tests::catalog());
        let event = objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        assert_eq!(objects.register_wnf_event(event), Ok(true));
        objects.wnf_subscriptions.next = u64::MAX;
        assert!(objects.subscribe_wnf(name, 0, 4).is_err());
        assert!(objects.wnf_subscription(name).is_none());
        assert!(matches!(
            objects.obj(event),
            Some(Object::Event { signaled: 0, .. })
        ));
        objects.wnf_subscriptions.next = 0;
        let id = objects.subscribe_wnf(name, 0, 4).unwrap();
        let before = objects.wnf_subscription(name).unwrap().clone();
        let owned = objects.objs.remove(&event).unwrap();
        assert!(objects.subscribe_wnf(name, 1, 8).is_err());
        assert_eq!(objects.wnf_subscription(name).unwrap(), &before);
        assert_eq!(objects.wnf_subscriptions.next, id);
        objects.objs.insert(event, owned);
        objects.wnf_subscriptions.next = u64::MAX;
        assert_eq!(objects.subscribe_wnf(name, 1, 8), Ok(id));
        assert_eq!(objects.wnf_subscription(name).unwrap().pending_mask, 8);
        objects.drain().for_each(drop);
        assert!(objects.wnf_subscription(name).is_none());
    }
    #[test]
    fn native_wnf_process_event_reference_overflow_is_transactional() {
        let mut objects = Objects::default();
        let id = objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        objects.objs.get_mut(&id).unwrap().refs = u32::MAX;
        assert!(objects.register_wnf_event(id).is_err());
        assert_eq!(objects.wnf_event, None);
        assert_eq!(objects.objs[&id].refs, u32::MAX);
        objects.objs.get_mut(&id).unwrap().refs = 0;
        assert_eq!(objects.register_wnf_event(id), Ok(true));
        assert_eq!(objects.wnf_event, Some(id));
        assert_eq!(objects.objs[&id].refs, 1);
        assert_eq!(objects.register_wnf_event(id), Ok(false));
        assert_eq!(objects.objs[&id].refs, 1);
        objects.drain().for_each(drop);
        assert_eq!(objects.wnf_event, None);
    }
}
