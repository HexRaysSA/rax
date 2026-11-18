//! Once-only process ETW notification Event ownership.
use super::{ObjId, Object, Objects};

impl Objects {
    /// Opens a distinct dormant provider resource with the measured grant.
    /// Repeated GUIDs are distinct resources; final close and drain own lifetime.
    /// Expected O(1) object insertion, O(H) lowest-free handle selection and
    /// O(1) retained state per registration (160 B request plus table entries).
    pub(crate) fn register_etw_provider(&mut self, request: Box<[u8; 160]>) -> Option<u32> {
        let id = self.try_create(Object::EtwRegistration {
            request,
            traits: None,
            binary_tracking_class: None,
            descriptor_type: None,
        })?;
        match self.open_access(id, false, 0x804) {
            Some(handle) => Some(handle),
            None => {
                self.release(id);
                None
            }
        }
    }
    /// Pins the first Event without changing its type or signal state.
    /// The caller validates handle/type/access before the busy check.
    /// Expected O(1) time and O(1) retained state, independent of WNF.
    pub(crate) fn register_etw_event(&mut self, id: ObjId) -> Result<bool, &'static str> {
        if self.etw_event.is_some() {
            return Ok(false);
        }
        if !matches!(self.obj(id), Some(Object::Event { .. })) {
            return Err("ETW notification object is not an Event");
        }
        self.retain_many(&[id])?;
        self.etw_event = Some(id);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_etw_registration_identifier_exhaustion_preserves_objects_and_handles() {
        let mut objects = Objects::default();
        let existing = objects.insert(Object::Event {
            manual: true,
            signaled: 1,
        });
        let baseline = (objects.handle_count(), objects.iter().count());
        objects.next = u32::MAX;
        assert_eq!(objects.register_etw_provider(Box::new([0xA5; 160])), None);
        assert_eq!((objects.handle_count(), objects.iter().count()), baseline);
        assert!(matches!(
            objects.get(existing.into()),
            Some(Object::Event {
                manual: true,
                signaled: 1
            })
        ));
        assert_eq!(objects.next, u32::MAX);
        objects.drain().for_each(drop);
        assert_eq!(objects.handle_count(), 0);
        assert_eq!(objects.iter().count(), 0);
    }

    #[test]
    fn native_etw_notification_reference_overflow_and_drain_are_transactional() {
        let mut objects = Objects::default();
        let id = objects.create(Object::Event {
            manual: true,
            signaled: 1,
        });
        objects.objs.get_mut(&id).unwrap().refs = u32::MAX;
        assert!(objects.register_etw_event(id).is_err());
        assert_eq!(objects.etw_event, None);
        assert_eq!(objects.objs[&id].refs, u32::MAX);
        objects.objs.get_mut(&id).unwrap().refs = 0;
        assert_eq!(objects.register_etw_event(id), Ok(true));
        assert_eq!(objects.objs[&id].refs, 1);
        assert_eq!(objects.register_etw_event(id), Ok(false));
        assert_eq!(objects.objs[&id].refs, 1);
        assert_eq!(objects.register_wnf_event(id), Ok(true));
        assert_eq!(objects.objs[&id].refs, 2);
        assert!(matches!(
            objects.obj(id),
            Some(Object::Event {
                manual: true,
                signaled: 1
            })
        ));
        objects.drain().for_each(drop);
        assert_eq!((objects.etw_event, objects.wnf_event), (None, None));
        assert_eq!(objects.iter().count(), 0);
    }
}
