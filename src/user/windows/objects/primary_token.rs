//! Process-owned primary-token identity, independent of caller handles.
use super::{Object, Objects};

impl Objects {
    /// Open with a previously validated grant. O(H) time for H live handles;
    /// only the first successful open creates the process-owned token object.
    pub(crate) fn open_primary_token(&mut self, grant: u32, inherit: bool) -> Option<u32> {
        if let Some(id) = self.primary_token {
            return self.open_access(id, inherit, grant);
        }
        let id = self.try_create(Object::PrimaryToken)?;
        if self.retain_many(&[id]).is_err() {
            self.release(id);
            return None;
        }
        let Some(handle) = self.open_access(id, inherit, grant) else {
            self.release(id);
            return None;
        };
        self.primary_token = Some(id);
        Some(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_process_token_handles_share_identity_and_survive_final_close() {
        let mut objects = Objects::default();
        let a = objects.open_primary_token(8, false).unwrap();
        let b = objects.open_primary_token(2, true).unwrap();
        let id = objects.id(a.into()).unwrap();
        assert_eq!(objects.id(b.into()), Some(id));
        assert_eq!(objects.access(a.into()), Some(8));
        assert_eq!(objects.access(b.into()), Some(2));
        assert_eq!(objects.flags(a.into()), Some(0));
        assert_eq!(objects.flags(b.into()), Some(1));
        objects.close(a.into()).unwrap();
        assert!(matches!(objects.get(b.into()), Some(Object::PrimaryToken)));
        objects.close(b.into()).unwrap();
        assert!(matches!(objects.obj(id), Some(Object::PrimaryToken)));
        let c = objects.open_primary_token(1, false).unwrap();
        assert_eq!(objects.id(c.into()), Some(id));
        assert_eq!(objects.access(c.into()), Some(1));
        assert_eq!(objects.drain().count(), 1);
        assert_eq!(objects.primary_token, None);
        assert_eq!(objects.handle_count(), 0);
        let d = objects.open_primary_token(8, false).unwrap();
        assert_ne!(objects.id(d.into()), Some(id));
    }

    #[test]
    fn native_process_token_identifier_exhaustion_has_no_birth() {
        let mut objects = Objects::default();
        objects.next = u32::MAX;
        assert_eq!(objects.open_primary_token(8, false), None);
        assert_eq!(objects.primary_token, None);
        assert_eq!(objects.handle_count(), 0);
        assert_eq!(objects.iter().count(), 0);
    }

    #[test]
    fn native_process_token_reference_exhaustion_preserves_existing_owner() {
        let mut objects = Objects::default();
        let handle = objects.open_primary_token(8, false).unwrap();
        let id = objects.id(handle.into()).unwrap();
        objects.objs.get_mut(&id).unwrap().refs = u32::MAX;
        assert_eq!(objects.open_primary_token(2, false), None);
        assert_eq!(objects.handle_count(), 1);
        assert_eq!(objects.primary_token, Some(id));
        assert_eq!(objects.objs[&id].refs, u32::MAX);
        assert_eq!(objects.access(handle.into()), Some(8));
    }
}
