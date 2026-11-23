//! Extended-attribute values share the workspace inode's ownership and quota.

use super::{Budget, Error, MAX_BYTES};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub(in crate::user) const MAX_VALUE: usize = MAX_BYTES;
pub(in crate::user) const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork";

type Values = BTreeMap<Vec<u8>, Arc<[u8]>>;

#[derive(Debug, Default)]
struct State {
    values: Values,
    resource_handles: usize,
}

pub(in crate::user) enum Set {
    Upsert,
    Create,
    Replace,
    CreateAndReplace,
}

#[derive(Debug)]
pub(in crate::user) struct Xattrs {
    state: Mutex<State>,
    budget: Arc<Mutex<Budget>>,
}

impl Xattrs {
    pub(super) fn new(budget: Arc<Mutex<Budget>>) -> Self {
        Self {
            state: Mutex::default(),
            budget,
        }
    }

    pub(in crate::user) fn get(&self, name: &[u8]) -> Result<Arc<[u8]>, Error> {
        self.state
            .lock()
            .map_err(|_| Error::Io)?
            .values
            .get(name)
            .filter(|value| visible(name, value))
            .cloned()
            .ok_or(Error::NotFound)
    }

    pub(in crate::user) fn list(&self) -> Result<Vec<u8>, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        let mut names = Vec::new();
        for (name, value) in &state.values {
            if visible(name, value) {
                names.extend_from_slice(name);
                names.push(0);
            }
        }
        Ok(names)
    }

    pub(in crate::user) fn set(
        &self,
        name: Vec<u8>,
        data: Option<Vec<u8>>,
        offset: Option<usize>,
        rule: Set,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        let old = state
            .values
            .get(&name)
            .filter(|value| visible(&name, value));
        match (rule, old) {
            (Set::Create | Set::CreateAndReplace, Some(_)) => return Err(Error::Exists),
            (Set::Replace | Set::CreateAndReplace, None) => return Err(Error::NotFound),
            _ => {}
        }
        let Some(data) = data else {
            return if old.is_some() {
                self.remove_locked(&mut state.values, &name)
            } else {
                Ok(())
            };
        };
        if let Some(offset) = offset {
            if !data.is_empty() {
                self.write_at(&mut state.values, name, Some(offset), &data)?;
            }
        } else {
            self.replace_locked(&mut state.values, name, data.len(), |_| data)?;
        }
        Ok(())
    }

    /// An empty named fork remains addressable, but has no visible xattr.
    pub(in crate::user) fn resource_value(&self) -> Result<Arc<[u8]>, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        state
            .values
            .get(RESOURCE_FORK)
            .cloned()
            .ok_or(Error::NotFound)
    }

    pub(in crate::user) fn open_resource(
        &self,
        create: bool,
        exclusive: bool,
        truncate: bool,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        let exists = state.values.contains_key(RESOURCE_FORK);
        if exists && exclusive {
            return Err(Error::Exists);
        }
        if !exists && !create {
            return Err(Error::NotFound);
        }
        if !exists || truncate {
            self.replace_locked(&mut state.values, RESOURCE_FORK.to_vec(), 0, |_| Vec::new())?;
        }
        state.resource_handles += 1;
        Ok(())
    }

    pub(in crate::user) fn close_resource(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.resource_handles -= 1;
    }

    pub(in crate::user) fn write_resource(
        &self,
        offset: Option<u64>,
        data: &[u8],
    ) -> Result<u64, Error> {
        let offset = offset
            .map(usize::try_from)
            .transpose()
            .map_err(|_| Error::NoSpace)?;
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        self.write_at(&mut state.values, RESOURCE_FORK.to_vec(), offset, data)
            .map(|end| end as u64)
    }

    pub(in crate::user) fn resize_resource(&self, size: u64) -> Result<(), Error> {
        let size = usize::try_from(size).map_err(|_| Error::NoSpace)?;
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        self.replace_locked(&mut state.values, RESOURCE_FORK.to_vec(), size, |old| {
            let mut bytes = vec![0; size];
            if let Some(old) = old {
                let copy = old.len().min(size);
                bytes[..copy].copy_from_slice(&old[..copy]);
            }
            bytes
        })
    }

    pub(in crate::user) fn remove(&self, name: &[u8]) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        if name == RESOURCE_FORK {
            let value = state.values.get(name).ok_or(Error::NotFound)?;
            if !visible(name, value) {
                return Err(Error::NotFound);
            }
            if state.resource_handles != 0 {
                return Err(Error::Busy);
            }
        }
        self.remove_locked(&mut state.values, name)
    }

    fn write_at(
        &self,
        values: &mut Values,
        name: Vec<u8>,
        offset: Option<usize>,
        data: &[u8],
    ) -> Result<usize, Error> {
        let length = values.get(&name).map_or(0, |value| value.len());
        let offset = offset.unwrap_or(length);
        let end = offset.checked_add(data.len()).ok_or(Error::NoSpace)?;
        let size = end.max(length);
        self.replace_locked(values, name, size, |old| {
            let mut bytes = vec![0; size];
            if let Some(old) = old {
                bytes[..length].copy_from_slice(old);
            }
            bytes[offset..end].copy_from_slice(data);
            bytes
        })?;
        Ok(end)
    }

    fn replace_locked(
        &self,
        values: &mut Values,
        name: Vec<u8>,
        size: usize,
        update: impl FnOnce(Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Error> {
        if size > MAX_VALUE {
            return Err(Error::NoSpace);
        }
        let old = values.get(&name);
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let retained = budget.bytes - old.map_or(0, |value| charge(&name, value.len()));
        let new_charge = charge(&name, size);
        if new_charge > MAX_BYTES - retained {
            return Err(Error::NoSpace);
        }
        let value = update(old.map(AsRef::as_ref));
        values.insert(name, value.into());
        budget.bytes = retained + new_charge;
        Ok(())
    }

    fn remove_locked(&self, values: &mut Values, name: &[u8]) -> Result<(), Error> {
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let removed = values.remove(name).ok_or(Error::NotFound)?;
        budget.bytes -= charge(name, removed.len());
        Ok(())
    }
}

fn visible(name: &[u8], value: &[u8]) -> bool {
    name != RESOURCE_FORK || !value.is_empty()
}

fn charge(name: &[u8], length: usize) -> usize {
    // Even an empty value reserves space for its name and collection entry.
    std::mem::size_of::<(Vec<u8>, Arc<[u8]>)>() + name.len() + 1 + length
}

impl Drop for Xattrs {
    fn drop(&mut self) {
        let values = &self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values;
        if !values.is_empty()
            && let Ok(mut budget) = self.budget.lock()
        {
            budget.bytes -= values
                .iter()
                .map(|(name, value)| charge(name, value.len()))
                .sum::<usize>();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_failure_keeps_the_old_value_and_inode_drop_releases_quota() {
        let budget = Arc::new(Mutex::new(Budget {
            bytes: MAX_BYTES - charge(b"name", 2),
            ..Budget::default()
        }));
        let attrs = Xattrs::new(budget.clone());
        attrs
            .set(b"name".to_vec(), Some(vec![7, 8]), None, Set::Create)
            .unwrap();
        assert_eq!(budget.lock().unwrap().bytes, MAX_BYTES);
        assert_eq!(
            attrs.set(b"name".to_vec(), Some(vec![9]), Some(2), Set::Replace),
            Err(Error::NoSpace)
        );
        assert_eq!(attrs.get(b"name").unwrap().as_ref(), &[7, 8]);
        assert_eq!(attrs.list().unwrap(), b"name\0");
        drop(attrs);
        assert_eq!(budget.lock().unwrap().bytes, MAX_BYTES - charge(b"name", 2));
    }
}
