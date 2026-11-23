//! Extended-attribute values share the workspace inode's ownership and quota.

use super::{Budget, Error, MAX_BYTES};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub(in crate::user) const MAX_VALUE: usize = MAX_BYTES;

pub(in crate::user) enum Set {
    Upsert,
    Create,
    Replace,
}

#[derive(Debug)]
pub(in crate::user) struct Xattrs {
    values: Mutex<BTreeMap<Vec<u8>, Arc<[u8]>>>,
    budget: Arc<Mutex<Budget>>,
}

impl Xattrs {
    pub(super) fn new(budget: Arc<Mutex<Budget>>) -> Self {
        Self {
            values: Mutex::default(),
            budget,
        }
    }

    pub(in crate::user) fn get(&self, name: &[u8]) -> Result<Arc<[u8]>, Error> {
        self.values
            .lock()
            .map_err(|_| Error::Io)?
            .get(name)
            .cloned()
            .ok_or(Error::NotFound)
    }

    pub(in crate::user) fn list(&self) -> Result<Vec<u8>, Error> {
        let values = self.values.lock().map_err(|_| Error::Io)?;
        let mut names = Vec::new();
        for name in values.keys() {
            names.extend_from_slice(name);
            names.push(0);
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
        let mut values = self.values.lock().map_err(|_| Error::Io)?;
        let old = values.get(&name);
        match (rule, old) {
            (Set::Create, Some(_)) => return Err(Error::Exists),
            (Set::Replace, None) => return Err(Error::NotFound),
            _ => {}
        }
        let Some(data) = data else {
            return if old.is_some() {
                self.remove_locked(&mut values, &name)
            } else {
                Ok(())
            };
        };
        if offset.is_some() && data.is_empty() {
            return Ok(());
        }
        let old_len = old.map_or(0, |value| value.len());
        let new_len = match offset {
            Some(offset) => offset
                .checked_add(data.len())
                .ok_or(Error::NoSpace)?
                .max(old_len),
            None => data.len(),
        };
        let old_charge = old.map_or(0, |value| charge(&name, value.len()));
        if new_len > MAX_VALUE {
            return Err(Error::NoSpace);
        }
        let new_charge = charge(&name, new_len);
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let retained = budget.bytes - old_charge;
        if new_charge > MAX_BYTES - retained {
            return Err(Error::NoSpace);
        }
        let value = if let Some(offset) = offset {
            let mut bytes = vec![0; new_len];
            if let Some(old) = old {
                bytes[..old_len].copy_from_slice(old);
            }
            bytes[offset..offset + data.len()].copy_from_slice(&data);
            bytes
        } else {
            data
        };
        values.insert(name, value.into());
        budget.bytes = retained + new_charge;
        Ok(())
    }

    pub(in crate::user) fn remove(&self, name: &[u8]) -> Result<(), Error> {
        let mut values = self.values.lock().map_err(|_| Error::Io)?;
        self.remove_locked(&mut values, name)
    }

    fn remove_locked(
        &self,
        values: &mut BTreeMap<Vec<u8>, Arc<[u8]>>,
        name: &[u8],
    ) -> Result<(), Error> {
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let removed = values.remove(name).ok_or(Error::NotFound)?;
        budget.bytes -= charge(name, removed.len());
        Ok(())
    }
}

fn charge(name: &[u8], length: usize) -> usize {
    // Even an empty value reserves space for its name and collection entry.
    std::mem::size_of::<(Vec<u8>, Arc<[u8]>)>() + name.len() + 1 + length
}

impl Drop for Xattrs {
    fn drop(&mut self) {
        let values = self
            .values
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
