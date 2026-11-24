//! Extended-attribute values share the workspace inode's ownership and quota.

use super::{Budget, DARWIN_BLOCK_BYTES, Error, MAX_BYTES};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::{io, os::unix::fs::FileExt};

#[cfg(target_os = "macos")]
mod darwin_resource;

pub(in crate::user) const MAX_VALUE: usize = MAX_BYTES;
pub(in crate::user) const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork";

pub(super) type Values = BTreeMap<Vec<u8>, Arc<[u8]>>;

type LiveValues = BTreeMap<Vec<u8>, Value>;

#[derive(Debug)]
enum Value {
    Bytes(Arc<[u8]>),
    #[cfg(target_os = "macos")]
    Resource(Box<darwin_resource::Fork>),
}

impl Value {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(data) => data.len(),
            #[cfg(target_os = "macos")]
            Self::Resource(fork) => fork.len,
        }
    }

    fn bytes(&self) -> Result<Arc<[u8]>, Error> {
        match self {
            Self::Bytes(data) => Ok(data.clone()),
            #[cfg(target_os = "macos")]
            Self::Resource(fork) => {
                let mut data = vec![0; fork.len];
                fork.file
                    .read_exact_at(&mut data, 0)
                    .map_err(|_| Error::Io)?;
                Ok(data.into())
            }
        }
    }

    fn charge(&self, name: &[u8]) -> usize {
        let reserved = match self {
            Self::Bytes(_) => 0,
            #[cfg(target_os = "macos")]
            Self::Resource(fork) => fork.reservation,
        };
        charge(name, self.len()) + reserved
    }

    fn visible(&self, name: &[u8]) -> bool {
        name != RESOURCE_FORK || self.len() != 0
    }
}

#[derive(Debug, Default)]
struct State {
    values: LiveValues,
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

    pub(super) fn clone_values(&self) -> Result<(Values, usize), Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        let values: Values = state
            .values
            .iter()
            .filter(|(name, value)| value.visible(name))
            .map(|(name, value)| Ok((name.clone(), value.bytes()?)))
            .collect::<Result<_, Error>>()?;
        let bytes = values
            .iter()
            .map(|(name, value)| charge(name, value.len()))
            .sum();
        Ok((values, bytes))
    }

    /// The caller reserves the charge for these values before publication.
    pub(super) fn from_charged_values(values: Values, budget: Arc<Mutex<Budget>>) -> Self {
        Self {
            state: Mutex::new(State {
                values: values
                    .into_iter()
                    .map(|(name, data)| (name, Value::Bytes(data)))
                    .collect(),
                resource_handles: 0,
            }),
            budget,
        }
    }

    pub(in crate::user) fn get(&self, name: &[u8]) -> Result<Arc<[u8]>, Error> {
        self.state
            .lock()
            .map_err(|_| Error::Io)?
            .values
            .get(name)
            .filter(|value| value.visible(name))
            .ok_or(Error::NotFound)?
            .bytes()
    }

    pub(in crate::user) fn list(&self) -> Result<Vec<u8>, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        let mut names = Vec::new();
        for (name, value) in &state.values {
            if value.visible(name) {
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
        let old = state.values.get(&name).filter(|value| value.visible(&name));
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
                self.write_at(&mut state.values, name, Some(offset), &data, true)?;
            }
        } else {
            self.replace_locked(&mut state.values, name, data.len(), |_| data)?;
        }
        Ok(())
    }

    /// An empty named fork remains addressable, but has no visible xattr.
    pub(in crate::user) fn resource_size(&self) -> Result<u64, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        state
            .values
            .get(RESOURCE_FORK)
            .map(|value| value.len() as u64)
            .ok_or(Error::NotFound)
    }

    pub(in crate::user) fn resource_stat(&self) -> Result<(u64, i64), Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        let value = state.values.get(RESOURCE_FORK).ok_or(Error::NotFound)?;
        let size = value.len() as u64;
        let blocks = match value {
            Value::Bytes(_) if cfg!(target_os = "macos") => {
                (size.div_ceil(DARWIN_BLOCK_BYTES as u64) * (DARWIN_BLOCK_BYTES / 512) as u64)
                    as i64
            }
            Value::Bytes(_) => size.div_ceil(512) as i64,
            #[cfg(target_os = "macos")]
            Value::Resource(fork) => fork.blocks().map_err(|_| Error::Io)?,
        };
        Ok((size, blocks))
    }

    pub(in crate::user) fn read_resource(
        &self,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        let value = state.values.get(RESOURCE_FORK).ok_or(Error::NotFound)?;
        let len = value.len() as u64;
        let start = len.min(offset) as usize;
        let count = out.len().min(len as usize - start);
        match value {
            Value::Bytes(bytes) => out[..count].copy_from_slice(&bytes[start..start + count]),
            #[cfg(target_os = "macos")]
            Value::Resource(fork) => fork
                .file
                .read_exact_at(&mut out[..count], start as u64)
                .map_err(|_| Error::Io)?,
        }
        Ok(count)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn resource_parent_blocks(&self) -> Result<i64, Error> {
        let state = self.state.lock().map_err(|_| Error::Io)?;
        match state.values.get(RESOURCE_FORK) {
            Some(Value::Resource(fork)) => fork.parent_blocks().map_err(|_| Error::Io),
            _ => Ok(0),
        }
    }

    #[cfg(target_os = "macos")]
    pub(in crate::user) fn preallocate_resource(
        &self,
        flags: u32,
        length: u64,
    ) -> (io::Result<()>, i64) {
        let allocate = || {
            let mut state = self.state.lock().map_err(|_| io::Error::other(Error::Io))?;
            let entry = state
                .values
                .get_mut(RESOURCE_FORK)
                .ok_or_else(|| io::Error::other(Error::NotFound))?;
            let mut budget = self
                .budget
                .lock()
                .map_err(|_| io::Error::other(Error::Io))?;
            let request = super::darwin_allocation::Request::new(flags, length, budget.bytes)?;
            if let Value::Bytes(bytes) = entry {
                *entry = Value::Resource(Box::new(darwin_resource::Fork::new(bytes)?));
            }
            let Value::Resource(fork) = entry else {
                unreachable!("resource fork backing initialized");
            };
            let (result, allocated, credit) = request.reserve(&fork.file);
            fork.reservation += credit;
            budget.bytes += credit;
            Ok((result, allocated))
        };
        allocate().unwrap_or_else(|error| (Err(error), 0))
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
        if !exists {
            self.replace_locked(&mut state.values, RESOURCE_FORK.to_vec(), 0, |_| Vec::new())?;
        } else if truncate {
            self.resize_resource_locked(&mut state.values, 0)?;
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
        self.write_at(
            &mut state.values,
            RESOURCE_FORK.to_vec(),
            offset,
            data,
            false,
        )
        .map(|end| end as u64)
    }

    pub(in crate::user) fn resize_resource(&self, size: u64) -> Result<(), Error> {
        let size = usize::try_from(size).map_err(|_| Error::NoSpace)?;
        let mut state = self.state.lock().map_err(|_| Error::Io)?;
        self.resize_resource_locked(&mut state.values, size)
    }

    fn resize_resource_locked(&self, values: &mut LiveValues, size: usize) -> Result<(), Error> {
        #[cfg(target_os = "macos")]
        if let Some(Value::Resource(fork)) = values.get_mut(RESOURCE_FORK) {
            return self
                .mutate_native_fork(fork, size, true, |fork| fork.file.set_len(size as u64))?
                .map_err(|_| Error::Io);
        }
        self.replace_locked(values, RESOURCE_FORK.to_vec(), size, |old| {
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
            if !value.visible(name) {
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
        values: &mut LiveValues,
        name: Vec<u8>,
        offset: Option<usize>,
        data: &[u8],
        _xattr: bool,
    ) -> Result<usize, Error> {
        let length = values.get(&name).map_or(0, |value| value.len());
        let offset = offset.unwrap_or(length);
        let end = offset.checked_add(data.len()).ok_or(Error::NoSpace)?;
        let size = end.max(length);
        #[cfg(target_os = "macos")]
        if let Some(Value::Resource(fork)) = values.get_mut(&name) {
            self.mutate_native_fork(fork, size, true, |fork| {
                if _xattr {
                    fork.write_xattr(offset as u32, data)
                } else {
                    fork.file.write_all_at(data, offset as u64)
                }
            })?
            .map_err(|_| Error::Io)?;
            return Ok(end);
        }
        #[cfg(target_os = "macos")]
        if _xattr && name == RESOURCE_FORK && size <= MAX_VALUE {
            let old = values.get(&name).map(Value::bytes).transpose()?;
            // Calling setxattr on the native inode commits the fork to the
            // parent's allocation count. Keep that state across a later
            // reserve. The bounded memory path still serves xattrs when the
            // host temporary volume cannot create a named fork.
            if let Ok(mut fork) = darwin_resource::Fork::new(old.as_deref().unwrap_or_default()) {
                let result = self.mutate_native_fork(&mut fork, size, old.is_some(), |fork| {
                    fork.write_xattr(offset as u32, data)
                })?;
                values.insert(name, Value::Resource(Box::new(fork)));
                result.map_err(|_| Error::Io)?;
                return Ok(end);
            }
        }
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

    #[cfg(target_os = "macos")]
    fn mutate_native_fork(
        &self,
        fork: &mut darwin_resource::Fork,
        size: usize,
        had_value: bool,
        update: impl FnOnce(&darwin_resource::Fork) -> io::Result<()>,
    ) -> Result<io::Result<()>, Error> {
        if size > MAX_VALUE {
            return Err(Error::NoSpace);
        }
        let reservation_after = |length| {
            if length < fork.len {
                0
            } else {
                fork.reservation.saturating_sub(length - fork.len)
            }
        };
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let prior_charge = if had_value {
            charge(RESOURCE_FORK, fork.len) + fork.reservation
        } else {
            0
        };
        let other = budget.bytes - prior_charge;
        if charge(RESOURCE_FORK, size) + reservation_after(size) > MAX_BYTES - other {
            return Err(Error::NoSpace);
        }
        let result = update(fork);
        // A short native write can extend the fork before returning an error.
        // Reconcile the logical size and the charge from the live descriptor.
        let length = fork.file.metadata().map_err(|_| Error::Io)?.len() as usize;
        fork.reservation = reservation_after(length);
        fork.len = length;
        budget.bytes = other + charge(RESOURCE_FORK, fork.len) + fork.reservation;
        Ok(result)
    }

    fn replace_locked(
        &self,
        values: &mut LiveValues,
        name: Vec<u8>,
        size: usize,
        update: impl FnOnce(Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Error> {
        if size > MAX_VALUE {
            return Err(Error::NoSpace);
        }
        let old = values.get(&name);
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let retained = budget.bytes - old.map_or(0, |value| value.charge(&name));
        let new_charge = charge(&name, size);
        if new_charge > MAX_BYTES - retained {
            return Err(Error::NoSpace);
        }
        let old = old.map(Value::bytes).transpose()?;
        let value = update(old.as_deref());
        values.insert(name, Value::Bytes(value.into()));
        budget.bytes = retained + new_charge;
        Ok(())
    }

    fn remove_locked(&self, values: &mut LiveValues, name: &[u8]) -> Result<(), Error> {
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let removed = values.remove(name).ok_or(Error::NotFound)?;
        budget.bytes -= removed.charge(name);
        Ok(())
    }
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
                .map(|(name, value)| value.charge(name))
                .sum::<usize>();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn resource_xattr_allocation_is_retained_when_reserving_the_named_fork() {
        let budget = Arc::new(Mutex::new(Budget::default()));
        let attrs = Xattrs::new(budget.clone());
        attrs
            .set(
                RESOURCE_FORK.to_vec(),
                Some(b"old".to_vec()),
                Some(4096),
                Set::Upsert,
            )
            .unwrap();
        assert_eq!(attrs.resource_stat(), Ok((4099, 16)));
        assert_eq!(attrs.resource_parent_blocks(), Ok(16));
        let prior = budget.lock().unwrap().bytes;
        let (outcome, allocated) = attrs.preallocate_resource(libc::F_ALLOCATEALL, 1);
        outcome.unwrap();
        assert_eq!(allocated, 1);
        assert_eq!(attrs.resource_stat(), Ok((4099, 24)));
        assert_eq!(attrs.resource_parent_blocks(), Ok(24));
        assert_eq!(budget.lock().unwrap().bytes, prior + 4096);

        attrs.open_resource(false, false, false).unwrap();
        let mut bytes = [0; 3];
        assert_eq!(attrs.read_resource(4096, &mut bytes), Ok(3));
        assert_eq!(&bytes, b"old");
        assert_eq!(attrs.remove(RESOURCE_FORK), Err(Error::Busy));
        attrs.close_resource();
        attrs.remove(RESOURCE_FORK).unwrap();
        assert_eq!(budget.lock().unwrap().bytes, 0);
    }

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
