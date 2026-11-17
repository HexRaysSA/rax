//! Owned CPU/syscall callback capability. It retains neither the endpoint nor
//! an active turn. Each call checks the current host process, host thread and
//! MM identity before sending one request under the session's native lease.

use std::fmt;
use std::io;
use std::sync::{Arc, Weak};

use super::{Endpoint, RemoteError};
use crate::user::mm::process_owner::{Operation, Value};

mod view;

#[derive(Clone)]
pub(crate) struct Access {
    endpoint: Weak<Endpoint>,
    space: u64,
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerAccess")
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl Access {
    pub(super) fn new(endpoint: &Arc<Endpoint>, space: u64) -> Self {
        Self {
            endpoint: Arc::downgrade(endpoint),
            space,
        }
    }

    pub(crate) fn space(&self) -> u64 {
        self.space
    }

    /// This is execution-window admission, not a physical-memory import or
    /// a promise that a particular guest address is mapped.
    pub(crate) fn active(&self) -> bool {
        self.endpoint
            .upgrade()
            .is_some_and(|endpoint| endpoint.current(self.space, None).is_ok())
    }

    /// One shared physical view and admission history per worker endpoint.
    pub(crate) fn cpu_memory(&self) -> Result<super::super::OwnerMemory, RemoteError> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        endpoint.current(self.space, None)?;
        let mut cached = endpoint
            .cpu_memory
            .lock()
            .map_err(|_| io::Error::other("owner CPU memory cache poisoned"))?;
        if let Some(inner) = cached.upgrade() {
            let memory = super::super::OwnerMemory::from_inner(inner);
            if memory.space() == self.space {
                return Ok(memory);
            }
        }
        let memory = super::super::OwnerMemory::import(self.clone())?;
        *cached = Arc::downgrade(memory.inner());
        Ok(memory)
    }

    pub(in crate::user::mm::process_owner) fn execution_identity(
        &self,
    ) -> Result<(u64, u64), RemoteError> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let active = endpoint.current(self.space, None)?;
        Ok((
            active.serial,
            endpoint.mutation.load(std::sync::atomic::Ordering::Acquire),
        ))
    }

    pub(crate) fn call(&self, operation: Operation) -> Result<Value, RemoteError> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        endpoint.memory(self.space, None, operation)
    }

    /// A whole personality MM operation under the active turn. Every such
    /// request conservatively invalidates local CPU admission history, even
    /// if the personality ultimately refuses the guest operation.
    pub(crate) fn transact<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        operation: &Q,
    ) -> Result<R, RemoteError> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        endpoint.personality(self.space, operation)
    }
}

#[cfg(test)]
mod tests;
