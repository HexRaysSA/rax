//! AIO context lookup and completion copies against the actual MM table.
//! Readiness, submission and sleeping still belong to the syscall scheduler;
//! this transaction neither copies their resources nor fabricates a context.

use serde::{Deserialize, Serialize};

use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{EFAULT, EINVAL};
use crate::user::linux::aio::{Context, EVENT_SIZE, Event, Handle, Table};
use crate::user::mm::AddressSpace;

/// One `aio_read_events` pass, including the count from earlier passes of the
/// same sleeping call. Counts are validated before indexing or allocation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AioRead {
    pub handle: Handle,
    pub min_nr: i64,
    pub nr: i64,
    pub events: u64,
    pub got: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AioReadResult {
    pub got: u64,
    pub done: bool,
}

impl Table {
    /// `lookup_ioctx`: read the ring index through guest memory, then require
    /// the actual live context's address to agree. A mapped inherited ring in
    /// a private child does not confer ownership of its parent's context.
    pub(crate) fn lookup_in_space(
        &mut self,
        space: &AddressSpace,
        address: u64,
    ) -> Result<Handle, Errno> {
        let mut index = [0; 4];
        space
            .read(address + Context::ring_id_offset(), &mut index)
            .map_err(|_| Errno(EINVAL))?;
        let index = u32::from_le_bytes(index);
        let context = self.lookup(address, index).ok_or(Errno(EINVAL))?;
        Ok(Handle {
            slot: index as usize,
            serial: context.serial,
        })
    }

    /// Copy at most `nr - got` completions and commit the shared ring head
    /// only after the complete batch reaches guest memory. A fault or a killed
    /// context ends this pass with the earlier count, if any. No pending poll,
    /// file reference, eventfd, quota or request accounting is replaced.
    /// For E available events this takes O(min(nr - got, E)) time and space.
    pub(crate) fn read_events(
        &mut self,
        space: &AddressSpace,
        arguments: AioRead,
    ) -> Result<AioReadResult, Errno> {
        let AioRead {
            handle,
            min_nr,
            nr,
            events,
            mut got,
        } = arguments;
        if min_nr < 0 || min_nr > nr || got > nr as u64 {
            return Err(Errno(EINVAL));
        }
        let stopped = |errno| {
            if got == 0 {
                Err(Errno(errno))
            } else {
                Ok(AioReadResult { got, done: true })
            }
        };
        let Some(context) = self.get(handle) else {
            return stopped(EINVAL);
        };
        let (taken, head) = context.peek_events((nr as u64 - got) as usize);
        if !taken.is_empty() {
            let bytes: Vec<u8> = taken.iter().flat_map(Event::encode).collect();
            let at = events.wrapping_add(got.wrapping_mul(EVENT_SIZE));
            if space.write(at, &bytes).is_err() {
                return stopped(EFAULT);
            }
            got += taken.len() as u64;
        }
        if let Some(head) = head {
            context.set_head(head);
        }
        Ok(AioReadResult {
            got,
            done: got >= min_nr as u64,
        })
    }
}

#[cfg(test)]
mod tests;
