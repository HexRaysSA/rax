//! AIO context lookup and completion copies against the actual MM table.
//! Readiness, submission and sleeping still belong to the syscall scheduler;
//! this transaction neither copies their resources nor fabricates a context.

use serde::{Deserialize, Serialize};

use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::{EFAULT, EINVAL};
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE};
use crate::user::linux::aio::{Context, EVENT_SIZE, Handle, Table};
use crate::user::mm::AddressSpace;

/// One `aio_read_events` pass, including the count from earlier passes of the
/// same sleeping call. Counts are validated before indexing or allocation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AioRead {
    pub abi: LinuxAbi,
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

/// Linux `copy_to_user` may leave a copied prefix on a later fault, unlike
/// the atomic-fault CPU memory write. Validate `access_ok` before any store,
/// then copy complete accessible page portions in order. This implements the
/// generic `include/linux/uaccess.h` contract with a maximal prefix; it does
/// not reproduce architecture/build-specific native short-copy granularity.
fn copy_events(
    space: &AddressSpace,
    abi: LinuxAbi,
    mut address: u64,
    mut bytes: &[u8],
) -> Result<(), Errno> {
    if address
        .checked_add(bytes.len() as u64)
        .is_none_or(|end| end > abi.user_ptr_max())
    {
        return Err(Errno(EFAULT));
    }
    while !bytes.is_empty() {
        let take = ((PAGE_SIZE - address % PAGE_SIZE) as usize).min(bytes.len());
        space
            .write(address, &bytes[..take])
            .map_err(|_| Errno(EFAULT))?;
        address += take as u64;
        bytes = &bytes[take..];
    }
    Ok(())
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
    /// context ends this pass with the earlier count, if any. A short copy
    /// keeps its output prefix while retaining every event in this batch.
    /// No pending poll, file reference, eventfd, quota or request accounting is
    /// replaced. For E available events this takes O(min(nr - got, E)) time
    /// with at most one source page of temporary storage.
    pub(crate) fn read_events(
        &mut self,
        space: &AddressSpace,
        arguments: AioRead,
    ) -> Result<AioReadResult, Errno> {
        let AioRead {
            abi,
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
        let (head, tail) = context.read_indices();
        if head == tail {
            return Ok(AioReadResult {
                got,
                done: got >= min_nr as u64,
            });
        }
        let mut head = head % context.nr_events;
        let tail = tail % context.nr_events;
        let mut copied = 0;
        while copied < nr as u64 - got && head != tail {
            let available = if head < tail {
                tail - head
            } else {
                context.nr_events - head
            };
            // `aio_read_events_ring`: each copy ends at the source page or
            // ring end, even when the destination is one contiguous range.
            let per_page = PAGE_SIZE / EVENT_SIZE;
            let page_left = per_page - (u64::from(head) + 1) % per_page;
            let take = (nr as u64 - got - copied)
                .min(u64::from(available))
                .min(page_left);
            let bytes = context.event_bytes(head, take as usize);
            let at = events.wrapping_add((got + copied).wrapping_mul(EVENT_SIZE));
            if copy_events(space, abi, at, &bytes).is_err() {
                return stopped(EFAULT);
            }
            copied += take;
            head = (head + take as u32) % context.nr_events;
        }
        context.set_head(head);
        got += copied;
        Ok(AioReadResult {
            got,
            done: got >= min_nr as u64,
        })
    }
}

#[cfg(test)]
mod tests;
