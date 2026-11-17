//! The actual AIO table participates in moving its ring VMA. The ring's
//! backing identity, not a worker-supplied slot or address, finds its context.

use super::Table;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::EINVAL;
use crate::user::linux::abi::vma_flags;
use crate::user::mm::{Backing, Vma};
use std::sync::Arc;

impl Table {
    /// `aio_ring_mremap`: an inherited ring without a live context is EINVAL.
    pub(crate) fn ring_owner(&self, vma: &Vma) -> Result<Option<usize>, Errno> {
        if vma.flags & vma_flags::AIO_RING == 0 {
            return Ok(None);
        }
        let Backing::Shared { object, .. } = &vma.backing else {
            return Err(Errno(EINVAL));
        };
        self.contexts
            .iter()
            .position(|x| x.as_ref().is_some_and(|x| Arc::ptr_eq(&x.ring, object)))
            .map(Some)
            .ok_or(Errno(EINVAL))
    }

    /// Publish the new user context address after the mapping has moved.
    pub(crate) fn ring_moved(&mut self, owner: Option<usize>, to: u64) {
        if let Some(ctx) = owner.and_then(|i| self.contexts[i].as_mut()) {
            ctx.id = to;
        }
    }
}
