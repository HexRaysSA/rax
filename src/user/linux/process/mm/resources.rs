//! Non-cloneable MM-owned Linux resources. Construct by consuming the actual
//! bookkeeping and AIO table, including live rings and pending OpenFile refs.
//! Shared workers retain this one record; private forks create an empty child
//! AIO table without changing the parent's live requests or inherited ring VMAs.

use super::MmState;
use crate::user::linux::aio::Table;
use crate::user::mm::{AddressSpace, MmError};

#[derive(Debug)]
pub(crate) struct MmResources {
    pub(crate) mm: MmState,
    pub(crate) aio: Table,
}

impl MmResources {
    /// No Default or Clone: adoption must move the real table explicitly.
    pub(crate) fn new(mm: MmState, aio: Table) -> Self {
        Self { mm, aio }
    }

    pub(crate) fn fork_private(&self, snapshot: &AddressSpace) -> Result<Self, MmError> {
        Ok(Self {
            mm: self.mm.fork_private(snapshot)?,
            aio: Table::default(),
        })
    }
}

#[cfg(unix)]
impl crate::user::mm::process_owner::ForkMetadata for MmResources {
    fn fork_private(&self, snapshot: &AddressSpace) -> Result<Self, MmError> {
        MmResources::fork_private(self, snapshot)
    }

    fn transact(
        &mut self,
        space: &AddressSpace,
        request: &[u8],
        backings: &std::collections::BTreeMap<
            crate::user::mm::process_owner::BackingId,
            crate::user::mm::Backing,
        >,
    ) -> std::io::Result<Vec<u8>> {
        super::remote::execute(self, space, request, backings)
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::pending_fixture;
