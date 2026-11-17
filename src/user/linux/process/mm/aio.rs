//! Complete AIO setup against the authoritative MM and its actual context
//! table. The ring mapping, charge, table entry and output handle are one
//! operation; no process-local descriptor or scheduler callback is needed.

use std::sync::Arc;

use super::{LockPolicy, MmState};
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::vma_flags;
use crate::user::linux::aio::{AIO_MAX_NR, Context, EVENT_SIZE, POSSIBLE_CPUS, Table};
use crate::user::linux::syscall::{SysResult, mlock, mseal};
use crate::user::mm::{AddressSpace, Backing, Mapping, Perms, SharedObject};

/// `ioctx_alloc` checks the expanded slot count before `aio-max-nr`.
fn geometry(max_reqs: u32) -> Result<(u32, u64), Errno> {
    let nr = max_reqs.max(POSSIBLE_CPUS * 4).wrapping_mul(2);
    if u64::from(nr) > 0x1000_0000 / EVENT_SIZE {
        return Err(Errno(EINVAL));
    }
    if nr == 0 || u64::from(max_reqs) > AIO_MAX_NR {
        return Err(Errno(EAGAIN));
    }
    Context::ring_geometry(max_reqs).ok_or(Errno(EINVAL))
}

impl MmState {
    /// `io_setup` / `compat_sys_io_setup` (Linux 6.19, `fs/aio.c`). Read
    /// `*context` before validating the count. A failed final copy destroys
    /// only the newly allocated context and releases its ring and charge.
    pub(crate) fn setup_aio(
        &mut self,
        space: &AddressSpace,
        table: &mut Table,
        policy: LockPolicy,
        nr_events: u32,
        context: u64,
    ) -> SysResult {
        let width = policy.abi.word_size() as usize;
        let mut previous = [0; 8];
        space
            .read(context, &mut previous[..width])
            .map_err(|_| Errno(EFAULT))?;
        if u64::from_le_bytes(previous) != 0 || nr_events == 0 {
            return Err(Errno(EINVAL));
        }
        let (slots, size) = geometry(nr_events)?;
        let at = self
            .unmapped_area(space, policy.abi, 0, size, 0)
            .map_err(|_| Errno(ENOMEM))?;
        // do_mmap checks MCL_FUTURE before the special ring VMA is
        // installed. The ring itself remains unlocked and uncounted.
        if !mlock::future_ok_mm(
            self,
            self.def_lock,
            size,
            policy.privileged,
            policy.memlock_limit >> 12,
        ) {
            return Err(Errno(ENOMEM));
        }
        let object = Arc::new(SharedObject::anonymous(size).map_err(|_| Errno(ENOMEM))?);
        space
            .map(
                at,
                size,
                Mapping {
                    perms: Perms::READ | Perms::WRITE,
                    backing: Backing::Shared {
                        object: object.clone(),
                        offset: 0,
                    },
                    shared: true,
                    name: Some("/[aio] (deleted)".into()),
                    flags: vma_flags::SPECIAL | vma_flags::AIO_RING,
                },
            )
            .map_err(|_| Errno(ENOMEM))?;
        if table.aio_nr + u64::from(nr_events) > AIO_MAX_NR {
            self.unmap_aio_ring(space, at, size);
            return Err(Errno(EAGAIN));
        }
        let index = table.free_index();
        let handle = table.insert(Context::new(at, index, object, size, slots, nr_events));
        table.aio_nr += u64::from(nr_events);
        if space.write(context, &at.to_le_bytes()[..width]).is_err() {
            // The new context has never been submitted to. Older contexts,
            // including their real pending files/eventfds, remain untouched.
            let allocated = table.contexts[handle.slot].take().expect("new AIO context");
            debug_assert!(allocated.polls.is_empty());
            table.aio_nr -= u64::from(allocated.max_reqs);
            self.unmap_aio_ring(space, allocated.id, allocated.mmap_size);
            return Err(Errno(EFAULT));
        }
        Ok(0)
    }

    /// `vm_munmap` of an AIO ring. A sealed mapping remains, as it does
    /// during io_destroy; unrelated locked-page accounting is preserved.
    pub(crate) fn unmap_aio_ring(&mut self, space: &AddressSpace, at: u64, size: u64) {
        if mseal::sealed_in_space(space, at, size) {
            return;
        }
        mlock::unmapped_mm(space, self, at, size);
        let _ = space.unmap(at, size);
    }
}
