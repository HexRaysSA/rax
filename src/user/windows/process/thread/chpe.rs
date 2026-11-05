//! Kernel-owned lifetime and guest storage for the current emulation context.
//! No pointer captured from the host's CHPE area is installed in the guest.
use super::*;
use crate::user::mm::AddressSpace;
use crate::user::windows::context::x64;
use crate::user::windows::memory::VirtualMemory;

#[derive(Clone, Debug)]
pub(crate) struct Area {
    pub(crate) base: u64,
    pub(crate) context: u64,
    owner: Arc<str>,
}

#[derive(Clone)]
pub(crate) struct Binding {
    pub(crate) area: Area,
    pub(crate) shadow: Vec<u8>,
}

impl Area {
    /// One 64 KiB reservation owns a 4 KiB context page, a guard page, and
    /// 20 KiB of emulator stack. Context, doorbell and stack addresses are
    /// guest addresses; allocation identity survives protection/run splits.
    pub(crate) fn allocate(vm: &mut VirtualMemory) -> Result<Self, u32> {
        let owner: Arc<str> = Arc::from("[CHPE thread context]");
        let base = vm
            .reserve(
                None,
                65536,
                prot::READWRITE,
                AllocKind::Private,
                false,
                Some(owner.clone()),
            )
            .map_err(|error| error.status())?;
        let result = (|| {
            vm.commit(base, PAGE_SIZE, prot::READWRITE)
                .map_err(|error| error.status())?;
            vm.commit(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .map_err(|error| error.status())?;
            vm.commit(base + 2 * PAGE_SIZE, 5 * PAGE_SIZE, prot::READWRITE)
                .map_err(|error| error.status())?;
            let area = Self {
                base,
                context: base + 0x8c0,
                owner,
            };
            for (offset, value) in [
                (8, base + 7 * PAGE_SIZE),
                (16, base + 2 * PAGE_SIZE),
                (24, area.context),
                (32, base + 0x80),
            ] {
                vm.space()
                    .w64(base + offset, value)
                    .map_err(|_| STATUS_NO_MEMORY)?;
            }
            vm.space().w8(base, 1).map_err(|_| STATUS_NO_MEMORY)?;
            Ok(area)
        })();
        if result.is_err() {
            let _ = vm.release(base);
        }
        result
    }

    pub(crate) fn owns_space(&self, space: &AddressSpace) -> bool {
        space.vma_at(self.base).is_some_and(|vma| {
            vma.start <= self.base
                && vma.end >= self.context + x64::SIZE as u64
                && vma
                    .name
                    .as_ref()
                    .is_some_and(|name| Arc::ptr_eq(name, &self.owner))
        })
    }

    pub(crate) fn release(&self, p: &mut Proc) {
        let owned = p.vm.allocation(self.base).is_some_and(|allocation| {
            allocation.base == self.base
                && allocation.size == 65536
                && allocation
                    .name
                    .as_ref()
                    .is_some_and(|name| Arc::ptr_eq(name, &self.owner))
        });
        if owned {
            let _ = p.vm.release(self.base);
        }
    }
}

#[cfg(test)]
mod tests;
