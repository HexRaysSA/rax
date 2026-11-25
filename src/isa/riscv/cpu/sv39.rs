//! Uncached supervisor virtual-address translation for the RV64 virt profile.

use super::{Memory, Priv, Trap, cause};

pub(super) const SATP_MODE_SHIFT: u32 = 60;
pub(super) const SATP_MODE_SV39: u64 = 8;
pub(super) const PAGE_SIZE: u64 = 1 << 12;
const PPN_MASK: u64 = (1 << 44) - 1;
const VPN_MASK: u64 = (1 << 9) - 1;
const PTE_VALID: u64 = 1;
const PTE_READ: u64 = 1 << 1;
const PTE_WRITE: u64 = 1 << 2;
const PTE_EXECUTE: u64 = 1 << 3;
const PTE_USER: u64 = 1 << 4;
const PTE_ACCESSED: u64 = 1 << 6;
const PTE_DIRTY: u64 = 1 << 7;
const PTE_RESERVED: u64 = !((1 << 54) - 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    Fetch,
    Load,
    Store,
    CacheManagement,
}

impl Access {
    pub(super) fn access_fault(self, address: u64) -> Trap {
        Trap {
            cause: match self {
                Self::Fetch => cause::INSTR_ACCESS_FAULT,
                Self::Load => cause::LOAD_ACCESS_FAULT,
                Self::Store | Self::CacheManagement => cause::STORE_ACCESS_FAULT,
            },
            tval: address,
        }
    }

    fn page_fault(self, address: u64) -> Trap {
        Trap {
            cause: match self {
                Self::Fetch => cause::INSTR_PAGE_FAULT,
                Self::Load => cause::LOAD_PAGE_FAULT,
                Self::Store | Self::CacheManagement => cause::STORE_PAGE_FAULT,
            },
            tval: address,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Sv39 {
    pub(super) satp: u64,
    pub(super) privilege: Priv,
    pub(super) sum: bool,
    pub(super) mxr: bool,
}

struct Leaf {
    pte_address: u64,
    pte: u64,
    physical: u64,
}

impl Sv39 {
    /// Resolve an architectural access and atomically publish any A/D update.
    pub(super) fn translate(
        self,
        memory: &mut dyn Memory,
        address: u64,
        access: Access,
    ) -> Result<u64, Trap> {
        let required = PTE_ACCESSED
            | if access == Access::Store {
                PTE_DIRTY
            } else {
                0
            };
        loop {
            let leaf = self.walk(memory, address, access)?;
            let updated = leaf.pte | required;
            if updated == leaf.pte
                || memory
                    .compare_exchange_page_table_entry(leaf.pte_address, leaf.pte, updated)
                    .map_err(|_| access.access_fault(address))?
            {
                return Ok(leaf.physical);
            }
        }
    }

    /// Resolve diagnostic instruction fetch without changing the page tables.
    pub(super) fn inspect_fetch(self, memory: &dyn Memory, address: u64) -> Result<u64, Trap> {
        self.walk(memory, address, Access::Fetch)
            .map(|leaf| leaf.physical)
    }

    fn walk(self, memory: &dyn Memory, address: u64, access: Access) -> Result<Leaf, Trap> {
        debug_assert!(self.privilege != Priv::Machine);
        let page_fault = access.page_fault(address);
        if (((address << 25) as i64) >> 25) as u64 != address {
            return Err(page_fault);
        }

        let mut table = (self.satp & PPN_MASK) << 12;
        for level in (0..3).rev() {
            let lower_bits = 9 * level;
            let vpn = (address >> (12 + lower_bits)) & VPN_MASK;
            let pte_address = table + vpn * 8;
            let pte = memory
                .read_page_table_entry(pte_address)
                .map_err(|_| access.access_fault(address))?;
            if pte & PTE_VALID == 0
                || pte & (PTE_READ | PTE_WRITE) == PTE_WRITE
                || pte & PTE_RESERVED != 0
            {
                return Err(page_fault);
            }

            let ppn = (pte >> 10) & PPN_MASK;
            if pte & (PTE_READ | PTE_EXECUTE) == 0 {
                if pte & (PTE_USER | PTE_ACCESSED | PTE_DIRTY) != 0 {
                    return Err(page_fault);
                }
                table = ppn << 12;
                continue;
            }

            let lower_ppn_mask = (1 << lower_bits) - 1;
            if ppn & lower_ppn_mask != 0 || !self.permits(pte, access) {
                return Err(page_fault);
            }
            let lower_address_mask = (1 << (12 + lower_bits)) - 1;
            return Ok(Leaf {
                pte_address,
                pte,
                physical: (ppn << 12) | (address & lower_address_mask),
            });
        }
        Err(page_fault)
    }

    fn permits(self, pte: u64, access: Access) -> bool {
        let user_page = pte & PTE_USER != 0;
        let privilege_ok = match self.privilege {
            Priv::User => user_page,
            Priv::Supervisor => !user_page || (self.sum && access != Access::Fetch),
            Priv::Machine => false,
        };
        let operation_ok = match access {
            Access::Fetch => pte & PTE_EXECUTE != 0,
            Access::Load | Access::CacheManagement => {
                pte & PTE_READ != 0 || (self.mxr && pte & PTE_EXECUTE != 0)
            }
            Access::Store => pte & PTE_WRITE != 0,
        };
        privilege_ok && operation_ok
    }
}
