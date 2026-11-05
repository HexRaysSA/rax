//! MMU-owned state and cold replacement over the target's external bindings.
use super::{InlineLapic, Mmu};
use crate::error::{Error, Result};
use crate::isa::x86_64::user_gdt::UserTables;
use crate::vm::vcpu::{MemAccess, MemRecord};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct AccessRecord {
    access: u8,
    addr: u64,
    size: u8,
    value: u64,
    rip: u64,
}

#[derive(Serialize, Deserialize)]
pub(in crate::isa::x86_64) struct MmuContext {
    lapic: InlineLapic,
    timer_age_nanos: Option<u64>,
    shared_lapic: bool,
    // RAXX8604 supplies this policy bit; older bodies keep their exact layout.
    #[serde(skip)]
    pub(in crate::isa::x86_64) ioapic_mmio: bool,
    pci: bool,
    pci_ap_lo: u64,
    pci_ap_hi: u64,
    flat: bool,
    mem_rec_on: bool,
    fetch_active: bool,
    mem_rec: Vec<AccessRecord>,
    user_tables: Option<Vec<u8>>,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("x86 MMU context: {message}"))
}

impl Mmu {
    pub(in crate::isa::x86_64) fn checkpoint_memory(
        &self,
    ) -> std::sync::Arc<vm_memory::GuestMemoryMmap> {
        self.memory.clone()
    }

    pub(in crate::isa::x86_64) fn checkpoint_state(&self) -> Result<MmuContext> {
        // Exhaustive: no host pointer, translation cache or mutable private
        // buffer can enter or leave a checkpoint without classification.
        let Self {
            memory: _,
            tlb: _,
            cached_cr3: _,
            cached_paging_mode: _,
            protection: _,
            code_page_bitmap: _,
            smc_dirty_pages: _,
            lapic,
            shared_lapic,
            shared_priority: _,
            shared_ioapic: _,
            ioapic_mmio,
            ram_host_base: _,
            ram_len: _,
            ram_fast_len: _,
            pci,
            pci_ap_lo,
            pci_ap_hi,
            mem_rec_on,
            fetch_active,
            mem_rec,
            flat,
            user_tables,
        } = self;
        let lapic = lapic.try_borrow().map_err(invalid)?.clone();
        let timer_age_nanos = lapic.timer_start_nanos.map(|start| {
            lapic
                .timer_elapsed_base
                .saturating_add(crate::vm::timing::elapsed_nanos().saturating_sub(start))
        });
        let mut records = Vec::new();
        records.try_reserve_exact(mem_rec.len()).map_err(invalid)?;
        for record in mem_rec {
            let MemRecord {
                access,
                addr,
                size,
                value,
                rip,
            } = *record;
            records.push(AccessRecord {
                access: match access {
                    MemAccess::Read => 0,
                    MemAccess::Write => 1,
                    MemAccess::Exec => 2,
                },
                addr,
                size,
                value,
                rip,
            });
        }
        Ok(MmuContext {
            lapic,
            timer_age_nanos,
            shared_lapic: shared_lapic.is_some(),
            ioapic_mmio: *ioapic_mmio,
            pci: pci.is_some(),
            pci_ap_lo: *pci_ap_lo,
            pci_ap_hi: *pci_ap_hi,
            flat: flat.is_some(),
            mem_rec_on: *mem_rec_on,
            fetch_active: *fetch_active,
            mem_rec: records,
            user_tables: user_tables.as_ref().map(|tables| tables.checkpoint_bytes()),
        })
    }
}

impl MmuContext {
    pub(in crate::isa::x86_64) fn validate_priority_projection(&self, cr8: u64) -> Result<()> {
        if cr8 > 15
            || (!self.shared_lapic
                && (self.lapic.tpr.load() > 255 || u64::from(self.lapic.tpr.load() >> 4) != cr8))
        {
            return Err(invalid("CPU CR8 and inline local APIC TPR disagree"));
        }
        Ok(())
    }
    pub(in crate::isa::x86_64) fn validate(&self, target: &Mmu) -> Result<()> {
        if self.shared_lapic != target.shared_lapic.is_some()
            || (self.ioapic_mmio && target.shared_ioapic.is_none())
            || self.pci != target.pci.is_some()
            || self.pci_ap_lo != target.pci_ap_lo
            || self.pci_ap_hi != target.pci_ap_hi
            || self.flat != target.flat.is_some()
        {
            return Err(invalid(
                "external controller, PCI or translation binding differs",
            ));
        }
        if self.timer_age_nanos.is_some() != self.lapic.timer_start_nanos.is_some()
            || self.mem_rec.iter().any(|record| record.access > 2)
            || self
                .user_tables
                .as_ref()
                .is_some_and(|bytes| UserTables::from_checkpoint(bytes).is_none())
        {
            return Err(invalid(
                "invalid timer phase, access record or descriptor table",
            ));
        }
        Ok(())
    }

    /// All allocation and admission occur in this offside replacement. RAM,
    /// PCI/controller ownership and process translations stay target-bound.
    pub(in crate::isa::x86_64) fn prepare(self, target: &Mmu) -> Result<Mmu> {
        self.validate(target)?;
        let mut result = Mmu::new(target.memory.clone());
        result.shared_lapic = target.shared_lapic.clone();
        result.shared_priority = target.shared_priority.clone();
        result.shared_ioapic = target.shared_ioapic.clone();
        result.ioapic_mmio = self.ioapic_mmio;
        result.pci = target.pci.clone();
        result.pci_ap_lo = target.pci_ap_lo;
        result.pci_ap_hi = target.pci_ap_hi;
        result.refresh_ram_fast_limit();
        result.flat = target.flat.clone();
        let mut lapic = self.lapic;
        if let Some(age) = self.timer_age_nanos {
            lapic.timer_start_nanos = Some(crate::vm::timing::elapsed_nanos());
            lapic.timer_elapsed_base = age;
        }
        result.lapic = std::cell::RefCell::new(lapic);
        result.mem_rec_on = self.mem_rec_on;
        result.fetch_active = self.fetch_active;
        result
            .mem_rec
            .try_reserve_exact(self.mem_rec.len())
            .map_err(invalid)?;
        for record in self.mem_rec {
            result.mem_rec.push(MemRecord {
                access: match record.access {
                    0 => MemAccess::Read,
                    1 => MemAccess::Write,
                    2 => MemAccess::Exec,
                    _ => unreachable!("admitted access kind"),
                },
                addr: record.addr,
                size: record.size,
                value: record.value,
                rip: record.rip,
            });
        }
        result.user_tables = self
            .user_tables
            .map(|bytes| {
                UserTables::from_checkpoint(&bytes)
                    .map(Box::new)
                    .ok_or_else(|| invalid("invalid descriptor table"))
            })
            .transpose()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
