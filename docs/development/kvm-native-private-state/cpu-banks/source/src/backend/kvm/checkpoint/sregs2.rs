//! Explicit SREGS2 wire fields; the SDK type has no checked byte representation.
use super::bank::Bank;
use kvm_bindings::{KVM_SREGS2_FLAGS_PDPTRS_VALID, kvm_sregs, kvm_sregs2};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    version: u16,
    common: Bank<kvm_sregs>,
    flags: u64,
    pdptrs: [u64; 4],
}

impl Image {
    pub(super) fn agrees_with(&self, legacy: &kvm_sregs) -> Result<bool, String> {
        self.decode()?;
        let mut common = *legacy;
        common.interrupt_bitmap = [0; 4];
        Ok(self.common == Bank::capture(&common)?)
    }

    pub(super) fn capture(value: &kvm_sregs2) -> Result<Self, String> {
        let common = kvm_sregs {
            cs: value.cs,
            ds: value.ds,
            es: value.es,
            fs: value.fs,
            gs: value.gs,
            ss: value.ss,
            tr: value.tr,
            ldt: value.ldt,
            gdt: value.gdt,
            idt: value.idt,
            cr0: value.cr0,
            cr2: value.cr2,
            cr3: value.cr3,
            cr4: value.cr4,
            cr8: value.cr8,
            efer: value.efer,
            apic_base: value.apic_base,
            // SREGS2 has no legacy interrupt bitmap. Native event/controller
            // records must preserve their own interrupt state separately.
            interrupt_bitmap: [0; 4],
        };
        let image = Self {
            version: 1,
            common: Bank::capture(&common)?,
            flags: value.flags,
            pdptrs: value.pdptrs,
        };
        image.decode()?;
        Ok(image)
    }

    /// This validates the wire envelope and supported UAPI flag set. It does
    /// not replace architectural admission or a native rollback transaction.
    pub(super) fn decode(&self) -> Result<kvm_sregs2, String> {
        if self.version != 1 || self.flags & !u64::from(KVM_SREGS2_FLAGS_PDPTRS_VALID) != 0 {
            return Err("SREGS2 wire version or flags are unsupported".into());
        }
        let common = self.common.decode()?;
        if common.interrupt_bitmap != [0; 4] {
            return Err("SREGS2 common record contains a legacy interrupt bitmap".into());
        }
        Ok(kvm_sregs2 {
            cs: common.cs,
            ds: common.ds,
            es: common.es,
            fs: common.fs,
            gs: common.gs,
            ss: common.ss,
            tr: common.tr,
            ldt: common.ldt,
            gdt: common.gdt,
            idt: common.idt,
            cr0: common.cr0,
            cr2: common.cr2,
            cr3: common.cr3,
            cr4: common.cr4,
            cr8: common.cr8,
            efer: common.efer,
            apic_base: common.apic_base,
            flags: self.flags,
            pdptrs: self.pdptrs,
        })
    }
}
