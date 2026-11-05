//! Shared PIC/IOAPIC banks and the separately owned userspace line source.
//!
//! This does not freeze kernel PIT/LAPIC timers. The complete producer must
//! establish timer and device boundaries before using these controller banks.
use super::bank::Bank;
use crate::backend::kvm::irq;
use crate::error::{Error, Result};
use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, kvm_ioapic_state,
    kvm_irqchip, kvm_pic_state,
};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    version: u16,
    pics: [Bank<kvm_pic_state>; 2],
    ioapic: Bank<kvm_ioapic_state>,
    levels: [bool; irq::PINS],
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native shared controller record: {message}"))
}

fn read(vm: &VmFd, chip_id: u32) -> Result<kvm_irqchip> {
    let mut chip = kvm_irqchip {
        chip_id,
        ..Default::default()
    };
    vm.get_irqchip(&mut chip)?;
    Ok(chip)
}

fn read_pic(vm: &VmFd, chip_id: u32) -> Result<Bank<kvm_pic_state>> {
    let chip = read(vm, chip_id)?;
    // SAFETY: successful GET_IRQCHIP with a PIC ID initializes this union
    // member, whose integer-only value is copied before the local is dropped.
    // VM exclusion prevents userspace entry/mutation. No pointer escapes.
    let pic = unsafe { chip.chip.pic };
    Bank::capture(&pic).map_err(invalid)
}

impl Image {
    pub(super) fn capture(vm: &VmFd, lines: &irq::Lines) -> Result<Self> {
        let chip = read(vm, KVM_IRQCHIP_IOAPIC)?;
        // SAFETY: successful GET_IRQCHIP with the IOAPIC ID initializes this
        // integer-only union member. Copy under VM exclusion; no alias escapes.
        let mut ioapic = unsafe { chip.chip.ioapic };
        ioapic.pad = 0;
        Ok(Self {
            version: 1,
            pics: [
                read_pic(vm, KVM_IRQCHIP_PIC_MASTER)?,
                read_pic(vm, KVM_IRQCHIP_PIC_SLAVE)?,
            ],
            ioapic: Bank::capture(&ioapic).map_err(invalid)?,
            levels: lines.levels(),
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(invalid("unsupported version"));
        }
        for pic in &self.pics {
            pic.validate().map_err(invalid)?;
        }
        if self.ioapic.decode().map_err(invalid)?.pad != 0 {
            return Err(invalid("IOAPIC padding is not zero"));
        }
        Ok(())
    }

    pub(super) fn restore_lines(&self, vm: &VmFd, lines: &mut irq::Lines) -> Result<()> {
        self.validate()?;
        lines.restore(vm, &self.levels)
    }

    /// Install after the stored CPU banks: SET_IRQCHIP reconstructs delivery
    /// and RTC EOI tracking from the actual destination LAPICs. Any line-replay
    /// transients must have been replaced by those CPU banks before this step.
    /// Like the native setters, this can fail after installing a prefix.
    pub(super) fn restore_controllers(&self, vm: &VmFd) -> Result<()> {
        self.validate()?;
        // SET_IRQCHIP recomputes the cascade after each PIC. Restore the slave
        // before the master so the final computation uses both saved banks.
        for (chip_id, bank) in [
            (KVM_IRQCHIP_PIC_SLAVE, &self.pics[1]),
            (KVM_IRQCHIP_PIC_MASTER, &self.pics[0]),
        ] {
            let mut chip = kvm_irqchip {
                chip_id,
                ..Default::default()
            };
            chip.chip.pic = bank.decode().map_err(invalid)?;
            vm.set_irqchip(&chip)?;
        }
        let mut chip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        chip.chip.ioapic = self.ioapic.decode().map_err(invalid)?;
        vm.set_irqchip(&chip)?;
        Ok(())
    }
}
