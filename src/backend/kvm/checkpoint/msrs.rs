//! Profile-admitted migration MSRs; advancing clocks have their own producer.
use crate::error::{Error, Result};
use kvm_bindings::{CpuId, Msrs, kvm_msr_entry};
use kvm_ioctls::{Kvm, VcpuFd};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;

const TSC: u32 = 0x10;
const HYPERV_REFERENCE_TIME: u32 = 0x4000_0020;
const HYPERV_VP_RUNTIME: u32 = 0x4000_0010;
const ASYNC_PF_INTERRUPT: u32 = 0x4b56_4d06;
const ASYNC_PF_INTERRUPT_FEATURE: u32 = 1 << 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::backend::kvm) struct Plan {
    indices: Vec<u32>,
    counter_indices: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::backend::kvm) struct Register {
    pub(in crate::backend::kvm) index: u32,
    pub(in crate::backend::kvm) value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::backend::kvm) struct Image {
    #[serde(deserialize_with = "registers")]
    registers: Vec<Register>,
    #[serde(deserialize_with = "registers")]
    counters: Vec<Register>,
}

fn registers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Register>, D::Error> {
    // Match the retained SDK's FAM allocation bound. The exact ordered
    // membership is checked against the current host plan after decoding.
    super::bounded::sequence::<_, _, { kvm_bindings::KVM_MAX_MSR_ENTRIES }>(deserializer)
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native KVM migration MSR bank: {message}"))
}

fn table(entries: &[kvm_msr_entry]) -> Result<Msrs> {
    Msrs::from_entries(entries).map_err(invalid)
}

impl Plan {
    /// Preserve the kernel's migration order in each bank. Three advancing
    /// counters require coordinated clock restoration. ASYNC_PF_INT needs the KVM
    /// guest feature and kernel LAPIC; GET support alone does not imply SET.
    pub(in crate::backend::kvm) fn capture(
        kvm: &Kvm,
        guest: &CpuId,
        irqchip: bool,
    ) -> Result<Self> {
        let features = if super::super::cpuid::has_kvm_signature(guest.as_slice()) {
            guest
                .as_slice()
                .iter()
                .find(|entry| entry.function == 0x4000_0001 && entry.index == 0)
                .map_or(0, |entry| entry.eax)
        } else {
            0
        };
        let indices = kvm.get_msr_index_list()?;
        let mut seen = HashSet::new();
        let mut admitted = Vec::new();
        let mut counters = Vec::new();
        for &index in indices.as_slice() {
            if !seen.insert(index) {
                return Err(invalid("duplicate kernel migration index"));
            }
            let feature = match index {
                0x11 | 0x12 => Some(1 << 0),
                0x4b56_4d00 | 0x4b56_4d01 => Some(1 << 3),
                0x4b56_4d02 => Some(1 << 4),
                0x4b56_4d03 => Some(1 << 5),
                0x4b56_4d04 => Some(1 << 6),
                0x4b56_4d05 => Some(1 << 12),
                0x4b56_4d06 | 0x4b56_4d07 => Some(ASYNC_PF_INTERRUPT_FEATURE),
                _ => None,
            };
            if feature.is_some_and(|feature| features & feature == 0)
                || (index == ASYNC_PF_INTERRUPT && !irqchip)
            {
                continue;
            }
            if matches!(index, TSC | HYPERV_REFERENCE_TIME | HYPERV_VP_RUNTIME) {
                counters.push(index);
            } else {
                admitted.push(index);
            }
        }
        Ok(Self {
            indices: admitted,
            counter_indices: counters,
        })
    }

    pub(in crate::backend::kvm) fn indices(&self) -> &[u32] {
        &self.indices
    }
}

impl Image {
    pub(in crate::backend::kvm) fn capture(cpu: &VcpuFd, plan: &Plan) -> Result<Self> {
        let entries: Vec<_> = plan
            .indices
            .iter()
            .chain(&plan.counter_indices)
            .map(|&index| kvm_msr_entry {
                index,
                ..Default::default()
            })
            .collect();
        let mut native = table(&entries)?;
        let count = cpu.get_msrs(&mut native)?;
        if count != entries.len() {
            return Err(invalid(format_args!(
                "read completed {count} of {} entries",
                entries.len()
            )));
        }
        Ok(Self {
            registers: native.as_slice()[..plan.indices.len()]
                .iter()
                .map(|entry| Register {
                    index: entry.index,
                    value: entry.data,
                })
                .collect(),
            counters: native.as_slice()[plan.indices.len()..]
                .iter()
                .map(|entry| Register {
                    index: entry.index,
                    value: entry.data,
                })
                .collect(),
        })
    }

    pub(in crate::backend::kvm) fn registers(&self) -> &[Register] {
        &self.registers
    }

    pub(in crate::backend::kvm) fn counters(&self) -> &[Register] {
        &self.counters
    }

    pub(in crate::backend::kvm) fn from_parts(
        registers: Vec<Register>,
        counters: Vec<Register>,
        plan: &Plan,
    ) -> Result<Self> {
        let image = Self {
            registers,
            counters,
        };
        image.validate(plan)?;
        Ok(image)
    }

    pub(in crate::backend::kvm) fn validate(&self, plan: &Plan) -> Result<()> {
        if self.counters.len() != plan.counter_indices.len()
            || self
                .counters
                .iter()
                .map(|entry| entry.index)
                .ne(plan.counter_indices.iter().copied())
            || self.registers.len() != plan.indices.len()
            || self
                .registers
                .iter()
                .map(|entry| entry.index)
                .ne(plan.indices.iter().copied())
        {
            return Err(invalid(
                "record order or membership differs from the selected profile",
            ));
        }
        Ok(())
    }

    /// Apply only to an exclusively stopped disposable destination or under a
    /// complete native rollback transaction. SET_MSRS may mutate a prefix on
    /// failure; this helper does not make the kernel batch transactional.
    /// Counter values are retained in the image for the coordinated clock
    /// producer. This method restores only the stored-register bank.
    pub(in crate::backend::kvm) fn restore_stored_registers(
        &self,
        cpu: &VcpuFd,
        plan: &Plan,
    ) -> Result<()> {
        self.validate(plan)?;
        let entries: Vec<_> = self
            .registers
            .iter()
            .map(|entry| kvm_msr_entry {
                index: entry.index,
                data: entry.value,
                ..Default::default()
            })
            .collect();
        let count = cpu.set_msrs(&table(&entries)?)?;
        if count != entries.len() {
            return Err(invalid(format_args!(
                "write completed {count} of {} entries; destination may be partially changed",
                entries.len()
            )));
        }
        // The kernel can accept host writes to read-only migration fields
        // while ignoring their supplied values. Count success alone does not
        // prove that the requested stored image was installed.
        let readback = Self::capture(cpu, plan)?;
        if let Some((expected, actual)) = self
            .registers
            .iter()
            .zip(&readback.registers)
            .find(|(expected, actual)| expected != actual)
        {
            return Err(invalid(format_args!(
                "stored-bank readback at {:#x} differs: expected {:#x}, observed {:#x}; destination may be partially changed",
                expected.index, expected.value, actual.value,
            )));
        }
        Ok(())
    }
}
