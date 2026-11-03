//! Machine-specific initial participation in the execution coordinator.
use crate::backend::{Vm, emulator::EmulatorVm};
use crate::error::{Error, Result};
use crate::isa::riscv::Xlen;
use crate::machine::{BootInfo, Machine};
use crate::vm::vcpu::{CpuState, VCpu};
use vm_memory::GuestMemoryMmap;

pub(super) fn boot_state(
    vm: &dyn Vm,
    machine: &dyn Machine,
    memory: &GuestMemoryMmap,
    boot: &BootInfo,
    cpu: &dyn VCpu,
    count: u8,
) -> Result<Option<CpuState>> {
    if vm
        .as_any()
        .downcast_ref::<EmulatorVm>()
        .is_some_and(EmulatorVm::boots_all_riscv_harts)
    {
        let config = cpu.riscv_configuration().ok_or_else(|| {
            Error::InvalidConfig("generic RV64 machine has no hart configuration".into())
        })?;
        if config.xlen != Xlen::Rv64 {
            return Err(Error::InvalidConfig(
                "RV64 machine requires RV64 boot harts".into(),
            ));
        }
        return crate::machine::riscv_virt::startup::hart_state(memory, boot, cpu.id(), count)
            .map(Some);
    }
    if cpu.id() == 0 {
        return machine.initial_cpu_state(memory, boot).map(Some);
    }
    Ok(None)
}
