//! RAX's generic RV64 bare-metal reset convention; not a Linux/SBI boot ABI.
use super::RiscvVirtMachine;
use crate::error::{Error, Result};
use crate::machine::{BootInfo, Machine};
use crate::vm::vcpu::CpuState;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};

const STACK_PAGE: u128 = 4096;

pub(crate) fn hart_state(
    memory: &GuestMemoryMmap,
    boot: &BootInfo,
    id: u32,
    count: u8,
) -> Result<CpuState> {
    if count == 0 || id >= u32::from(count) {
        return Err(Error::InvalidConfig(
            "invalid RISC-V boot hart topology".into(),
        ));
    }
    let image = boot
        .as_riscv()
        .ok_or_else(|| Error::InvalidConfig("expected RISC-V boot image".into()))?;
    let image_end = image
        .load_addr
        .checked_add(image.image_size)
        .ok_or_else(|| Error::KernelLoad("RISC-V image range overflow".into()))?;
    let end = (u128::from(memory.last_addr().raw_value()) + 1) & !15;
    let reserved = u128::from(count) * STACK_PAGE;
    let base = end
        .checked_sub(reserved)
        .ok_or_else(|| Error::KernelLoad("RAM cannot hold RISC-V bootstrap stacks".into()))?;
    let base = u64::try_from(base)
        .map_err(|_| Error::KernelLoad("RISC-V stack address exceeds XLEN".into()))?;
    if base < image_end || !memory.check_range(GuestAddress(base), reserved as usize) {
        return Err(Error::KernelLoad(
            "RISC-V bootstrap stacks overlap image or unmapped RAM".into(),
        ));
    }
    crate::vm::memory::reservations::preflight_write(memory, base, reserved as usize)?;
    let mut state = RiscvVirtMachine::new().initial_cpu_state(memory, boot)?;
    let CpuState::RiscV(hart) = &mut state else {
        unreachable!()
    };
    // Privileged 3.4 leaves integer reset state unspecified. This platform
    // supplies a0=mhartid and a disjoint page; firmware owns later stack sizing.
    hart.regs.x[10] = u64::from(id);
    hart.regs.x[2] = (end - 16 - u128::from(id) * STACK_PAGE) as u64;
    Ok(state)
}
