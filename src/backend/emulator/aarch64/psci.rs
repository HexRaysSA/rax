//! PSCI1.1 calls use an asynchronous VM-owned power-state machine.
use super::{Aarch64Vcpu, GICD_SIZE, UART_BASE, UART_SIZE, in_window};
use crate::error::Result;
use crate::isa::arm::cpu_trait::ArmCpu;
use crate::machine::arm_virt::AARCH64_GICD_BASE;
use crate::vm::vcpu::VcpuExit;
use vm_memory::{GuestAddress, GuestMemory};

impl Aarch64Vcpu {
    pub(super) fn handle_psci(&mut self, immediate: u16) -> Result<Option<VcpuExit>> {
        if immediate != 0 {
            return Ok(Some(VcpuExit::Unknown(format!(
                "unsupported firmware call immediate {immediate:#x}"
            ))));
        }
        const VERSION: u32 = 0x8400_0000;
        const CPU_OFF: u32 = 0x8400_0002;
        const CPU_ON32: u32 = 0x8400_0003;
        const CPU_ON64: u32 = 0xc400_0003;
        const AFFINITY32: u32 = 0x8400_0004;
        const AFFINITY64: u32 = 0xc400_0004;
        const MIGRATE_TYPE: u32 = 0x8400_0006;
        const SYSTEM_OFF: u32 = 0x8400_0008;
        const SYSTEM_RESET: u32 = 0x8400_0009;
        const FEATURES: u32 = 0x8400_000a;
        let function = self.cpu.get_gpr(0) as u32;
        // DEN0022D5.2.1: every SMC64/HVC64 call from AArch32 returns
        // NOT_SUPPORTED, including AFFINITY_INFO and unknown functions.
        if self.cpu.pstate_bits() & 16 != 0 && function & (1 << 30) != 0 {
            self.cpu.set_gpr(0, u64::MAX);
            return Ok(None);
        }
        let argument = |index| {
            let value = self.cpu.get_gpr(index);
            if function & (1 << 30) != 0 {
                value
            } else {
                u64::from(value as u32)
            }
        };
        let result: i32 = match function {
            VERSION => 0x0001_0001,
            MIGRATE_TYPE => 2,
            SYSTEM_OFF | SYSTEM_RESET => return Ok(Some(VcpuExit::Shutdown)),
            FEATURES => {
                let queried = argument(1) as u32;
                match queried {
                    VERSION | MIGRATE_TYPE | SYSTEM_OFF | SYSTEM_RESET | FEATURES => 0,
                    CPU_OFF | CPU_ON32 | CPU_ON64 | AFFINITY32 | AFFINITY64
                        if self.cluster.is_some() =>
                    {
                        0
                    }
                    _ => -1,
                }
            }
            CPU_ON32 | CPU_ON64 => {
                if let Some(cluster) = &self.cluster {
                    let caller = self.cpu.pstate_bits();
                    let aarch32 = caller & 16 != 0;
                    let raw_entry = argument(2);
                    let pstate = if aarch32 {
                        0x1c0
                            | (if caller & 31 == 0x1a { 0x1a } else { 0x13 })
                            | ((raw_entry & 1) << 5)
                    } else {
                        0x3c1 | (caller & 0xc)
                    };
                    let entry = if aarch32 { raw_entry & !1 } else { raw_entry };
                    let device = in_window(entry, AARCH64_GICD_BASE, GICD_SIZE)
                        || crate::machine::arm_virt::aarch64_redist_frame(
                            entry,
                            cluster.count(),
                            cluster.high_redist_base,
                        )
                        .is_some()
                        || in_window(entry, UART_BASE, UART_SIZE);
                    if entry & (if pstate & 0x30 == 0x30 { 1 } else { 3 }) != 0
                        || device
                        || !self.physical_memory.check_range(
                            GuestAddress(entry),
                            if pstate & 0x30 == 0x30 { 2 } else { 4 },
                        )
                    {
                        -9
                    } else {
                        cluster.request_on(argument(1), entry, argument(3), pstate)?
                    }
                } else {
                    -3
                }
            }
            CPU_OFF => {
                if let Some(cluster) = &self.cluster {
                    cluster.request_off(self.id)?;
                    self.powered_off = true;
                    return Ok(Some(VcpuExit::Hlt));
                }
                -1
            }
            AFFINITY32 | AFFINITY64 => match &self.cluster {
                Some(cluster) => cluster.affinity_info(argument(1), argument(2) as u32)?,
                None => -1,
            },
            _ => -1,
        };
        // PSCI errors are signed int32 values. Preserve the adapter's existing
        // sign-extended representation; callers consume the defined low32 bits.
        self.cpu.set_gpr(0, i64::from(result) as u64);
        Ok(None)
    }
}
