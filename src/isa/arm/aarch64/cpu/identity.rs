//! Stable PE affinity supplied by the embedding execution environment.
use super::{AArch64Config, AArch64Cpu, ArmMemory};
impl AArch64Cpu {
    /// Encode a linear CPU ID into the four eight-bit MPIDR affinity levels.
    /// RES1 bit 31 is set; U, MT and all reserved fields are clear. The caller
    /// owns topology allocation and uniqueness. CPU zero retains `new`'s value.
    pub const fn mpidr_for_cpu_id(id: u32) -> u64 {
        0x8000_0000 | ((id as u64) & 0x00ff_ffff) | (((id as u64) >> 24) << 32)
    }

    /// Construct a PE with immutable configured affinity. Warm reset and
    /// system-state import preserve this hardware identity. The original
    /// `new` constructor continues to represent CPU zero.
    pub fn new_with_cpu_id(config: AArch64Config, memory: Box<dyn ArmMemory>, id: u32) -> Self {
        let mut cpu = Self::new(config, memory);
        cpu.sysregs.mpidr_el1 = Self::mpidr_for_cpu_id(id);
        cpu
    }
}
