use super::*;
use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;
use crate::vm::vcpu::{CpuState, VCpu};

#[path = "thread_context/compat.rs"]
mod compat;

impl Arm64EcCpu {
    /// Native controls establish V16-V31/YMM-high context aliases for AMD64,
    /// independently of the ABI's restriction on using these ARM64 registers.
    /// Reconcile only changed values so an unselected native vector survives
    /// a legacy or CONTROL-only update. Simultaneous changes follow the core
    /// that owns execution. Work and storage are bounded by sixteen registers.
    pub(super) fn sync_ymm(&mut self) {
        for n in 0..16 {
            let x64 = self.x64.vcpu().user_regs().ymm_high[n];
            let native = self.arm64.core().get_simd((n + 16) as u8);
            let arm64 = [native as u64, (native >> 64) as u64];
            let value = if x64 == arm64 || arm64 == self.ymm_shadow[n] {
                x64
            } else if x64 == self.ymm_shadow[n] || self.active {
                arm64
            } else {
                x64
            };
            self.x64.vcpu_mut().user_regs_mut().ymm_high[n] = value;
            self.arm64.core_mut().set_simd(
                (n + 16) as u8,
                u128::from(value[0]) | (u128::from(value[1]) << 64),
            );
            self.ymm_shadow[n] = value;
        }
    }
}

impl WinCpu {
    pub(crate) fn kernel_ymm_high(&self) -> Result<[[u64; 2]; 16], u32> {
        if let Self::Arm64Ec(cpu) = self {
            let mut copy = cpu.clone_thread();
            copy.sync_ymm();
            return Ok(copy.x64.vcpu().user_regs().ymm_high);
        }
        Ok(self
            .x86()
            .ok_or(STATUS_INVALID_PARAMETER)?
            .vcpu()
            .user_regs()
            .ymm_high)
    }

    pub(crate) fn apply_kernel_ymm_high(&mut self, values: [[u64; 2]; 16]) -> Result<(), u32> {
        if let Self::Arm64Ec(cpu) = self {
            cpu.sync_ymm();
        }
        let count = if self.arch() == WinArch::X86 { 8 } else { 16 };
        self.x86_mut()
            .ok_or(STATUS_INVALID_PARAMETER)?
            .vcpu_mut()
            .user_regs_mut()
            .ymm_high[..count]
            .copy_from_slice(&values[..count]);
        if let Self::Arm64Ec(cpu) = self {
            cpu.sync_ymm();
        }
        Ok(())
    }

    pub(crate) fn kernel_debug_context(&self, arch: WinArch) -> Result<Vec<u8>, u32> {
        if arch == WinArch::Arm64 {
            let core = match self {
                Self::Arm64(cpu) => cpu.core(),
                Self::Arm64Ec(cpu) => cpu.arm64.core(),
                Self::X86(_, WinArch::X64) => {
                    let mut copy = self.new_thread();
                    copy.enable_arm64ec()
                        .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    return copy.kernel_debug_context(arch);
                }
                _ => return Err(STATUS_INVALID_PARAMETER),
            };
            let state = core.user_debug_registers();
            let mut bytes = Vec::with_capacity(120);
            for v in &state.breakpoint_control[..8] {
                bytes.extend_from_slice(&(*v as u32).to_le_bytes());
            }
            for v in &state.breakpoint_value[..8] {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            for v in &state.watchpoint_control[..2] {
                bytes.extend_from_slice(&(*v as u32).to_le_bytes());
            }
            for v in &state.watchpoint_value[..2] {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            return Ok(bytes);
        }
        let state = self
            .x86()
            .ok_or(STATUS_INVALID_PARAMETER)?
            .vcpu()
            .get_state()
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        let CpuState::X86_64(state) = state else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let s = state.sregs;
        let values = [s.dr0, s.dr1, s.dr2, s.dr3, s.dr6, s.dr7];
        let mut bytes = Vec::with_capacity(6 * arch.ptr_size() as usize);
        for value in values {
            if arch == WinArch::X86 {
                bytes.extend_from_slice(&(value as u32).to_le_bytes());
            } else {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        Ok(bytes)
    }

    pub(crate) fn apply_kernel_debug_context(
        &mut self,
        arch: WinArch,
        bytes: &[u8],
        user_limit: u64,
    ) -> Result<(), u32> {
        if arch == WinArch::Arm64 {
            if bytes.len() != 120 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if matches!(self, Self::X86(_, WinArch::X64)) {
                self.enable_arm64ec()
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
            }
            let core = match self {
                Self::Arm64(cpu) => cpu.core_mut(),
                Self::Arm64Ec(cpu) => cpu.arm64.core_mut(),
                _ => return Err(STATUS_INVALID_PARAMETER),
            };
            let mut state = core.user_debug_registers();
            let u32_at =
                |off| u64::from(u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()));
            let u64_at = |off| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            for n in 0..8 {
                state.breakpoint_control[n] = (u32_at(n * 4) & 0xffff_3ffd) | 4;
                let address = u64_at(32 + n * 8);
                state.breakpoint_value[n] = if address < user_limit { address } else { 0 };
            }
            for n in 0..2 {
                state.watchpoint_control[n] = (u32_at(96 + n * 4) & 0xffff_3ffd) | 4;
                let address = u64_at(104 + n * 8);
                state.watchpoint_value[n] = if address < user_limit { address } else { 0 };
            }
            core.set_user_debug_registers(state);
            return Ok(());
        }
        let width = arch.ptr_size() as usize;
        if bytes.len() != 6 * width {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let cpu = self.x86_mut().ok_or(STATUS_INVALID_PARAMETER)?;
        let mut state = cpu
            .vcpu()
            .get_state()
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        let CpuState::X86_64(x86) = &mut state else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        for (slot, input) in [
            &mut x86.sregs.dr0,
            &mut x86.sregs.dr1,
            &mut x86.sregs.dr2,
            &mut x86.sregs.dr3,
            &mut x86.sregs.dr6,
            &mut x86.sregs.dr7,
        ]
        .into_iter()
        .zip(bytes.chunks_exact(width))
        {
            *slot = if width == 4 {
                u64::from(u32::from_le_bytes(input.try_into().unwrap()))
            } else {
                u64::from_le_bytes(input.try_into().unwrap())
            };
        }
        cpu.vcpu_mut()
            .set_state(&state)
            .map_err(|_| STATUS_INVALID_PARAMETER)
    }
}

#[cfg(test)]
#[path = "thread_context/tests.rs"]
mod tests;
