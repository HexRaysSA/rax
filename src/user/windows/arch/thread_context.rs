use super::*;
use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;

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

    /// The measured AMD64 kernel view stores DR0-DR3 in BVR0-BVR3 and
    /// DR6 in BVR4. Only enabled instruction comparators reach the x86 core;
    /// the measured compatibility API normalizes data comparators off.
    pub(super) fn project_native_debug(&mut self) -> Result<(), u32> {
        use crate::user::windows::context::debug;
        let native = self.arm64.core().user_debug_registers();
        let mut bytes = Vec::with_capacity(48);
        for value in &native.breakpoint_value[..4] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&(native.breakpoint_value[4] | 0xffff_0ff0).to_le_bytes());
        let mut control = 0;
        for slot in 0..4 {
            if native.breakpoint_control[slot] & 1 != 0 && native.breakpoint_value[slot] != 0 {
                control |= 1 << (slot * 2);
            }
        }
        if control != 0 {
            control |= 0x400;
        }
        bytes.extend_from_slice(&u64::to_le_bytes(control));
        debug::apply_x86(&mut self.x64, WinArch::X64, &bytes)
    }

    pub(super) fn capture_native_debug_status(&mut self) -> Result<(), u32> {
        use crate::user::windows::context::debug;
        let bytes = debug::capture_x86(&self.x64, WinArch::X64)?;
        let mut native = self.arm64.core().user_debug_registers();
        native.breakpoint_value[4] = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        self.arm64.core_mut().set_user_debug_registers(native);
        Ok(())
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
        use crate::user::windows::context::debug;
        if arch == WinArch::Arm64 {
            return match self {
                Self::Arm64(cpu) => Ok(debug::capture_arm64(cpu)),
                Self::Arm64Ec(cpu) => Ok(debug::capture_arm64(&cpu.arm64)),
                Self::X86(_, WinArch::X64) => {
                    let mut copy = self.new_thread();
                    copy.enable_arm64ec()
                        .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    copy.kernel_debug_context(arch)
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            };
        }
        debug::capture_x86(self.x86().ok_or(STATUS_INVALID_PARAMETER)?, arch)
    }

    pub(crate) fn apply_kernel_debug_context(
        &mut self,
        arch: WinArch,
        bytes: &[u8],
        user_limit: u64,
    ) -> Result<(), u32> {
        use crate::user::windows::context::debug;
        if arch == WinArch::Arm64 {
            if bytes.len() != 120 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if matches!(self, Self::X86(_, WinArch::X64)) {
                self.enable_arm64ec()
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
            }
            return match self {
                Self::Arm64(cpu) => debug::apply_arm64(cpu, bytes, user_limit),
                Self::Arm64Ec(cpu) => {
                    debug::apply_arm64(&mut cpu.arm64, bytes, user_limit)?;
                    cpu.project_native_debug()
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            };
        }
        debug::apply_x86(self.x86_mut().ok_or(STATUS_INVALID_PARAMETER)?, arch, bytes)
    }
}

#[cfg(test)]
#[path = "thread_context/tests.rs"]
mod tests;
