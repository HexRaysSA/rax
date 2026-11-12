use super::*;
use crate::user::windows::context::{RegContext, arm64};

impl WinCpu {
    /// Decode the SDK ARM64EC_NT_CONTEXT overlay while retaining native-only
    /// registers and every unselected register group from the target CPU.
    pub(crate) fn arm64_context_from_amd64(
        &self,
        input: &[u8],
        selected: u32,
    ) -> Result<RegContext, u32> {
        if input.len() < 672 || self.arch() != WinArch::X64 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let u32_at = |off| u32::from_le_bytes(input[off..off + 4].try_into().unwrap());
        let u64_at = |off| u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        let mut context = self.arm64_kernel_context()?;
        let mut flags = 0x0040_0000;
        if selected & 1 != 0 {
            flags |= 1;
            context.set_sp(u64_at(152));
            context.set_pc(u64_at(248));
            context.set_gpr(29, u64_at(160));
            context.set_gpr(30, u64_at(288));
        }
        if selected & 2 != 0 {
            flags |= 2;
            for (arm, x64) in super::super::INTEGER {
                if arm != 29 {
                    context.set_gpr(arm as usize, u64_at(120 + x64 * 8));
                }
            }
            let mut high = [0u64; 2];
            for (n, arm) in super::super::X87_LOW.into_iter().enumerate() {
                if n != 0 {
                    context.set_gpr(arm as usize, u64_at(288 + n * 16));
                }
                let value =
                    u16::from_le_bytes(input[296 + n * 16..298 + n * 16].try_into().unwrap());
                high[n / 4] |= u64::from(value) << ((n % 4) * 16);
            }
            context.set_gpr(16, high[0]);
            context.set_gpr(17, high[1]);
        }
        if selected & 8 != 0 {
            flags |= 4;
            for n in 0..16 {
                context.set_v(
                    n,
                    u128::from_le_bytes(input[416 + n * 16..432 + n * 16].try_into().unwrap()),
                );
            }
        }
        let mut bytes = context.bytes().to_vec();
        if selected & 1 != 0 {
            let value = u32_at(68);
            let nzcv = ((value >> 7) & 1) << 31
                | ((value >> 6) & 1) << 30
                | (value & 1) << 29
                | ((value >> 11) & 1) << 28;
            bytes[arm64::CPSR..arm64::CPSR + 4].copy_from_slice(&nzcv.to_le_bytes());
        }
        if selected & 8 != 0 {
            let value = u32_at(52);
            let rounding = ((value >> 13) & 1) << 23 | ((value >> 14) & 1) << 22;
            let enables =
                ((!value >> 7) & 1) << 8 | ((!value >> 9) & 0xf) << 9 | ((!value >> 8) & 1) << 15;
            let fpcr = rounding | ((value >> 15) & 1) << 24 | enables;
            let fpsr = (value & 1) | ((value >> 2) & 0xf) << 1 | ((value >> 1) & 1) << 7;
            bytes[arm64::FPCR..arm64::FPCR + 4].copy_from_slice(&fpcr.to_le_bytes());
            bytes[arm64::FPSR..arm64::FPSR + 4].copy_from_slice(&fpsr.to_le_bytes());
        }
        let mut context = RegContext::from_bytes(WinArch::Arm64, bytes);
        context.set_flags(flags);
        Ok(context)
    }
}
