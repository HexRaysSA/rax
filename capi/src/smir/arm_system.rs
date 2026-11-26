//! Static GPR effects at privileged ARM frontiers. This is NOT a SMIR lift.
use super::*;
use crate::arch::RaxArch;
use crate::{RAX_MODE_ARM, RAX_MODE_LITTLE_ENDIAN};
use rax_engine::isa::arm::{
    ExecutionState,
    decoder::{Decoder, Mnemonic, Operand},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RaxArmSystemInfo {
    pub struct_size: u32,
    pub abi_version: u32,
    pub kind: u32,
    pub flags: u32,
    pub gpr_written: u32,
    pub gpr_read: u32,
    pub system_register: u32,
    pub reserved: u32,
}

/// Classify only system instructions; unknown state/memory/trap effects remain explicit.
#[unsafe(no_mangle)]
pub extern "C" fn rax_arm_system_info(
    arch: i32,
    mode: u32,
    pc: u64,
    bytes: *const c_void,
    len: usize,
    out: *mut RaxArmSystemInfo,
) -> RaxStatus {
    guard(|| {
        if out.is_null() {
            return RaxStatus::Arg;
        }
        let mut result = RaxArmSystemInfo {
            struct_size: size_of::<RaxArmSystemInfo>() as u32,
            abi_version: 1,
            ..Default::default()
        };
        // SAFETY: caller supplies a full aligned, writable output disjoint from input.
        unsafe { out.write(result) };
        let state = match RaxArch::from_i32(arch) {
            Some(RaxArch::Arm64) if mode & !RAX_MODE_LITTLE_ENDIAN == 0 => ExecutionState::Aarch64,
            Some(RaxArch::Arm) if mode & !(RAX_MODE_ARM | RAX_MODE_LITTLE_ENDIAN) == 0 => {
                ExecutionState::Aarch32
            }
            Some(RaxArch::Arm64 | RaxArch::Arm) => return RaxStatus::Mode,
            _ => return RaxStatus::Arch,
        };
        if bytes.is_null()
            || len != 4
            || pc & 3 != 0
            || (state == ExecutionState::Aarch32 && pc > u32::MAX as u64)
        {
            return RaxStatus::Arg;
        }
        // SAFETY: the input contract supplies four readable bytes, not overlapping out.
        let input = unsafe { slice::from_raw_parts(bytes.cast::<u8>(), len) };
        let Ok(decoded) = Decoder::new(state).decode(input) else {
            return RaxStatus::Unsupported;
        };
        let raw = u32::from_le_bytes(input.try_into().unwrap());
        result.kind = if state == ExecutionState::Aarch64 && matches!(raw, 0xd50040bf | 0xd50041bf)
        {
            // MSR SPSel,#0/#1: native metadata is UNDEFINED/SYS respectively.
            2
        } else {
            match decoded.mnemonic {
                Mnemonic::MRS | Mnemonic::MRC | Mnemonic::SYSL | Mnemonic::VMRS => 1,
                Mnemonic::MSR | Mnemonic::MCR | Mnemonic::VMSR => 2,
                Mnemonic::SYS | Mnemonic::DMB | Mnemonic::DSB | Mnemonic::ISB => 3,
                _ => return RaxStatus::Unsupported,
            }
        };
        // State changes, exceptions, privilege checks and memory effects are unknown.
        result.flags = 1;
        result.system_register = u32::MAX;
        // Native metadata currently calls the whole SYS/SYSL space SYS and
        // omits Rt. Preserve SYSL's GPR destination instead of assuming none.
        if state == ExecutionState::Aarch64 && decoded.mnemonic == Mnemonic::SYS && result.kind == 3
        {
            let rt = raw & 31;
            if raw & (1 << 21) != 0 {
                result.kind = 1;
                if rt < 31 {
                    result.gpr_written = 1 << rt;
                }
            } else if rt < 31 {
                result.gpr_read = 1 << rt;
            }
        }
        for operand in &decoded.operands {
            if let Operand::SysReg(encoding) = operand {
                result.system_register = u32::from(*encoding);
            }
            if let Operand::Reg(reg) = operand {
                if reg.num
                    < if state == ExecutionState::Aarch64 {
                        31
                    } else {
                        15
                    }
                {
                    if result.kind == 1 {
                        result.gpr_written |= 1u32 << reg.num;
                    } else {
                        result.gpr_read |= 1u32 << reg.num;
                    }
                }
            }
        }
        // Some A32 native metadata omits MSR operands. Read-all is conservative.
        if result.kind != 1 && result.gpr_read == 0 {
            result.gpr_read = if state == ExecutionState::Aarch64 {
                0x7fffffff
            } else {
                0x7fff
            };
        }
        // SAFETY: same initialized output extent as the initial write.
        unsafe { out.write(result) };
        RaxStatus::Ok
    })
}
