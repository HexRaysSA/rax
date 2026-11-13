//! Fixed Windows CONTEXT debug-register groups shared by API and SEH paths.
use super::{RegContext, STATUS_INVALID_PARAMETER, WinArch};
use crate::user::cpu::{aarch64::A64UserCpu, x86_64::X86UserCpu};
use crate::vm::vcpu::{CpuState, VCpu};

/// Debug fields in the fixed Windows CONTEXT layouts.
pub(crate) fn context_range(arch: WinArch) -> std::ops::Range<usize> {
    match arch {
        WinArch::Arm64 => 792..912,
        WinArch::X86 => 4..28,
        WinArch::X64 => 72..120,
    }
}

pub(crate) fn capture_arm64(cpu: &A64UserCpu) -> Vec<u8> {
    let state = cpu.core().user_debug_registers();
    let mut bytes = Vec::with_capacity(120);
    for value in &state.breakpoint_control[..8] {
        bytes.extend_from_slice(&(*value as u32).to_le_bytes());
    }
    for value in &state.breakpoint_value[..8] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in &state.watchpoint_control[..2] {
        bytes.extend_from_slice(&(*value as u32).to_le_bytes());
    }
    for value in &state.watchpoint_value[..2] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

pub(crate) fn apply_arm64(cpu: &mut A64UserCpu, bytes: &[u8], user_limit: u64) -> Result<(), u32> {
    if bytes.len() != 120 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut state = cpu.core().user_debug_registers();
    let control = |offset| {
        let value = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        u64::from((value & 0xffff_3ffd) | 4)
    };
    let address = |offset| {
        let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if value < user_limit { value } else { 0 }
    };
    for slot in 0..8 {
        state.breakpoint_control[slot] = control(slot * 4);
        state.breakpoint_value[slot] = address(32 + slot * 8);
    }
    for slot in 0..2 {
        state.watchpoint_control[slot] = control(96 + slot * 4);
        state.watchpoint_value[slot] = address(104 + slot * 8);
    }
    cpu.core_mut().set_user_debug_registers(state);
    Ok(())
}

pub(crate) fn capture_x86(cpu: &X86UserCpu, arch: WinArch) -> Result<Vec<u8>, u32> {
    let CpuState::X86_64(state) = cpu
        .vcpu()
        .get_state()
        .map_err(|_| STATUS_INVALID_PARAMETER)?
    else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let registers = state.sregs;
    let width = arch.ptr_size() as usize;
    let mut bytes = Vec::with_capacity(6 * width);
    for value in [
        registers.dr0,
        registers.dr1,
        registers.dr2,
        registers.dr3,
        registers.dr6,
        registers.dr7,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes()[..width]);
    }
    Ok(bytes)
}

pub(crate) fn apply_x86(cpu: &mut X86UserCpu, arch: WinArch, bytes: &[u8]) -> Result<(), u32> {
    let width = arch.ptr_size() as usize;
    if bytes.len() != 6 * width {
        return Err(STATUS_INVALID_PARAMETER);
    }
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

impl RegContext {
    pub(super) fn capture_x86_debug(&mut self, cpu: &X86UserCpu) {
        // A concrete software x86 core always returns its own CpuState variant.
        let bytes = capture_x86(cpu, self.arch).expect("software x86 debug-register capture");
        let start = if self.arch == WinArch::X86 { 4 } else { 72 };
        self.bytes[start..start + bytes.len()].copy_from_slice(&bytes);
    }

    pub(super) fn apply_x86_debug(&self, cpu: &mut X86UserCpu) -> Result<(), u32> {
        if self.flags() & super::DEBUG_X86 != 0 {
            let range = if self.arch == WinArch::X86 {
                4..28
            } else {
                72..120
            };
            apply_x86(cpu, self.arch, &self.bytes[range])?;
        }
        Ok(())
    }
}
