//! memory.rs

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::instructions::neon::*;
use crate::isa::arm::aarch32::instructions::*;
use crate::isa::arm::aarch32::vfp::{
    Fpscr, NeonSize, RoundingMode, vabs_f16_bits, vabs_f32, vabs_f64, vadd_f16_bits, vadd_f32,
    vadd_f64, vadd_i, vand, vbic, vcls_i, vclz_i, vcmp_f16_bits_with_exception,
    vcmp_f32_with_exception, vcmp_f64_with_exception, vcnt_i8, vcvt_f16_bits_f32,
    vcvt_f32_f16_bits, vcvt_f32_f64, vcvt_f32_s32, vcvt_f32_s32_fixed, vcvt_f32_u32,
    vcvt_f32_u32_fixed, vcvt_f64_f32, vcvt_f64_s32, vcvt_f64_s32_fixed, vcvt_f64_u32,
    vcvt_f64_u32_fixed, vcvt_s32_f32, vcvt_s32_f32_fixed, vcvt_s32_f32_round, vcvt_s32_f64,
    vcvt_s32_f64_fixed, vcvt_s32_f64_round, vcvt_u32_f32, vcvt_u32_f32_fixed, vcvt_u32_f32_round,
    vcvt_u32_f64, vcvt_u32_f64_fixed, vcvt_u32_f64_round, vcvtr_s32_f32, vcvtr_s32_f64,
    vcvtr_u32_f32, vcvtr_u32_f64, vdiv_f16_bits, vdiv_f32, vdiv_f64, veor, vfma_f16_bits, vfma_f32,
    vfma_f64, vfms_f16_bits, vfms_f32, vfms_f64, vfnma_f16_bits, vfnma_f32, vfnma_f64,
    vfnms_f16_bits, vfnms_f32, vfnms_f64, vfp_expand_imm_f16, vfp_expand_imm_f32,
    vfp_expand_imm_f64, vmaxnm_f16_bits, vmaxnm_f32, vmaxnm_f64, vminnm_f16_bits, vminnm_f32,
    vminnm_f64, vmla_f16_bits, vmla_f32, vmla_f64, vmls_f16_bits, vmls_f32, vmls_f64,
    vmul_f16_bits, vmul_f32, vmul_f64, vmvn, vneg_f16_bits, vneg_f32, vneg_f64, vnmla_f16_bits,
    vnmla_f32, vnmla_f64, vnmls_f16_bits, vnmls_f32, vnmls_f64, vnmul_f16_bits, vnmul_f32,
    vnmul_f64, vorn, vorr, vrev, vrint_f16_bits, vrint_f32, vrint_f64, vsqrt_f16_bits, vsqrt_f32,
    vsqrt_f64, vsub_f16_bits, vsub_f32, vsub_f64, vsub_i,
};
use crate::isa::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};

impl<'a, M: ArmMemory> Executor<'a, M> {
    /// VLDR and VSTR's `MemA`: a halfword (half precision) or a word
    /// aligned to its size, whatever SCTLR.A says.
    fn vfp_misaligned(addr: u32, size: u32) -> Option<ExecResult> {
        let align = if size == 16 { 2 } else { 4 };
        (addr % align != 0).then_some(ExecResult::MemoryFault(MemoryError::Unaligned(addr)))
    }

    pub(crate) fn exec_vldr(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((addr, size, d)) = self.decode_vfp_mem(insn) else {
            return ExecResult::Undefined;
        };
        if let Some(fault) = Self::vfp_misaligned(addr, size) {
            return fault;
        }
        match size {
            16 => match self.mem.read_halfword(addr) {
                Ok(bits) => {
                    self.cpu.vfp.write_s_bits(d, bits as u32);
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            },
            32 => match self.mem.read_word(addr) {
                Ok(bits) => {
                    self.cpu.vfp.write_s_bits(d, bits);
                    ExecResult::Continue
                }
                Err(e) => ExecResult::MemoryFault(e),
            },
            64 => {
                let lo = match self.mem.read_word(addr) {
                    Ok(v) => v,
                    Err(e) => return ExecResult::MemoryFault(e),
                };
                let hi = match self.mem.read_word(addr.wrapping_add(4)) {
                    Ok(v) => v,
                    Err(e) => return ExecResult::MemoryFault(e),
                };
                self.cpu
                    .vfp
                    .write_d_bits(d, ((hi as u64) << 32) | lo as u64);
                ExecResult::Continue
            }
            _ => ExecResult::Undefined,
        }
    }

    pub(crate) fn exec_vstr(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((addr, size, d)) = self.decode_vfp_mem(insn) else {
            return ExecResult::Undefined;
        };
        if let Some(fault) = Self::vfp_misaligned(addr, size) {
            return fault;
        }
        match size {
            16 => match self
                .mem
                .write_halfword(addr, self.cpu.vfp.read_s_bits(d) as u16)
            {
                Ok(()) => ExecResult::Continue,
                Err(e) => ExecResult::MemoryFault(e),
            },
            32 => match self.mem.write_word(addr, self.cpu.vfp.read_s_bits(d)) {
                Ok(()) => ExecResult::Continue,
                Err(e) => ExecResult::MemoryFault(e),
            },
            64 => {
                let bits = self.cpu.vfp.read_d_bits(d);
                if let Err(e) = self.mem.write_word(addr, bits as u32) {
                    return ExecResult::MemoryFault(e);
                }
                if let Err(e) = self
                    .mem
                    .write_word(addr.wrapping_add(4), (bits >> 32) as u32)
                {
                    return ExecResult::MemoryFault(e);
                }
                ExecResult::Continue
            }
            _ => ExecResult::Undefined,
        }
    }

    pub(crate) fn exec_vldm(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((addr, final_addr, size, first, count, writeback, rn)) =
            self.decode_vfp_block_mem(insn)
        else {
            return ExecResult::Undefined;
        };
        // MemA: word alignment, checked at the first word.
        if addr & 3 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(addr));
        }

        let mut current = addr;
        for index in 0..count {
            let reg = first.wrapping_add(index);
            match size {
                32 => {
                    let bits = match self.mem.read_word(current) {
                        Ok(v) => v,
                        Err(e) => return ExecResult::MemoryFault(e),
                    };
                    self.cpu.vfp.write_s_bits(reg, bits);
                    current = current.wrapping_add(4);
                }
                64 => {
                    let lo = match self.mem.read_word(current) {
                        Ok(v) => v,
                        Err(e) => return ExecResult::MemoryFault(e),
                    };
                    let hi = match self.mem.read_word(current.wrapping_add(4)) {
                        Ok(v) => v,
                        Err(e) => return ExecResult::MemoryFault(e),
                    };
                    self.cpu
                        .vfp
                        .write_d_bits(reg, ((hi as u64) << 32) | lo as u64);
                    current = current.wrapping_add(8);
                }
                _ => return ExecResult::Undefined,
            }
        }

        if writeback {
            self.cpu.regs[rn] = final_addr;
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vstm(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((addr, final_addr, size, first, count, writeback, rn)) =
            self.decode_vfp_block_mem(insn)
        else {
            return ExecResult::Undefined;
        };
        // MemA: word alignment, checked at the first word.
        if addr & 3 != 0 {
            return ExecResult::MemoryFault(MemoryError::Unaligned(addr));
        }

        let mut current = addr;
        for index in 0..count {
            let reg = first.wrapping_add(index);
            match size {
                32 => {
                    if let Err(e) = self.mem.write_word(current, self.cpu.vfp.read_s_bits(reg)) {
                        return ExecResult::MemoryFault(e);
                    }
                    current = current.wrapping_add(4);
                }
                64 => {
                    let bits = self.cpu.vfp.read_d_bits(reg);
                    if let Err(e) = self.mem.write_word(current, bits as u32) {
                        return ExecResult::MemoryFault(e);
                    }
                    if let Err(e) = self
                        .mem
                        .write_word(current.wrapping_add(4), (bits >> 32) as u32)
                    {
                        return ExecResult::MemoryFault(e);
                    }
                    current = current.wrapping_add(8);
                }
                _ => return ExecResult::Undefined,
            }
        }

        if writeback {
            self.cpu.regs[rn] = final_addr;
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld1_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_all_lanes(insn) {
            return self.exec_vld_all_lanes(info);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vld_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let NeonStructMem {
            addr,
            regs,
            first,
            writeback,
            rn,
            rm,
            ..
        } = info;

        let mut current = addr;
        for index in 0..regs {
            let mut bits = 0u64;
            for byte in 0..8 {
                let value = match self.mem.read_byte(current) {
                    Ok(v) => v,
                    Err(e) => return ExecResult::MemoryFault(e),
                };
                bits |= (value as u64) << (byte * 8);
                current = current.wrapping_add(1);
            }
            self.cpu.vfp.write_d_bits(first + index, bits);
        }

        if writeback {
            self.cpu.regs[rn] = self.neon_struct_writeback(addr, regs, 1, rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vst1_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vst_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let NeonStructMem {
            addr,
            regs,
            first,
            writeback,
            rn,
            rm,
            ..
        } = info;

        let mut current = addr;
        for index in 0..regs {
            let bits = self.cpu.vfp.read_d_bits(first + index);
            for byte in 0..8 {
                if let Err(e) = self.mem.write_byte(current, (bits >> (byte * 8)) as u8) {
                    return ExecResult::MemoryFault(e);
                }
                current = current.wrapping_add(1);
            }
        }

        if writeback {
            self.cpu.regs[rn] = self.neon_struct_writeback(addr, regs, 1, rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld2_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_all_lanes(insn) {
            return self.exec_vld_all_lanes(info);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vld_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for r in 0..info.regs {
            for element in 0..elements {
                let first = match self.neon_read_mem_elem(current, info.ebytes) {
                    Ok(v) => v,
                    Err(e) => return ExecResult::MemoryFault(e),
                };
                let second_value = match self
                    .neon_read_mem_elem(current.wrapping_add(info.ebytes as u32), info.ebytes)
                {
                    Ok(v) => v,
                    Err(e) => return ExecResult::MemoryFault(e),
                };
                self.neon_write_d_elem(info.first + r, element, info.ebytes, first);
                self.neon_write_d_elem(second + r, element, info.ebytes, second_value);
                current = current.wrapping_add((info.ebytes * 2) as u32);
            }
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 2, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vst2_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vst_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for r in 0..info.regs {
            for element in 0..elements {
                let first = self.neon_read_d_elem(info.first + r, element, info.ebytes);
                let second_value = self.neon_read_d_elem(second + r, element, info.ebytes);
                if let Err(e) = self.neon_write_mem_elem(current, info.ebytes, first) {
                    return ExecResult::MemoryFault(e);
                }
                if let Err(e) = self.neon_write_mem_elem(
                    current.wrapping_add(info.ebytes as u32),
                    info.ebytes,
                    second_value,
                ) {
                    return ExecResult::MemoryFault(e);
                }
                current = current.wrapping_add((info.ebytes * 2) as u32);
            }
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 2, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld3_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_all_lanes(insn) {
            return self.exec_vld_all_lanes(info);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vld_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let third = second + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for element in 0..elements {
            let first = match self.neon_read_mem_elem(current, info.ebytes) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let second_value = match self
                .neon_read_mem_elem(current.wrapping_add(info.ebytes as u32), info.ebytes)
            {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let third_value = match self
                .neon_read_mem_elem(current.wrapping_add((info.ebytes * 2) as u32), info.ebytes)
            {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            self.neon_write_d_elem(info.first, element, info.ebytes, first);
            self.neon_write_d_elem(second, element, info.ebytes, second_value);
            self.neon_write_d_elem(third, element, info.ebytes, third_value);
            current = current.wrapping_add((info.ebytes * 3) as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 3, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vst3_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vst_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let third = second + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for element in 0..elements {
            let first = self.neon_read_d_elem(info.first, element, info.ebytes);
            let second_value = self.neon_read_d_elem(second, element, info.ebytes);
            let third_value = self.neon_read_d_elem(third, element, info.ebytes);
            if let Err(e) = self.neon_write_mem_elem(current, info.ebytes, first) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self.neon_write_mem_elem(
                current.wrapping_add(info.ebytes as u32),
                info.ebytes,
                second_value,
            ) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self.neon_write_mem_elem(
                current.wrapping_add((info.ebytes * 2) as u32),
                info.ebytes,
                third_value,
            ) {
                return ExecResult::MemoryFault(e);
            }
            current = current.wrapping_add((info.ebytes * 3) as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 3, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld4_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_all_lanes(insn) {
            return self.exec_vld_all_lanes(info);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vld_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let third = second + info.inc;
        let fourth = third + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for element in 0..elements {
            let first = match self.neon_read_mem_elem(current, info.ebytes) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let second_value = match self
                .neon_read_mem_elem(current.wrapping_add(info.ebytes as u32), info.ebytes)
            {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let third_value = match self
                .neon_read_mem_elem(current.wrapping_add((info.ebytes * 2) as u32), info.ebytes)
            {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let fourth_value = match self
                .neon_read_mem_elem(current.wrapping_add((info.ebytes * 3) as u32), info.ebytes)
            {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            self.neon_write_d_elem(info.first, element, info.ebytes, first);
            self.neon_write_d_elem(second, element, info.ebytes, second_value);
            self.neon_write_d_elem(third, element, info.ebytes, third_value);
            self.neon_write_d_elem(fourth, element, info.ebytes, fourth_value);
            current = current.wrapping_add((info.ebytes * 4) as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 4, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld_single_lane(&mut self, info: NeonSingleLaneMem) -> ExecResult {
        let mut current = info.addr;
        for stream in 0..info.streams {
            let value = match self.neon_read_mem_elem(current, info.ebytes) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            self.neon_write_d_elem(
                info.first + stream * info.inc,
                info.index,
                info.ebytes,
                value,
            );
            current = current.wrapping_add(info.ebytes as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] =
                self.neon_lane_writeback(info.addr, info.streams, info.ebytes, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vld_all_lanes(&mut self, info: NeonAllLanesMem) -> ExecResult {
        let mut current = info.addr;
        for stream in 0..info.streams {
            let value = match self.neon_read_mem_elem(current, info.ebytes) {
                Ok(v) => v,
                Err(e) => return ExecResult::MemoryFault(e),
            };
            let bits = Self::neon_replicate_elem(value, info.ebytes);
            let first = info.first + stream * info.inc;
            for reg in 0..info.regs {
                self.cpu.vfp.write_d_bits(first + reg, bits);
            }
            current = current.wrapping_add(info.ebytes as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] = if info.rm == 13 {
                info.addr
                    .wrapping_add((info.streams as u32) * (info.ebytes as u32))
            } else {
                info.addr.wrapping_add(self.reg(info.rm))
            };
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vst4_multiple(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if let Some(info) = self.decode_neon_vld_vst_single_lane(insn) {
            return self.exec_vst_single_lane(info);
        }
        let Some(info) = self.decode_neon_vld_vst_multiple(insn) else {
            return ExecResult::Undefined;
        };
        let second = info.first + info.inc;
        let third = second + info.inc;
        let fourth = third + info.inc;
        let elements = 8 / info.ebytes;
        let mut current = info.addr;

        for element in 0..elements {
            let first = self.neon_read_d_elem(info.first, element, info.ebytes);
            let second_value = self.neon_read_d_elem(second, element, info.ebytes);
            let third_value = self.neon_read_d_elem(third, element, info.ebytes);
            let fourth_value = self.neon_read_d_elem(fourth, element, info.ebytes);
            if let Err(e) = self.neon_write_mem_elem(current, info.ebytes, first) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self.neon_write_mem_elem(
                current.wrapping_add(info.ebytes as u32),
                info.ebytes,
                second_value,
            ) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self.neon_write_mem_elem(
                current.wrapping_add((info.ebytes * 2) as u32),
                info.ebytes,
                third_value,
            ) {
                return ExecResult::MemoryFault(e);
            }
            if let Err(e) = self.neon_write_mem_elem(
                current.wrapping_add((info.ebytes * 3) as u32),
                info.ebytes,
                fourth_value,
            ) {
                return ExecResult::MemoryFault(e);
            }
            current = current.wrapping_add((info.ebytes * 4) as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] = self.neon_struct_writeback(info.addr, info.regs, 4, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vst_single_lane(&mut self, info: NeonSingleLaneMem) -> ExecResult {
        let mut current = info.addr;
        for stream in 0..info.streams {
            let value =
                self.neon_read_d_elem(info.first + stream * info.inc, info.index, info.ebytes);
            if let Err(e) = self.neon_write_mem_elem(current, info.ebytes, value) {
                return ExecResult::MemoryFault(e);
            }
            current = current.wrapping_add(info.ebytes as u32);
        }

        if info.writeback {
            self.cpu.regs[info.rn] =
                self.neon_lane_writeback(info.addr, info.streams, info.ebytes, info.rm);
        }
        ExecResult::Continue
    }

    pub(crate) fn decode_neon_vld_vst_multiple(&self, insn: &DecodedInsn) -> Option<NeonStructMem> {
        let ty = (insn.raw >> 8) & 0xF;
        let size = ((insn.raw >> 6) & 0x3) as u8;
        let (regs, inc, streams) = match insn.mnemonic {
            Mnemonic::VLD1 | Mnemonic::VST1 => match ty {
                0b0111 => (1, 1, 1),
                0b1010 => (2, 1, 1),
                0b0110 => (3, 1, 1),
                0b0010 => (4, 1, 1),
                _ => return None,
            },
            Mnemonic::VLD2 | Mnemonic::VST2 => match ty {
                0b1000 => (1, 1, 2),
                0b1001 => (1, 2, 2),
                0b0011 => (2, 2, 2),
                _ => return None,
            },
            Mnemonic::VLD3 | Mnemonic::VST3 => match ty {
                0b0100 => (1, 1, 3),
                0b0101 => (1, 2, 3),
                _ => return None,
            },
            Mnemonic::VLD4 | Mnemonic::VST4 => match ty {
                0b0000 => (1, 1, 4),
                0b0001 => (1, 2, 4),
                _ => return None,
            },
            _ => return None,
        };

        let align = (insn.raw >> 4) & 0x3;
        match insn.mnemonic {
            Mnemonic::VLD1 | Mnemonic::VST1 => {
                if (regs == 1 || regs == 3) && (align & 0b10) != 0 {
                    return None;
                }
                if regs == 2 && align == 0b11 {
                    return None;
                }
            }
            Mnemonic::VLD2 | Mnemonic::VST2 => {
                if size == 0b11 || (regs == 1 && align == 0b11) {
                    return None;
                }
            }
            Mnemonic::VLD3 | Mnemonic::VST3 => {
                if size == 0b11 || (align & 0b10) != 0 {
                    return None;
                }
            }
            Mnemonic::VLD4 | Mnemonic::VST4 => {
                if size == 0b11 {
                    return None;
                }
            }
            _ => return None,
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let first = (d_bit << 4) | vd;
        let last = first
            .checked_add((streams - 1) * inc)?
            .checked_add(regs - 1)?;
        if last >= 32 {
            return None;
        }

        let rn = ((insn.raw >> 16) & 0xF) as usize;
        if rn == 15 {
            return None;
        }
        let rm = (insn.raw & 0xF) as usize;
        let writeback = rm != 15;
        Some(NeonStructMem {
            addr: self.reg(rn),
            regs,
            first,
            inc,
            ebytes: 1 << size,
            writeback,
            rn,
            rm,
        })
    }

    pub(crate) fn decode_neon_vld_all_lanes(&self, insn: &DecodedInsn) -> Option<NeonAllLanesMem> {
        if ((insn.raw >> 23) & 1) != 1 || ((insn.raw >> 21) & 1) != 1 {
            return None;
        }

        let ty = (insn.raw >> 8) & 0xF;
        let size = ((insn.raw >> 6) & 0x3) as u8;
        let t = ((insn.raw >> 5) & 1) as u8;
        let a = ((insn.raw >> 4) & 1) as u8;
        let (streams, regs, inc, ebytes) = match insn.mnemonic {
            Mnemonic::VLD1 if ty == 0b1100 => {
                if size == 0b11 || (size == 0 && a == 1) {
                    return None;
                }
                (1, if t == 0 { 1 } else { 2 }, 1, 1 << size)
            }
            Mnemonic::VLD2 if ty == 0b1101 => {
                if size == 0b11 {
                    return None;
                }
                (2, 1, if t == 0 { 1 } else { 2 }, 1 << size)
            }
            Mnemonic::VLD3 if ty == 0b1110 => {
                if size == 0b11 || a == 1 {
                    return None;
                }
                (3, 1, if t == 0 { 1 } else { 2 }, 1 << size)
            }
            Mnemonic::VLD4 if ty == 0b1111 => {
                if size == 0b11 && a == 0 {
                    return None;
                }
                (
                    4,
                    1,
                    if t == 0 { 1 } else { 2 },
                    if size == 0b11 { 4 } else { 1 << size },
                )
            }
            _ => return None,
        };

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let first = (d_bit << 4) | vd;
        let last = first
            .checked_add((streams - 1) * inc)?
            .checked_add(regs - 1)?;
        if last >= 32 {
            return None;
        }

        let rn = ((insn.raw >> 16) & 0xF) as usize;
        if rn == 15 {
            return None;
        }
        let rm = (insn.raw & 0xF) as usize;
        Some(NeonAllLanesMem {
            addr: self.reg(rn),
            streams,
            regs,
            first,
            inc,
            ebytes,
            writeback: rm != 15,
            rn,
            rm,
        })
    }

    pub(crate) fn decode_neon_vld_vst_single_lane(
        &self,
        insn: &DecodedInsn,
    ) -> Option<NeonSingleLaneMem> {
        if ((insn.raw >> 23) & 1) != 1 {
            return None;
        }
        let l = (insn.raw >> 21) & 1;
        if (l == 1)
            != matches!(
                insn.mnemonic,
                Mnemonic::VLD1 | Mnemonic::VLD2 | Mnemonic::VLD3 | Mnemonic::VLD4
            )
        {
            return None;
        }

        let size = ((insn.raw >> 10) & 0x3) as u8;
        let streams = (((insn.raw >> 8) & 0x3) + 1) as u8;
        let index_align = ((insn.raw >> 4) & 0xF) as u8;
        let (ebytes, index, inc) = Self::decode_neon_single_lane_shape(streams, size, index_align)?;

        let expected = match insn.mnemonic {
            Mnemonic::VLD1 | Mnemonic::VST1 => 1,
            Mnemonic::VLD2 | Mnemonic::VST2 => 2,
            Mnemonic::VLD3 | Mnemonic::VST3 => 3,
            Mnemonic::VLD4 | Mnemonic::VST4 => 4,
            _ => return None,
        };
        if streams != expected {
            return None;
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let first = (d_bit << 4) | vd;
        let last = first.checked_add((streams - 1) * inc)?;
        if last >= 32 {
            return None;
        }

        let rn = ((insn.raw >> 16) & 0xF) as usize;
        if rn == 15 {
            return None;
        }
        let rm = (insn.raw & 0xF) as usize;
        Some(NeonSingleLaneMem {
            addr: self.reg(rn),
            streams,
            first,
            inc,
            ebytes,
            index,
            writeback: rm != 15,
            rn,
            rm,
        })
    }

    pub(crate) fn decode_neon_single_lane_shape(
        streams: u8,
        size: u8,
        index_align: u8,
    ) -> Option<(u8, u8, u8)> {
        match (streams, size) {
            (1, 0) if (index_align & 0b0001) == 0 => Some((1, index_align >> 1, 1)),
            (1, 1) if (index_align & 0b0010) == 0 => Some((2, index_align >> 2, 1)),
            (1, 2)
                if (index_align & 0b0100) == 0 && matches!(index_align & 0b0011, 0b00 | 0b11) =>
            {
                Some((4, index_align >> 3, 1))
            }
            (2, 0) => Some((1, index_align >> 1, 1)),
            (2, 1) => Some((
                2,
                index_align >> 2,
                if (index_align & 0b0010) == 0 { 1 } else { 2 },
            )),
            (2, 2) if (index_align & 0b0010) == 0 => Some((
                4,
                index_align >> 3,
                if (index_align & 0b0100) == 0 { 1 } else { 2 },
            )),
            (3, 0) if (index_align & 0b0001) == 0 => Some((1, index_align >> 1, 1)),
            (3, 1) if (index_align & 0b0001) == 0 => Some((
                2,
                index_align >> 2,
                if (index_align & 0b0010) == 0 { 1 } else { 2 },
            )),
            (3, 2) if (index_align & 0b0011) == 0 => Some((
                4,
                index_align >> 3,
                if (index_align & 0b0100) == 0 { 1 } else { 2 },
            )),
            (4, 0) => Some((1, index_align >> 1, 1)),
            (4, 1) => Some((
                2,
                index_align >> 2,
                if (index_align & 0b0010) == 0 { 1 } else { 2 },
            )),
            (4, 2) if (index_align & 0b0011) != 0b0011 => Some((
                4,
                index_align >> 3,
                if (index_align & 0b0100) == 0 { 1 } else { 2 },
            )),
            _ => None,
        }
    }

    pub(crate) fn neon_read_vector_elements(&self, first: u8, regs: u8, ebytes: u8) -> Vec<u32> {
        let elements_per_d = 8 / ebytes;
        let mut elements = Vec::with_capacity(regs as usize * elements_per_d as usize);
        for reg in 0..regs {
            for element in 0..elements_per_d {
                elements.push(self.neon_read_d_elem(first + reg, element, ebytes));
            }
        }
        elements
    }

    pub(crate) fn neon_read_vector_elements_u64(
        &self,
        first: u8,
        regs: u8,
        ebytes: u8,
    ) -> Vec<u64> {
        let elements_per_d = 8 / ebytes;
        let mut elements = Vec::with_capacity(regs as usize * elements_per_d as usize);
        for reg in 0..regs {
            for element in 0..elements_per_d {
                elements.push(self.neon_read_d_elem_u64(first + reg, element, ebytes));
            }
        }
        elements
    }

    pub(crate) fn neon_write_vector_elements(
        &mut self,
        first: u8,
        regs: u8,
        ebytes: u8,
        elements: &[u32],
    ) {
        let elements_per_d = 8 / ebytes;
        debug_assert_eq!(elements.len(), regs as usize * elements_per_d as usize);
        let mut next = 0;
        for reg in 0..regs {
            for element in 0..elements_per_d {
                self.neon_write_d_elem(first + reg, element, ebytes, elements[next]);
                next += 1;
            }
        }
    }

    pub(crate) fn neon_write_vector_elements_u64(
        &mut self,
        first: u8,
        regs: u8,
        ebytes: u8,
        elements: &[u64],
    ) {
        let elements_per_d = 8 / ebytes;
        debug_assert_eq!(elements.len(), regs as usize * elements_per_d as usize);
        let mut next = 0;
        for reg in 0..regs {
            for element in 0..elements_per_d {
                self.neon_write_d_elem_u64(first + reg, element, ebytes, elements[next]);
                next += 1;
            }
        }
    }
}
