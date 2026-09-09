//! Exact helper-backed EVEX gather/scatter lowering with per-lane commit.

use std::collections::HashMap;

use super::{X86_64Lowerer, X86Cond, X86Emitter};
use crate::smir::ir::types::{
    Address, DispSize, MemWidth, OpWidth, SignExtend, VReg, VecElementType, VecWidth, X86Reg,
};
use crate::smir::ir::{SmirBlock, X86EvexVsibMemoryEncoding};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CS_L_OFFSET, X86_GUEST_FS_BASE_OFFSET, X86_GUEST_GS_BASE_OFFSET,
    X86_GUEST_K_OFFSET, X86_GUEST_VSIB_INSTRUCTION_ORDINAL_OFFSET, X86_GUEST_ZMM_OFFSET,
};

/// One architecturally selected VSIB lane. This descriptor is generated only
/// after the source bytes and complete SMIR decomposition have been matched.
#[derive(Clone, Copy)]
pub(super) struct X86JitVsibLane {
    pub encoding: X86EvexVsibMemoryEncoding,
    pub lane: u8,
}

impl X86JitVsibLane {
    pub(super) fn validate(self, is_load: bool, width: MemWidth) -> Result<(), LowerError> {
        let encoding = self.encoding;
        if is_load == encoding.scatter
            || !matches!(
                encoding.data_elem,
                VecElementType::I32 | VecElementType::I64
            )
            || !matches!(
                encoding.index_elem,
                VecElementType::I32 | VecElementType::I64
            )
            || width.bytes() != encoding.data_elem.bytes()
            || encoding.data_register >= 32
            || encoding.index_register >= 32
            || !(1..=7).contains(&encoding.writemask)
            || !(1..=16).contains(&encoding.lanes)
            || self.lane >= encoding.lanes
            || !matches!(encoding.scale, 1 | 2 | 4 | 8)
            || encoding.base.is_some_and(|base| base >= 32)
            || !matches!(
                encoding.segment,
                None | Some(X86Reg::FsBase | X86Reg::GsBase)
            )
            || i32::try_from(encoding.displacement).is_err()
            || (!encoding.scatter && encoding.data_register == encoding.index_register)
        {
            return Err(LowerError::InvalidOperand {
                op: "jit-mem VSIB lane".to_string(),
                operand: "invalid validated VSIB lane descriptor".to_string(),
            });
        }
        Ok(())
    }

    fn data_offset(self) -> i32 {
        X86_GUEST_ZMM_OFFSET
            + i32::from(self.encoding.data_register) * 64
            + i32::from(self.lane) * self.encoding.data_elem.bytes() as i32
    }

    fn data_width(self) -> OpWidth {
        if self.encoding.data_elem == VecElementType::I32 {
            OpWidth::W32
        } else {
            OpWidth::W64
        }
    }
}

impl X86_64Lowerer {
    /// The graph and byte classifier describe 64-bit code. Compatibility-mode
    /// vector-register extensions and address-size defaults differ, so exit
    /// at this instruction before even a zero-mask completion changes state.
    fn emit_jit_vsib_long_mode_guard(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_bytes(&[0x48, 0x83, 0xB8]); // cmp qword [rax+cs_l],0
        self.code.emit_u32(X86_GUEST_CS_L_OFFSET as u32);
        self.code.emit_u8(0);
        let enabled = self.emit_jcc_placeholder(X86Cond::Ne);
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        self.emit_native_exit(guest_pc);
        self.patch_rel32_to_current(enabled)?;
        // One dynamic VSIB occurrence, including zero-mask completion. This
        // internal ordinal distinguishes repeated visits to the same guest PC
        // when a native backedge executes before a later lane fault.
        self.code.emit_bytes(&[0x48, 0xFF, 0x80]); // inc qword [rax+ordinal]
        self.code
            .emit_u32(X86_GUEST_VSIB_INSTRUCTION_ORDINAL_OFFSET as u32);
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        Ok(())
    }

    /// RAX points to the already synchronized guest state; every guest GPR
    /// and status flag has been saved by the scalar helper prologue.
    ///
    /// offset = base + sign_extend(index[lane]) * scale + displacement;
    /// linear = zero_extend(offset mod 2^32) + segment_base for addr32,
    /// otherwise offset mod 2^64 + segment_base. Segment addition is last.
    pub(super) fn emit_jit_vsib_lane_address(
        &mut self,
        lane: X86JitVsibLane,
    ) -> Result<(), LowerError> {
        let encoding = lane.encoding;
        let index_offset = X86_GUEST_ZMM_OFFSET
            + i32::from(encoding.index_register) * 64
            + i32::from(lane.lane) * encoding.index_elem.bytes() as i32;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if encoding.index_elem == VecElementType::I32 {
                emitter.emit_movsx_rm_disp(
                    PhysReg::Rsi,
                    PhysReg::Rax,
                    index_offset,
                    DispSize::Disp32,
                    OpWidth::W32,
                    OpWidth::W64,
                );
            } else {
                emitter.emit_mov_rm(PhysReg::Rsi, PhysReg::Rax, index_offset, OpWidth::W64);
            }
            let shift = encoding.scale.trailing_zeros() as u8;
            if shift != 0 {
                emitter.emit_shl_ri(PhysReg::Rsi, shift, OpWidth::W64);
            }
            if let Some(base) = encoding.base {
                emitter.emit_mov_rm(
                    PhysReg::Rdi,
                    PhysReg::Rax,
                    i32::from(base) * 8,
                    OpWidth::W64,
                );
                emitter.emit_add_rr(PhysReg::Rsi, PhysReg::Rdi, OpWidth::W64);
            }
            if encoding.displacement != 0 {
                emitter.emit_add_ri(PhysReg::Rsi, encoding.displacement, OpWidth::W64);
            }
            if encoding.address_32 {
                emitter.emit_mov_rr(PhysReg::Rsi, PhysReg::Rsi, OpWidth::W32);
            }
            if let Some(segment) = encoding.segment {
                let offset = match segment {
                    X86Reg::FsBase => X86_GUEST_FS_BASE_OFFSET,
                    X86Reg::GsBase => X86_GUEST_GS_BASE_OFFSET,
                    _ => {
                        return Err(LowerError::InvalidOperand {
                            op: "jit-mem VSIB segment".to_string(),
                            operand: "non-FS/GS segment".to_string(),
                        });
                    }
                };
                emitter.emit_mov_rm(PhysReg::Rdi, PhysReg::Rax, offset, OpWidth::W64);
                emitter.emit_add_rr(PhysReg::Rsi, PhysReg::Rdi, OpWidth::W64);
            }
        }
        Ok(())
    }

    /// Marshal exactly 4 or 8 source bytes into the store helper's u64 value.
    pub(super) fn emit_jit_vsib_store_value(&mut self, lane: X86JitVsibLane) {
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_rm(
            PhysReg::Rdx,
            PhysReg::Rax,
            lane.data_offset(),
            lane.data_width(),
        );
    }

    /// RCX is the state pointer and RAX is the successful load result (or the
    /// store success flag). Commit before reloading physical vector/mask
    /// carriers, so every subsequent helper fault exposes completed lanes.
    pub(super) fn emit_jit_vsib_lane_commit(&mut self, lane: X86JitVsibLane) {
        let mut emitter = X86Emitter::new(&mut self.code);
        if !lane.encoding.scatter {
            emitter.emit_mov_mr(
                PhysReg::Rcx,
                lane.data_offset(),
                PhysReg::Rax,
                lane.data_width(),
            );
        }
        let mask_offset = X86_GUEST_K_OFFSET + i32::from(lane.encoding.writemask) * 8;
        emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rcx, mask_offset, OpWidth::W64);
        emitter.emit_and_ri(PhysReg::Rdx, !(1i64 << lane.lane), OpWidth::W64);
        emitter.emit_mov_mr(PhysReg::Rcx, mask_offset, PhysReg::Rdx, OpWidth::W64);
    }

    fn emit_guarded_jit_vsib_lane(
        &mut self,
        guest_pc: u64,
        lane: X86JitVsibLane,
    ) -> Result<(), LowerError> {
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push guest RAX
        // At most 16 lanes exist. KMOVW requires AVX512F, not AVX512BW.
        self.emit_opmask_mask_to_rax16(lane.encoding.writemask);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_test_ri(PhysReg::Rax, 1i64 << lane.lane, OpWidth::W32);
        }
        let inactive = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        let width = if lane.encoding.data_elem == VecElementType::I32 {
            MemWidth::B4
        } else {
            MemWidth::B8
        };
        self.emit_jit_mem_op_with_vsib_lane(
            guest_pc,
            !lane.encoding.scatter,
            None,
            None,
            None,
            None,
            None,
            &Address::Absolute(0),
            width,
            SignExtend::Zero,
            0,
            false,
            None,
            0,
            false,
            Some(lane),
        )?;
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);
        self.patch_rel32_to_current(inactive)?;
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9D);
        self.patch_rel32_to_current(done)
    }

    fn emit_jit_vsib_completion(&mut self, encoding: X86EvexVsibMemoryEncoding) {
        self.code.emit_u8(0x50); // push guest RAX; MOV/VMOVDQU/KMOV preserve flags
        self.emit_load_state_ptr_rax();
        if !encoding.scatter {
            let offset = X86_GUEST_ZMM_OFFSET + i32::from(encoding.data_register) * 64;
            let register = PhysReg::Zmm(encoding.data_register);
            // A zero-mask instruction may follow a native vector producer;
            // publish its current carrier before retaining inactive low lanes.
            self.emit_unaligned_vector_store(register, VecWidth::V512, offset);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                let used = i32::from(encoding.lanes) * encoding.data_elem.bytes() as i32;
                for byte in (used..64).step_by(8) {
                    emitter.emit_mov_mi_disp(
                        PhysReg::Rax,
                        offset + byte,
                        DispSize::Disp32,
                        0,
                        OpWidth::W64,
                    );
                }
            }
            self.emit_unaligned_vector_load(register, VecWidth::V512, offset);
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mi_disp(
                PhysReg::Rax,
                X86_GUEST_K_OFFSET + i32::from(encoding.writemask) * 8,
                DispSize::Disp32,
                0,
                OpWidth::W64,
            );
            emitter.emit_mov_ri(PhysReg::Rax, 0, OpWidth::W32);
        }
        self.code
            .emit_bytes(&[0xC5, 0xF8, 0x92, 0xC0 | (encoding.writemask << 3)]); // KMOVW k,eax
        self.code.emit_u8(0x58);
    }

    /// Fuse only the exact complete VSIB graph. Generated native code has
    /// O(lanes) size, uses O(1) host stack space, and invokes one ordinary
    /// guest-MMU helper per active lane, in ascending lane order. It emits no
    /// host gather/scatter and does not call an instruction interpreter.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_evex_vsib_memory(
        &mut self,
        block: &SmirBlock,
        index: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_evex_vsib_memory_sequence(
            block,
            index,
            true,
            &self.x86_instruction_bytes,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };
        if self.avx_ymm16_vector_state
            || !self.native_vector_state_active
            || !self.preserve_vector_mem_helpers
        {
            return Err(LowerError::InvalidOperand {
                op: "EVEX VSIB memory".to_string(),
                operand: "full AVX512F vector/mask helper state bridge is required".to_string(),
            });
        }
        self.emit_jit_vsib_long_mode_guard(block.ops[index].guest_pc)?;
        for lane in 0..sequence.encoding.lanes {
            self.emit_guarded_jit_vsib_lane(
                block.ops[index].guest_pc,
                X86JitVsibLane {
                    encoding: sequence.encoding,
                    lane,
                },
            )?;
        }
        self.emit_jit_vsib_completion(sequence.encoding);
        Ok(Some(sequence.consumed))
    }
}
