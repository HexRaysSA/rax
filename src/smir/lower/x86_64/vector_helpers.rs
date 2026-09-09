//! Vector-state preservation across native-to-Rust helper boundaries.

use super::{X86_64Lowerer, X86Emitter};
use crate::smir::ir::ops::{X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{Address, DispSize, MemWidth, OpWidth, VecWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_K_OFFSET, X86_GUEST_MXCSR_OFFSET, X86_GUEST_VECTOR_SCRATCH_OFFSET,
    X86_GUEST_ZMM_OFFSET, X86_HOST_MXCSR_OFFSET, X86_JIT_VECTOR_SCRATCH_INDEX,
};

impl X86_64Lowerer {
    pub fn set_native_vector_state_active(&mut self, on: bool) {
        self.native_vector_state_active = on;
    }

    /// Select the AVX-only helper boundary used by YMM16-safe replay regions.
    pub fn set_avx_ymm16_vector_state(&mut self, on: bool) {
        self.avx_ymm16_vector_state = on;
    }

    pub(super) fn emit_unaligned_vector_load(
        &mut self,
        register: PhysReg,
        width: VecWidth,
        offset: i32,
    ) {
        let mut emitter = X86Emitter::new(&mut self.code);
        match width {
            VecWidth::V128 | VecWidth::V256 => {
                emitter.emit_vex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    width,
                    false,
                    register.vec_ext(),
                    0,
                    PhysReg::Rax.vec_ext(),
                    0,
                );
            }
            VecWidth::V512 => {
                emitter.emit_evex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    width,
                    true,
                    register.vec_ext(),
                    0,
                    PhysReg::Rax.vec_ext(),
                    register.vec_ext2(),
                    0,
                    PhysReg::Rax.vec_ext2(),
                    0,
                );
            }
            _ => unreachable!("JIT vector transfer width"),
        }
        emitter.code.emit_u8(0x6F); // VMOVDQU xmm/ymm or VMOVDQU64 zmm
        emitter.emit_modrm_mem_disp(register, PhysReg::Rax, offset, DispSize::Disp32);
    }

    pub(super) fn emit_unaligned_vector_store(
        &mut self,
        register: PhysReg,
        width: VecWidth,
        offset: i32,
    ) {
        let mut emitter = X86Emitter::new(&mut self.code);
        match width {
            VecWidth::V128 | VecWidth::V256 => {
                emitter.emit_vex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    width,
                    false,
                    register.vec_ext(),
                    0,
                    PhysReg::Rax.vec_ext(),
                    0,
                );
            }
            VecWidth::V512 => {
                emitter.emit_evex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    width,
                    true,
                    register.vec_ext(),
                    0,
                    PhysReg::Rax.vec_ext(),
                    register.vec_ext2(),
                    0,
                    PhysReg::Rax.vec_ext2(),
                    0,
                );
            }
            _ => unreachable!("JIT vector transfer width"),
        }
        emitter.code.emit_u8(0x7F); // VMOVDQU/VMOVDQU64 memory destination
        emitter.emit_modrm_mem_disp(register, PhysReg::Rax, offset, DispSize::Disp32);
    }

    /// Synchronize one low architectural vector register between its physical
    /// carrier and `GuestRegs`. RAX must contain the state pointer.
    pub(crate) fn emit_state_backed_xmm_sync(&mut self, index: u8, store: bool) {
        debug_assert!(index < 16);
        let offset = X86_GUEST_ZMM_OFFSET + i32::from(index) * 64;
        let (register, width) = if self.avx_ymm16_vector_state {
            (PhysReg::Ymm(index), VecWidth::V256)
        } else {
            (PhysReg::Zmm(index), VecWidth::V512)
        };
        if store {
            self.emit_unaligned_vector_store(register, width, offset);
        } else {
            self.emit_unaligned_vector_load(register, width, offset);
        }
    }

    /// Import a helper-produced nonarchitectural value into a borrowed vector
    /// register.
    pub(crate) fn emit_jit_vector_scratch_load(&mut self, register: PhysReg, width: VecWidth) {
        self.emit_unaligned_vector_load(register, width, X86_GUEST_VECTOR_SCRATCH_OFFSET);
    }

    /// Copy one borrowed vector register into the nonarchitectural helper
    /// transfer slot. RAX must contain the state pointer.
    pub(crate) fn emit_jit_vector_scratch_store(&mut self, register: PhysReg, width: VecWidth) {
        self.emit_unaligned_vector_store(register, width, X86_GUEST_VECTOR_SCRATCH_OFFSET);
    }

    /// Copy the low 16 helper-produced bytes into a reserved stack slot while
    /// preserving guest RAX, RFLAGS, and the complete architectural ZMM0.
    /// The caller owns `[rsp, rsp + 16)`; the temporary push places that slot
    /// at `[rsp + 8]` during the unaligned store.
    pub(crate) fn emit_jit_vector_scratch_stack_store_128(&mut self) {
        let scratch = PhysReg::Xmm(0);
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch, VecWidth::V128);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_vex_prefix(
                X86VecMap::Map0F,
                X86SsePrefix::Rep,
                VecWidth::V128,
                false,
                scratch.vec_ext(),
                0,
                PhysReg::Rsp.vec_ext(),
                0,
            );
            emitter.code.emit_u8(0x7F); // VMOVDQU [rsp+8],xmm0
            emitter.emit_modrm_mem_disp(scratch, PhysReg::Rsp, 8, DispSize::Disp8);
        }
        self.emit_jit_vector_scratch_restore(0);
        self.code.emit_u8(0x58); // pop guest RAX
    }

    /// Copy the low 32 helper-produced bytes into a reserved stack slot while
    /// preserving guest RAX, RFLAGS, and the complete architectural ZMM0.
    /// The caller owns `[rsp, rsp + 32)`; the temporary push places that slot
    /// at `[rsp + 8]` during the unaligned store.
    pub(crate) fn emit_jit_vector_scratch_stack_store_256(&mut self) {
        let scratch = PhysReg::Ymm(0);
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_load(scratch, VecWidth::V256);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_vex_prefix(
                X86VecMap::Map0F,
                X86SsePrefix::Rep,
                VecWidth::V256,
                false,
                scratch.vec_ext(),
                0,
                PhysReg::Rsp.vec_ext(),
                0,
            );
            emitter.code.emit_u8(0x7F); // VMOVDQU [rsp+8],ymm0
            emitter.emit_modrm_mem_disp(scratch, PhysReg::Rsp, 8, DispSize::Disp8);
        }
        self.emit_jit_vector_scratch_restore(0);
        self.code.emit_u8(0x58); // pop guest RAX
    }

    /// Copy the low 1/2/4/8 bytes of RAX into the nonarchitectural helper
    /// transfer slot. RCX must contain the state pointer. The emitted MOV
    /// preserves RFLAGS.
    pub(crate) fn emit_jit_vector_scratch_gpr_store(&mut self, width: MemWidth) {
        match width {
            MemWidth::B1 => self.code.emit_bytes(&[0x88, 0x81]),
            MemWidth::B2 => self.code.emit_bytes(&[0x66, 0x89, 0x81]),
            MemWidth::B4 => self.code.emit_bytes(&[0x89, 0x81]),
            MemWidth::B8 => self.code.emit_bytes(&[0x48, 0x89, 0x81]),
            _ => unreachable!("validated VEX scalar-extract memory width"),
        }
        self.code.emit_u32(X86_GUEST_VECTOR_SCRATCH_OFFSET as u32);
    }

    /// Copy one selected qword from an architectural XMM register into the
    /// nonarchitectural helper-transfer slot. RAX must contain the state
    /// pointer. The VEX store is a bit transfer and does not update MXCSR.
    pub(crate) fn emit_jit_vector_scratch_qword_store(&mut self, register: PhysReg, lane: u8) {
        debug_assert!(matches!(register, PhysReg::Xmm(_)));
        debug_assert!(lane < 2);
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_vex_prefix(
            X86VecMap::Map0F,
            X86SsePrefix::None,
            VecWidth::V128,
            false,
            register.vec_ext(),
            0,
            PhysReg::Rax.vec_ext(),
            0,
        );
        emitter.code.emit_u8(if lane == 0 { 0x13 } else { 0x17 });
        emitter.emit_modrm_mem_disp(
            register,
            PhysReg::Rax,
            X86_GUEST_VECTOR_SCRATCH_OFFSET,
            DispSize::Disp32,
        );
    }

    /// Transfer one low dword or qword between an architectural XMM register
    /// and the nonarchitectural helper-transfer slot. RAX must contain the
    /// state pointer. The canonical VEX VMOVD/VMOVQ bit transfer clears upper
    /// destination bits on loads and does not update MXCSR or flags.
    pub(crate) fn emit_jit_vector_scratch_scalar_move(
        &mut self,
        register: PhysReg,
        width: OpWidth,
        load: bool,
    ) {
        debug_assert!(matches!(register, PhysReg::Xmm(_)));
        debug_assert!(matches!(width, OpWidth::W32 | OpWidth::W64));
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_vex_prefix(
            X86VecMap::Map0F,
            X86SsePrefix::OpSize,
            VecWidth::V128,
            width == OpWidth::W64,
            register.vec_ext(),
            0,
            PhysReg::Rax.vec_ext(),
            0,
        );
        emitter.code.emit_u8(if load { 0x6E } else { 0x7E });
        emitter.emit_modrm_mem_disp(
            register,
            PhysReg::Rax,
            X86_GUEST_VECTOR_SCRATCH_OFFSET,
            DispSize::Disp32,
        );
    }

    /// Transfer one 4- or 8-byte scalar between precise guest memory and an
    /// architectural XMM register through the nonarchitectural helper slot.
    ///
    /// Loads commit only after a successful helper return, zero every
    /// architectural vector bit above the scalar, and repair the state-backed
    /// ZMM upper half used by the AVX-only bridge. Stores publish the scalar to
    /// scratch before the helper; scratch is nonarchitectural, so a fault
    /// leaves all guest-visible register and memory state uncommitted.
    pub(crate) fn emit_jit_vector_scratch_scalar_memory_transfer(
        &mut self,
        guest_pc: u64,
        load: bool,
        vector: u8,
        address: &Address,
        memory_width: MemWidth,
    ) -> Result<(), LowerError> {
        let (width, size) = match memory_width {
            MemWidth::B4 => (OpWidth::W32, 4),
            MemWidth::B8 => (OpWidth::W64, 8),
            _ => {
                return Err(LowerError::InvalidOperand {
                    op: "VEX scalar memory transfer".to_string(),
                    operand: format!("unsupported memory width {memory_width:?}"),
                });
            }
        };
        let register = PhysReg::Xmm(vector);

        if load {
            self.emit_jit_vector_mem_helper(
                guest_pc,
                true,
                X86_JIT_VECTOR_SCRATCH_INDEX as u8,
                address,
                size,
                true,
                true,
            )?;
        }

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.emit_jit_vector_scratch_scalar_move(register, width, load);
        self.code.emit_u8(0x58); // pop guest RAX

        if load {
            if self.avx_ymm16_vector_state {
                self.emit_avx_ymm16_state_backed_upper_clear(vector);
            }
        } else {
            self.emit_jit_vector_mem_helper(
                guest_pc,
                false,
                X86_JIT_VECTOR_SCRATCH_INDEX as u8,
                address,
                size,
                false,
                true,
            )?;
        }
        Ok(())
    }

    /// Restore the complete architectural vector register borrowed as a
    /// helper-result carrier. The AVX-only bridge owns YMM0-YMM15; the general
    /// bridge owns complete ZMM state.
    pub(crate) fn emit_jit_vector_scratch_restore(&mut self, index: u8) {
        if self.avx_ymm16_vector_state {
            self.emit_unaligned_vector_load(
                PhysReg::Ymm(index),
                VecWidth::V256,
                X86_GUEST_ZMM_OFFSET + i32::from(index) * 64,
            );
        } else {
            self.emit_unaligned_vector_load(
                PhysReg::Zmm(index),
                VecWidth::V512,
                X86_GUEST_ZMM_OFFSET + i32::from(index) * 64,
            );
        }
    }

    /// Spill or reload every host-resident architectural vector register
    /// through `GuestRegs`. `base` is RAX before a helper call and RCX after it.
    ///
    /// The general path preserves ZMM0-ZMM31 and K0-K7. The AVX-only path
    /// preserves YMM0-YMM15; upper ZMM halves and opmasks never leave the
    /// state-backed image and therefore cannot be clobbered by the host ABI.
    pub(crate) fn emit_helper_vector_state(&mut self, base: PhysReg, store: bool) {
        if self.avx_ymm16_vector_state {
            for index in 0..16u8 {
                let reg = PhysReg::Ymm(index);
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_vex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    VecWidth::V256,
                    false,
                    reg.vec_ext(),
                    0,
                    base.vec_ext(),
                    0,
                );
                emitter.code.emit_u8(if store { 0x7F } else { 0x6F });
                emitter.emit_modrm_mem_disp(
                    reg,
                    base,
                    X86_GUEST_ZMM_OFFSET + i32::from(index) * 64,
                    DispSize::Disp32,
                );
            }
        } else {
            for index in 0..32u8 {
                let reg = PhysReg::Zmm(index);
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_evex_prefix(
                    X86VecMap::Map0F,
                    X86SsePrefix::Rep,
                    VecWidth::V512,
                    true,
                    reg.vec_ext(),
                    0,
                    base.vec_ext(),
                    reg.vec_ext2(),
                    0,
                    base.vec_ext2(),
                    0,
                );
                emitter.code.emit_u8(if store { 0x7F } else { 0x6F });
                emitter.emit_modrm_mem_disp(
                    reg,
                    base,
                    X86_GUEST_ZMM_OFFSET / 64 + i32::from(index),
                    DispSize::Disp8,
                );
            }

            for index in 0..8u8 {
                if self.narrow_vector_opmask_helpers {
                    // KMOVW m16,k / k,m16: VEX.L0.66.0F.W0 90/91. A 16-bit
                    // memory store intentionally leaves K[63:16] untouched.
                    self.code.emit_u8(0xC5);
                    self.code.emit_u8(0xF8);
                } else {
                    // KMOVQ m64,k / k,m64: VEX.W1.0F 90/91.
                    self.code.emit_u8(0xC4);
                    self.code.emit_u8(0xE1);
                    self.code.emit_u8(0xF8);
                }
                self.code.emit_u8(if store { 0x91 } else { 0x90 });
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_modrm_mem_disp(
                    PhysReg::Xmm(index),
                    base,
                    X86_GUEST_K_OFFSET + i32::from(index) * 8,
                    DispSize::Disp32,
                );
            }
        }

        if store {
            // Capture guest MXCSR before entering a Rust helper.
            self.code.emit_u8(0x0F);
            self.code.emit_u8(0xAE);
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_modrm_mem_disp(
                PhysReg::Rbx, // STMXCSR /3
                base,
                X86_GUEST_MXCSR_OFFSET,
                DispSize::Disp32,
            );
            // Rust executes under the host thread's original MXCSR.
            self.code.emit_u8(0x0F);
            self.code.emit_u8(0xAE);
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_modrm_mem_disp(
                PhysReg::Rdx, // LDMXCSR /2
                base,
                X86_HOST_MXCSR_OFFSET,
                DispSize::Disp32,
            );
        } else {
            // Resume native guest execution under the current guest MXCSR.
            self.code.emit_u8(0x0F);
            self.code.emit_u8(0xAE);
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_modrm_mem_disp(
                PhysReg::Rdx, // LDMXCSR /2
                base,
                X86_GUEST_MXCSR_OFFSET,
                DispSize::Disp32,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avx_ymm16_helper_boundary_uses_only_vex_moves_and_mxcsr_state() {
        let mut store = X86_64Lowerer::new();
        store.set_avx_ymm16_vector_state(true);
        store.emit_helper_vector_state(PhysReg::Rax, true);
        let store = store.code.as_slice();
        assert_eq!(store.len(), 16 * 8 + 14);
        assert_eq!(&store[..8], &[0xC5, 0xFE, 0x7F, 0x80, 0x40, 0x01, 0, 0]);
        assert_eq!(
            &store[15 * 8..16 * 8],
            &[0xC5, 0x7E, 0x7F, 0xB8, 0x00, 0x05, 0, 0]
        );
        assert!(!store.contains(&0x62), "AVX-only boundary emitted EVEX");

        let mut load = X86_64Lowerer::new();
        load.set_avx_ymm16_vector_state(true);
        load.emit_helper_vector_state(PhysReg::Rcx, false);
        let load = load.code.as_slice();
        assert_eq!(load.len(), 16 * 8 + 7);
        assert_eq!(&load[..8], &[0xC5, 0xFE, 0x6F, 0x81, 0x40, 0x01, 0, 0]);
        assert_eq!(
            &load[15 * 8..16 * 8],
            &[0xC5, 0x7E, 0x6F, 0xB9, 0x00, 0x05, 0, 0]
        );
        assert!(!load.contains(&0x62), "AVX-only boundary emitted EVEX");
    }
}
