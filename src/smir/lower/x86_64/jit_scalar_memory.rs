//! Scalar guest-memory helper calls and precise fault boundaries.

use super::evex_vsib_memory::X86JitVsibLane;
use super::{X86_64Lowerer, X86Emitter};
use crate::smir::ir::types::{Address, DispSize, MemWidth, OpWidth, SignExtend, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CTX_OFFSET, X86_GUEST_EXIT_PC_OFFSET, X86_GUEST_LOAD_FN_OFFSET,
    X86_GUEST_STORE_FN_OFFSET, X86_GUEST_VSIB_FRONTIER_LANE_PLUS_ONE_OFFSET, X86_STATE_PTR_AT_RBP,
};

impl X86_64Lowerer {
    /// Lower a guest `Load`/`Store` as a call into the MMU via the helper
    /// function pointers in `GuestRegs`. Spills all guest GPRs to the struct,
    /// computes the effective guest address, calls the helper, and on a fault/MMIO return (`ok==0`)
    /// records `exit_pc=guest_pc` and returns to the interpreter WITHOUT
    /// committing the op (precise restart). `fault_stack_cleanup` removes any
    /// flag-neutral caller-owned temporary stack space before the fault exit.
    /// Only reached when `mem_helpers` is set and every address component is
    /// representable by the GuestRegs-backed address builder.
    pub(crate) fn emit_jit_mem_op(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op_inner(
            guest_pc,
            is_load,
            load_dst,
            load_stack_dst,
            store_src_reg,
            store_src_imm,
            store_stack_src,
            addr,
            mem_width,
            sign,
            fault_stack_cleanup,
            false,
            None,
            0,
            false,
        )
    }

    /// As [`Self::emit_jit_mem_op`], with a flag-neutral byte displacement
    /// added after the complete architectural effective address is computed.
    /// This is distinct from modifying an [`Address::X86Addr32`] displacement:
    /// masked-vector lanes advance in 64-bit linear-address space after the
    /// 32-bit effective offset has wrapped and the segment base was applied.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_jit_mem_op_linear_offset(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
        linear_offset: i32,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op_inner(
            guest_pc,
            is_load,
            load_dst,
            load_stack_dst,
            store_src_reg,
            store_src_imm,
            store_stack_src,
            addr,
            mem_width,
            sign,
            fault_stack_cleanup,
            false,
            None,
            linear_offset,
            false,
        )
    }

    /// As [`Self::emit_jit_mem_op`], with an extra architectural bit-offset
    /// term folded into the effective address. `BT`/`BTS`/`BTR`/`BTC` with a
    /// register bit offset address memory as
    /// `base + ((sign_extend(index) >> log2(bits)) << log2(bytes))`, which no
    /// [`Address`] can express; the term is evaluated where the helper prologue
    /// has already spilled every guest GPR, so RSI/RDI are free scratch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_jit_mem_op_bit_offset(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
        bit_offset: crate::smir::lower::X86JitBitOffsetTerm,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op_inner(
            guest_pc,
            is_load,
            load_dst,
            load_stack_dst,
            store_src_reg,
            store_src_imm,
            store_stack_src,
            addr,
            mem_width,
            sign,
            fault_stack_cleanup,
            false,
            Some(bit_offset),
            0,
            false,
        )
    }

    /// Exact 32-bit-address variant used by fused long-mode instructions whose
    /// lifter represents zero-extended EDI as a virtual SSA value. The helper
    /// computes the offset modulo 2^32 without materializing that virtual into
    /// an identity-mapped guest GPR.
    pub(crate) fn emit_jit_mem_op_addr32(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op_inner(
            guest_pc,
            is_load,
            load_dst,
            load_stack_dst,
            store_src_reg,
            store_src_imm,
            store_stack_src,
            addr,
            mem_width,
            sign,
            fault_stack_cleanup,
            true,
            None,
            0,
            false,
        )
    }

    pub(super) fn emit_jit_mem_op_inner(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
        address_size_32: bool,
        bit_offset: Option<crate::smir::lower::X86JitBitOffsetTerm>,
        linear_offset: i32,
        zero_extend_stack_store: bool,
    ) -> Result<(), LowerError> {
        self.emit_jit_mem_op_with_vsib_lane(
            guest_pc,
            is_load,
            load_dst,
            load_stack_dst,
            store_src_reg,
            store_src_imm,
            store_stack_src,
            addr,
            mem_width,
            sign,
            fault_stack_cleanup,
            address_size_32,
            bit_offset,
            linear_offset,
            zero_extend_stack_store,
            None,
        )
    }

    /// The optional VSIB transfer commits one architectural vector lane and
    /// its writemask bit only after a successful scalar memory helper. All
    /// other callers retain the existing scalar marshalling contract.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_jit_mem_op_with_vsib_lane(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        load_dst: Option<VReg>,
        load_stack_dst: Option<i32>,
        store_src_reg: Option<VReg>,
        store_src_imm: Option<i64>,
        store_stack_src: Option<i32>,
        addr: &Address,
        mem_width: MemWidth,
        sign: SignExtend,
        fault_stack_cleanup: i32,
        address_size_32: bool,
        bit_offset: Option<crate::smir::lower::X86JitBitOffsetTerm>,
        linear_offset: i32,
        zero_extend_stack_store: bool,
        vsib_lane: Option<X86JitVsibLane>,
    ) -> Result<(), LowerError> {
        let size: i32 = match mem_width {
            MemWidth::B1 => 1,
            MemWidth::B2 => 2,
            MemWidth::B4 => 4,
            MemWidth::B8 => 8,
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: "jit-mem: vector width".to_string(),
                });
            }
        };
        let signed: i32 = matches!(sign, SignExtend::Sign) as i32;
        let store_sources = usize::from(store_src_reg.is_some())
            + usize::from(store_src_imm.is_some())
            + usize::from(store_stack_src.is_some())
            + usize::from(vsib_lane.is_some() && !is_load);
        let load_destinations = usize::from(load_dst.is_some())
            + usize::from(load_stack_dst.is_some())
            + usize::from(vsib_lane.is_some() && is_load);
        if is_load && (load_destinations != 1 || store_sources != 0) {
            return Err(LowerError::InvalidOperand {
                op: "jit-mem load".to_string(),
                operand:
                    "exactly one register or host-stack destination and no store source is required"
                        .to_string(),
            });
        }
        if !is_load && (load_destinations != 0 || store_sources != 1) {
            return Err(LowerError::InvalidOperand {
                op: "jit-mem store".to_string(),
                operand: "exactly one register, immediate, or host-stack source is required"
                    .to_string(),
            });
        }
        if let Some(lane) = vsib_lane {
            lane.validate(is_load, mem_width)?;
            if address_size_32
                || bit_offset.is_some()
                || linear_offset != 0
                || zero_extend_stack_store
                || fault_stack_cleanup != 0
            {
                return Err(LowerError::InvalidOperand {
                    op: "jit-mem VSIB lane".to_string(),
                    operand:
                        "VSIB addressing cannot be combined with scalar address or stack overrides"
                            .to_string(),
                });
            }
        }
        let load_dst_enc = match load_dst {
            Some(d) => Some(self.jit_arch_enc(d)?),
            None => None,
        };
        let store_src_enc = match store_src_reg {
            Some(s) => Some(self.jit_arch_enc(s)?),
            None => None,
        };

        // --- spill: push rax; rax=state ptr; SAVE FLAGS; spill 13 GPRs + RAX ---
        self.code.emit_u8(0x50); // push rax  ([rsp]=guest RAX)
        // mov rax, [rbp+state_ptr]
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x45);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        // pushfq: preserve the guest STATUS flags across the helper call — x86
        // loads/stores do NOT affect flags, but `call`/`test`/`add rsp` here do,
        // and a folded `Jcc` later in the block reads the live flags. This also
        // 16-aligns RSP for the call (push rax + pushfq = 16 bytes). After this,
        // [rsp]=guest flags, [rsp+8]=guest RAX.
        self.code.emit_u8(0x9C);
        for enc in [1u8, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            self.emit_struct_mov(PhysReg::Rax, enc, (enc as i32) * 8, true);
        }
        // mov rcx, [rsp+8]   (guest RAX, now below the saved flags)  (48 8B 4C 24 08)
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4C);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
        self.emit_struct_mov(PhysReg::Rax, 1, 0, true);

        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);

        if let Some(lane) = vsib_lane {
            self.emit_jit_vsib_lane_address(lane)?;
        } else {
            self.emit_jit_mem_effective_address(addr, address_size_32)?;
        }
        if let Some(term) = bit_offset {
            self.emit_jit_mem_bit_offset_term(term)?;
        }
        if linear_offset != 0 {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsi, PhysReg::Rsi, linear_offset);
        }

        // --- args + call ---
        if is_load {
            self.emit_struct_mov(PhysReg::Rax, 7, X86_GUEST_CTX_OFFSET, false); // rdi = ctx
            self.code.emit_u8(0xBA); // mov edx, size
            self.code.emit_u32(size as u32);
            self.code.emit_u8(0xB9); // mov ecx, signed
            self.code.emit_u32(signed as u32);
        } else {
            if let Some(lane) = vsib_lane {
                self.emit_jit_vsib_store_value(lane);
            } else if let Some(stack_off) = store_stack_src {
                if zero_extend_stack_store {
                    self.emit_jit_stack_store_value_argument(stack_off, mem_width);
                } else {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, stack_off, OpWidth::W64);
                }
            } else if let Some(imm) = store_src_imm {
                self.emit_movabs(2, imm as u64); // movabs rdx, imm (value)
            } else if let Some(senc) = store_src_enc {
                self.emit_struct_mov(PhysReg::Rax, 2, (senc as i32) * 8, false); // rdx = value
            } else {
                return Err(LowerError::UnsupportedOp {
                    op: "jit-mem: store without source".to_string(),
                });
            }
            self.emit_struct_mov(PhysReg::Rax, 7, X86_GUEST_CTX_OFFSET, false); // rdi = ctx
            self.code.emit_u8(0xB9); // mov ecx, size
            self.code.emit_u32(size as u32);
        }
        // RSP is 16-aligned at the call: the block prologue's `push rbp` lands
        // the region's RSP ≡ 0 (mod 16), and `push rax` + `pushfq` add 16 more,
        // so RSP is ≡ 0 (mod 16) here — exactly what SysV requires at a `call`.
        // call [rax + load_fn/store_fn]   (FF 90 id)
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90);
        self.code.emit_u32(if is_load {
            X86_GUEST_LOAD_FN_OFFSET as u32
        } else {
            X86_GUEST_STORE_FN_OFFSET as u32
        });
        // mov rcx, [rbp+state_ptr]   (state ptr; RAX now holds the return value)
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4D);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        // test <ok>, <ok>  : load -> ok in RDX (48 85 D2), store -> ok in RAX (48 85 C0)
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x85);
        self.code.emit_u8(if is_load { 0xD2 } else { 0xC0 });
        // jz .fault  (0F 84 rel32)
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x84);
        let jz_pos = self.code.position();
        self.code.emit_u32(0);

        // --- OK path ---
        if let Some(lane) = vsib_lane {
            self.emit_jit_vsib_lane_commit(lane);
        } else if is_load {
            if let Some(stack_off) = load_stack_dst {
                // The load helper returns a zero-extended scalar in RAX. Stage
                // a complete 64-bit value in caller-owned host stack space;
                // no architectural GuestRegs slot is modified.
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rsp, stack_off, PhysReg::Rax, OpWidth::W64);
            } else {
                let denc = load_dst_enc.unwrap() as i32;
                let off = (denc * 8) as u32;
                // Deliver the loaded value (in RAX) into the destination's GuestRegs
                // slot, RESPECTING x86 partial-register write semantics — `mov
                // al/ax,[mem]` (B1/B2) writes only the low 1/2 bytes and PRESERVES
                // the upper register bits, whereas `mov eax,[mem]` (B4) zero-extends
                // to 64 (the helper already returned a zero-extended value, so a full
                // 8-byte store is correct) and B8 is a full store. Writing the full
                // full RAX for an unsigned architectural B1/B2 load would
                // wrongly clobber the upper bits — exactly the divergence a
                // `mov al, gs:[...]` per-CPU read exposes. Signed loads replace
                // the complete destination with the helper's sign extension.
                match (mem_width, sign) {
                    (MemWidth::B1, SignExtend::Zero) => {
                        // mov byte [rcx + off], al  (88 81 <disp32>)
                        self.code.emit_u8(0x88);
                        self.code.emit_u8(0x81);
                        self.code.emit_u32(off);
                    }
                    (MemWidth::B2, SignExtend::Zero) => {
                        // mov word [rcx + off], ax  (66 89 81 <disp32>)
                        self.code.emit_u8(0x66);
                        self.code.emit_u8(0x89);
                        self.code.emit_u8(0x81);
                        self.code.emit_u32(off);
                    }
                    _ => {
                        // Signed B1/B2/B4, unsigned B4, and B8 are complete
                        // 64-bit values under the load-helper ABI.
                        self.emit_struct_mov(PhysReg::Rcx, 0, denc * 8, true);
                    }
                }
                // Guest RBP is state-backed: hardware RBP is the native frame
                // pointer and the prologue saved the guest value at [RBP]. A
                // load that architecturally writes RBP must keep that saved
                // word coherent so the epilogue POP returns the loaded value.
                // RAX is reloaded from the state file below, so using it as the
                // transfer scratch here is safe.
                if denc == 5 {
                    self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
                }
            }
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        // popfq: restore the guest STATUS flags saved on entry (pops [rsp]).
        self.code.emit_u8(0x9D);
        // lea rsp,[rsp+8]: pop the guest-RAX slot WITHOUT touching flags (an
        // `add rsp,8` would clobber the flags we just restored, breaking a
        // folded Jcc later in the block). (48 8D 64 24 08)
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8D);
        self.code.emit_u8(0x64);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
        // jmp .done  (E9 rel32)
        self.code.emit_u8(0xE9);
        let jmp_pos = self.code.position();
        self.code.emit_u32(0);

        // --- fault path ---
        let fault = self.code.position();
        self.code
            .patch_i32(jz_pos, (fault as i64 - (jz_pos as i64 + 4)) as i32);
        if let Some(lane) = vsib_lane {
            // Internal verification metadata, not architectural state. A
            // failed/deferred helper identifies the independently replayable
            // prefix without inferring completion from native K results.
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mi_disp(
                PhysReg::Rcx,
                X86_GUEST_VSIB_FRONTIER_LANE_PLUS_ONE_OFFSET,
                DispSize::Disp32,
                i64::from(lane.lane) + 1,
                OpWidth::W64,
            );
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        // popfq: restore the guest STATUS flags (pops [rsp]).
        self.code.emit_u8(0x9D);
        // lea rsp,[rsp+8]: flag-preserving pop of the guest-RAX slot.
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8D);
        self.code.emit_u8(0x64);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
        if fault_stack_cleanup != 0 {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, fault_stack_cleanup);
        }
        // exit stub: record exit_pc = guest_pc, return to trampoline.
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x45);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rax,[rbp+state_ptr]
        self.code.emit_u8(0xC7);
        self.code.emit_u8(0x80);
        self.code.emit_u32(X86_GUEST_EXIT_PC_OFFSET as u32);
        self.code.emit_u32(guest_pc as u32);
        self.code.emit_u8(0xC7);
        self.code.emit_u8(0x80);
        self.code.emit_u32((X86_GUEST_EXIT_PC_OFFSET + 4) as u32);
        self.code.emit_u32((guest_pc >> 32) as u32);
        self.code.emit_u8(0x58); // pop rax
        self.emit_epilogue_with_ret(None);

        // --- done ---
        let done = self.code.position();
        self.code
            .patch_i32(jmp_pos, (done as i64 - (jmp_pos as i64 + 4)) as i32);
        Ok(())
    }
}
