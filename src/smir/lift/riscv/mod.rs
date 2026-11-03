//! RISC-V instruction lifter for SMIR.
//!
//! This module lifts RISC-V instructions to SMIR operations.
//! Supports RV64I base, M (multiply/divide), A (atomics), and C (compressed) extensions.

use crate::isa::riscv::{
    Isa as RvIsa, Op as RvOp, Xlen as RvXlen, decode as rv_decode, rvc::decode_rvc as rv_decode_rvc,
};
use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::ops::{OpKind, RvVectorState, SmirOp};
use crate::smir::ir::types::*;
use crate::smir::ir::{SmirBlock, SmirFunction};

use super::{ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter};

// ---- module tree (auto-split) ----
mod bitmanip;
pub(crate) use bitmanip::*;
mod compressed;
pub(crate) use compressed::*;
mod control_flow;
pub(crate) use control_flow::*;
mod fp;
pub(crate) use fp::*;
mod memory;
pub(crate) use memory::*;
mod misc;
pub(crate) use misc::*;
mod system;
pub(crate) use system::*;
mod vector;
pub(crate) use vector::*;

/// A term in a SHA/SM3 xor-fold: a rotate / shift / identity of the source.
#[derive(Clone, Copy)]
enum CryptoTerm {
    /// ror, 32-bit width
    R,
    /// ror, 64-bit width
    RW,
    /// rol, 32-bit width
    L,
    /// logical shift right, 32-bit
    S,
    /// logical shift right, 64-bit
    SW,
    /// identity (use the source directly)
    X,
}

// ============================================================================
// RISC-V Extensions Configuration
// ============================================================================

/// RISC-V extension configuration
#[derive(Clone, Copy, Debug, Default)]
pub struct RiscVExtensions {
    /// M extension: Integer multiplication and division
    pub m: bool,
    /// A extension: Atomic instructions
    pub a: bool,
    /// F extension: Single-precision floating-point
    pub f: bool,
    /// D extension: Double-precision floating-point
    pub d: bool,
    /// Q extension: Quad-precision floating-point decode/disassembly parity
    pub q: bool,
    /// C extension: Compressed instructions
    pub c: bool,
    /// Zicsr extension: Control and status register access
    pub zicsr: bool,
    /// Zifencei extension: Instruction-stream fence
    pub zifencei: bool,
    /// Zihintpause extension: PAUSE hint
    pub zihintpause: bool,
    /// Zihintntl extension: non-temporal locality hints
    pub zihintntl: bool,
    /// Zacas extension: atomic compare-and-swap
    pub zacas: bool,
    /// Zawrs extension: wait-on-reservation-set hints
    pub zawrs: bool,
    /// Zicbom extension: cache-block clean/flush/invalidate
    pub zicbom: bool,
    /// Zicboz extension: Cache-block zero
    pub zicboz: bool,
    /// Zicbop extension: cache-block prefetch hints
    pub zicbop: bool,
    /// Zba extension: Address bit manipulation
    pub zba: bool,
    /// Zbb extension: Basic bit manipulation
    pub zbb: bool,
    /// Zbc extension: Carry-less multiplication
    pub zbc: bool,
    /// Zbs extension: Single-bit instructions
    pub zbs: bool,
    /// Zicond extension: Integer conditional operations
    pub zicond: bool,
    /// Zfa extension: Additional floating-point instructions
    pub zfa: bool,
    /// Zbkb extension: Bit-manipulation for cryptography
    pub zbkb: bool,
    /// Zfh extension: Half-precision floating point
    pub zfh: bool,
    /// Zbkx extension: Crossbar permutations
    pub zbkx: bool,
    /// Zknh extension: NIST SHA-256/512 hash transforms
    pub zknh: bool,
    /// Zksh extension: ShangMi SM3 hash transforms
    pub zksh: bool,
    /// Zksed extension: ShangMi SM4 block cipher
    pub zksed: bool,
    /// Zkne extension: NIST AES encryption
    pub zkne: bool,
    /// Zknd extension: NIST AES decryption
    pub zknd: bool,
    /// Zcb extension: Additional compressed instructions
    pub zcb: bool,
    /// Zcmp extension: Compressed PUSH/POP and double-move instructions
    pub zcmp: bool,
    /// Zcmt extension: Compressed table-jump instructions
    pub zcmt: bool,
    /// Zclsd extension: RV32 compressed load/store register-pair instructions
    pub zclsd: bool,
    /// Zilsd extension: RV32 load/store register-pair instructions
    pub zilsd: bool,
    /// H extension: Hypervisor privileged instructions
    pub h: bool,
    /// Svinval extension: Fine-grained address-translation cache invalidation
    pub svinval: bool,
    /// V extension: Vector instructions
    pub v: bool,
    /// XAndesPerf vendor extension: Andes performance custom instructions
    pub xandes: bool,
    /// XThead vendor extension: T-Head/Xuantie custom instructions
    pub xthead: bool,
    /// XHazard3 vendor extension: Hazard3/RP2350 custom instructions
    pub xhazard3: bool,
    /// XidaSltw compatibility decode for Hex-Rays/IDA's non-standard `sltw`.
    pub xida_sltw: bool,
}

impl RiscVExtensions {
    /// Standard test/differential configuration used by this crate.
    pub fn rv64gc() -> Self {
        Self {
            m: true,
            a: true,
            f: true,
            d: true,
            q: false,
            c: true,
            zicsr: true,
            zifencei: true,
            zihintpause: true,
            zihintntl: true,
            zacas: true,
            zawrs: true,
            zicbom: true,
            zicboz: true,
            zicbop: true,
            zba: true,
            zbb: true,
            zbc: true,
            zbs: true,
            zicond: true,
            zfa: true,
            zbkb: true,
            zfh: true,
            zbkx: true,
            zknh: true,
            zksh: true,
            zksed: true,
            zkne: true,
            zknd: true,
            zcb: true,
            zcmp: false,
            zcmt: false,
            zclsd: false,
            zilsd: false,
            h: true,
            svinval: true,
            v: true,
            xandes: false,
            xthead: false,
            xhazard3: false,
            xida_sltw: false,
        }
    }

    /// Minimal RV64I configuration
    pub fn rv64i() -> Self {
        Self::default()
    }

    /// RV64IMAC (common embedded configuration)
    pub fn rv64imac() -> Self {
        Self {
            m: true,
            a: true,
            c: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// RISC-V Lifter
// ============================================================================

/// RISC-V instruction lifter
pub struct RiscVLifter {
    /// Register width (32 or 64)
    xlen: u8,
    /// Enabled extensions
    extensions: RiscVExtensions,
}

// ============================================================================
// SmirLifter Implementation
// ============================================================================

impl SmirLifter for RiscVLifter {
    fn source_arch(&self) -> SourceArch {
        if self.xlen == 64 {
            SourceArch::RiscV64
        } else {
            SourceArch::RiscV32
        }
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Incomplete {
                addr,
                have: 0,
                need: 2,
            });
        }

        // Determine instruction length from low bits
        let len = if bytes[0] & 0x03 != 0x03 {
            // Compressed instruction (16-bit)
            if !self.extensions.c {
                return Err(LiftError::Unsupported {
                    addr,
                    mnemonic: "compressed instruction (C extension disabled)".to_string(),
                });
            }
            2
        } else if bytes[0] & 0x1F == 0x1F {
            // 48-bit or longer (future extension)
            return Err(LiftError::Unsupported {
                addr,
                mnemonic: "extended instruction (>32 bits)".to_string(),
            });
        } else {
            // Standard 32-bit
            4
        };

        if bytes.len() < len {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need: len,
            });
        }

        let (ops, control_flow) = if len == 2 {
            let insn = u16::from_le_bytes([bytes[0], bytes[1]]);
            self.lift_insn16(insn, addr, ctx)?
        } else {
            let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            self.lift_insn32(insn, addr, ctx)?
        };

        // Collect branch targets for block discovery
        let branch_targets = match &control_flow {
            ControlFlow::DirectBranch(target) => vec![*target],
            ControlFlow::CondBranchReg {
                taken, not_taken, ..
            } => vec![*taken, *not_taken],
            _ => vec![],
        };

        Ok(LiftResult {
            ops,
            bytes_consumed: len,
            control_flow,
            branch_targets,
        })
    }

    fn lift_block(
        &mut self,
        addr: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirBlock, LiftError> {
        use crate::smir::ir::{SmirBlock, Terminator, TrapKind};

        let block_id = ctx.get_or_create_block(addr);
        let mut all_ops = Vec::new();
        let mut current_addr = addr;

        loop {
            // Read enough bytes for a compressed or normal instruction
            let bytes = mem
                .read(current_addr, 4)
                .map_err(|e| LiftError::MemoryError {
                    addr: current_addr,
                    error: e,
                })?;

            let result = self.lift_insn(current_addr, &bytes, ctx)?;
            all_ops.extend(result.ops);
            current_addr += result.bytes_consumed as u64;

            if result.control_flow.ends_block() {
                let terminator = match result.control_flow {
                    ControlFlow::Fallthrough | ControlFlow::NextInsn => unreachable!(),
                    ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
                        Terminator::Branch {
                            target: ctx.get_or_create_block(target),
                        }
                    }
                    ControlFlow::CondBranch {
                        target,
                        fallthrough,
                        ..
                    } => {
                        let cond_vreg = ctx.alloc_vreg();
                        Terminator::CondBranch {
                            cond: cond_vreg,
                            true_target: ctx.get_or_create_block(target),
                            false_target: ctx.get_or_create_block(fallthrough),
                        }
                    }
                    ControlFlow::CondBranchReg {
                        cond,
                        taken,
                        not_taken,
                    } => Terminator::CondBranch {
                        cond,
                        true_target: ctx.get_or_create_block(taken),
                        false_target: ctx.get_or_create_block(not_taken),
                    },
                    ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                        target,
                        possible_targets: vec![],
                    },
                    ControlFlow::IndirectBranchMem { addr } => Terminator::IndirectBranchMem {
                        addr,
                        possible_targets: vec![],
                    },
                    ControlFlow::Call { target } => Terminator::Call {
                        target,
                        args: vec![],
                        continuation: ctx.get_or_create_block(current_addr),
                    },
                    ControlFlow::Return => Terminator::Return { values: vec![] },
                    ControlFlow::Trap { kind } => Terminator::Trap { kind },
                    ControlFlow::Syscall => Terminator::Trap {
                        kind: TrapKind::SystemCall,
                    },
                };

                return Ok(SmirBlock {
                    id: block_id,
                    guest_pc: addr,
                    phis: vec![],
                    ops: all_ops,
                    terminator,
                    exec_count: 0,
                });
            }
        }
    }

    fn lift_function(
        &mut self,
        entry: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirFunction, LiftError> {
        use crate::smir::ir::{CallingConv, FunctionAttrs, SmirFunction};
        use std::collections::HashSet;

        let func_id = FunctionId(ctx.known_functions.len() as u32);
        ctx.known_functions.insert(entry, func_id);

        let mut blocks = Vec::new();
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();
        let mut min_addr = entry;
        let mut max_addr = entry;

        while let Some(addr) = worklist.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);

            let block = self.lift_block(addr, mem, ctx)?;

            if block.guest_pc < min_addr {
                min_addr = block.guest_pc;
            }
            // Estimate block end (varies due to compressed instructions)
            let block_end = block.guest_pc + (block.ops.len() * 4) as u64;
            if block_end > max_addr {
                max_addr = block_end;
            }

            for succ in block.successors() {
                if let Some(&succ_addr) = ctx
                    .block_cache
                    .iter()
                    .find(|(_, id)| **id == succ)
                    .map(|(addr, _)| addr)
                {
                    if !visited.contains(&succ_addr) {
                        worklist.push(succ_addr);
                    }
                }
            }

            blocks.push(block);
        }

        let calling_convention = if self.xlen == 64 {
            CallingConv::RiscVStd
        } else {
            CallingConv::RiscVStd
        };

        Ok(SmirFunction {
            id: func_id,
            entry: ctx.get_or_create_block(entry),
            blocks,
            locals: vec![],
            guest_range: (min_addr, max_addr),
            calling_convention,
            attrs: FunctionAttrs::default(),
            x86_instruction_bytes: std::collections::HashMap::new(),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::ir::Terminator;

    fn test_ctx() -> LiftContext {
        LiftContext::new(SourceArch::RiscV64)
    }

    fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    fn i_type(imm12: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        ((imm12 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    fn b_type(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
        let imm = (imm as u32) & 0x1fff;
        ((imm >> 12) << 31)
            | (((imm >> 5) & 0x3f) << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | (((imm >> 1) & 0xf) << 8)
            | (((imm >> 11) & 1) << 7)
            | 0x63
    }

    fn j_type(imm: i32, rd: u32) -> u32 {
        let imm = (imm as u32) & 0x1f_ffff;
        ((imm >> 20) << 31)
            | (((imm >> 1) & 0x3ff) << 21)
            | (((imm >> 11) & 1) << 20)
            | (((imm >> 12) & 0xff) << 12)
            | (rd << 7)
            | 0x6f
    }

    #[track_caller]
    fn assert_invalid_lift(mut lifter: RiscVLifter, word: u32) {
        let mut ctx = test_ctx();
        let err = match lifter.lift_insn(0x1000, &word.to_le_bytes(), &mut ctx) {
            Err(err) => err,
            Ok(_) => panic!("instruction {word:#010x} must not lift as a no-op"),
        };
        assert!(
            matches!(err, LiftError::InvalidEncoding { .. }),
            "expected InvalidEncoding for {word:#010x}, got {err:?}"
        );
    }

    #[track_caller]
    fn assert_unsupported_lift(mut lifter: RiscVLifter, word: u32) {
        let mut ctx = test_ctx();
        let err = match lifter.lift_insn(0x1000, &word.to_le_bytes(), &mut ctx) {
            Err(err) => err,
            Ok(_) => panic!("instruction {word:#010x} requires interpreter fallback"),
        };
        assert!(
            matches!(err, LiftError::Unsupported { .. }),
            "expected Unsupported for {word:#010x}, got {err:?}"
        );
    }

    fn execute_lifted_gpr_result(
        mut lifter: RiscVLifter,
        source: SourceArch,
        word: u32,
        rs1: u64,
        rs2: u64,
        rd: u8,
    ) -> u64 {
        let mut lift_ctx = LiftContext::new(source);
        let result = lifter
            .lift_insn(0x1000, &word.to_le_bytes(), &mut lift_ctx)
            .expect("instruction should lift");
        let mut ops = result.ops;
        for (idx, op) in ops.iter_mut().enumerate() {
            op.id = OpId(idx as u16);
        }
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops,
            terminator: Terminator::Trap {
                kind: crate::smir::TrapKind::Breakpoint,
            },
            exec_count: 0,
        };

        let mut ctx = crate::smir::SmirContext::new_riscv();
        ctx.source_arch = source;
        ctx.pc = 0x1000;
        ctx.arch_regs.set_pc(0x1000);
        ctx.write_arch_reg(ArchReg::RiscV(RiscVReg::X(1)), rs1);
        ctx.write_arch_reg(ArchReg::RiscV(RiscVReg::X(2)), rs2);

        let mut memory = crate::smir::FlatMemory::with_base(0, 0x10000);
        let interp = crate::smir::SmirInterpreter::new();
        interp.execute_block(&mut ctx, &mut memory, &block);

        let final_reg = lift_ctx.get_arch_reg(ArchReg::RiscV(RiscVReg::X(rd)));
        ctx.read_vreg(final_reg)
    }

    #[test]
    fn no_c_control_flow_falls_back_only_when_alignment_needs_runtime_handling() {
        let no_c = RiscVExtensions {
            c: false,
            ..RiscVExtensions::rv64gc()
        };

        for word in [j_type(2, 1), b_type(2, 0, 0, 0)] {
            assert_unsupported_lift(RiscVLifter::new_rv64(no_c), word);
        }
        assert_unsupported_lift(RiscVLifter::new_rv64(no_c), i_type(0, 1, 0, 1, 0x67));

        for word in [j_type(8, 1), b_type(8, 0, 0, 0)] {
            let mut lifter = RiscVLifter::new_rv64(no_c);
            let mut ctx = test_ctx();
            lifter
                .lift_insn(0x1000, &word.to_le_bytes(), &mut ctx)
                .expect("statically aligned no-C control flow should lift");
        }

        for word in [j_type(2, 1), b_type(2, 0, 0, 0), i_type(0, 1, 0, 1, 0x67)] {
            let mut lifter = RiscVLifter::rv64gc();
            let mut ctx = test_ctx();
            lifter
                .lift_insn(0x1000, &word.to_le_bytes(), &mut ctx)
                .expect("C-enabled control flow permits 16-bit-aligned targets");
        }
    }

    #[test]
    fn jalr_requires_the_standard_zero_funct3() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();
        lifter
            .lift_insn(0x1000, &i_type(0, 1, 0, 1, 0x67).to_le_bytes(), &mut ctx)
            .expect("standard JALR should lift");

        for funct3 in 1..=7 {
            assert_invalid_lift(RiscVLifter::rv64gc(), i_type(0, 1, funct3, 1, 0x67));
        }
    }

    #[test]
    fn fence_and_csr_lifts_honor_independent_extension_profiles() {
        let fence_i = 0x0000_100fu32;
        let read_fcsr = i_type(0x003, 0, 0b010, 1, 0x73);
        let read_vl = i_type(0xc20, 0, 0b010, 1, 0x73);

        assert_invalid_lift(RiscVLifter::new_rv64(RiscVExtensions::rv64i()), fence_i);
        let mut lifter = RiscVLifter::new_rv64(RiscVExtensions {
            zifencei: true,
            ..RiscVExtensions::rv64i()
        });
        lifter
            .lift_insn(0x1000, &fence_i.to_le_bytes(), &mut test_ctx())
            .expect("Zifencei should enable FENCE.I");

        assert_invalid_lift(
            RiscVLifter::new_rv64(RiscVExtensions {
                f: true,
                ..RiscVExtensions::rv64i()
            }),
            read_fcsr,
        );
        assert_invalid_lift(
            RiscVLifter::new_rv64(RiscVExtensions {
                zicsr: true,
                ..RiscVExtensions::rv64i()
            }),
            read_fcsr,
        );
        let mut lifter = RiscVLifter::new_rv64(RiscVExtensions {
            f: true,
            zicsr: true,
            ..RiscVExtensions::rv64i()
        });
        lifter
            .lift_insn(0x1000, &read_fcsr.to_le_bytes(), &mut test_ctx())
            .expect("F and Zicsr should enable fcsr access");

        assert_invalid_lift(
            RiscVLifter::new_rv64(RiscVExtensions {
                zicsr: true,
                ..RiscVExtensions::rv64i()
            }),
            read_vl,
        );
        let mut lifter = RiscVLifter::new_rv64(RiscVExtensions {
            v: true,
            zicsr: true,
            ..RiscVExtensions::rv64i()
        });
        lifter
            .lift_insn(0x1000, &read_vl.to_le_bytes(), &mut test_ctx())
            .expect("V and Zicsr should enable vector CSR reads");
    }

    #[test]
    fn scalar_loads_to_x0_keep_the_memory_operation_for_every_width() {
        let cases = [
            (0, MemWidth::B1, SignExtend::Sign),
            (1, MemWidth::B2, SignExtend::Sign),
            (2, MemWidth::B4, SignExtend::Sign),
            (3, MemWidth::B8, SignExtend::Zero),
            (4, MemWidth::B1, SignExtend::Zero),
            (5, MemWidth::B2, SignExtend::Zero),
            (6, MemWidth::B4, SignExtend::Zero),
        ];

        for (funct3, expected_width, expected_sign) in cases {
            let word = i_type(0, 1, funct3, 0, 0x03);
            let mut lifter = RiscVLifter::rv64gc();
            let mut ctx = test_ctx();
            let result = lifter
                .lift_insn(0x1000, &word.to_le_bytes(), &mut ctx)
                .expect("load to x0 should lift");
            assert_eq!(result.ops.len(), 1, "funct3={funct3:#05b}");
            assert!(
                matches!(
                    result.ops[0].kind,
                    OpKind::Load {
                        dst: VReg::Virtual(_),
                        width,
                        sign,
                        ..
                    } if width == expected_width && sign == expected_sign
                ),
                "load to x0 lost its memory operation for funct3={funct3:#05b}: {:?}",
                result.ops
            );
        }
    }

    #[test]
    fn zb_helpers_reject_illegal_rd_x0_before_noop() {
        let cases = [
            r_type(0x7f, 0, 0, 0, 0, 0x33),
            i_type(0x7ff, 0, 0b001, 0, 0x13),
            i_type(0x7ff, 0, 0b001, 0, 0x1b),
        ];

        for word in cases {
            assert_invalid_lift(RiscVLifter::rv64gc(), word);
        }
    }

    #[test]
    fn zb_helpers_decode_with_configured_extensions() {
        let rori = (0b011000 << 26) | (1 << 20) | (1 << 15) | (0b101 << 12) | (2 << 7) | 0x13;

        assert_invalid_lift(RiscVLifter::new_rv64(RiscVExtensions::rv64i()), rori);

        let mut lifter = RiscVLifter::new_rv64(RiscVExtensions {
            zbb: true,
            ..RiscVExtensions::rv64i()
        });
        let mut ctx = test_ctx();
        let result = lifter
            .lift_insn(0x1000, &rori.to_le_bytes(), &mut ctx)
            .expect("enabled Zbb RORI should lift");

        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::Ror { .. })),
            "enabled Zbb RORI did not produce a rotate: {:?}",
            result.ops
        );
    }

    #[test]
    fn rv32_shift_immediates_with_shamt_bit_five_fail_at_decode_frontier() {
        let shift_imm = |funct6: u32, funct3: u32| {
            (funct6 << 26) | (0b10_0000 << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | 0x13
        };
        let words = [
            shift_imm(0b000000, 0b001),
            shift_imm(0b001010, 0b001),
            shift_imm(0b010010, 0b001),
            shift_imm(0b011010, 0b001),
            shift_imm(0b000000, 0b101),
            shift_imm(0b010000, 0b101),
            shift_imm(0b011000, 0b101),
            shift_imm(0b010010, 0b101),
        ];

        for word in words {
            let mut lifter = RiscVLifter::new_rv32(RiscVExtensions::rv64gc());
            let mut context = LiftContext::new(SourceArch::RiscV32);
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, &word.to_le_bytes(), &mut context),
                    Err(LiftError::InvalidEncoding { .. })
                ),
                "reserved RV32 shift {word:#010x} passed the lift frontier"
            );
        }
    }

    #[test]
    fn fp_and_vector_helpers_decode_with_the_configured_profile() {
        let fld = i_type(0, 1, 0b011, 1, 0x07);
        let fadd_d = r_type(0b0000001, 2, 1, 0, 3, 0x53);
        let fmadd_d = (3 << 27) | (0b01 << 25) | (2 << 20) | (1 << 15) | (4 << 7) | 0x43;
        let vadd = 0x0221_80d7; // vadd.vv v1,v2,v3

        // Keep F enabled so each double-precision encoding reaches its helper;
        // disabling F at the outer dispatcher would not exercise the decoder.
        let single_only = RiscVExtensions {
            f: true,
            d: false,
            ..RiscVExtensions::rv64imac()
        };
        for word in [fld, fadd_d, fmadd_d] {
            assert_invalid_lift(RiscVLifter::new_rv64(single_only), word);
        }

        let no_vector = RiscVExtensions {
            v: false,
            ..RiscVExtensions::rv64gc()
        };
        assert_invalid_lift(RiscVLifter::new_rv64(no_vector), vadd);

        // Controls establish that the same encodings lift when their required
        // profile bits are enabled.
        for word in [fld, fadd_d, fmadd_d, vadd] {
            let mut lifter = RiscVLifter::rv64gc();
            let mut ctx = test_ctx();
            assert!(
                lifter
                    .lift_insn(0x1000, &word.to_le_bytes(), &mut ctx)
                    .is_ok()
            );
        }
    }

    #[test]
    fn rv32_pack_uses_16_bit_halves_and_32_bit_result() {
        let pack = r_type(0b0000100, 2, 1, 0b100, 3, 0x33);
        let mut lifter = RiscVLifter::new_rv32(RiscVExtensions {
            zbkb: true,
            ..RiscVExtensions::rv64i()
        });
        let mut ctx = LiftContext::new(SourceArch::RiscV32);
        let result = lifter
            .lift_insn(0x1000, &pack.to_le_bytes(), &mut ctx)
            .expect("RV32 Zbkb pack should lift");

        let zero_extend_halves = result
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op.kind,
                    OpKind::ZeroExtend {
                        from_width: OpWidth::W16,
                        to_width: OpWidth::W32,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            zero_extend_halves, 2,
            "RV32 pack must use two 16-bit halves"
        );
        assert!(result.ops.iter().any(|op| {
            matches!(
                op.kind,
                OpKind::Shl {
                    amount: SrcOperand::Imm(16),
                    width: OpWidth::W32,
                    ..
                }
            )
        }));
        assert!(result.ops.iter().any(|op| {
            matches!(
                op.kind,
                OpKind::Or {
                    width: OpWidth::W32,
                    ..
                }
            )
        }));
    }

    #[test]
    fn zcb_compressed_requires_zcb_extension() {
        let zcb_cases = [
            0x8000u16, // c.lbu x8, 0(x8)
            0x9c45u16, // c.mul x8, x9
            0x9c61u16, // c.zext.b x8
        ];

        for word in zcb_cases {
            assert_invalid_lift(
                RiscVLifter::new_rv64(RiscVExtensions::rv64imac()),
                word as u32,
            );
        }

        let mut lifter = RiscVLifter::new_rv64(RiscVExtensions {
            zcb: true,
            ..RiscVExtensions::rv64imac()
        });
        for word in zcb_cases {
            let mut ctx = test_ctx();
            let result = lifter
                .lift_insn(0x1000, &word.to_le_bytes(), &mut ctx)
                .expect("enabled Zcb compressed instruction should lift");
            assert!(
                !result.ops.is_empty(),
                "enabled Zcb instruction {word:#06x} lifted to no ops"
            );
        }
    }

    #[test]
    fn cbo_zero_lifts_aligned_cache_block_zeroing() {
        let cbo_zero = (0x004u32 << 20) | (10 << 15) | (2 << 12) | 0x0f;
        assert_invalid_lift(RiscVLifter::new_rv64(RiscVExtensions::rv64i()), cbo_zero);

        let mut lifter = RiscVLifter::rv64gc();
        let mut lift_ctx = test_ctx();
        let result = lifter
            .lift_insn(0x1000, &cbo_zero.to_le_bytes(), &mut lift_ctx)
            .expect("enabled Zicboz CBO.ZERO should lift");
        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
        assert_eq!(result.ops.len(), 9);
        assert!(matches!(result.ops[0].kind, OpKind::And { .. }));
        assert_eq!(
            result
                .ops
                .iter()
                .filter(|op| matches!(
                    op.kind,
                    OpKind::Store {
                        width: MemWidth::B8,
                        ..
                    }
                ))
                .count(),
            8
        );

        let mut ops = result.ops;
        for (idx, op) in ops.iter_mut().enumerate() {
            op.id = OpId(idx as u16);
        }
        let block = SmirBlock {
            id: BlockId(0),
            guest_pc: 0x1000,
            phis: vec![],
            ops,
            terminator: Terminator::Trap {
                kind: crate::smir::TrapKind::Breakpoint,
            },
            exec_count: 0,
        };

        let mut ctx = crate::smir::SmirContext::new_riscv();
        ctx.source_arch = SourceArch::RiscV64;
        ctx.write_arch_reg(ArchReg::RiscV(RiscVReg::X(10)), 0x4043);

        let mut memory = crate::smir::FlatMemory::with_base(0, 0x10000);
        {
            use crate::smir::SmirMemory;
            memory.write(0x4000, &[0xa5; 0xc0]).unwrap();
        }

        let interp = crate::smir::SmirInterpreter::new();
        interp.execute_block(&mut ctx, &mut memory, &block);

        let mut before = [0u8; 0x40];
        let mut zeroed = [0xffu8; 0x40];
        let mut after = [0u8; 0x40];
        {
            use crate::smir::SmirMemory;
            memory.read(0x4000, &mut before).unwrap();
            memory.read(0x4040, &mut zeroed).unwrap();
            memory.read(0x4080, &mut after).unwrap();
        }
        assert_eq!(before, [0xa5; 0x40]);
        assert_eq!(zeroed, [0; 0x40]);
        assert_eq!(after, [0xa5; 0x40]);
    }

    #[test]
    fn divw_overflow_returns_sign_extended_i32_min() {
        let divw = r_type(0b0000001, 2, 1, 0b100, 3, 0x3b);
        let result = execute_lifted_gpr_result(
            RiscVLifter::rv64gc(),
            SourceArch::RiscV64,
            divw,
            0x8000_0000,
            0xffff_ffff,
            3,
        );

        assert_eq!(result, 0xffff_ffff_8000_0000);
    }

    #[test]
    fn xida_sltw_lifts_signed_low_word_compare() {
        let sltw = r_type(0, 2, 1, 0b010, 3, 0x3b);
        let mut ext = RiscVExtensions::rv64gc();
        ext.xida_sltw = true;
        let result = execute_lifted_gpr_result(
            RiscVLifter::new_rv64(ext),
            SourceArch::RiscV64,
            sltw,
            0x0000_0000_8000_0000,
            0x0000_0000_7fff_ffff,
            3,
        );

        assert_eq!(result, 1);
    }

    #[test]
    fn rv32_div_overflow_returns_i32_min() {
        let div = r_type(0b0000001, 2, 1, 0b100, 3, 0x33);
        let lifter = RiscVLifter::new_rv32(RiscVExtensions {
            m: true,
            ..RiscVExtensions::rv64i()
        });
        let result = execute_lifted_gpr_result(
            lifter,
            SourceArch::RiscV32,
            div,
            0x8000_0000,
            0xffff_ffff,
            3,
        );

        assert_eq!(result, 0x8000_0000);
    }

    #[test]
    fn rv32_aes32_lifts_through_int_crypto_fallback() {
        let aes32esmi = r_type(0x33, 2, 1, 0, 3, 0x33);
        let lifter = RiscVLifter::new_rv32(RiscVExtensions {
            zkne: true,
            ..RiscVExtensions::rv64i()
        });
        let result = execute_lifted_gpr_result(
            lifter,
            SourceArch::RiscV32,
            aes32esmi,
            0x1020_3040,
            0x0011_2233,
            3,
        );

        assert_eq!(result, 0x83b3_0dee);
    }

    #[test]
    fn rv32_sha512_pair_lifts_through_int_crypto_fallback() {
        let sha512sum1r = r_type(0x29, 2, 1, 0, 3, 0x33);
        let lifter = RiscVLifter::new_rv32(RiscVExtensions {
            zknh: true,
            ..RiscVExtensions::rv64i()
        });
        let result = execute_lifted_gpr_result(
            lifter,
            SourceArch::RiscV32,
            sha512sum1r,
            0x89ab_cdef,
            0x0123_4567,
            3,
        );

        assert_eq!(result, 0x3347_5567);
    }

    #[test]
    fn test_riscv_lifter_addi() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // addi x1, x0, 42  (encoded as: 0x02a00093)
        let bytes = [0x93, 0x00, 0xa0, 0x02];
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);
        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
        assert_eq!(result.ops.len(), 1);

        if let OpKind::Mov {
            dst,
            src: SrcOperand::Imm(42),
            ..
        } = &result.ops[0].kind
        {
            // x0 + 42 optimizes to mov 42
            assert_eq!(*dst, VReg::Arch(ArchReg::RiscV(RiscVReg::X(1))));
        } else if let OpKind::Add {
            dst,
            src2: SrcOperand::Imm(42),
            ..
        } = &result.ops[0].kind
        {
            // Or add x0, 42
            assert_eq!(*dst, VReg::Arch(ArchReg::RiscV(RiscVReg::X(1))));
        } else {
            panic!(
                "Expected ADDI to generate Mov or Add: {:?}",
                result.ops[0].kind
            );
        }
    }

    #[test]
    fn test_rv_vector_defines_scalar_results_for_following_ops() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // vmv.x.s a1,v2
        let vmv_x_s: u32 = (0b010000 << 26) | (1 << 25) | (2 << 20) | (2 << 12) | (11 << 7) | 0x57;
        let vector = lifter
            .lift_insn(0x1000, &vmv_x_s.to_le_bytes(), &mut ctx)
            .unwrap();
        let x11_after_vector = match &vector.ops[0].kind {
            OpKind::RvVector { state, .. } => state.x_dsts[11],
            other => panic!("expected RvVector, got {other:?}"),
        };
        assert_eq!(
            x11_after_vector,
            VReg::Arch(ArchReg::RiscV(RiscVReg::X(11)))
        );

        // addi a2,a1,1
        let addi: u32 = (1 << 20) | (11 << 15) | (12 << 7) | 0x13;
        let scalar = lifter
            .lift_insn(0x1004, &addi.to_le_bytes(), &mut ctx)
            .unwrap();

        assert!(
            scalar.ops.iter().any(|op| matches!(
                &op.kind,
                OpKind::Add {
                    src1,
                    src2: SrcOperand::Imm(1),
                    ..
                } if *src1 == x11_after_vector
            )),
            "following scalar op did not read the RVV-produced a1 value: {:?}",
            scalar.ops
        );
    }

    #[test]
    fn test_rv_vector_uses_prior_scalar_result_as_source() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // addi a0,a0,16
        let addi: u32 = (16 << 20) | (10 << 15) | (10 << 7) | 0x13;
        lifter
            .lift_insn(0x1000, &addi.to_le_bytes(), &mut ctx)
            .unwrap();
        let a0_after_addi = VReg::Arch(ArchReg::RiscV(RiscVReg::X(10)));

        // vle32.v v1,(a0)
        let vle32_v1_a0: u32 = (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07;
        let vector = lifter
            .lift_insn(0x1004, &vle32_v1_a0.to_le_bytes(), &mut ctx)
            .unwrap();

        match &vector.ops[0].kind {
            OpKind::RvVector { rs1, state, .. } => {
                assert_eq!(*rs1, a0_after_addi);
                assert_eq!(state.x_srcs[10], a0_after_addi);
            }
            other => panic!("expected RvVector, got {other:?}"),
        }
    }

    #[test]
    fn test_riscv_lifter_jal() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // jal x1, 0x100  (J-type, jump forward 256 bytes)
        // imm[20|10:1|11|19:12] = 0x100 = 0b0000_0001_0000_0000
        // Encoding: imm[20]=0, imm[10:1]=0x80, imm[11]=0, imm[19:12]=0
        let bytes = [0xef, 0x00, 0x00, 0x10]; // jal ra, 0x100
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);

        if let ControlFlow::DirectBranch(target) = result.control_flow {
            // Should jump to 0x1000 + offset
            assert!(target > 0x1000);
        } else {
            panic!("Expected DirectBranch");
        }
    }

    #[test]
    fn test_riscv_lifter_beq() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // beq x1, x2, 0x10  (B-type)
        let bytes = [0x63, 0x08, 0x20, 0x00]; // beq x1, x2, 16
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);

        if let ControlFlow::CondBranchReg {
            taken, not_taken, ..
        } = result.control_flow
        {
            assert_eq!(taken, 0x1010);
            assert_eq!(not_taken, 0x1004);
        } else {
            panic!("Expected CondBranchReg");
        }
    }

    #[test]
    fn test_riscv_lifter_load_store() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // ld x1, 8(x2)
        let bytes = [0x83, 0x30, 0x81, 0x00]; // ld x1, 8(x2)
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);
        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
        assert_eq!(result.ops.len(), 1);

        if let OpKind::Load {
            width: MemWidth::B8,
            ..
        } = &result.ops[0].kind
        {
            // OK
        } else {
            panic!("Expected 64-bit Load");
        }
    }

    #[test]
    fn test_riscv_lifter_compressed_addi() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // c.addi x1, 5  (encoded as: 0x0515)
        let bytes = [0x85, 0x00]; // c.addi x1, 1
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 2);
        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
    }

    #[test]
    fn test_riscv_lifter_compressed_j() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // c.j 0x10 (jump forward 16 bytes)
        let bytes = [0x21, 0xa0]; // c.j 8
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 2);

        if let ControlFlow::DirectBranch(_target) = result.control_flow {
            // OK - target varies by encoding
        } else {
            panic!("Expected DirectBranch");
        }
    }

    #[test]
    fn test_riscv_mul_div() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // mul x1, x2, x3  (M extension)
        let bytes = [0xb3, 0x80, 0x31, 0x02]; // mul x1, x3, x3
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);
        assert!(matches!(result.control_flow, ControlFlow::NextInsn));
    }

    #[test]
    fn test_riscv_atomic() {
        let mut lifter = RiscVLifter::rv64gc();
        let mut ctx = test_ctx();

        // amoadd.d x1, x2, (x3)
        let bytes = [0xaf, 0x30, 0x21, 0x00]; // amoadd.w x1, x2, (x2)
        let result = lifter.lift_insn(0x1000, &bytes, &mut ctx).unwrap();

        assert_eq!(result.bytes_consumed, 4);

        if let OpKind::AtomicRmw {
            op: AtomicOp::Add, ..
        } = &result.ops[0].kind
        {
            // OK
        } else {
            panic!("Expected AtomicRmw Add");
        }
    }

    #[test]
    fn amocas_q_lifts_pair_operands_and_rejects_odd_pairs() {
        let encode = |rd: u8, rs2: u8| {
            (0b00101 << 27)
                | (1 << 26) // aq
                | (1 << 25) // rl
                | (u32::from(rs2) << 20)
                | (10 << 15)
                | (0b100 << 12)
                | (u32::from(rd) << 7)
                | 0x2f
        };
        let mut lifter = RiscVLifter::rv64gc();
        let mut context = test_ctx();
        let result = lifter
            .lift_insn(0x1000, &encode(6, 8).to_le_bytes(), &mut context)
            .expect("lift AMOCAS.Q");
        assert_eq!(result.ops.len(), 1);
        assert!(matches!(
            result.ops[0].kind,
            OpKind::CasPair {
                dst_lo: VReg::Arch(ArchReg::RiscV(RiscVReg::X(6))),
                dst_hi: VReg::Arch(ArchReg::RiscV(RiscVReg::X(7))),
                expected_lo: VReg::Arch(ArchReg::RiscV(RiscVReg::X(6))),
                expected_hi: VReg::Arch(ArchReg::RiscV(RiscVReg::X(7))),
                new_lo: VReg::Arch(ArchReg::RiscV(RiscVReg::X(8))),
                new_hi: VReg::Arch(ArchReg::RiscV(RiscVReg::X(9))),
                order: MemoryOrder::SeqCst,
                failure_order: MemoryOrder::Acquire,
                ..
            }
        ));

        let mut context = test_ctx();
        let x0_pairs = lifter
            .lift_insn(0x1000, &encode(0, 0).to_le_bytes(), &mut context)
            .expect("lift AMOCAS.Q with x0 pairs");
        assert!(matches!(
            x0_pairs.ops[0].kind,
            OpKind::CasPair {
                dst_lo: VReg::Virtual(_),
                dst_hi: VReg::Virtual(_),
                expected_lo: VReg::Imm(0),
                expected_hi: VReg::Imm(0),
                new_lo: VReg::Imm(0),
                new_hi: VReg::Imm(0),
                ..
            }
        ));

        for invalid in [encode(7, 8), encode(6, 9), encode(31, 8)] {
            assert_invalid_lift(RiscVLifter::rv64gc(), invalid);
        }
    }

    #[test]
    fn lr_sc_ordering_bits_emit_fences_at_the_memory_boundary() {
        let encode = |funct5: u32, aq: bool, rl: bool| {
            // LR reserves rs2=x0; SC reads its store value from x2.
            let rs2 = if funct5 == 0b00010 { 0 } else { 2 };
            (funct5 << 27)
                | (u32::from(aq) << 26)
                | (u32::from(rl) << 25)
                | (rs2 << 20)
                | (1 << 15)
                | (0b010 << 12)
                | (3 << 7)
                | 0x2f
        };
        for (funct5, expected_memory_op) in
            [(0b00010, "load-exclusive"), (0b00011, "store-exclusive")]
        {
            let mut lifter = RiscVLifter::rv64gc();
            let mut context = test_ctx();
            let instruction = encode(funct5, true, true);
            let result = lifter
                .lift_insn(0x1000, &instruction.to_le_bytes(), &mut context)
                .expect("lift ordered LR/SC");
            assert!(matches!(result.ops[0].kind, OpKind::Fence { .. }));
            match (expected_memory_op, &result.ops[1].kind) {
                ("load-exclusive", OpKind::LoadExclusive { .. })
                | ("store-exclusive", OpKind::StoreExclusive { .. }) => {}
                (_, other) => panic!("unexpected ordered LR/SC memory op: {other:?}"),
            }
            assert!(matches!(result.ops[2].kind, OpKind::Fence { .. }));
        }
    }

    #[test]
    fn test_lift_context_riscv() {
        let mut ctx = LiftContext::new(SourceArch::RiscV64);

        let v0 = ctx.alloc_vreg();
        let v1 = ctx.alloc_vreg();

        assert_ne!(v0, v1);
        assert!(v0.is_virtual());
    }
}
