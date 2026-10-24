//! SMIR IR structures.
//!
//! This module defines the hierarchical IR structure:
//! - Module: top-level container
//! - Function: a lifted function
//! - Block: a basic block
//! - Terminator: block terminators (branches, returns, etc.)

mod arm_instruction;
pub(crate) use arm_instruction::validate_aarch64_instructions;
mod aarch64_state;
#[cfg(test)]
mod aarch64_state_tests;
mod call;
pub use call::{CallTarget, RuntimeFunc};
pub mod context;
pub mod flags;
pub mod memory;
pub mod ops;
mod trap;
pub use trap::{TrapKind, X86Segment, X86StringIoKind};
pub mod types;
mod x86_native_replay;
pub use x86_native_replay::*;

use std::collections::HashMap;

use crate::smir::ir::ops::SmirOp;
use crate::smir::ir::types::*;

// ============================================================================
// Module
// ============================================================================

/// Top-level IR module containing all lifted code
#[derive(Clone, Debug)]
pub struct SmirModule {
    /// Unique module identifier
    pub id: ModuleId,
    /// Source architecture
    pub source_arch: SourceArch,
    /// Functions in this module
    pub functions: Vec<SmirFunction>,
    /// Global symbol table (name -> address)
    pub symbols: HashMap<String, GuestAddr>,
    /// External references (imports)
    pub externals: Vec<ExternalRef>,
    /// Module-level metadata
    pub metadata: ModuleMetadata,
}

impl SmirModule {
    /// Create a new empty module
    pub fn new(id: ModuleId, source_arch: SourceArch) -> Self {
        SmirModule {
            id,
            source_arch,
            functions: Vec::new(),
            symbols: HashMap::new(),
            externals: Vec::new(),
            metadata: ModuleMetadata::default(),
        }
    }

    /// Add a function to the module
    pub fn add_function(&mut self, func: SmirFunction) {
        self.functions.push(func);
    }

    /// Find a function by its entry address
    pub fn find_function(&self, addr: GuestAddr) -> Option<&SmirFunction> {
        self.functions
            .iter()
            .find(|f| f.guest_range.0 <= addr && addr < f.guest_range.1)
    }

    /// Find a function by its ID
    pub fn get_function(&self, id: FunctionId) -> Option<&SmirFunction> {
        self.functions.iter().find(|f| f.id == id)
    }
}

/// External reference (import)
#[derive(Clone, Debug)]
pub struct ExternalRef {
    /// Symbol name
    pub name: String,
    /// Expected address (if known)
    pub addr: Option<GuestAddr>,
}

/// Module metadata
#[derive(Clone, Debug, Default)]
pub struct ModuleMetadata {
    /// Guest entry point address
    pub entry_point: Option<GuestAddr>,
    /// Guest stack base (if known)
    pub stack_base: Option<GuestAddr>,
    /// Text section range
    pub text_range: Option<(GuestAddr, GuestAddr)>,
}

// ============================================================================
// Function
// ============================================================================

/// A lifted function
#[derive(Clone, Debug)]
pub struct SmirFunction {
    /// Function identifier
    pub id: FunctionId,
    /// Entry block ID
    pub entry: BlockId,
    /// All basic blocks
    pub blocks: Vec<SmirBlock>,
    /// Local variable slots (spills, temporaries)
    pub locals: Vec<LocalSlot>,
    /// Guest address range covered
    pub guest_range: (GuestAddr, GuestAddr),
    /// Calling convention
    pub calling_convention: CallingConv,
    /// Function attributes
    pub attrs: FunctionAttrs,
    /// Exact source bytes for x86 instructions retained in this function,
    /// keyed by `(block, guest PC)`. These bytes are provenance metadata: the
    /// interpreter and architecture-independent optimizers use the semantic
    /// SMIR operations, while the same-architecture x86 lowerer may replay a
    /// narrowly validated register-only instruction to avoid materializing
    /// otherwise unrepresentable vector temporaries.
    pub x86_instruction_bytes: HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
}

impl SmirFunction {
    /// Create a new function
    pub fn new(id: FunctionId, entry: BlockId, guest_start: GuestAddr) -> Self {
        SmirFunction {
            id,
            entry,
            blocks: Vec::new(),
            locals: Vec::new(),
            guest_range: (guest_start, guest_start),
            calling_convention: CallingConv::GuestPreserveAll,
            attrs: FunctionAttrs::default(),
            x86_instruction_bytes: HashMap::new(),
        }
    }

    /// Add a block to the function
    pub fn add_block(&mut self, block: SmirBlock) {
        // Update guest range
        if block.guest_pc < self.guest_range.0 {
            self.guest_range.0 = block.guest_pc;
        }
        if block.guest_pc > self.guest_range.1 {
            self.guest_range.1 = block.guest_pc;
        }
        self.blocks.push(block);
    }

    /// Get a block by ID
    pub fn get_block(&self, id: BlockId) -> Option<&SmirBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Get a mutable block by ID
    pub fn get_block_mut(&mut self, id: BlockId) -> Option<&mut SmirBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    /// Get the entry block
    pub fn entry_block(&self) -> Option<&SmirBlock> {
        self.get_block(self.entry)
    }

    /// Total number of operations across all blocks
    pub fn op_count(&self) -> usize {
        self.blocks.iter().map(|b| b.ops.len()).sum()
    }
}

/// Calling convention
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallingConv {
    /// Preserve all guest state
    #[default]
    GuestPreserveAll,
    /// x86_64 System V ABI
    X86SysV,
    /// x86_64 Windows ABI
    X86Win64,
    /// AArch64 AAPCS
    Aarch64Aapcs,
    /// Hexagon standard
    HexagonStd,
    /// RISC-V standard
    RiscVStd,
}

/// Local variable slot
#[derive(Clone, Debug)]
pub struct LocalSlot {
    pub id: LocalId,
    pub size: u32,
    pub align: u32,
}

/// Function attributes
#[derive(Clone, Copy, Debug, Default)]
pub struct FunctionAttrs {
    /// May not return (infinite loop, abort)
    pub no_return: bool,
    /// Has no side effects beyond return value
    pub pure_fn: bool,
    /// Entry point of the guest program
    pub is_entry: bool,
    /// Exception handler
    pub is_exception_handler: bool,
    /// Permit forwarding repeated ordinary loads within a basic block.
    ///
    /// This may be set only when every [`OpKind::Load`](crate::smir::ir::ops::OpKind::Load)
    /// in the function is non-faulting and non-volatile (no MMIO/device read),
    /// and an equal address, width, and extension mode returns the same value
    /// until an intervening SMIR memory write. Guest-memory JIT regions must
    /// normally leave this false because each read is architecturally visible.
    pub allow_redundant_load_elimination: bool,
    /// Preserve zero-operation `Return` blocks used as explicit interpreter
    /// handoff frontiers. Merging such a block into its predecessor would move
    /// the frontier to the predecessor and make the native runtime reject or
    /// re-execute otherwise valid work.
    pub preserve_interpreter_frontiers: bool,
}

// ============================================================================
// Block
// ============================================================================

/// A basic block
#[derive(Clone, Debug)]
pub struct SmirBlock {
    /// Block identifier
    pub id: BlockId,
    /// Guest PC at block entry
    pub guest_pc: GuestAddr,
    /// Phi nodes (for SSA, may be empty)
    pub phis: Vec<PhiNode>,
    /// Operations in this block
    pub ops: Vec<SmirOp>,
    /// Block terminator
    pub terminator: Terminator,
    /// Estimated execution count (for hot path detection)
    pub exec_count: u64,
}

impl SmirBlock {
    /// Create a new block
    pub fn new(id: BlockId, guest_pc: GuestAddr) -> Self {
        SmirBlock {
            id,
            guest_pc,
            phis: Vec::new(),
            ops: Vec::new(),
            terminator: Terminator::Unreachable,
            exec_count: 0,
        }
    }

    /// Add an operation to the block
    pub fn push_op(&mut self, op: SmirOp) {
        self.ops.push(op);
    }

    /// Set the terminator
    pub fn set_terminator(&mut self, term: Terminator) {
        self.terminator = term;
    }

    /// Get successor block IDs
    pub fn successors(&self) -> Vec<BlockId> {
        self.terminator.successors()
    }

    /// Check if block is empty (no ops, unreachable terminator)
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && matches!(self.terminator, Terminator::Unreachable)
    }
}

/// Phi node (SSA)
#[derive(Clone, Debug)]
pub struct PhiNode {
    pub dst: VReg,
    pub sources: Vec<(BlockId, VReg)>,
}

// ============================================================================
// Terminator
// ============================================================================

/// Block terminator
#[derive(Clone, Debug)]
pub enum Terminator {
    /// Unconditional branch
    Branch { target: BlockId },

    /// Conditional branch
    CondBranch {
        cond: VReg,
        true_target: BlockId,
        false_target: BlockId,
    },

    /// Multi-way branch (switch)
    Switch {
        index: VReg,
        targets: Vec<BlockId>,
        default: BlockId,
    },

    /// Indirect branch (computed goto)
    IndirectBranch {
        target: VReg,
        /// Possible targets (for analysis, may be incomplete)
        possible_targets: Vec<BlockId>,
    },

    /// Indirect branch through memory
    IndirectBranchMem {
        addr: Address,
        /// Possible targets (for analysis, may be incomplete)
        possible_targets: Vec<BlockId>,
    },

    /// Function return
    Return { values: Vec<VReg> },

    /// Call with continuation
    Call {
        target: CallTarget,
        args: Vec<VReg>,
        continuation: BlockId,
    },

    /// Tail call (no return)
    TailCall { target: CallTarget, args: Vec<VReg> },

    /// Trap (undefined, breakpoint, etc.)
    Trap { kind: TrapKind },

    /// Unreachable (for dead code)
    Unreachable,
}

impl Terminator {
    /// Get successor block IDs
    pub fn successors(&self) -> Vec<BlockId> {
        match self {
            Terminator::Branch { target } => vec![*target],
            Terminator::CondBranch {
                true_target,
                false_target,
                ..
            } => vec![*true_target, *false_target],
            Terminator::Switch {
                targets, default, ..
            } => {
                let mut v = targets.clone();
                v.push(*default);
                v
            }
            Terminator::IndirectBranch {
                possible_targets, ..
            } => possible_targets.clone(),
            Terminator::IndirectBranchMem {
                possible_targets, ..
            } => possible_targets.clone(),
            Terminator::Call { continuation, .. } => vec![*continuation],
            Terminator::Return { .. }
            | Terminator::TailCall { .. }
            | Terminator::Trap { .. }
            | Terminator::Unreachable => vec![],
        }
    }

    /// Check if this is a return
    pub fn is_return(&self) -> bool {
        matches!(self, Terminator::Return { .. })
    }

    /// Check if this is a trap
    pub fn is_trap(&self) -> bool {
        matches!(self, Terminator::Trap { .. })
    }

    /// Check if this terminates the function (no successors)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Terminator::Return { .. }
                | Terminator::TailCall { .. }
                | Terminator::Trap { .. }
                | Terminator::Unreachable
        )
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for constructing SMIR functions
pub struct FunctionBuilder {
    func: SmirFunction,
    current_block: BlockId,
    next_op_id: u16,
    block_alloc: BlockIdAllocator,
    vreg_alloc: VRegAllocator,
}

impl FunctionBuilder {
    /// Create a new function builder
    pub fn new(func_id: FunctionId, entry_pc: GuestAddr) -> Self {
        let mut block_alloc = BlockIdAllocator::new();
        let entry = block_alloc.alloc();

        let mut func = SmirFunction::new(func_id, entry, entry_pc);
        func.blocks.push(SmirBlock::new(entry, entry_pc));

        FunctionBuilder {
            func,
            current_block: entry,
            next_op_id: 0,
            block_alloc,
            vreg_alloc: VRegAllocator::new(),
        }
    }

    /// Allocate a new virtual register
    pub fn alloc_vreg(&mut self) -> VReg {
        self.vreg_alloc.alloc()
    }

    /// Create a new block and return its ID
    pub fn create_block(&mut self, guest_pc: GuestAddr) -> BlockId {
        let id = self.block_alloc.alloc();
        self.func.blocks.push(SmirBlock::new(id, guest_pc));
        id
    }

    /// Switch to a different block for appending ops
    pub fn switch_to_block(&mut self, block: BlockId) {
        self.current_block = block;
        self.next_op_id = 0;
    }

    /// Get the current block ID
    pub fn current_block(&self) -> BlockId {
        self.current_block
    }

    /// Push an operation to the current block
    pub fn push_op(&mut self, guest_pc: GuestAddr, kind: crate::smir::ir::ops::OpKind) {
        let op = SmirOp::new(OpId(self.next_op_id), guest_pc, kind);
        self.next_op_id += 1;

        if let Some(block) = self.func.get_block_mut(self.current_block) {
            block.push_op(op);
        }
    }

    /// Set the terminator for the current block
    pub fn set_terminator(&mut self, term: Terminator) {
        if let Some(block) = self.func.get_block_mut(self.current_block) {
            block.set_terminator(term);
        }
    }

    /// Finish building and return the function
    pub fn finish(self) -> SmirFunction {
        self.func
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::ir::ops::OpKind;

    #[test]
    fn test_function_builder() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let v0 = builder.alloc_vreg();
        let v1 = builder.alloc_vreg();
        let v2 = builder.alloc_vreg();

        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::imm(42),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1004,
            OpKind::Add {
                dst: v2,
                src1: v0,
                src2: SrcOperand::Reg(v1),
                width: OpWidth::W64,
                flags: crate::smir::ir::flags::FlagUpdate::None,
            },
        );

        builder.set_terminator(Terminator::Return { values: vec![v2] });

        let func = builder.finish();

        assert_eq!(func.blocks.len(), 1);
        assert_eq!(func.blocks[0].ops.len(), 2);
        assert!(func.blocks[0].terminator.is_return());
    }

    #[test]
    fn test_terminator_successors() {
        let term = Terminator::CondBranch {
            cond: VReg::virt(0),
            true_target: BlockId(1),
            false_target: BlockId(2),
        };

        let succs = term.successors();
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&BlockId(1)));
        assert!(succs.contains(&BlockId(2)));

        let term = Terminator::Return { values: vec![] };
        assert!(term.successors().is_empty());
        assert!(term.is_terminal());
    }

    #[test]
    fn x86_evex_fp_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xF1, 0x6C, 0x48, 0x58, 0xCB][..], Some(false)),
            (&[0x62, 0xA1, 0x6C, 0xA1, 0x58, 0xCB][..], Some(true)),
            (&[0x62, 0xF1, 0x6E, 0x89, 0x58, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0xEF, 0x09, 0x5F, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0x6C, 0x58, 0x58, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0x6E, 0x28, 0x58, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0x7C, 0x58, 0x5D, 0xCB][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_fp_arithmetic_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF1, 0x6C, 0x48, 0x58],       // incomplete
            &[0x62, 0xF5, 0x6C, 0x48, 0x58, 0xCB], // MAP5 / FP16
            &[0x62, 0xF1, 0x6C, 0x48, 0x58, 0x08], // memory source
            &[0x62, 0xF1, 0x6C, 0x88, 0x58, 0xCB], // {z} with k0
            &[0x62, 0xF1, 0x68, 0x48, 0x58, 0xCB], // fixed-one bit clear
            &[0x62, 0xF1, 0xEC, 0x48, 0x58, 0xCB], // PS with W1
            &[0x62, 0xF1, 0x6D, 0x48, 0x58, 0xCB], // PD with W0
            &[0x62, 0xF1, 0x6C, 0x68, 0x58, 0xCB], // packed L'L=3
            &[0x62, 0xF1, 0x6E, 0x68, 0x58, 0xCB], // scalar L'L=3 without ER
            &[0x62, 0xF1, 0x6C, 0x48, 0x51, 0xCB], // different opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_fp_arithmetic_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
        assert!(X86InstructionBytes::new(&[]).is_none());
        assert!(X86InstructionBytes::new(&[0x90; 16]).is_none());
    }

    #[test]
    fn x86_evex_fp_replay_spans_require_block_provenance_and_contiguity() {
        let mut block = SmirBlock::new(BlockId(7), 0x1000);
        block.push_op(SmirOp::new(OpId(0), 0x1000, OpKind::Nop));
        block.push_op(SmirOp::new(OpId(1), 0x1000, OpKind::Nop));
        block.push_op(SmirOp::new(OpId(2), 0x1006, OpKind::Nop));
        let instruction = X86InstructionBytes::new(&[0x62, 0xF1, 0x6C, 0x48, 0x58, 0xCB]).unwrap();
        let mut provenance = HashMap::from([((BlockId(7), 0x1000), instruction)]);

        let spans = x86_evex_fp_replay_spans(&block, &provenance);
        assert_eq!(spans.get(&0).map(|span| span.end), Some(2));

        provenance.clear();
        provenance.insert((BlockId(8), 0x1000), instruction);
        assert!(x86_evex_fp_replay_spans(&block, &provenance).is_empty());

        provenance.clear();
        provenance.insert((BlockId(7), 0x1000), instruction);
        block.push_op(SmirOp::new(OpId(3), 0x1000, OpKind::Nop));
        assert!(x86_evex_fp_replay_spans(&block, &provenance).is_empty());
    }

    #[test]
    fn x86_evex_logic_replay_classifier_tracks_vl_and_dq_exactly() {
        let valid = [
            (
                &[0x62, 0xF1, 0x7C, 0x09, 0x54, 0xC8][..],
                Some((true, true)),
            ),
            (
                &[0x62, 0xF1, 0xFD, 0x49, 0x57, 0xC8][..],
                Some((false, true)),
            ),
            (
                &[0x62, 0xA1, 0x7D, 0xA1, 0xEF, 0xCB][..],
                Some((true, false)),
            ),
            (
                &[0x62, 0xF1, 0xFD, 0x49, 0xDB, 0xCB][..],
                Some((false, false)),
            ),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_logic_requirements(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7C, 0x09, 0x54, 0xC8], // wrong map
            &[0x62, 0xF1, 0x7C, 0x09, 0x54, 0x08], // memory source
            &[0x62, 0xF1, 0x7C, 0x19, 0x54, 0xC8], // EVEX.b
            &[0x62, 0xF1, 0x7C, 0x88, 0x54, 0xC8], // {z} with k0
            &[0x62, 0xF1, 0x7E, 0x09, 0x54, 0xC8], // floating F3 prefix
            &[0x62, 0xF1, 0xFC, 0x09, 0x54, 0xC8], // PS with W1
            &[0x62, 0xF1, 0x7C, 0x09, 0xDB, 0xC8], // integer without 66
            &[0x62, 0xF1, 0x7D, 0x69, 0xDB, 0xC8], // L'L=3
            &[0x62, 0xF1, 0x7D, 0x09, 0x58, 0xC8], // arithmetic opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_logic_requirements(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_integer_arithmetic_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xF1, 0x75, 0x09, 0xFC, 0xC8][..], Some(true)),
            // WIG byte/word operations also admit W1.
            (&[0x62, 0xF1, 0xF5, 0x29, 0xE9, 0xC8][..], Some(true)),
            (&[0x62, 0xF1, 0x7D, 0x49, 0xFA, 0xC8][..], Some(false)),
            (&[0x62, 0xF1, 0xFD, 0xC9, 0xD4, 0xC8][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_arithmetic_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x75, 0x09, 0xFC, 0xC8], // wrong map
            &[0x62, 0xF1, 0x75, 0x09, 0xFC, 0x08], // memory source
            &[0x62, 0xF1, 0x75, 0x19, 0xFC, 0xC8], // EVEX.b
            &[0x62, 0xF1, 0x75, 0x88, 0xFC, 0xC8], // {z} with k0
            &[0x62, 0xF1, 0x74, 0x09, 0xFC, 0xC8], // missing 66 prefix
            &[0x62, 0xF1, 0xFD, 0x09, 0xFA, 0xC8], // VPSUBD with W1
            &[0x62, 0xF1, 0x7D, 0x09, 0xD4, 0xC8], // VPADDQ with W0
            &[0x62, 0xF1, 0x75, 0x69, 0xFC, 0xC8], // L'L=3
            &[0x62, 0xF1, 0x75, 0x09, 0xDB, 0xC8], // logical opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_arithmetic_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_shared_count_shift_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xA1, 0x6D, 0xC1, 0xF1, 0xCB][..], Some(false)),
            // WIG word shifts also admit W1.
            (&[0x62, 0xF1, 0xFD, 0x29, 0xD1, 0xC8][..], Some(true)),
            (&[0x62, 0xF1, 0x7D, 0x09, 0xD2, 0xC8][..], Some(true)),
            (&[0x62, 0xF1, 0xFD, 0x49, 0xE2, 0xC8][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_shared_count_shift_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0xD2, 0xC8], // wrong map
            &[0x62, 0xF1, 0x7D, 0x09, 0xD2, 0x08], // memory count
            &[0x62, 0xF1, 0x7D, 0x19, 0xD2, 0xC8], // EVEX.b
            &[0x62, 0xF1, 0x7D, 0x88, 0xD2, 0xC8], // {z} with k0
            &[0x62, 0xF1, 0x7C, 0x09, 0xD2, 0xC8], // missing 66 prefix
            &[0x62, 0xF1, 0xFD, 0x09, 0xD2, 0xC8], // VPSRLD with W1
            &[0x62, 0xF1, 0x7D, 0x09, 0xD3, 0xC8], // VPSRLQ with W0
            &[0x62, 0xF1, 0x7D, 0x69, 0xD2, 0xC8], // L'L=3
            &[0x62, 0xF1, 0x7D, 0x09, 0xD4, 0xC8], // packed-add opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_shared_count_shift_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_immediate_count_shift_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xB1, 0x75, 0xC1, 0x71, 0xF2, 0x05][..], Some(false)),
            // WIG word shifts also admit W1.
            (&[0x62, 0xF1, 0xFD, 0x29, 0x71, 0xD0, 0x03][..], Some(true)),
            (&[0x62, 0xF1, 0x75, 0x09, 0x72, 0xD0, 0x03][..], Some(true)),
            (&[0x62, 0xF1, 0xF5, 0x49, 0x72, 0xE0, 0x03][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_immediate_count_shift_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x75, 0x09, 0x72, 0xD0, 0x03], // wrong map
            &[0x62, 0xF1, 0x75, 0x09, 0x72, 0x10, 0x03], // memory source
            &[0x62, 0xF1, 0x75, 0x19, 0x72, 0xD0, 0x03], // EVEX.b
            &[0x62, 0xF1, 0x75, 0x88, 0x72, 0xD0, 0x03], // {z} with k0
            &[0x62, 0xF1, 0x74, 0x09, 0x72, 0xD0, 0x03], // missing 66 prefix
            &[0x62, 0xF1, 0xF5, 0x09, 0x72, 0xD0, 0x03], // VPSRLD with W1
            &[0x62, 0xF1, 0x75, 0x09, 0x73, 0xD0, 0x03], // VPSRLQ with W0
            &[0x62, 0xF1, 0xF5, 0x09, 0x73, 0xE0, 0x03], // invalid /4 group
            &[0x62, 0xF1, 0x75, 0x09, 0x72, 0xC0, 0x03], // invalid /0 group
            &[0x62, 0xF1, 0x75, 0x69, 0x72, 0xD0, 0x03], // L'L=3
            &[0x62, 0xF1, 0x75, 0x09, 0x70, 0xD0, 0x03], // unrelated opcode
            &[0x62, 0xF1, 0x75, 0x09, 0x72, 0xD0],       // missing imm8
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_immediate_count_shift_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_rotate_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // Immediate VPRORD/VPROLD/VPRORQ/VPROLQ.
            (&[0x62, 0xF1, 0x75, 0x08, 0x72, 0xC2, 0x00][..], Some(true)),
            (&[0x62, 0xB1, 0x75, 0xA7, 0x72, 0xCA, 0xFF][..], Some(true)),
            (&[0x62, 0x91, 0xFD, 0x40, 0x72, 0xC7, 0x3F][..], Some(false)),
            (&[0x62, 0x91, 0x8D, 0x01, 0x72, 0xCF, 0x40][..], Some(true)),
            // R/R' are ignored when ModR/M.reg is the /0 or /1 extension.
            (&[0x62, 0x61, 0x75, 0x08, 0x72, 0xC2, 0x00][..], Some(true)),
            // Variable VPRORVD/VPROLVD/VPRORVQ/VPROLVQ.
            (&[0x62, 0xF2, 0x6D, 0x08, 0x14, 0xCB][..], Some(true)),
            (&[0x62, 0xA2, 0x6D, 0xA7, 0x15, 0xCB][..], Some(true)),
            (&[0x62, 0x02, 0x8D, 0x40, 0x14, 0xEF][..], Some(false)),
            (&[0x62, 0x22, 0xFD, 0x01, 0x15, 0xF9][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_rotate_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x75, 0x08, 0x72, 0xC2, 0x00], // immediate wrong map
            &[0x62, 0xF1, 0x75, 0x08, 0x72, 0x02, 0x00], // immediate memory source
            &[0x62, 0xF1, 0x75, 0x18, 0x72, 0xC2, 0x00], // immediate EVEX.b
            &[0x62, 0xF1, 0x75, 0x88, 0x72, 0xC2, 0x00], // immediate {z} with k0
            &[0x62, 0xF1, 0x74, 0x08, 0x72, 0xC2, 0x00], // immediate missing 66
            &[0x62, 0xF1, 0x75, 0x08, 0x72, 0xD2, 0x00], // immediate invalid /2
            &[0x62, 0xF1, 0x75, 0x68, 0x72, 0xC2, 0x00], // immediate L'L=3
            &[0x62, 0xF1, 0x75, 0x08, 0x73, 0xC2, 0x00], // immediate wrong opcode
            &[0x62, 0xF1, 0x75, 0x08, 0x72, 0xC2],       // missing imm8
            &[0x62, 0xF1, 0x6D, 0x08, 0x14, 0xCB],       // variable wrong map
            &[0x62, 0xF2, 0x6D, 0x08, 0x14, 0x0B],       // variable memory count
            &[0x62, 0xF2, 0x6D, 0x18, 0x14, 0xCB],       // variable EVEX.b
            &[0x62, 0xF2, 0x6D, 0x88, 0x14, 0xCB],       // variable {z} with k0
            &[0x62, 0xF2, 0x6C, 0x08, 0x14, 0xCB],       // variable missing 66
            &[0x62, 0xF2, 0x6D, 0x68, 0x14, 0xCB],       // variable L'L=3
            &[0x62, 0xF2, 0x6D, 0x08, 0x13, 0xCB],       // variable wrong opcode
            &[0x62, 0xF2, 0x6D, 0x08, 0x14],             // missing ModR/M
            &[0x62, 0xF2, 0x6D, 0x08, 0x14, 0xCB, 0x00], // spurious imm8
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_rotate_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_fma_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xA2, 0xED, 0xC1, 0x98, 0xCB][..], Some(false)),
            (&[0x62, 0xF2, 0x6D, 0x29, 0xA6, 0xC8][..], Some(true)),
            (&[0x62, 0xF2, 0xED, 0x09, 0xBE, 0xC8][..], Some(true)),
            // EVEX.b repurposes L'L as embedded rounding and implies 512 bits.
            (&[0x62, 0xA2, 0xED, 0x91, 0x98, 0xCB][..], Some(false)),
            (&[0x62, 0xA2, 0xED, 0xF1, 0x98, 0xCB][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_fma_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xA1, 0xED, 0xC1, 0x98, 0xCB], // wrong map
            &[0x62, 0xA2, 0xE9, 0xC1, 0x98, 0xCB], // missing EVEX fixed-one bit
            &[0x62, 0xA2, 0xEC, 0xC1, 0x98, 0xCB], // missing 66 prefix
            &[0x62, 0xA2, 0xED, 0xC1, 0x98, 0x0B], // memory source
            &[0x62, 0xA2, 0xED, 0xC8, 0x98, 0xCB], // {z} with k0
            &[0x62, 0xA2, 0xED, 0xE1, 0x98, 0xCB], // L'L=3
            &[0x62, 0xA2, 0xED, 0xC1, 0x99, 0xCB], // scalar FMA opcode
            &[0x62, 0xA2, 0xED, 0xC1, 0x9B, 0xCB], // unrelated opcode
            &[0x62, 0xA2, 0xED, 0xC1, 0x98],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_fma_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_scalar_fma_replay_classifier_is_exact_and_fail_closed() {
        let valid: &[&[u8]] = &[
            // vfmadd231sd xmm17{k1}{z}, xmm18, xmm19
            &[0x62, 0xA2, 0xED, 0x81, 0xB9, 0xCB],
            // W0 selects scalar binary32.
            &[0x62, 0xF2, 0x6D, 0x09, 0x99, 0xC8],
            &[0x62, 0xF2, 0xED, 0x09, 0xAF, 0xC8],
            // Defined LLIG aliases without embedded rounding.
            &[0x62, 0xA2, 0xED, 0xA1, 0xB9, 0xCB],
            &[0x62, 0xA2, 0xED, 0xC1, 0xB9, 0xCB],
            &[0x62, 0xA2, 0xED, 0xE1, 0xB9, 0xCB],
            // EVEX.b repurposes all four L'L values as embedded rounding.
            &[0x62, 0x02, 0xA5, 0x74, 0x9F, 0xD4],
        ];
        for bytes in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_scalar_fma_needs_vl(),
                Some(false),
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xA1, 0xED, 0x81, 0xB9, 0xCB], // wrong map
            &[0x62, 0xA2, 0xE9, 0x81, 0xB9, 0xCB], // missing EVEX fixed-one bit
            &[0x62, 0xA2, 0xEC, 0x81, 0xB9, 0xCB], // missing 66 prefix
            &[0x62, 0xA2, 0xED, 0x81, 0xB9, 0x0B], // memory source
            &[0x62, 0xA2, 0xED, 0x80, 0xB9, 0xCB], // {z} with k0
            &[0x62, 0xA2, 0xED, 0x81, 0xB8, 0xCB], // packed FMA opcode
            &[0x62, 0xA2, 0xED, 0x81, 0xA7, 0xCB], // unrelated opcode
            &[0x62, 0xA2, 0xED, 0x81, 0xB9],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_scalar_fma_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_fp16_fma_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xF6, 0x6D, 0x08, 0x98, 0xCB][..], Some(true)),
            (&[0x62, 0xA6, 0x6D, 0xA1, 0xA8, 0xCB][..], Some(true)),
            (&[0x62, 0xA6, 0x6D, 0xC1, 0xB7, 0xCB][..], Some(false)),
            (&[0x62, 0x86, 0x3D, 0xD3, 0xBC, 0xF9][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_fp16_fma_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x6D, 0x08, 0x98, 0xCB], // wrong map
            &[0x62, 0xF6, 0x69, 0x08, 0x98, 0xCB], // missing EVEX fixed-one bit
            &[0x62, 0xF6, 0x6C, 0x08, 0x98, 0xCB], // missing 66 prefix
            &[0x62, 0xF6, 0xED, 0x08, 0x98, 0xCB], // W1
            &[0x62, 0xF6, 0x6D, 0x08, 0x98, 0x0B], // memory source
            &[0x62, 0xF6, 0x6D, 0x88, 0x98, 0xCB], // {z} with k0
            &[0x62, 0xF6, 0x6D, 0x68, 0x98, 0xCB], // L'L=3
            &[0x62, 0xF6, 0x6D, 0x08, 0x99, 0xCB], // scalar FMA opcode
            &[0x62, 0xF6, 0x6D, 0x08, 0x95, 0xCB], // unrelated opcode
            &[0x62, 0xF6, 0x6D, 0x08, 0x98],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_fp16_fma_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_scalar_fp16_fma_replay_classifier_is_exact_and_fail_closed() {
        let valid: &[&[u8]] = &[
            &[0x62, 0xF6, 0x6D, 0x08, 0x99, 0xCB],
            &[0x62, 0xA6, 0x6D, 0x81, 0xBF, 0xCB],
            &[0x62, 0xF6, 0x6D, 0x28, 0x99, 0xCB],
            &[0x62, 0xF6, 0x6D, 0x48, 0x99, 0xCB],
            &[0x62, 0xF6, 0x6D, 0x68, 0x99, 0xCB],
            &[0x62, 0xA6, 0x6D, 0x56, 0xB9, 0xCB],
        ];
        for bytes in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_scalar_fp16_fma_needs_vl(),
                Some(false),
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x6D, 0x08, 0x99, 0xCB], // wrong map
            &[0x62, 0xF6, 0x69, 0x08, 0x99, 0xCB], // missing EVEX fixed-one bit
            &[0x62, 0xF6, 0x6C, 0x08, 0x99, 0xCB], // missing 66 prefix
            &[0x62, 0xF6, 0xED, 0x08, 0x99, 0xCB], // W1
            &[0x62, 0xF6, 0x6D, 0x08, 0x99, 0x0B], // memory source
            &[0x62, 0xF6, 0x6D, 0x80, 0x99, 0xCB], // {z} with k0
            &[0x62, 0xF6, 0x6D, 0x08, 0x98, 0xCB], // packed FMA opcode
            &[0x62, 0xF6, 0x6D, 0x08, 0x95, 0xCB], // unrelated opcode
            &[0x62, 0xF6, 0x6D, 0x08, 0x99],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_scalar_fp16_fma_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_fp16_fma_replay_spans_carry_exact_host_requirements() {
        for (bytes, needs_vl) in [
            (&[0x62, 0xF6, 0x6D, 0x08, 0x98, 0xCB][..], true),
            (&[0x62, 0xA6, 0x6D, 0xC1, 0xB8, 0xCB][..], false),
            (&[0x62, 0xA6, 0x6D, 0x81, 0xBF, 0xCB][..], false),
        ] {
            let mut block = SmirBlock::new(BlockId(7), 0x1000);
            block.push_op(SmirOp::new(OpId(0), 0x1000, OpKind::Nop));
            let instruction = X86InstructionBytes::new(bytes).unwrap();
            let provenance = HashMap::from([((BlockId(7), 0x1000), instruction)]);
            let spans = x86_evex_native_replay_spans(&block, &provenance);
            let span = spans.get(&0).unwrap_or_else(|| panic!("{bytes:02X?}"));
            assert_eq!(span.end, 1, "{bytes:02X?}");
            assert_eq!(span.instruction, instruction, "{bytes:02X?}");
            assert_eq!(span.needs_avx512vl, needs_vl, "{bytes:02X?}");
            assert!(!span.needs_avx512dq, "{bytes:02X?}");
            assert!(span.needs_avx512fp16, "{bytes:02X?}");
        }
    }

    #[test]
    fn x86_evex_integer_minmax_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xA2, 0x6D, 0xC1, 0x38, 0xCB][..], Some(false)),
            (&[0x62, 0xF2, 0xED, 0x29, 0x39, 0xC8][..], Some(true)),
            // Map-1 byte/word operations are WIG.
            (&[0x62, 0xF1, 0xFD, 0x09, 0xDA, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_minmax_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0xDA, 0xC8], // map-1 opcode in map 2
            &[0x62, 0xF1, 0x7D, 0x09, 0x38, 0xC8], // map-2 opcode in map 1
            &[0x62, 0xF2, 0x79, 0x09, 0x38, 0xC8], // missing EVEX fixed-one bit
            &[0x62, 0xF2, 0x7C, 0x09, 0x38, 0xC8], // missing 66 prefix
            &[0x62, 0xF2, 0x7D, 0x09, 0x38, 0x08], // memory source
            &[0x62, 0xF2, 0x7D, 0x19, 0x38, 0xC8], // EVEX.b
            &[0x62, 0xF2, 0x7D, 0x88, 0x38, 0xC8], // {z} with k0
            &[0x62, 0xF2, 0x7D, 0x69, 0x38, 0xC8], // L'L=3
            &[0x62, 0xF2, 0x7D, 0x09, 0x37, 0xC8], // unrelated opcode
            &[0x62, 0xF2, 0x7D, 0x09, 0x38],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_minmax_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_integer_multiply_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (
                &[0x62, 0xA2, 0xED, 0xC1, 0x40, 0xCB][..],
                Some((false, true)),
            ),
            (
                &[0x62, 0xF2, 0x6D, 0x29, 0x40, 0xC8][..],
                Some((true, false)),
            ),
            // Word operations are WIG.
            (
                &[0x62, 0xF1, 0xFD, 0x09, 0xD5, 0xC8][..],
                Some((true, false)),
            ),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_multiply_requirements(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0xD5, 0xC8], // map-1 opcode in map 2
            &[0x62, 0xF1, 0x7D, 0x09, 0x40, 0xC8], // map-2 opcode in map 1
            &[0x62, 0xF2, 0x79, 0x09, 0x40, 0xC8], // missing EVEX fixed-one bit
            &[0x62, 0xF2, 0x7C, 0x09, 0x40, 0xC8], // missing 66 prefix
            &[0x62, 0xF2, 0x7D, 0x09, 0x40, 0x08], // memory source
            &[0x62, 0xF2, 0x7D, 0x19, 0x40, 0xC8], // EVEX.b
            &[0x62, 0xF2, 0x7D, 0x88, 0x40, 0xC8], // {z} with k0
            &[0x62, 0xF2, 0x7D, 0x69, 0x40, 0xC8], // L'L=3
            &[0x62, 0xF1, 0x7D, 0x09, 0xF4, 0xC8], // VPMULUDQ with W0
            &[0x62, 0xF2, 0x7D, 0x09, 0x28, 0xC8], // VPMULDQ with W0
            &[0x62, 0xF2, 0x7D, 0x09, 0x41, 0xC8], // unrelated opcode
            &[0x62, 0xF2, 0x7D, 0x09, 0x40],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_multiply_requirements(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_integer_interleave_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vpunpckhqdq zmm17{k1}{z}, zmm18, zmm19
            (&[0x62, 0xA1, 0xED, 0xC1, 0x6D, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0x6D, 0x29, 0x62, 0xC8][..], Some(true)),
            // Byte/word forms are WIG.
            (&[0x62, 0xF1, 0xED, 0x09, 0x60, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_interleave_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0x60, 0xC8], // wrong map
            &[0x62, 0xF1, 0x79, 0x09, 0x60, 0xC8], // missing EVEX fixed-one bit
            &[0x62, 0xF1, 0x7C, 0x09, 0x60, 0xC8], // missing 66 prefix
            &[0x62, 0xF1, 0x7D, 0x09, 0x60, 0x08], // memory source
            &[0x62, 0xF1, 0x7D, 0x19, 0x60, 0xC8], // EVEX.b
            &[0x62, 0xF1, 0x7D, 0x88, 0x60, 0xC8], // {z} with k0
            &[0x62, 0xF1, 0x7D, 0x69, 0x60, 0xC8], // L'L=3
            &[0x62, 0xF1, 0xFD, 0x09, 0x62, 0xC8], // VPUNPCKLDQ with W1
            &[0x62, 0xF1, 0x7D, 0x09, 0x6C, 0xC8], // VPUNPCKLQDQ with W0
            &[0x62, 0xF1, 0x7D, 0x09, 0x63, 0xC8], // unrelated opcode
            &[0x62, 0xF1, 0x7D, 0x09, 0x60],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_interleave_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_integer_pack_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vpackusdw zmm17{k1}{z}, zmm18, zmm19
            (&[0x62, 0xA2, 0x6D, 0xC1, 0x2B, 0xCB][..], Some(false)),
            (&[0x62, 0xF1, 0x6D, 0x29, 0x6B, 0xC8][..], Some(true)),
            // Byte-result operations specify WIG.
            (&[0x62, 0xF1, 0xED, 0x09, 0x63, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_pack_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0x63, 0xC8], // map-1 opcode in map 2
            &[0x62, 0xF1, 0x7D, 0x09, 0x2B, 0xC8], // map-2 opcode in map 1
            &[0x62, 0xF2, 0x79, 0x09, 0x2B, 0xC8], // missing fixed-one bit
            &[0x62, 0xF2, 0x7C, 0x09, 0x2B, 0xC8], // missing 66 prefix
            &[0x62, 0xF2, 0xFD, 0x09, 0x2B, 0xC8], // VPACKUSDW with W1
            &[0x62, 0xF2, 0x7D, 0x09, 0x2B, 0x08], // memory source
            &[0x62, 0xF2, 0x7D, 0x19, 0x2B, 0xC8], // EVEX.b
            &[0x62, 0xF2, 0x7D, 0x88, 0x2B, 0xC8], // {z} with k0
            &[0x62, 0xF2, 0x7D, 0x69, 0x2B, 0xC8], // L'L=3
            &[0x62, 0xF2, 0x7D, 0x09, 0x2C, 0xC8], // unrelated opcode
            &[0x62, 0xF2, 0x7D, 0x09, 0x2B],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_integer_pack_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_abs_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vpabsq zmm17{k1}{z}, zmm18
            (&[0x62, 0xA2, 0xFD, 0xC9, 0x1F, 0xCA][..], Some(false)),
            (&[0x62, 0xF2, 0x7D, 0x29, 0x1E, 0xC8][..], Some(true)),
            // Byte/word forms specify WIG.
            (&[0x62, 0xF2, 0xFD, 0x09, 0x1C, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_abs_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF1, 0x7D, 0x09, 0x1C, 0xC8], // wrong map
            &[0x62, 0xF2, 0x79, 0x09, 0x1C, 0xC8], // missing fixed-one bit
            &[0x62, 0xF2, 0x7C, 0x09, 0x1C, 0xC8], // missing 66 prefix
            &[0x62, 0xF2, 0x6D, 0x09, 0x1C, 0xC8], // non-reserved EVEX.vvvv
            &[0x62, 0xF2, 0x7D, 0x01, 0x1C, 0xC8], // non-reserved EVEX.V'
            &[0x62, 0xF2, 0xFD, 0x09, 0x1E, 0xC8], // VPABSD with W1
            &[0x62, 0xF2, 0x7D, 0x09, 0x1F, 0xC8], // VPABSQ with W0
            &[0x62, 0xF2, 0x7D, 0x09, 0x1C, 0x08], // memory source
            &[0x62, 0xF2, 0x7D, 0x19, 0x1C, 0xC8], // EVEX.b
            &[0x62, 0xF2, 0x7D, 0x88, 0x1C, 0xC8], // {z} with k0
            &[0x62, 0xF2, 0x7D, 0x69, 0x1C, 0xC8], // L'L=3
            &[0x62, 0xF2, 0x7D, 0x09, 0x20, 0xC8], // unrelated opcode
            &[0x62, 0xF2, 0x7D, 0x09, 0x1C],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_abs_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_average_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vpavgw zmm17{k1}{z}, zmm18, zmm19
            (&[0x62, 0xA1, 0x6D, 0xC1, 0xE3, 0xCB][..], Some(false)),
            // Both byte and word forms specify WIG.
            (&[0x62, 0xF1, 0xED, 0x29, 0xE0, 0xC8][..], Some(true)),
            (&[0x62, 0xF1, 0x6D, 0x09, 0xE3, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_average_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0xE0, 0xC8], // wrong map
            &[0x62, 0xF1, 0x79, 0x09, 0xE0, 0xC8], // missing fixed-one bit
            &[0x62, 0xF1, 0x7C, 0x09, 0xE0, 0xC8], // missing 66 prefix
            &[0x62, 0xF1, 0x7D, 0x09, 0xE0, 0x08], // memory source
            &[0x62, 0xF1, 0x7D, 0x19, 0xE0, 0xC8], // EVEX.b
            &[0x62, 0xF1, 0x7D, 0x88, 0xE0, 0xC8], // {z} with k0
            &[0x62, 0xF1, 0x7D, 0x69, 0xE0, 0xC8], // L'L=3
            &[0x62, 0xF1, 0x7D, 0x09, 0xE1, 0xC8], // unrelated opcode
            &[0x62, 0xF1, 0x7D, 0x09, 0xE0],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_average_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_test_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vptestnmq k2{k1}, zmm18, zmm19
            (&[0x62, 0xB2, 0xEE, 0x41, 0x27, 0xD3][..], Some(false)),
            (&[0x62, 0xF2, 0x7D, 0x29, 0x26, 0xC8][..], Some(true)),
            (&[0x62, 0xF2, 0xFE, 0x09, 0x26, 0xC8][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_test_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF1, 0x7D, 0x09, 0x26, 0xC8], // wrong map
            &[0x62, 0xE2, 0x7D, 0x09, 0x26, 0xC8], // extended K destination
            &[0x62, 0xF2, 0x79, 0x09, 0x26, 0xC8], // missing EVEX fixed-one bit
            &[0x62, 0xF2, 0x7C, 0x09, 0x26, 0xC8], // invalid mandatory prefix
            &[0x62, 0xF2, 0x7D, 0x09, 0x26, 0x08], // memory source
            &[0x62, 0xF2, 0x7D, 0x19, 0x26, 0xC8], // EVEX.b
            &[0x62, 0xF2, 0x7D, 0x89, 0x26, 0xC8], // reserved EVEX.z
            &[0x62, 0xF2, 0x7D, 0x69, 0x26, 0xC8], // L'L=3
            &[0x62, 0xF2, 0x7D, 0x09, 0x28, 0xC8], // unrelated opcode
            &[0x62, 0xF2, 0x7D, 0x09, 0x26],       // missing ModR/M
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_test_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_packed_compare_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            // vpcmpq k2{k1}, zmm18, zmm19, equal
            (&[0x62, 0xB3, 0xED, 0x41, 0x1F, 0xD3, 0x00][..], Some(false)),
            (&[0x62, 0xF3, 0x6D, 0x29, 0x3E, 0xC8, 0x03][..], Some(true)),
            (&[0x62, 0xF3, 0xED, 0x09, 0x3F, 0xC8, 0x07][..], Some(true)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_compare_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xF2, 0x7D, 0x09, 0x1F, 0xC8, 0x00], // wrong map
            &[0x62, 0xE3, 0x7D, 0x09, 0x1F, 0xC8, 0x00], // extended K destination
            &[0x62, 0xF3, 0x79, 0x09, 0x1F, 0xC8, 0x00], // missing fixed-one bit
            &[0x62, 0xF3, 0x7C, 0x09, 0x1F, 0xC8, 0x00], // missing 66 prefix
            &[0x62, 0xF3, 0x7D, 0x09, 0x1F, 0x08, 0x00], // memory source
            &[0x62, 0xF3, 0x7D, 0x19, 0x1F, 0xC8, 0x00], // EVEX.b
            &[0x62, 0xF3, 0x7D, 0x89, 0x1F, 0xC8, 0x00], // reserved EVEX.z
            &[0x62, 0xF3, 0x7D, 0x69, 0x1F, 0xC8, 0x00], // L'L=3
            &[0x62, 0xF3, 0x7D, 0x09, 0x20, 0xC8, 0x00], // unrelated opcode
            &[0x62, 0xF3, 0x7D, 0x09, 0x1F, 0xC8],       // missing imm8
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_packed_compare_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_broadcast_replay_classifier_tracks_vl_and_dq_exactly() {
        let valid = [
            // vbroadcastss xmm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0x7D, 0x89, 0x18, 0xCA][..],
                Some((true, false)),
            ),
            (
                &[0x62, 0xA2, 0x7D, 0xC9, 0x18, 0xCA][..],
                Some((false, false)),
            ),
            // vbroadcastsd ymm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0xFD, 0xA9, 0x19, 0xCA][..],
                Some((true, false)),
            ),
            // vbroadcastf32x2 zmm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0x7D, 0xC9, 0x19, 0xCA][..],
                Some((false, true)),
            ),
            // vpbroadcastd xmm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0x7D, 0x89, 0x58, 0xCA][..],
                Some((true, false)),
            ),
            // vpbroadcastq zmm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0xFD, 0xC9, 0x59, 0xCA][..],
                Some((false, false)),
            ),
            // vbroadcasti32x2 xmm17{k1}{z},xmm18
            (
                &[0x62, 0xA2, 0x7D, 0x89, 0x59, 0xCA][..],
                Some((true, true)),
            ),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_broadcast_requirements(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xA2, 0x7D, 0x89, 0x18],       // incomplete
            &[0x62, 0xA1, 0x7D, 0x89, 0x18, 0xCA], // wrong map
            &[0x62, 0xA2, 0x79, 0x89, 0x18, 0xCA], // fixed-one bit clear
            &[0x62, 0xA2, 0x7C, 0x89, 0x18, 0xCA], // missing 66 prefix
            &[0x62, 0xA2, 0x75, 0x89, 0x18, 0xCA], // reserved EVEX.vvvv
            &[0x62, 0xA2, 0x7D, 0x81, 0x18, 0xCA], // reserved EVEX.V'
            &[0x62, 0xA2, 0x7D, 0x89, 0x18, 0x08], // memory source
            &[0x62, 0xA2, 0x7D, 0x99, 0x18, 0xCA], // EVEX.b
            &[0x62, 0xA2, 0x7D, 0x88, 0x18, 0xCA], // {z} with k0
            &[0x62, 0xA2, 0x7D, 0xE9, 0x18, 0xCA], // L'L=3
            &[0x62, 0xA2, 0xFD, 0x89, 0x19, 0xCA], // VBROADCASTSD VL=128
            &[0x62, 0xA2, 0x7D, 0x89, 0x19, 0xCA], // VBROADCASTF32X2 VL=128
            &[0x62, 0xA2, 0x7D, 0x89, 0x5A, 0xCA], // unrelated opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_broadcast_requirements(),
                None,
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn x86_evex_narrow_broadcast_replay_classifier_is_exact_and_fail_closed() {
        let valid = [
            (&[0x62, 0xA2, 0x7D, 0x89, 0x78, 0xCA][..], Some(true)),
            (&[0x62, 0xA2, 0x7D, 0xA9, 0x79, 0xCA][..], Some(true)),
            (&[0x62, 0xA2, 0x7D, 0xC9, 0x78, 0xCA][..], Some(false)),
            (&[0x62, 0xA2, 0x7D, 0xC9, 0x79, 0xCA][..], Some(false)),
        ];
        for (bytes, expected) in valid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_narrow_broadcast_needs_vl(),
                expected,
                "{bytes:02X?}"
            );
        }

        let invalid: &[&[u8]] = &[
            &[0x62, 0xA2, 0x7D, 0x89, 0x78],       // incomplete
            &[0x62, 0xA1, 0x7D, 0x89, 0x78, 0xCA], // wrong map
            &[0x62, 0xA2, 0xFD, 0x89, 0x78, 0xCA], // W1
            &[0x62, 0xA2, 0x79, 0x89, 0x78, 0xCA], // fixed-one bit clear
            &[0x62, 0xA2, 0x7C, 0x89, 0x78, 0xCA], // missing 66 prefix
            &[0x62, 0xA2, 0x75, 0x89, 0x78, 0xCA], // reserved EVEX.vvvv
            &[0x62, 0xA2, 0x7D, 0x81, 0x78, 0xCA], // reserved EVEX.V'
            &[0x62, 0xA2, 0x7D, 0x89, 0x78, 0x08], // memory source
            &[0x62, 0xA2, 0x7D, 0x99, 0x78, 0xCA], // EVEX.b
            &[0x62, 0xA2, 0x7D, 0x88, 0x78, 0xCA], // {z} with k0
            &[0x62, 0xA2, 0x7D, 0xE9, 0x78, 0xCA], // L'L=3
            &[0x62, 0xA2, 0x7D, 0x89, 0x77, 0xCA], // unrelated opcode
        ];
        for bytes in invalid {
            assert_eq!(
                X86InstructionBytes::new(bytes)
                    .unwrap()
                    .evex_register_narrow_broadcast_needs_vl(),
                None,
                "{bytes:02X?}"
            );
        }
    }
}
