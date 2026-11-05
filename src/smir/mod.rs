//! SMIR - Sigma Machine IR
//!
//! This module provides a cross-platform intermediate representation for CPU emulation.
//! It supports lifting from multiple architectures (x86-64, AArch64, Hexagon, RISC-V)
//! and execution via interpretation or JIT compilation.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐     ┌────────────┐     ┌────────────┐
//! │  x86-64    │     │  AArch64   │     │  Hexagon   │
//! │  Binary    │     │  Binary    │     │  Binary    │
//! └─────┬──────┘     └─────┬──────┘     └─────┬──────┘
//!       │                  │                  │
//!       ▼                  ▼                  ▼
//! ┌─────────────────────────────────────────────────┐
//! │                    Lifters                       │
//! │  (x86_lift, arm_lift, hexagon_lift, riscv_lift) │
//! └─────────────────────────────────────────────────┘
//!                         │
//!                         ▼
//! ┌─────────────────────────────────────────────────┐
//! │                    SMIR IR                       │
//! │  (SmirModule, SmirFunction, SmirBlock, SmirOp)  │
//! └─────────────────────────────────────────────────┘
//!                         │
//!           ┌─────────────┼─────────────┐
//!           ▼             ▼             ▼
//!     ┌──────────┐  ┌──────────┐  ┌──────────┐
//!     │Interpreter│  │   JIT    │  │ Analysis │
//!     │(interpret)│ │ (future) │  │ (future) │
//!     └──────────┘  └──────────┘  └──────────┘
//! ```
//!
//! # Key Features
//!
//! - **Lazy flag evaluation**: Flags are computed on-demand, critical for x86 performance
//! - **Virtual registers**: SSA-style unlimited registers
//! - **Unified addressing**: Common address modes across architectures
//! - **Memory model**: Support for atomics, exclusive monitors, fences
//!
//! # Example
//!
//! ```ignore
//! use rax::smir::{SmirContext, SmirInterpreter, FlatMemory};
//!
//! // Create execution context
//! let mut ctx = SmirContext::new_x86_64();
//! let mut memory = FlatMemory::new(0x10000);
//!
//! // Load code into memory...
//! memory.load(0, &code_bytes);
//!
//! // Create interpreter and run
//! let mut interp = SmirInterpreter::new(SourceArch::X86_64);
//! ctx.pc = 0x1000;
//! let exit = interp.run(&mut ctx, &mut memory);
//! ```

pub mod interpret;
pub mod ir;
pub mod lift;
pub mod lower;
pub mod optimize;
/// Experimental portable module framing; decoding does not admit execution.
pub mod portable;

// Compatibility module aliases. The canonical locations are under `ir/`, but
// these preserve the existing public Rust paths while downstream users migrate.
pub use interpret as interp;
pub use ir::{context, flags, memory, ops, types};
pub use optimize as opt;

// Re-export commonly used types
pub use interpret::{BlockResult, SmirInterpreter};
pub use ir::context::{
    Aarch64RegState, ArchRegState, DebugState, EbpfRegState, ExitReason, HexagonRegState,
    RiscVRegState, SmirContext, VRegFile, X86RegState, X86X87State,
};
pub use ir::flags::{FlagSet, FlagState, FlagUpdate, LazyFlagOp, LazyFlags, MaterializedFlags};
pub use ir::memory::{
    ExclusiveMonitor, FlatMemory, MemoryError, MemoryReader, SmirMemory, bytes_to_u64,
    check_alignment, u64_to_bytes,
};
pub use ir::ops::{OpKind, SmirOp, X86SatFpFormat};
pub use ir::types::{
    Address, ArchReg, ArmReg, AtomicOp, Avx10DotProductKind, Avx10Encoding, Avx10FP16Op, BlockId,
    BlockIdAllocator, Condition, EbpfReg, Endian, ExtendOp, FenceKind, FpPrecision, FpRoundMode,
    FunctionId, GuestAddr, HexagonReg, LocalId, MemWidth, MemoryOrder, ModuleId, OpId, OpWidth,
    RiscVReg, ShiftOp, SignExtend, SourceArch, SrcOperand, VLaneOp, VReg, VRegAllocator,
    VShiftVKind, VecCmpCond, VecElementType, VecPermuteKind, VecReduceOp, VecUnaryOp, VecWidth,
    VirtualId, X86FmaKind, X86FmaOrder, X86FpBinaryOp, X86NarrowMode, X86Reg,
};
pub use ir::{
    CallTarget, CallingConv, FunctionBuilder, PhiNode, RuntimeFunc, SmirBlock, SmirFunction,
    SmirModule, Terminator, TrapKind, X86EvexFpReplaySpan, X86InstructionBytes,
    X86NativeReplaySpan, x86_evex_avx512f_permute_replay_spans, x86_evex_fp_replay_spans,
    x86_evex_fp_shuffle_replay_spans, x86_evex_immediate_count_shift_replay_spans,
    x86_evex_integer_arithmetic_replay_spans, x86_evex_integer_interleave_replay_spans,
    x86_evex_integer_minmax_replay_spans, x86_evex_integer_multiply_replay_spans,
    x86_evex_integer_pack_replay_spans, x86_evex_logic_replay_spans, x86_evex_native_replay_spans,
    x86_evex_packed_abs_replay_spans, x86_evex_packed_average_replay_spans,
    x86_evex_packed_compare_replay_spans, x86_evex_packed_fma_replay_spans,
    x86_evex_packed_fp16_arithmetic_replay_spans, x86_evex_packed_fp16_fma_replay_spans,
    x86_evex_packed_test_replay_spans, x86_evex_scalar_fma_replay_spans,
    x86_evex_scalar_fp16_arithmetic_replay_spans, x86_evex_scalar_fp16_fma_replay_spans,
    x86_evex_shared_count_shift_replay_spans,
};
pub use lift::aarch64::Aarch64Lifter;
pub use lift::avx10::{Avx10Lifter, EvexPrefix};
pub use lift::ebpf::EbpfLifter;
pub use lift::hexagon::HexagonLifter;
pub use lift::riscv::RiscVLifter;
pub use lift::x86_64::X86_64Lifter;
pub use lift::{ControlFlow, LiftContext, LiftError, LiftResult, SmirLifter};
pub use lower::avx10::{Avx10Lowerer, EvexEncoder};
pub use lower::regalloc::{PhysReg, RegAlloc, RegLocation};
pub use lower::x86_64::{X86_64Lowerer, X86Cond, X86Emitter};
pub use lower::{
    CodeBuffer, LowerError, LowerResult, RelocKind, RelocTarget, Relocation, RuntimeHelper,
    SmirLowerer,
};
pub use optimize::{OptLevel, OptStats, optimize_function};
