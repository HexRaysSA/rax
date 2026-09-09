//! Byte-validated native replay metadata for x86 instructions.
//!
//! These classifiers accept exact register-only instruction shapes whose
//! source bytes, or a byte-validated deterministic canonical encoding, can
//! safely replace the contiguous semantic SMIR group emitted for the same
//! guest instruction.

use std::collections::HashMap;

use super::SmirBlock;
use super::types::{BlockId, GuestAddr};

/// Exact bytes of one x86 instruction. Architectural x86 instructions are at
/// most 15 bytes; keeping a fixed-size value makes function provenance cheap to
/// clone and prevents metadata from carrying an unbounded byte sequence into a
/// native lowerer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86InstructionBytes {
    bytes: [u8; 15],
    len: u8,
}

/// Byte-validated unmasked VEX/EVEX VPCLMULQDQ memory encoding rewritten to
/// use one nonarchitectural low vector register as its second source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86VpclmulqdqMemoryEncoding {
    pub(crate) width: crate::smir::ir::types::VecWidth,
    pub(crate) destination: u8,
    pub(crate) source1: u8,
    pub(crate) scratch: u8,
    pub(crate) immediate: u8,
    pub(crate) register_instruction: X86InstructionBytes,
    pub(crate) needs_pclmulqdq: bool,
    pub(crate) needs_vpclmulqdq: bool,
    pub(crate) needs_avx512vl: bool,
    pub(crate) supports_avx_ymm16: bool,
}

/// Exact VEX GFNI operation selected by one byte-validated memory encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86VexGfniMemoryKind {
    Multiply,
    Affine,
    AffineInverse,
}

/// Byte-validated VEX GFNI memory encoding rewritten to use one
/// nonarchitectural low vector register as its second source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86VexGfniMemoryEncoding {
    pub(crate) kind: X86VexGfniMemoryKind,
    pub(crate) width: crate::smir::ir::types::VecWidth,
    pub(crate) destination: u8,
    pub(crate) source1: u8,
    pub(crate) scratch: u8,
    pub(crate) immediate: Option<u8>,
    pub(crate) register_instruction: X86InstructionBytes,
}

/// Byte-validated original VEX `CMPccXADD` memory encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86VexCmpccxaddMemoryEncoding {
    /// ModR/M.reg comparison operand and architectural old-value destination.
    pub(crate) cmp: u8,
    /// VEX.vvvv addend operand.
    pub(crate) add: u8,
    /// Low opcode nibble selecting one of the 16 x86 condition codes.
    pub(crate) condition_code: u8,
    /// Locked memory transaction width.
    pub(crate) width: crate::smir::ir::types::MemWidth,
    /// Whether a noncanonical effective-address range selects #SS(0).
    pub(crate) stack_segment: bool,
}

impl X86InstructionBytes {
    /// Capture one complete x86 instruction.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > 15 {
            return None;
        }
        let mut captured = [0u8; 15];
        captured[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            bytes: captured,
            len: bytes.len() as u8,
        })
    }

    /// Return the complete instruction byte sequence.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

mod aggregate;
mod classifiers;
mod family_spans;
mod grouping;

use grouping::x86_native_replay_spans_where;

pub use family_spans::*;

pub(crate) use classifiers::{
    X86EvexAlignrMemoryEncoding, X86EvexBf16MemoryEncoding, X86EvexBf16MemoryKind,
    X86EvexBf16MemoryReplay, X86EvexBroadcastInterleaveMemoryEncoding,
    X86EvexBroadcastLogicMemoryEncoding, X86EvexBroadcastMemoryEncoding, X86EvexBwShuffleMaddKind,
    X86EvexBwShuffleMaddMemoryEncoding, X86EvexChunkExtractMemoryEncoding,
    X86EvexChunkInsertMemoryEncoding, X86EvexChunkShuffleMemoryEncoding,
    X86EvexChunkShuffleMemoryReplay, X86EvexCompressMemoryEncoding, X86EvexDbpsadbwMemoryEncoding,
    X86EvexDuplicateMoveMemoryEncoding, X86EvexExpandMemoryEncoding, X86EvexExpandMemoryReplay,
    X86EvexFixupImmMemoryEncoding, X86EvexFixupImmMemoryReplay,
    X86EvexFourDotProductMemoryEncoding, X86EvexFourFmaMemoryEncoding,
    X86EvexFp16NarrowMemoryEncoding, X86EvexFpClassMemoryEncoding, X86EvexFpClassMemoryReplay,
    X86EvexFpFlagCompareMemoryEncoding, X86EvexFpInterleaveMemoryEncoding,
    X86EvexFpInterleaveMemoryReplay, X86EvexFpShuffleMemoryEncoding, X86EvexFpShuffleMemoryReplay,
    X86EvexFullPermuteControl, X86EvexFullPermuteMemoryEncoding, X86EvexFullPermuteMemoryReplay,
    X86EvexGfniAffineMemoryEncoding, X86EvexGfniAffineMemoryReplay,
    X86EvexGfniMultiplyMemoryEncoding, X86EvexGfniMultiplyMemoryReplay,
    X86EvexHalfMoveMemoryEncoding, X86EvexHalfMoveStoreEncoding,
    X86EvexIntegerArithmeticMemoryEncoding, X86EvexIntegerArithmeticMemoryReplay,
    X86EvexIntegerInterleaveMemoryEncoding, X86EvexIntegerMinMaxMemoryEncoding,
    X86EvexIntegerNarrowMemoryEncoding, X86EvexIntegerPackMemoryEncoding,
    X86EvexIntegerUnaryMemoryEncoding, X86EvexIntegerUnaryMemoryKind,
    X86EvexIntegerUnaryMemoryReplay, X86EvexLaneShuffleKind, X86EvexLaneShuffleMemoryEncoding,
    X86EvexLaneShuffleMemoryReplay, X86EvexLogicMemoryEncoding, X86EvexLogicMemoryKind,
    X86EvexMaskBlendMemoryEncoding, X86EvexMaskBlendMemoryReplay, X86EvexMaskedLogicMemoryEncoding,
    X86EvexMultiShiftMemoryEncoding, X86EvexMultiShiftMemoryReplay, X86EvexPackedAbsMemoryEncoding,
    X86EvexPackedConvertMemoryEncoding, X86EvexPackedConvertMemoryKind,
    X86EvexPackedConvertMemoryReplay, X86EvexPackedExtendMemoryEncoding,
    X86EvexPackedExtendMemoryReplay, X86EvexPackedFma3MemoryEncoding,
    X86EvexPackedFma3MemoryReplay, X86EvexPackedFp16ArithmeticMemoryEncoding,
    X86EvexPackedFp16ArithmeticMemoryReplay, X86EvexPackedFp16ComplexMemoryEncoding,
    X86EvexPackedFp16ComplexMemoryReplay, X86EvexPackedFp16ConvertMemoryEncoding,
    X86EvexPackedFp16ConvertMemoryKind, X86EvexPackedFp16ConvertMemoryReplay,
    X86EvexPackedFpArithmeticMemoryEncoding, X86EvexPackedFpArithmeticMemoryReplay,
    X86EvexPackedFpCompareMemoryEncoding, X86EvexPackedFpCompareMemoryReplay,
    X86EvexPackedFpUnaryMemoryEncoding, X86EvexPackedFpUnaryMemoryKind,
    X86EvexPackedFpUnaryMemoryReplay, X86EvexPackedFunnelShiftMemoryEncoding,
    X86EvexPackedFunnelShiftMemoryReplay, X86EvexPackedIntegerMaskMemoryEncoding,
    X86EvexPackedIntegerMaskMemoryReplay, X86EvexPackedIntegerMaskOperation,
    X86EvexPackedMoveMemoryEncoding, X86EvexPackedMoveMemoryKind,
    X86EvexPackedRotateMemoryEncoding, X86EvexPackedRotateMemoryReplay,
    X86EvexPackedShiftImmMemoryEncoding, X86EvexPackedShiftImmMemoryReplay,
    X86EvexPackedVariableShiftMemoryEncoding, X86EvexPackedVariableShiftMemoryReplay,
    X86EvexPsadbwMemoryEncoding, X86EvexRangeMemoryEncoding, X86EvexRangeMemoryReplay,
    X86EvexScalarExtractMemoryEncoding, X86EvexScalarFma3MemoryEncoding,
    X86EvexScalarFpArithmeticMemoryEncoding, X86EvexScalarFpCompareMemoryEncoding,
    X86EvexScalarFpConvertMemoryEncoding, X86EvexScalarFpToIntMemoryEncoding,
    X86EvexScalarFpUnaryMemoryEncoding, X86EvexScalarFpUnaryMemoryKind,
    X86EvexScalarInsertMemoryEncoding, X86EvexScalarIntToFpMemoryEncoding,
    X86EvexScalarMoveMemoryEncoding, X86EvexScalarMoveMemoryKind, X86EvexScaleFMemoryEncoding,
    X86EvexScaleFMemoryReplay, X86EvexSharedCountShiftMemoryEncoding,
    X86EvexTernaryLogicMemoryEncoding, X86EvexTernaryLogicMemoryReplay,
    X86EvexTwoTablePermuteMemoryEncoding, X86EvexTwoTablePermuteMemoryReplay,
    X86EvexVariablePermuteMemoryEncoding, X86EvexVectorAlignMemoryEncoding,
    X86EvexVectorAlignMemoryReplay, X86EvexVp2IntersectMemoryEncoding,
    X86EvexVp2IntersectMemoryReplay, X86EvexVpshufbitqmbMemoryEncoding,
    X86EvexVpshufbitqmbMemoryReplay, X86EvexVsibMemoryEncoding, X86ScalarInsertMemoryKind,
    X86VexChunkExtractMemoryEncoding, X86VexCrossLane128MemoryEncoding, X86VexFma4MemoryEncoding,
    X86VexFp16NarrowMemoryEncoding, X86VexHalfMoveMemoryEncoding, X86VexHalfMoveStoreEncoding,
    X86VexImmediateBlendMemoryFields, X86VexImmediatePermuteMemoryEncoding,
    X86VexMaskedMemoryEncoding, X86VexMovntdqaMemoryEncoding, X86VexNeConvertKind,
    X86VexNeConvertMemoryEncoding, X86VexPackedConvertMemoryEncoding,
    X86VexPackedConvertMemoryKind, X86VexPackedStringMemoryEncoding,
    X86VexPhminposuwMemoryEncoding, X86VexPtestMemoryEncoding, X86VexRoundMemoryEncoding,
    X86VexScalarConvertMemoryEncoding, X86VexScalarConvertMemoryKind,
    X86VexScalarExtractMemoryEncoding, X86VexScalarFpMemoryEncoding, X86VexScalarFpMemoryKind,
    X86VexScalarInsertMemoryFields, X86VexScalarInsertMemoryKind,
    X86VexScalarIntegerMemoryEncoding, X86VexScalarIntegerMemoryKind, X86VexSm3Sm4MemoryEncoding,
    X86VexSm3Sm4MemoryKind, X86VexVariableBlendMemoryEncoding, X86VexVariablePermuteMemoryEncoding,
    X86VexVpermil2MemoryEncoding,
};
pub(crate) use classifiers::{
    X86EvexMovntdqaMemoryEncoding, X86LegacyAesReplay, X86LegacyAlignrReplay, X86LegacyBlendReplay,
    X86LegacyDotProductReplay, X86LegacyGfniReplay, X86LegacyHighByteCrc32Replay,
    X86LegacyHighByteGroup2Kind, X86LegacyHighByteGroup2Replay, X86LegacyHighByteMultiplyKind,
    X86LegacyHighByteMultiplyReplay, X86LegacyInsertpsReplay, X86LegacyLaneShuffleKind,
    X86LegacyLaneShuffleReplay, X86LegacyPackedExtendReplay, X86LegacyPackedFpConvertKind,
    X86LegacyPackedFpConvertReplay, X86LegacyPackedShiftCount, X86LegacyPackedShiftReplay,
    X86LegacyPclmulqdqReplay, X86LegacyPtestReplay, X86LegacyRoundReplay,
    X86LegacyScalarExtractKind, X86LegacyScalarExtractReplay, X86LegacyScalarFpConvertKind,
    X86LegacyScalarFpConvertReplay, X86LegacyScalarInsertKind, X86LegacyScalarInsertReplay,
    X86LegacyScalarXmmMovqReplay, X86LegacyShaReplay, X86LegacyWideningDwordMultiplyReplay,
};

pub use aggregate::{
    x86_legacy_vex_fp_estimate_replay_spans, x86_native_replay_spans,
    x86_vex_scalar_fp_to_int_replay_spans, x86_vex_scalar_int_to_fp_replay_spans,
};

/// A contiguous semantic-op group that may be replaced by one exact native x86
/// instruction after byte-level validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86NativeReplaySpan {
    /// Exclusive semantic-op end index.
    pub end: usize,
    /// Exact instruction to emit. This is normally the source instruction;
    /// documented generation-dependent scalar VEX.L=1 sources, scalar EVEX
    /// FMA3 LLIG sources, non-memory address/segment-prefixed sources, prefixed
    /// high-byte MUL/IMUL sources, and the high-byte Group 3 `/1` TEST alias
    /// carry deterministic canonical encodings.
    pub instruction: X86InstructionBytes,
    /// Whether native execution requires AVX-512VL.
    pub needs_avx512vl: bool,
    /// Whether native execution requires AVX-512DQ.
    pub needs_avx512dq: bool,
    /// Whether native execution requires AVX-512-FP16.
    pub needs_avx512fp16: bool,
    /// Whether replay must restore MXCSR.DE to its value immediately before
    /// the source instruction.
    pub preserve_mxcsr_de: bool,
}

/// Compatibility name for the first replay family.
pub type X86EvexFpReplaySpan = X86NativeReplaySpan;

fn x86_evex_replay_spans_where(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
    classify: impl Fn(&X86InstructionBytes) -> Option<(bool, bool, bool)>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, classify)
}

/// Identify valid register-only EVEX floating-point replay groups in `block`.
/// Construction is O(N) time and O(P) space for N SMIR operations and P unique
/// guest PCs. A guest PC occurring in multiple non-contiguous groups is
/// rejected, preventing one source instruction from replacing reordered or
/// fabricated semantic fragments.
pub fn x86_evex_fp_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86EvexFpReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp_arithmetic_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX binary floating-point
/// arithmetic replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs. Memory forms use their precise
/// helper-backed path. Scalar `VEX.L=1` sources are emitted only after exact
/// validation and deterministic canonicalization to `VEX.L=0`.
pub fn x86_legacy_vex_fp_arithmetic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_fp_arithmetic_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX floating-point compare
/// replay groups in `block` in O(N) time and O(P) space for N operations and P
/// unique guest PCs. Memory forms remain at the precise SMIR interpreter
/// boundary.
pub fn x86_legacy_vex_fp_compare_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_fp_compare_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify defined register-only AVX VEX scalar flag-compare replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
/// Memory forms use their precise helper-backed path. Generation-dependent
/// `VEX.L=1` sources are emitted only as byte-validated deterministic
/// `VEX.L=0` instructions.
pub fn x86_vex_fp_flag_compare_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fp_flag_compare()
            .then_some((false, false, false))
    })
}

/// Identify defined register-only AVX VEX packed and scalar floating-point
/// round replay groups in `block` in O(N) time and O(P) space for N operations
/// and P unique guest PCs. Memory forms remain at the precise SMIR interpreter
/// boundary.
pub fn x86_vex_round_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_round_destination_index()
            .map(|_| (false, false, false))
    })
}

/// Identify defined register-only AVX VEX scalar binary32/binary64 precision
/// conversion replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs. Memory forms use their precise
/// helper-backed path. Generation-dependent `VEX.L=1` sources are emitted
/// only as byte-validated deterministic `VEX.L=0` instructions.
pub fn x86_vex_scalar_fp_convert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_scalar_fp_convert_destination_index()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX floating-point
/// shuffle/interleave replay groups in `block` in O(N) time and O(P) space for
/// N operations and P unique guest PCs. Memory forms remain at the precise
/// SMIR interpreter boundary.
pub fn x86_legacy_vex_fp_shuffle_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_fp_shuffle_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only legacy SSE3 and AVX VEX packed
/// floating-point horizontal/add-sub replay groups in `block` in O(N) time and
/// O(P) space for N operations and P unique guest PCs. This source-replay
/// classifier remains register-only; exact VEX memory forms use helper-backed
/// admission so guest-memory faults remain precise.
pub fn x86_legacy_vex_fp_horizontal_addsub_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_fp_horizontal_addsub_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX packed-single high/low
/// move replay groups in `block` in O(N) time and O(P) space for N operations
/// and P unique guest PCs. `MOVHLPS`/`MOVLHPS` and their VEX forms are
/// admitted; the architecturally invalid memory and `VEX.L=1` forms remain at
/// the precise SMIR interpreter boundary.
pub fn x86_legacy_vex_high_low_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_high_low_move_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX VEX widening doubleword-multiply replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. VEX.128 `VPMULUDQ`/`VPMULDQ` require AVX; VEX.256 forms require
/// AVX2. This span classifier remains register-only; exact memory-source
/// semantic chains are admitted separately by the helper-backed runtime gate.
pub fn x86_vex_widening_dword_multiply_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_widening_dword_multiply_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX packed sign/zero-extension replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. VEX.128 forms require AVX and VEX.256 forms require AVX2.
/// Memory forms remain at the precise SMIR interpreter boundary.
pub fn x86_vex_packed_extend_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_packed_extend_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX VEX `VMOVAPS`/`VMOVAPD` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VEX.128 and VEX.256 forms both require AVX. Memory forms remain at the
/// precise SMIR interpreter boundary because their alignment faults must be
/// checked against guest memory.
pub fn x86_vex_aligned_packed_fp_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_aligned_packed_fp_move()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX `VMOVUPS`/`VMOVUPD` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VEX.128 and VEX.256 forms both require AVX. Memory forms remain at the
/// precise SMIR interpreter boundary.
pub fn x86_vex_unaligned_packed_fp_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_unaligned_packed_fp_move()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX `VMOVDQA`/`VMOVDQU` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VEX.128 and VEX.256 forms both require AVX. Memory forms remain at the
/// precise SMIR interpreter boundary; aligned `VMOVDQA` memory forms must
/// retain their guest alignment checks.
pub fn x86_vex_packed_integer_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_packed_integer_move()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX scalar `VMOVQ` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. The `F3 0F 7E` and `66 0F D6` XMM aliases are admitted; memory forms
/// remain at the precise SMIR interpreter boundary.
pub fn x86_vex_scalar_vmovq_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_scalar_vmovq()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX2 VEX scalar-broadcast replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VBROADCASTSS/SD and VPBROADCASTB/W/D/Q register forms are admitted;
/// memory forms remain at the precise SMIR interpreter boundary.
pub fn x86_vex_register_broadcast_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_broadcast_element_bits()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX one-source lane-shuffle replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. Duplicate moves require AVX at both vector lengths; packed
/// immediate shuffles require AVX for VEX.128 and AVX2 for VEX.256. Memory
/// forms remain at the precise SMIR interpreter boundary.
pub fn x86_vex_lane_shuffle_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_lane_shuffle_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify operandless AVX `VZEROUPPER`/`VZEROALL` replay groups in `block`
/// in O(N) time and O(P) space for N operations and P unique guest PCs.
/// Both instructions require AVX; their complete 512-bit architectural state
/// effects are supplied by the selected native vector-state bridge.
pub fn x86_vex_zero_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_zeroes_all_register_bits()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX scalar floating-point
/// move replay groups in `block` in O(N) time and O(P) space for N operations
/// and P unique guest PCs. Memory forms use their separate precise
/// helper-backed path. `VMOVSS` with `VEX.L=1` is emitted only as a
/// byte-validated deterministic `VEX.L=0` instruction.
pub fn x86_legacy_vex_scalar_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_scalar_move_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only EVEX logical replay groups in `block` in O(N)
/// time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_logic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_logic_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX packed integer arithmetic replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_integer_arithmetic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_integer_arithmetic_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX shared-count shift replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_shared_count_shift_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_shared_count_shift_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX immediate-count shift replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_immediate_count_shift_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_immediate_count_shift_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed-rotate replay groups in `block`
/// in O(N) time and O(P) space for N operations and P unique guest PCs.
/// Immediate and per-element variable-count doubleword/quadword forms are
/// admitted; memory forms remain at the fault-precise interpreter boundary.
pub fn x86_evex_packed_rotate_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_rotate_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed FMA replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_packed_fma_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_fma_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX scalar FMA replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_scalar_fma_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_fma_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only AVX VEX FMA3 replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_fma3_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fma3()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AMD AVX VEX FMA4 replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_fma4_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fma4()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AMD XOP VPERMIL2 replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_vpermil2_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_vpermil2()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX floating-point dot-product replay
/// groups in `block` in O(N) time and O(P) space for N operations and P
/// unique guest PCs. Memory forms and architecturally invalid `VDPPD`
/// `VEX.L=1` encodings remain at the precise SMIR interpreter boundary.
pub fn x86_vex_fp_dot_product_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_fp_dot_product_uses_ymm()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX-VNNI-INT8/INT16 VEX extended integer
/// dot-product replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs. Memory forms remain at the precise SMIR
/// interpreter boundary.
pub fn x86_vex_integer_dot_ext_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_integer_dot_ext_is_int16()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX VEX immediate-blend replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_immediate_blend_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_immediate_blend_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify exact register-only legacy SSE4.1 immediate- and variable-blend
/// replay groups in `block` in O(N) time and O(P + V) space for N operations,
/// P unique guest PCs, and V virtual registers. Memory and reserved-prefix
/// forms remain at the precise SMIR interpreter boundary.
pub fn x86_legacy_blend_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_register_blend_replay()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX immediate-permute replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VPERMILPS/PD require AVX; VPERMQ/PD require AVX2. Memory forms remain
/// at the precise SMIR interpreter boundary.
pub fn x86_vex_immediate_permute_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_immediate_permute_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-destination AVX/AVX2 VEX 128-bit chunk-extraction
/// replay groups in `block` in O(N) time and O(P) space for N operations and P
/// unique guest PCs. VEXTRACTF128 requires AVX and VEXTRACTI128 requires AVX2.
/// Memory destinations remain at the precise SMIR interpreter boundary.
pub fn x86_vex_chunk_extract_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_chunk_extract_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-destination AVX VEX scalar lane-extraction replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. Every GPR destination for `VEXTRACTPS` and `VPEXTRB/D/Q/W` is
/// admitted; memory forms remain at the precise SMIR interpreter boundary.
pub fn x86_vex_scalar_extract_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_scalar_extract()
            .then_some((false, false, false))
    })
}

/// Identify exact AVX/AVX2 VEX vector sign-mask extracts whose r32
/// destination is guest RSP or RBP. Other GPR destinations retain their
/// existing semantic lowering; register-only stack destinations replay through
/// a state-backed lowerer wrapper at the exact guest instruction frontier.
pub fn x86_vex_mov_mask_stack_destination_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_mov_mask_stack_destination_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify exact legacy MMX/SSE/SSE2 `PMOVMSKB`, `MOVMSKPS`, and `MOVMSKPD`
/// instructions whose r32/r64 destination is guest RSP or RBP. Other GPR
/// destinations retain canonical semantic lowering. Segment/address-size-
/// prefixed register forms replay the deterministic canonical instruction
/// selected by the shared non-memory prefix policy.
pub fn x86_legacy_mov_mask_stack_destination_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_mov_mask_stack_destination_replay()
            .map(|_| (false, false, false))
    })
}

/// Identify exact legacy MMX/SSE2 MOVD/MOVQ register transfers whose GPR
/// operand is guest RSP or RBP. The replay lowerer redirects that operand
/// through the corresponding `GuestRegs` slot, while preserving MMX/x87 or
/// XMM/YMM state through the applicable native bridge.
pub fn x86_legacy_movd_q_stack_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_movd_q_stack_replay()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX VEX `VPTEST`, `VTESTPS`, and `VTESTPD`
/// replay groups in `block` in O(N) time and O(P) space for N operations and P
/// unique guest PCs. Exact memory decompositions are admitted separately by
/// the helper-backed JIT gate.
pub fn x86_vex_ptest_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_ptest()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX variable-blend replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_variable_blend_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_variable_blend_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX variable-permute replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_variable_permute_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_variable_permute_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX VPALIGNR replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. VEX.128 requires AVX and VEX.256 requires AVX2; memory forms remain at
/// the precise SMIR interpreter boundary.
pub fn x86_vex_alignr_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_alignr_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX/AVX2 VEX 128-bit cross-lane replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_vex_cross_lane_128_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .vex_register_cross_lane_128_needs_avx2()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only AVX VEX `VPINSR*`/`VINSERTPS` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. Guest RSP/RBP sources and memory forms remain at the precise SMIR
/// interpreter boundary.
pub fn x86_vex_scalar_insert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_scalar_insert()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only AVX VEX floating logical replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_vex_fp_logic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fp_logic()
            .then_some((false, false, false))
    })
}

/// Identify register-only packed AVX-512-FP16 arithmetic replay groups whose
/// `EVEX.b=1` supplies embedded rounding or SAE. Construction is O(N) time and
/// O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_packed_fp16_arithmetic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_fp16_embedded_control_needs_vl()
            .map(|needs_vl| (needs_vl, false, true))
    })
}

/// Identify valid register-only EVEX packed binary16 FMA replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_packed_fp16_fma_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_fp16_fma_needs_vl()
            .map(|needs_vl| (needs_vl, false, true))
    })
}

/// Identify valid register-only EVEX scalar binary16 FMA replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_scalar_fp16_fma_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_fp16_fma_needs_vl()
            .map(|needs_vl| (needs_vl, false, true))
    })
}

/// Identify valid register-only EVEX scalar binary16 arithmetic and
/// square-root replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs.
pub fn x86_evex_scalar_fp16_arithmetic_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_fp16_arithmetic_needs_vl()
            .map(|needs_vl| (needs_vl, false, true))
    })
}

/// Identify valid register-only EVEX packed integer min/max replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_integer_minmax_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_integer_minmax_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed integer multiply replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_integer_multiply_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_integer_multiply_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX packed integer interleave replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_integer_interleave_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_integer_interleave_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX signed/unsigned saturating pack replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs.
pub fn x86_evex_integer_pack_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_integer_pack_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed integer absolute-value replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs.
pub fn x86_evex_packed_abs_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_abs_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX rounded unsigned packed average replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs.
pub fn x86_evex_packed_average_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_average_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed integer test replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_packed_test_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_test_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX packed integer compare replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_packed_compare_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_packed_compare_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX opmask-selector blend replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_mask_blend_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_mask_blend_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX vector-to-opmask conversion replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_vector_to_mask_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_vector_to_mask_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX opmask-to-vector conversion replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_mask_to_vector_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_mask_to_vector_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX opmask-to-vector broadcast replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_mask_broadcast_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_mask_broadcast_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX one-source lane-shuffle replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_lane_shuffle_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_lane_shuffle_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX VALIGND/Q replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_vector_align_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_vector_align_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX VPSHUFB/VPMADDUBSW/VPMADDWD replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_bw_shuffle_madd_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_bw_shuffle_madd_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX VPALIGNR/VDBPSADBW replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_bw_immediate_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_bw_immediate_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX 128-bit-chunk shuffle replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_chunk_shuffle_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_chunk_shuffle_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX vector-chunk insert replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_chunk_insert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_chunk_insert_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX vector-chunk extract replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs.
pub fn x86_evex_chunk_extract_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_chunk_extract_requirements()
            .map(|(needs_vl, needs_dq)| (needs_vl, needs_dq, false))
    })
}

/// Identify valid register-only EVEX VFPCLASS* replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
pub fn x86_evex_fp_class_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction.evex_register_fp_class_requirements()
    })
}

/// Identify valid register-only EVEX floating-point comparison replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. Register-source `VCMPPS/PD/SS/SD/PH/SH`, `VCOMISS/SD/SH`, and
/// `VUCOMISS/SD/SH` forms are admitted here. Packed EVEX memory forms are
/// admitted separately only as exact helper-backed Type-E2 sequences.
pub fn x86_evex_fp_compare_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp_compare_requirements()
            .or_else(|| instruction.evex_register_fp16_flag_compare_requirements())
            .or_else(|| instruction.evex_register_fp32_fp64_flag_compare_requirements())
            .map(|(needs_vl, needs_fp16)| (needs_vl, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX binary16 widening-conversion replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. Register-source `VCVTPH2PD`, `VCVTPH2PS`, and `VCVTPH2PSX`
/// forms are admitted; every memory form remains at the precise SMIR
/// interpreter boundary.
pub fn x86_evex_fp16_widen_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp16_widen_requirements()
            .map(|(needs_vl, needs_fp16)| (needs_vl, false, needs_fp16))
    })
}

/// Identify valid register-only F16C VEX `VCVTPH2PS` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. Every memory-source form remains at the precise SMIR interpreter
/// boundary.
pub fn x86_vex_fp16_widen_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fp16_widen()
            .then_some((false, false, false))
    })
}

/// Identify valid register-destination F16C VEX `VCVTPS2PH` replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. Exact memory-destination forms are admitted separately through a
/// helper-backed sole-store sequence.
pub fn x86_vex_fp16_narrow_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fp16_narrow()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only EVEX binary16 narrowing-conversion replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. Register-only `VCVTPD2PH`, `VCVTPS2PH`, and `VCVTPS2PHX` forms
/// are admitted here. Exact F16C VEX `VCVTPS2PH` memory destinations use a
/// separate helper-backed sequence; other memory forms remain at the precise
/// SMIR interpreter boundary.
pub fn x86_evex_fp16_narrow_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp16_narrow_requirements()
            .map(|(needs_vl, needs_fp16)| (needs_vl, false, needs_fp16))
    })
}

/// Identify valid register-only AVX VEX binary32/binary64
/// precision-conversion replay groups in `block` in O(N) time and O(P) space
/// for N operations and P unique guest PCs. Register-source `VCVTPS2PD` and
/// `VCVTPD2PS` forms are admitted; every memory form remains at the precise
/// SMIR interpreter boundary.
pub fn x86_vex_fp32_fp64_convert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .is_vex_register_fp32_fp64_convert()
            .then_some((false, false, false))
    })
}

/// Identify valid register-only EVEX binary32/binary64 precision-conversion
/// replay groups in `block` in O(N) time and O(P) space for N operations and P
/// unique guest PCs. Register-source `VCVTPS2PD` and `VCVTPD2PS` forms are
/// admitted; every memory form remains at the precise SMIR interpreter
/// boundary.
pub fn x86_evex_fp32_fp64_convert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp32_fp64_convert_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

/// Identify valid register-only EVEX floating-point square-root replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. Register-source `VSQRTPS/PD/SS/SD/PH` forms are admitted; every memory
/// form remains at the precise SMIR interpreter boundary.
pub fn x86_evex_fp_sqrt_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_fp_sqrt_requirements()
            .map(|(needs_vl, needs_fp16)| (needs_vl, false, needs_fp16))
    })
}

/// Identify valid register-only legacy SSE and AVX VEX floating-point
/// square-root replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs. Memory forms use their precise
/// helper-backed path. Scalar `VEX.L=1` sources are emitted only after exact
/// validation and deterministic canonicalization to `VEX.L=0`.
pub fn x86_legacy_vex_fp_sqrt_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_native_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .legacy_vex_register_fp_sqrt_needs_avx()
            .map(|_| (false, false, false))
    })
}

/// Identify valid register-only EVEX scalar-move replay groups in `block` in
/// O(N) time and O(P) space for N operations and P unique guest PCs.
/// `VMOVSH/SS/SD` register forms in both opcode directions are admitted;
/// memory forms use their separate exact helper-backed path.
pub fn x86_evex_scalar_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_move_requires_fp16()
            .map(|needs_fp16| (false, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX scalar-integer move replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. XMM-to-XMM `VMOVQ` and safe GPR-to/from-XMM `VMOVW` forms are
/// admitted; memory forms and VMOVW operands using RSP/RBP remain at the
/// precise SMIR interpreter boundary.
pub fn x86_evex_scalar_integer_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_integer_move_requires_fp16()
            .map(|needs_fp16| (false, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX scalar floating-point-to-integer replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. `VCVT{SS,SD,SH}2{SI,USI}` and their truncating forms are
/// admitted; memory forms and RSP/RBP destinations remain at the precise SMIR
/// interpreter boundary.
pub fn x86_evex_scalar_fp_to_int_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_fp_to_int_requires_fp16()
            .map(|needs_fp16| (false, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX scalar floating-point precision-
/// conversion replay groups in `block` in O(N) time and O(P) space for N
/// operations and P unique guest PCs. The six scalar F16/F32/F64 conversion
/// directions are admitted; memory forms remain at the precise SMIR
/// interpreter boundary.
pub fn x86_evex_scalar_fp_convert_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_fp_convert_requires_fp16()
            .map(|needs_fp16| (false, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX scalar integer-to-floating-point replay
/// groups in `block` in O(N) time and O(P) space for N operations and P unique
/// guest PCs. `VCVT{,U}SI2{SS,SD,SH}` forms are admitted; memory forms and
/// RSP/RBP sources remain at the precise SMIR interpreter boundary.
pub fn x86_evex_scalar_int_to_fp_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_int_to_fp_requires_fp16()
            .map(|needs_fp16| (false, false, needs_fp16))
    })
}

/// Identify valid register-only EVEX scalar lane-transfer replay groups in
/// `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. `VEXTRACTPS`, `VINSERTPS`, `VPEXTR*`, and `VPINSR*` register forms are
/// admitted; memory forms and GPR operands using RSP/RBP remain at the precise
/// SMIR interpreter boundary.
pub fn x86_evex_scalar_lane_transfer_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_scalar_lane_transfer_requires_dq()
            .map(|needs_dq| (false, needs_dq, false))
    })
}

/// Identify valid register-only EVEX packed-single high/low move replay groups
/// in `block` in O(N) time and O(P) space for N operations and P unique guest
/// PCs. `VMOVHLPS` and `VMOVLHPS` are admitted; their architecturally invalid
/// memory ModR/M forms and every malformed EVEX field remain rejected.
pub fn x86_evex_high_low_move_replay_spans(
    block: &SmirBlock,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
) -> HashMap<usize, X86NativeReplaySpan> {
    x86_evex_replay_spans_where(block, instruction_bytes, |instruction| {
        instruction
            .evex_register_high_low_move_needs_vl()
            .map(|needs_vl| (needs_vl, false, false))
    })
}

#[cfg(test)]
#[path = "x86_native_replay_tests.rs"]
mod tests;
