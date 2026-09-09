//! Exact EVEX VSIB provenance, graph, lowering, and partial-progress coverage.

use std::collections::HashMap;

use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{BlockId, FunctionId, SourceArch, VReg, VecElementType, VecWidth};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::runtime::{
    X86JitEvexVsibMemorySequence, is_native_clobber_safe_excluding,
    is_x86_aarch64_native_clobber_safe_excluding, uses_x86_native_vectors_excluding,
    x86_jit_evex_vsib_memory_sequence, x86_native_replay_feature_requirements,
    x86_native_vector_uses_avx_ymm16_only_excluding, x86_native_vector_uses_k16_opmasks_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::optimize::{OptLevel, optimize_function};

mod classification;
#[cfg(target_arch = "x86_64")]
mod native;

const PC: u64 = 0x5653_4942;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

#[derive(Clone, Copy, Debug)]
struct Case {
    scatter: bool,
    floating: bool,
    data_bytes: u8,
    index_bytes: u8,
    ll: u8,
    data: u8,
    index: u8,
    mask: u8,
}

impl Case {
    fn lanes(self) -> usize {
        (16usize << self.ll) / usize::from(self.data_bytes.max(self.index_bytes))
    }
    fn width(self) -> VecWidth {
        [VecWidth::V128, VecWidth::V256, VecWidth::V512][self.ll as usize]
    }
    fn bytes(self) -> Vec<u8> {
        self.address(Some(0), 1, None, false, None, false)
    }

    /// Displacements here are encoded signed disp8 values; the architectural
    /// tuple multiplier is the data element size. A missing base uses disp32=0.
    fn address(
        self,
        base: Option<u8>,
        scale: u8,
        disp8: Option<i8>,
        addr32: bool,
        segment: Option<u8>,
        unused_x4: bool,
    ) -> Vec<u8> {
        assert!(base.is_some() || disp8.is_none());
        let mut bytes = Vec::new();
        if let Some(segment) = segment {
            bytes.push(segment);
        }
        if addr32 {
            bytes.push(0x67);
        }
        let base_encoding = base.unwrap_or(5);
        let p0 = 2
            | ((!self.data & 8) << 4)
            | (!self.data & 16)
            | ((!self.index & 8) << 3)
            | ((!base_encoding & 8) << 2)
            | ((base_encoding & 16) >> 1);
        let p1 = 0x79 | (u8::from(!unused_x4) << 2) | (u8::from(self.data_bytes == 8) << 7);
        let p2 = (self.ll << 5) | ((!self.index & 16) >> 1) | self.mask;
        let needs_disp = disp8.is_some() || base.is_some_and(|base| base & 7 == 5);
        let mode = if needs_disp { 0x40 } else { 0 };
        let opcode = (if self.scatter { 0xA0 } else { 0x90 })
            | (u8::from(self.floating) << 1)
            | u8::from(self.index_bytes == 8);
        bytes.extend_from_slice(&[
            0x62,
            p0,
            p1,
            p2,
            opcode,
            mode | ((self.data & 7) << 3) | 4,
            ((scale.trailing_zeros() as u8) << 6) | ((self.index & 7) << 3) | (base_encoding & 7),
        ]);
        if needs_disp {
            bytes.push(disp8.unwrap_or(0) as u8);
        }
        if base.is_none() {
            bytes.extend_from_slice(&0i32.to_le_bytes());
        }
        bytes
    }
}

fn cases() -> Vec<Case> {
    let mut result = Vec::new();
    for scatter in [false, true] {
        for floating in [false, true] {
            for data_bytes in [4, 8] {
                for index_bytes in [4, 8] {
                    for ll in 0..3 {
                        result.push(Case {
                            scatter,
                            floating,
                            data_bytes,
                            index_bytes,
                            ll,
                            data: 17,
                            index: 30,
                            mask: 3,
                        });
                    }
                }
            }
        }
    }
    result
}

fn lift(bytes: &[u8], level: OptLevel) -> SmirFunction {
    let result = X86_64Lifter::strict()
        .lift_insn(PC, bytes, &mut LiftContext::new(SourceArch::X86_64))
        .unwrap_or_else(|e| panic!("{bytes:02X?}: {e:?}"));
    assert_eq!(result.bytes_consumed, bytes.len());
    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
        .x86_instruction_bytes
        .insert((BlockId(0), PC), X86InstructionBytes::new(bytes).unwrap());
    optimize_function(&mut function, level);
    function
}

fn virtual_counts(function: &SmirFunction) -> (HashMap<VReg, usize>, HashMap<VReg, usize>) {
    let mut definitions = HashMap::new();
    let mut uses = HashMap::new();
    for block in &function.blocks {
        for op in &block.ops {
            for reg in op.kind.dests() {
                if matches!(reg, VReg::Virtual(_)) {
                    *definitions.entry(reg).or_default() += 1;
                }
            }
            for reg in op.kind.source_vregs() {
                if matches!(reg, VReg::Virtual(_)) {
                    *uses.entry(reg).or_default() += 1;
                }
            }
        }
    }
    (definitions, uses)
}

fn sequence(function: &SmirFunction, allow_mem: bool) -> Option<X86JitEvexVsibMemorySequence> {
    let index = usize::from(
        function.blocks[0]
            .ops
            .first()
            .is_some_and(|op| matches!(op.kind, OpKind::X86RequireApx)),
    );
    let (defs, uses) = virtual_counts(function);
    x86_jit_evex_vsib_memory_sequence(
        &function.blocks[0],
        index,
        allow_mem,
        &function.x86_instruction_bytes,
        &defs,
        &uses,
    )
}

fn lower(function: &SmirFunction) -> (Vec<u8>, usize) {
    let excluded = HashMap::new();
    assert!(is_native_clobber_safe_excluding(function, &excluded, true));
    assert!(!is_native_clobber_safe_excluding(
        function, &excluded, false
    ));
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        function, &excluded
    ));
    assert!(uses_x86_native_vectors_excluding(function, &excluded));
    assert!(!x86_native_vector_uses_avx_ymm16_only_excluding(
        function, &excluded
    ));
    assert!(x86_native_vector_uses_k16_opmasks_excluding(
        function, &excluded
    ));
    let requirements = x86_native_replay_feature_requirements(function, &excluded);
    assert!(requirements.any && requirements.needs_avx && requirements.has_k16_opmask_span);
    assert!(
        !requirements.needs_avx512bw
            && !requirements.needs_avx512vl
            && !requirements.needs_avx512dq
    );
    assert!(!requirements.all_spans_support_avx_ymm16);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_native_vector_state_active(true);
    lowerer.set_narrow_vector_opmask_helpers(true);
    lowerer.set_avx_ymm16_vector_state(false);
    lowerer.set_jit_fault_deopt_guards(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|e| panic!("VSIB lowering: {e:?}"));
    assert!(result.relocations.is_empty());
    (lowerer.finalize().unwrap(), result.entry_offset)
}
