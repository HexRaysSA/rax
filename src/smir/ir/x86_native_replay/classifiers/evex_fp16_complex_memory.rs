//! EVEX packed and scalar binary16-complex memory-source replay classification.

use super::X86InstructionBytes;
use super::evex_memory::{memory_operand_end, vector_legacy_prefix_len};
use crate::smir::ir::types::VecWidth;

/// Native replay strategy for one exact packed/scalar binary16-complex memory source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86EvexPackedFp16ComplexMemoryReplay {
    /// A complete vector helper load followed by a register-source rewrite
    /// using one nonarchitectural low vector register.
    Vector {
        scratch: u8,
        register_instruction: X86InstructionBytes,
    },
    /// One scalar helper load followed by the original m32 broadcast or scalar
    /// operation rewritten to consume the staged complex pair from `[rsp]`.
    Broadcast {
        stack_instruction: X86InstructionBytes,
    },
    /// Per-active-complex-pair helper loads accumulated in a nonarchitectural
    /// stack vector, followed by the original writemasked operation using
    /// `[rsp]`.
    MaskedVector {
        stack_instruction: X86InstructionBytes,
    },
}

/// Exact EVEX binary16-complex memory encoding and byte-validated helper-backed
/// native replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86EvexPackedFp16ComplexMemoryEncoding {
    pub(crate) width: VecWidth,
    pub(crate) destination: u8,
    pub(crate) source1: u8,
    pub(crate) writemask: Option<u8>,
    pub(crate) zeroing: bool,
    pub(crate) scalar: bool,
    pub(crate) accumulate: bool,
    pub(crate) conjugate: bool,
    pub(crate) replay: X86EvexPackedFp16ComplexMemoryReplay,
    pub(crate) needs_avx512vl: bool,
}

impl X86InstructionBytes {
    /// Validate one register-only packed AVX-512-FP16 complex operation using
    /// dynamic MXCSR rounding and report whether AVX-512VL is required.
    ///
    /// This deliberately excludes register forms with `EVEX.b=1`, for which
    /// `L'L` carries embedded rounding. Memory-source rewrites retain
    /// `EVEX.b=0` when converted to a register source, so this validator is an
    /// independent check on every synthesized register instruction.
    pub(crate) fn evex_register_packed_fp16_complex_needs_vl(&self) -> Option<bool> {
        let [0x62, p0, p1, p2, opcode, modrm] = self.as_slice() else {
            return None;
        };
        let mask = p2 & 0x07;
        let zeroing = p2 & 0x80 != 0;
        if p0 & 0x07 != 6
            || !matches!(p1 & 0x83, 2 | 3)
            || p2 & 0x10 != 0
            || p2 & 0x60 == 0x60
            || !matches!(opcode, 0x56 | 0xD6)
            || modrm >> 6 != 3
            || (zeroing && mask == 0)
        {
            return None;
        }

        let destination =
            (u8::from(p0 & 0x80 == 0) << 3) | (u8::from(p0 & 0x10 == 0) << 4) | ((modrm >> 3) & 7);
        let source1 = ((!p1 >> 3) & 0x0F) | (u8::from(p2 & 0x08 == 0) << 4);
        let source2 =
            (u8::from(p0 & 0x20 == 0) << 3) | (u8::from(p0 & 0x40 == 0) << 4) | (modrm & 7);
        if destination == source1 || destination == source2 {
            return None;
        }

        Some((p2 >> 5) & 3 != 2)
    }

    /// Validate one EVEX packed/scalar `VFCMADDCPH`/`VFMADDCPH`/
    /// `VFCMULCPH`/`VFMULCPH` or `VFCMADDCSH`/`VFMADDCSH`/
    /// `VFCMULCSH`/`VFMULCSH` memory source and select its exact native replay.
    ///
    /// Intel SDM Vol. 2 assigns the packed instructions to MAP6.W0, F2/F3,
    /// opcodes 56H/D6H, Full Mem tuples, and Type E4 exceptions. Their masking
    /// and m32 broadcast operate on complete 32-bit quantities containing two
    /// FP16 components. The scalar 57H/D7H forms are LLIG, use a Scalar m32
    /// tuple, follow Type E10, and suppress the complete access when k1[0] is
    /// clear. Unmasked full vectors use one complete-vector helper load;
    /// writemasked vectors use ascending per-active-pair 4-byte helper loads;
    /// broadcasts and scalar forms use at most one 4-byte helper load.
    /// Segment/address-size prefixes and APX address extensions are consumed
    /// only by helper address evaluation and are removed from the rewritten
    /// native instruction.
    pub(crate) fn evex_packed_fp16_complex_memory_encoding(
        &self,
    ) -> Option<X86EvexPackedFp16ComplexMemoryEncoding> {
        let bytes = self.as_slice();
        let start = vector_legacy_prefix_len(bytes);
        if bytes.get(start) != Some(&0x62) {
            return None;
        }

        let p0 = *bytes.get(start + 1)?;
        let p1 = *bytes.get(start + 2)?;
        let p2 = *bytes.get(start + 3)?;
        let opcode = *bytes.get(start + 4)?;
        let modrm_index = start + 5;
        let modrm = *bytes.get(modrm_index)?;
        let mask = p2 & 0x07;
        let zeroing = p2 & 0x80 != 0;
        let broadcast = p2 & 0x10 != 0;
        let scalar = opcode & 1 != 0;
        if p0 & 0x07 != 6
            || !matches!(p1 & 0x83, 2 | 3)
            || (!scalar && p2 & 0x60 == 0x60)
            || !matches!(opcode, 0x56 | 0x57 | 0xD6 | 0xD7)
            || (scalar && broadcast)
            || modrm >> 6 == 3
            || (zeroing && mask == 0)
            || memory_operand_end(bytes, modrm_index)? != bytes.len()
        {
            return None;
        }

        let width = if scalar {
            VecWidth::V128
        } else {
            match (p2 >> 5) & 3 {
                0 => VecWidth::V128,
                1 => VecWidth::V256,
                2 => VecWidth::V512,
                _ => unreachable!("reserved vector length rejected"),
            }
        };
        let destination =
            (u8::from(p0 & 0x80 == 0) << 3) | (u8::from(p0 & 0x10 == 0) << 4) | ((modrm >> 3) & 7);
        let source1 = ((!p1 >> 3) & 0x0F) | (u8::from(p2 & 0x08 == 0) << 4);
        if destination == source1 {
            return None;
        }
        let writemask = (mask != 0).then_some(mask);
        let needs_avx512vl = !scalar && width != VecWidth::V512;

        let replay = if scalar || broadcast || writemask.is_some() {
            let stack_instruction = X86InstructionBytes::new(&[
                0x62,
                // Preserve R/R' and MAP6, select unextended SIB index/base,
                // and clear APX B4 because the rewritten base is RSP.
                (p0 & 0x97) | 0x60,
                // Preserve W0/vvvv/F2-or-F3 and restore ordinary EVEX.U.
                p1 | 0x04,
                // Scalar Type E10 ignores L'L (Intel SDM Vol. 2A 2.8.9).
                // Canonicalize it to 00b: preserving 11b faults on hosts
                // that otherwise support AVX-512-FP16. Packed L'L retains
                // its vector-length meaning. Preserve z, b, V', and aaa.
                if scalar { p2 & !0x60 } else { p2 },
                opcode,
                (modrm & 0x38) | 0x04,
                0x24,
            ])
            .unwrap();
            if scalar || broadcast {
                X86EvexPackedFp16ComplexMemoryReplay::Broadcast { stack_instruction }
            } else {
                X86EvexPackedFp16ComplexMemoryReplay::MaskedVector { stack_instruction }
            }
        } else {
            let scratch = (0..16u8)
                .find(|candidate| *candidate != destination && *candidate != source1)
                .expect("two operands cannot consume every low vector register");
            let register_instruction = X86InstructionBytes::new(&[
                0x62,
                // Register EVEX.X/B encode scratch bits 4/3 with inverted
                // polarity. Clear APX B4 and retain destination extensions.
                (p0 & 0x97) | 0x40 | if scratch & 8 == 0 { 0x20 } else { 0 },
                // Preserve W0/vvvv/F2-or-F3 and restore ordinary EVEX.U.
                p1 | 0x04,
                // Preserve z, L'L, V', and aaa; clear memory broadcast.
                p2 & !0x10,
                opcode,
                0xC0 | (modrm & 0x38) | (scratch & 7),
            ])
            .unwrap();
            if register_instruction.evex_register_packed_fp16_complex_needs_vl()
                != Some(needs_avx512vl)
            {
                return None;
            }
            X86EvexPackedFp16ComplexMemoryReplay::Vector {
                scratch,
                register_instruction,
            }
        };

        Some(X86EvexPackedFp16ComplexMemoryEncoding {
            width,
            destination,
            source1,
            writemask,
            zeroing,
            scalar,
            accumulate: opcode & !1 == 0x56,
            conjugate: p1 & 3 == 3,
            replay,
            needs_avx512vl,
        })
    }
}
