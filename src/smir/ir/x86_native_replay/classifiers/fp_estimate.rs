//! Legacy SSE and AVX VEX reciprocal-estimate replay classification.

use super::X86InstructionBytes;
use crate::smir::ir::types::VecWidth;

impl X86InstructionBytes {
    /// Validate one complete VEX `VRCPPS`, `VRCPSS`, `VRSQRTPS`, or
    /// `VRSQRTSS` memory-source instruction.
    ///
    /// Returns `(destination, scalar merge source, logical width, encoded
    /// width, memory size, opcode, W)`. Packed forms reserve VEX.vvvv and read
    /// 16 or 32 bytes according to VEX.L. Scalar forms consume VEX.vvvv as
    /// their upper-lane merge source and read exactly 4 bytes. Their logical
    /// vector width is 128 bits, while the separately returned encoded width
    /// retains both architecturally ignored VEX.L values as guest provenance.
    /// Native emission canonicalizes scalar VEX.L to zero. VEX.W is ignored
    /// for every form. Runtime and auxiliary space are O(1).
    pub(crate) fn vex_memory_fp_estimate_fields(
        &self,
    ) -> Option<(u8, Option<u8>, VecWidth, VecWidth, u32, u8, bool)> {
        let fields = self.vex_memory_fields()?;
        if fields.map != 1 || !matches!(fields.opcode, 0x52 | 0x53) {
            return None;
        }
        let encoded_width = if fields.width_256 {
            VecWidth::V256
        } else {
            VecWidth::V128
        };
        match fields.pp {
            0 if fields.source1 == 0 => Some((
                fields.destination,
                None,
                encoded_width,
                encoded_width,
                encoded_width.bytes(),
                fields.opcode,
                fields.w,
            )),
            2 => Some((
                fields.destination,
                Some(fields.source1),
                VecWidth::V128,
                encoded_width,
                4,
                fields.opcode,
                fields.w,
            )),
            _ => None,
        }
    }

    /// Validate one register-only legacy SSE or AVX VEX reciprocal estimate
    /// and report whether it requires AVX.
    ///
    /// The admitted set is `RCPPS`, `RCPSS`, `RSQRTPS`, `RSQRTSS` and their
    /// VEX forms. Packed VEX forms reserve `vvvv`; scalar VEX forms use it as
    /// the upper-lane merge source. Intel specifies scalar `VEX.LIG`, so both
    /// encoded L values are admitted. C4 W and register-form X are ignored.
    /// Memory sources and every non-exact byte string fail closed.
    pub fn legacy_vex_register_fp_estimate_needs_avx(&self) -> Option<bool> {
        let bytes = self.as_slice();
        let legacy_modrm = match bytes {
            [0x0F, 0x52 | 0x53, modrm] => Some(*modrm),
            [0xF3, 0x0F, 0x52 | 0x53, modrm] => Some(*modrm),
            [0x40..=0x4F, 0x0F, 0x52 | 0x53, modrm] => Some(*modrm),
            [0xF3, 0x40..=0x4F, 0x0F, 0x52 | 0x53, modrm] => Some(*modrm),
            _ => None,
        };
        if let Some(modrm) = legacy_modrm {
            return (modrm >> 6 == 3).then_some(false);
        }

        let (p1, opcode, modrm) = match bytes {
            [0xC5, p1, opcode, modrm] => (*p1, *opcode, *modrm),
            [0xC4, p0, p1, opcode, modrm] if p0 & 0x1F == 1 => (*p1, *opcode, *modrm),
            _ => return None,
        };
        if !matches!(opcode, 0x52 | 0x53) || modrm >> 6 != 3 {
            return None;
        }

        match p1 & 0x03 {
            0 if p1 & 0x78 == 0x78 => Some(true),
            2 => Some(true),
            _ => None,
        }
    }

    /// Select the equivalent host encoding of one validated VEX estimate.
    ///
    /// Intel specifies scalar reciprocal estimates as VEX.LIG. Some translated
    /// hosts reject L=1 despite that definition, so emit L=0 for scalar forms.
    /// Packed L, ignored W/X, operands, and original guest provenance remain
    /// unchanged. Validation and rewriting take O(1) time and space.
    pub(crate) fn vex_fp_estimate_native_encoding(&self) -> Option<Self> {
        self.vex_fp_estimate_destination_index()?;
        let mut encoding = *self;
        let prefix = if encoding.bytes[0] == 0xC5 { 1 } else { 2 };
        if encoding.bytes[prefix] & 3 == 2 {
            encoding.bytes[prefix] &= !4;
        }
        Some(encoding)
    }

    /// Return the architectural destination of a validated VEX reciprocal
    /// estimate. Legacy forms return `None` because they preserve all vector
    /// state above XMM and require no state-backed upper clear.
    pub(crate) fn vex_fp_estimate_destination_index(&self) -> Option<u8> {
        self.legacy_vex_register_fp_estimate_needs_avx()?;
        match self.as_slice() {
            [0xC5, p1, _opcode, modrm] => {
                Some(((modrm >> 3) & 7) | (u8::from(p1 & 0x80 == 0) << 3))
            }
            [0xC4, p0, _p1, _opcode, modrm] => {
                Some(((modrm >> 3) & 7) | (u8::from(p0 & 0x80 == 0) << 3))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Form {
        C5,
        C4 { w: bool },
    }

    fn instruction(
        destination: u8,
        source1: Option<u8>,
        base: u8,
        opcode: u8,
        encoded_width: VecWidth,
        form: Form,
    ) -> Vec<u8> {
        assert!(matches!(opcode, 0x52 | 0x53));
        assert!(matches!(encoded_width, VecWidth::V128 | VecWidth::V256));
        let pp = if source1.is_some() { 2 } else { 0 };
        let encoded_vvvv = source1.map_or(0x0F, |index| !index & 0x0F);
        let l = u8::from(encoded_width == VecWidth::V256);
        let modrm = 0x40 | ((destination & 7) << 3) | (base & 7);
        match form {
            Form::C5 => {
                assert!(base < 8);
                vec![
                    0xC5,
                    (if destination < 8 { 0x80 } else { 0 }) | (encoded_vvvv << 3) | (l << 2) | pp,
                    opcode,
                    modrm,
                    0x20,
                ]
            }
            Form::C4 { w } => vec![
                0xC4,
                (if destination < 8 { 0x80 } else { 0 })
                    | 0x40
                    | (if base < 8 { 0x20 } else { 0 })
                    | 1,
                (u8::from(w) << 7) | (encoded_vvvv << 3) | (l << 2) | pp,
                opcode,
                modrm,
                0x20,
            ],
        }
    }

    #[test]
    fn classifies_all_5440_vex_estimate_operand_opcode_width_w_and_base_cells() {
        let mut classified = 0usize;
        let packed_sources = [None];
        let scalar_sources = (0..16).map(Some).collect::<Vec<_>>();
        for opcode in [0x52, 0x53] {
            for source1s in [packed_sources.as_slice(), scalar_sources.as_slice()] {
                for encoded_width in [VecWidth::V128, VecWidth::V256] {
                    for &source1 in source1s {
                        for destination in 0..16 {
                            let logical_width = source1.map_or(encoded_width, |_| VecWidth::V128);
                            let memory_size = source1.map_or_else(|| encoded_width.bytes(), |_| 4);
                            let bytes = instruction(
                                destination,
                                source1,
                                3,
                                opcode,
                                encoded_width,
                                Form::C5,
                            );
                            assert_eq!(
                                X86InstructionBytes::new(&bytes)
                                    .unwrap()
                                    .vex_memory_fp_estimate_fields(),
                                Some((
                                    destination,
                                    source1,
                                    logical_width,
                                    encoded_width,
                                    memory_size,
                                    opcode,
                                    false,
                                )),
                                "{bytes:02X?}"
                            );
                            classified += 1;

                            for base in [3, 11] {
                                for w in [false, true] {
                                    let bytes = instruction(
                                        destination,
                                        source1,
                                        base,
                                        opcode,
                                        encoded_width,
                                        Form::C4 { w },
                                    );
                                    assert_eq!(
                                        X86InstructionBytes::new(&bytes)
                                            .unwrap()
                                            .vex_memory_fp_estimate_fields(),
                                        Some((
                                            destination,
                                            source1,
                                            logical_width,
                                            encoded_width,
                                            memory_size,
                                            opcode,
                                            w,
                                        )),
                                        "{bytes:02X?}"
                                    );
                                    classified += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(classified, 5_440);
    }

    #[test]
    fn complete_address_shapes_and_malformed_vex_estimate_encodings_fail_closed() {
        // addr32 FS: VRSQRTSS xmm14,xmm13,[r14d+r15d*2+0x44332211],
        // with architecturally ignored W=1 and L=1 retained in metadata.
        let complete = [
            0x64, 0x67, 0xC4, 0x01, 0x96, 0x52, 0xB4, 0x7E, 0x11, 0x22, 0x33, 0x44,
        ];
        assert_eq!(
            X86InstructionBytes::new(&complete)
                .unwrap()
                .vex_memory_fp_estimate_fields(),
            Some((14, Some(13), VecWidth::V128, VecWidth::V256, 4, 0x52, true,))
        );

        let scalar = instruction(9, Some(10), 11, 0x53, VecWidth::V256, Form::C4 { w: true });
        let packed = instruction(9, None, 11, 0x52, VecWidth::V256, Form::C4 { w: true });
        let mut cases = Vec::new();

        let mut nonreserved_packed_vvvv = packed;
        nonreserved_packed_vvvv[2] &= !0x08;
        cases.push(nonreserved_packed_vvvv);

        let mut wrong_map = scalar.clone();
        wrong_map[1] = (wrong_map[1] & !0x1F) | 2;
        cases.push(wrong_map);

        let mut wrong_prefix = scalar.clone();
        wrong_prefix[2] = (wrong_prefix[2] & !0x03) | 1;
        cases.push(wrong_prefix);

        let mut wrong_opcode = scalar.clone();
        wrong_opcode[3] = 0x51;
        cases.push(wrong_opcode);

        let mut register_source = scalar.clone();
        register_source[4] |= 0xC0;
        register_source.remove(5);
        cases.push(register_source);

        let mut truncated_displacement = scalar.clone();
        truncated_displacement[4] = (truncated_displacement[4] & 0x3F) | 0x80;
        cases.push(truncated_displacement);

        let mut trailing = scalar.clone();
        trailing.push(0);
        cases.push(trailing);

        let mut forbidden_prefix = scalar;
        forbidden_prefix.insert(0, 0xF3);
        cases.push(forbidden_prefix);

        cases.push(vec![0xF3, 0x0F, 0x53, 0x40, 0x20]);

        for bytes in cases {
            assert_eq!(
                X86InstructionBytes::new(&bytes)
                    .unwrap()
                    .vex_memory_fp_estimate_fields(),
                None,
                "{bytes:02X?}"
            );
        }
    }
}
