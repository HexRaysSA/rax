//! Exact EVEX gather/scatter VSIB memory encodings.

use super::X86InstructionBytes;
use super::evex_memory::{memory_operand_end, vector_legacy_prefix_len};
use crate::smir::ir::types::{VecElementType, VecWidth, X86Reg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86EvexVsibMemoryEncoding {
    pub(crate) scatter: bool,
    pub(crate) data_register: u8,
    pub(crate) index_register: u8,
    pub(crate) writemask: u8,
    pub(crate) width: VecWidth,
    pub(crate) data_elem: VecElementType,
    pub(crate) index_elem: VecElementType,
    pub(crate) lanes: u8,
    pub(crate) base: Option<u8>,
    pub(crate) scale: u8,
    /// Sign-extended displacement in bytes, including disp8 tuple scaling.
    pub(crate) displacement: i64,
    pub(crate) address_32: bool,
    pub(crate) segment: Option<X86Reg>,
    pub(crate) requires_apx: bool,
}

impl X86InstructionBytes {
    /// Intel SDM 086: EVEX.66.0F38 90–93/A0–A3 use Type E12 VSIB
    /// addressing and partial completion. Intel APX 355828-007US
    /// §3.1.2.3.3/Table 3.3 extends BASE with B4 but not VIDX with X4.
    /// This classifier describes 64-bit code with 64/32-bit effective
    /// addresses; it does not admit VEX or prefetch forms.
    pub(crate) fn evex_vsib_memory_encoding(&self) -> Option<X86EvexVsibMemoryEncoding> {
        let bytes = self.as_slice();
        let start = vector_legacy_prefix_len(bytes);
        if bytes.get(start) != Some(&0x62) {
            return None;
        }
        let p0 = *bytes.get(start + 1)?;
        let p1 = *bytes.get(start + 2)?;
        let p2 = *bytes.get(start + 3)?;
        let opcode = *bytes.get(start + 4)?;
        let modrm = *bytes.get(start + 5)?;
        let sib = *bytes.get(start + 6)?;
        let end = memory_operand_end(bytes, start + 5)?;
        if p0 & 7 != 2
            || p1 & 3 != 1
            || p1 & 0x78 != 0x78
            || p2 & 0x90 != 0
            || p2 & 7 == 0
            || p2 & 0x60 == 0x60
            || !matches!(opcode, 0x90..=0x93 | 0xA0..=0xA3)
            || modrm >> 6 == 3
            || modrm & 7 != 4
            || end != bytes.len()
        {
            return None;
        }
        let scatter = opcode & 0x20 != 0;
        let data_register =
            ((modrm >> 3) & 7) | (u8::from(p0 & 0x80 == 0) << 3) | (u8::from(p0 & 0x10 == 0) << 4);
        let index_register =
            ((sib >> 3) & 7) | (u8::from(p0 & 0x40 == 0) << 3) | (u8::from(p2 & 8 == 0) << 4);
        if !scatter && data_register == index_register {
            return None;
        }
        let width = match (p2 >> 5) & 3 {
            0 => VecWidth::V128,
            1 => VecWidth::V256,
            2 => VecWidth::V512,
            _ => return None,
        };
        let data_elem = if p1 & 0x80 != 0 {
            VecElementType::I64
        } else {
            VecElementType::I32
        };
        let index_elem = if opcode & 1 != 0 {
            VecElementType::I64
        } else {
            VecElementType::I32
        };
        let lanes = width.lanes(data_elem).min(width.lanes(index_elem)) as u8;
        let no_base = modrm >> 6 == 0 && sib & 7 == 5;
        let base = (!no_base)
            .then_some((sib & 7) | (u8::from(p0 & 0x20 == 0) << 3) | (u8::from(p0 & 8 != 0) << 4));
        let displacement_bytes = &bytes[start + 7..end];
        let displacement = match displacement_bytes {
            [] => 0,
            [disp] => i64::from(*disp as i8) * i64::from(data_elem.bytes()),
            [a, b, c, d] => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
            _ => return None,
        };
        // Group-2 segment prefixes use the last occurrence. In long mode all
        // bases except FS/GS are ignored, including an override after FS/GS.
        let segment = bytes[..start]
            .iter()
            .rev()
            .find(|byte| **byte != 0x67)
            .and_then(|byte| match byte {
                0x64 => Some(X86Reg::FsBase),
                0x65 => Some(X86Reg::GsBase),
                _ => None,
            });
        Some(X86EvexVsibMemoryEncoding {
            scatter,
            data_register,
            index_register,
            writemask: p2 & 7,
            width,
            data_elem,
            index_elem,
            lanes,
            base,
            scale: 1 << (sib >> 6),
            displacement,
            address_32: bytes[..start].contains(&0x67),
            segment,
            requires_apx: base.is_some_and(|register| register >= 16),
        })
    }
}
