//! Complete SDK XSAVE images and architectural projections.
//! Intel SDM December 2024, Vol.1 Chapter 13 and Vol.2 FXSAVE/XSAVE/XRSTOR.
//! The legacy area is 512 bytes; the XSAVE header occupies bytes 512..576.
use crate::error::{Error, Result};
use crate::vm::snapshot::{EmulatorState, FpuSnapshot};
use crate::vm::vcpu::Registers;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_IMAGE: usize = 1024 * 1024;
const HEADER_END: usize = 576;
const COMPACTED: u64 = 1 << 63;

#[cfg(test)]
#[path = "intel_xsave_tests.rs"]
mod tests;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native Intel XSAVE: {message}"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Component {
    pub bit: u8,
    pub size: u32,
    pub offset: u32,
    pub align64: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Layout {
    pub mask: u64,
    pub size: u32,
    pub components: Vec<Component>,
    pub mxcsr_mask: u32,
}

impl Layout {
    pub fn validate(&self) -> Result<()> {
        if self.mask & 7 != 7 || self.mask & COMPACTED != 0 {
            return Err(invalid(
                "host cannot represent the advertised x87/SSE/AVX state",
            ));
        }
        if !(HEADER_END..=MAX_IMAGE).contains(&(self.size as usize))
            || self.mxcsr_mask == 0
            || self.mxcsr_mask & !0xffff != 0
        {
            return Err(invalid("invalid host image size or MXCSR mask"));
        }
        let mut described = 3;
        let mut previous_bit = 1;
        let mut spans = Vec::new();
        for component in &self.components {
            if component.bit <= previous_bit
                || component.bit >= 63
                || self.mask & (1u64 << component.bit) == 0
                || component.size == 0
                || component.offset < HEADER_END as u32
            {
                return Err(invalid("invalid or unordered component descriptor"));
            }
            let end = component
                .offset
                .checked_add(component.size)
                .filter(|&end| end <= self.size)
                .ok_or_else(|| invalid("component exceeds the host image"))?;
            if spans
                .iter()
                .any(|&(start, old_end)| component.offset < old_end && start < end)
            {
                return Err(invalid("overlapping standard components"));
            }
            spans.push((component.offset, end));
            described |= 1u64 << component.bit;
            previous_bit = component.bit;
        }
        if described != self.mask {
            return Err(invalid("host mask differs from its component table"));
        }
        let ymm = self
            .components
            .iter()
            .find(|component| component.bit == 2)
            .ok_or_else(|| invalid("missing YMM component"))?;
        if ymm.size != 256 {
            return Err(invalid("YMM component is not 16 upper 128-bit lanes"));
        }
        for (bit, size) in [(5, 64), (6, 512), (7, 1024), (9, 8)] {
            if self
                .component(bit)
                .is_some_and(|component| component.size != size)
            {
                return Err(invalid("unexpected architectural component width"));
            }
        }
        Ok(())
    }

    fn component(&self, bit: u8) -> Option<&Component> {
        self.components
            .iter()
            .find(|component| component.bit == bit)
    }

    fn offset(&self, image: &[u8], bit: u8) -> Result<Option<usize>> {
        let Some(component) = self.component(bit) else {
            return Ok(None);
        };
        let compact = u64_at(image, 520);
        if compact == 0 {
            return Ok(Some(component.offset as usize));
        }
        let mut offset = HEADER_END;
        for current in &self.components {
            if compact & (1u64 << current.bit) == 0 {
                continue;
            }
            if current.align64 {
                offset = offset
                    .checked_add(63)
                    .ok_or_else(|| invalid("compact offset overflow"))?
                    & !63;
            }
            let start = offset;
            offset = offset
                .checked_add(current.size as usize)
                .filter(|&end| end <= image.len())
                .ok_or_else(|| invalid("compact component exceeds image"))?;
            if current.bit == bit {
                return Ok(Some(start));
            }
        }
        Ok(None)
    }

    pub fn validate_image(&self, image: &[u8]) -> Result<()> {
        self.validate()?;
        if image.len() != self.size as usize {
            return Err(invalid(
                "image length differs from the admitted host layout",
            ));
        }
        let present = u64_at(image, 512);
        let compact = u64_at(image, 520);
        if present & !self.mask != 0
            || (compact != 0
                && (compact & COMPACTED == 0 || compact & !(COMPACTED | self.mask) != 0))
            || (compact != 0 && present & !(compact & !COMPACTED) != 0)
            || image[528..HEADER_END].iter().any(|&byte| byte != 0)
        {
            return Err(invalid("invalid XSAVE header or unsupported state bits"));
        }
        if (compact == 0 || present & 2 != 0) && u32_at(image, 24) & !self.mxcsr_mask != 0 {
            return Err(invalid("MXCSR contains unsupported bits"));
        }
        for component in &self.components {
            if present & (1u64 << component.bit) != 0 {
                let start = self
                    .offset(image, component.bit)?
                    .ok_or_else(|| invalid("present compact component is absent"))?;
                start
                    .checked_add(component.size as usize)
                    .filter(|&end| end <= image.len())
                    .ok_or_else(|| invalid("component exceeds image"))?;
            }
        }
        Ok(())
    }

    /// Normalize compacted images before a public register overlay. O(n) time
    /// and storage in the bounded image length; untouched components survive.
    fn standard(&self, image: &[u8]) -> Result<Vec<u8>> {
        self.validate_image(image)?;
        let present = u64_at(image, 512);
        let compact = u64_at(image, 520);
        let mut standard = if compact == 0 {
            image.to_vec()
        } else {
            let mut standard = vec![0; image.len()];
            standard[..520].copy_from_slice(&image[..520]);
            for component in &self.components {
                if present & (1u64 << component.bit) == 0 {
                    continue;
                }
                let offset = self
                    .offset(image, component.bit)?
                    .ok_or_else(|| invalid("missing compact component"))?;
                let target = component.offset as usize;
                let length = component.size as usize;
                standard[target..target + length].copy_from_slice(&image[offset..offset + length]);
            }
            standard
        };
        // A later overlay can mark either legacy component in use. Materialize
        // its initial state before that transition so stale bytes never become
        // architectural values. Standard XRSTOR always loads MXCSR; compacted
        // XRSTOR initializes it when SSE is absent (SDM Vol.1 13.8.1-13.8.2).
        if present & 1 == 0 {
            standard[..24].fill(0);
            standard[..2].copy_from_slice(&0x037fu16.to_le_bytes());
            standard[32..160].fill(0);
        }
        if present & 2 == 0 {
            standard[160..416].fill(0);
            if compact != 0 {
                standard[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
            }
        }
        Ok(standard)
    }

    pub fn project(&self, image: &[u8], registers: &mut Registers) -> Result<EmulatorState> {
        self.validate_image(image)?;
        let present = u64_at(image, 512);
        let mut emulator = EmulatorState::default();
        if present & 1 != 0 {
            let status = u16_at(image, 2);
            let top = ((status >> 11) & 7) as usize;
            let mut fpu = FpuSnapshot {
                control_word: u16_at(image, 0),
                status_word: status,
                tag_word: 0,
                data_ptr: u64_at(image, 16),
                instr_ptr: u64_at(image, 8),
                last_opcode: u16_at(image, 6),
                st: [[0; 10]; 8],
                top: top as u8,
            };
            for logical in 0..8 {
                let physical = (top + logical) & 7;
                let offset = 32 + 16 * logical;
                fpu.st[physical].copy_from_slice(&image[offset..offset + 10]);
                registers.mm[physical] = u64_at(image, offset);
                let tag = if image[4] & (1 << physical) == 0 {
                    3
                } else {
                    x87_tag(&fpu.st[physical])
                };
                fpu.tag_word |= tag << (2 * physical);
            }
            emulator.fpu = fpu;
        } else {
            registers.mm = [0; 8];
        }
        registers.xmm = [[0; 2]; 16];
        registers.ymm_high = [[0; 2]; 16];
        registers.zmm_high = [[0; 4]; 16];
        registers.zmm_ext = [[0; 8]; 16];
        registers.k = [0; 8];
        if u64_at(image, 520) == 0 || present & 2 != 0 {
            emulator.mxcsr = u32_at(image, 24);
        }
        if present & 2 != 0 {
            lanes(image, 160, &mut registers.xmm);
        }
        if present & 4 != 0 {
            let offset = self
                .offset(image, 2)?
                .ok_or_else(|| invalid("missing YMM state"))?;
            lanes(image, offset, &mut registers.ymm_high);
        }
        for (bit, expected) in [(5, 64), (6, 512), (7, 1024), (9, 8)] {
            if present & (1 << bit) == 0 {
                continue;
            }
            let component = self
                .component(bit)
                .ok_or_else(|| invalid("missing extended component"))?;
            if component.size as usize != expected {
                return Err(invalid("unexpected extended component size"));
            }
            let offset = self
                .offset(image, bit)?
                .ok_or_else(|| invalid("missing extended state"))?;
            match bit {
                5 => {
                    for (index, value) in registers.k.iter_mut().enumerate() {
                        *value = u64_at(image, offset + 8 * index);
                    }
                }
                6 => lanes(image, offset, &mut registers.zmm_high),
                7 => lanes(image, offset, &mut registers.zmm_ext),
                9 => emulator.pkru = u32_at(image, offset),
                _ => (),
            }
        }
        Ok(emulator)
    }

    /// Change only the stable public register banks; x87 control/status, exact
    /// 80-bit upper words, MXCSR and unprojected host components are retained.
    pub fn overlay(&self, image: &[u8], registers: &Registers) -> Result<Vec<u8>> {
        let mut image = self.standard(image)?;
        let extended_gprs = [
            registers.r16,
            registers.r17,
            registers.r18,
            registers.r19,
            registers.r20,
            registers.r21,
            registers.r22,
            registers.r23,
            registers.r24,
            registers.r25,
            registers.r26,
            registers.r27,
            registers.r28,
            registers.r29,
            registers.r30,
            registers.r31,
        ];
        if extended_gprs.iter().any(|&value| value != 0) {
            return Err(invalid("APX registers are not exposed by the native SDK"));
        }
        let present = u64_at(&image, 512);
        let top = if present & 1 != 0 {
            ((u16_at(&image, 2) >> 11) & 7) as usize
        } else {
            0
        };
        if present & 1 == 0 {
            image[..24].fill(0);
            image[..2].copy_from_slice(&0x037fu16.to_le_bytes());
            image[32..160].fill(0);
        }
        for logical in 0..8 {
            let physical = (top + logical) & 7;
            image[32 + 16 * logical..40 + 16 * logical]
                .copy_from_slice(&registers.mm[physical].to_le_bytes());
        }
        write_lanes(&mut image, 160, &registers.xmm);
        let ymm = self
            .component(2)
            .ok_or_else(|| invalid("missing YMM descriptor"))?;
        write_lanes(&mut image, ymm.offset as usize, &registers.ymm_high);
        let mut updated = present | 7;
        for (bit, nonzero) in [
            (5, registers.k.iter().any(|&value| value != 0)),
            (
                6,
                registers.zmm_high.iter().flatten().any(|&value| value != 0),
            ),
            (
                7,
                registers.zmm_ext.iter().flatten().any(|&value| value != 0),
            ),
        ] {
            let Some(component) = self.component(bit) else {
                if nonzero {
                    return Err(invalid(
                        "public vector bank exceeds the admitted host profile",
                    ));
                }
                continue;
            };
            let offset = component.offset as usize;
            match bit {
                5 if component.size == 64 => {
                    for (index, value) in registers.k.iter().enumerate() {
                        image[offset + index * 8..offset + index * 8 + 8]
                            .copy_from_slice(&value.to_le_bytes());
                    }
                }
                6 if component.size == 512 => write_lanes(&mut image, offset, &registers.zmm_high),
                7 if component.size == 1024 => write_lanes(&mut image, offset, &registers.zmm_ext),
                _ => return Err(invalid("unexpected vector component width")),
            }
            updated |= 1 << bit;
        }
        image[512..520].copy_from_slice(&updated.to_le_bytes());
        self.validate_image(&image)?;
        Ok(image)
    }

    pub fn overlay_emulator(&self, image: &[u8], emulator: &EmulatorState) -> Result<Vec<u8>> {
        let mut image = self.standard(image)?;
        let fpu = &emulator.fpu;
        if fpu.top > 7
            || ((fpu.status_word >> 11) & 7) != u16::from(fpu.top)
            || fpu.last_opcode & !0x7ff != 0
            || emulator.mxcsr & !self.mxcsr_mask != 0
        {
            return Err(invalid("unrepresentable x87 or MXCSR state"));
        }
        let mut abridged = 0;
        for physical in 0..8 {
            let tag = (fpu.tag_word >> (2 * physical)) & 3;
            if tag != 3 {
                if tag != x87_tag(&fpu.st[physical]) {
                    return Err(invalid(
                        "full x87 tag cannot be represented by this XSAVE image",
                    ));
                }
                abridged |= 1 << physical;
            }
        }
        image[..2].copy_from_slice(&fpu.control_word.to_le_bytes());
        image[2..4].copy_from_slice(&fpu.status_word.to_le_bytes());
        image[4] = abridged;
        image[6..8].copy_from_slice(&fpu.last_opcode.to_le_bytes());
        image[8..16].copy_from_slice(&fpu.instr_ptr.to_le_bytes());
        image[16..24].copy_from_slice(&fpu.data_ptr.to_le_bytes());
        image[24..28].copy_from_slice(&emulator.mxcsr.to_le_bytes());
        for logical in 0..8 {
            let physical = (usize::from(fpu.top) + logical) & 7;
            image[32 + 16 * logical..42 + 16 * logical].copy_from_slice(&fpu.st[physical]);
        }
        let mut present = u64_at(&image, 512) | 3;
        if let Some(component) = self.component(9) {
            let offset = component.offset as usize;
            image[offset..offset + 4].copy_from_slice(&emulator.pkru.to_le_bytes());
            image[offset + 4..offset + 8].fill(0);
            present |= 1 << 9;
        } else if emulator.pkru != 0 {
            return Err(invalid("PKRU is not present in the host profile"));
        }
        image[512..520].copy_from_slice(&present.to_le_bytes());
        self.validate_image(&image)?;
        Ok(image)
    }
}

fn x87_tag(value: &[u8; 10]) -> u16 {
    let significand = u64::from_le_bytes(value[..8].try_into().unwrap());
    let exponent = u16::from_le_bytes(value[8..].try_into().unwrap()) & 0x7fff;
    if exponent == 0 && significand == 0 {
        1
    } else if exponent != 0 && exponent != 0x7fff && significand >> 63 != 0 {
        0
    } else {
        2
    }
}

fn lanes<const N: usize, const M: usize>(
    image: &[u8],
    offset: usize,
    registers: &mut [[u64; M]; N],
) {
    for (index, value) in registers.iter_mut().flatten().enumerate() {
        *value = u64_at(image, offset + 8 * index);
    }
}
fn write_lanes<const N: usize, const M: usize>(
    image: &mut [u8],
    offset: usize,
    registers: &[[u64; M]; N],
) {
    for (index, value) in registers.iter().flatten().enumerate() {
        image[offset + 8 * index..offset + 8 * index + 8].copy_from_slice(&value.to_le_bytes());
    }
}
fn u16_at(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap())
}
fn u32_at(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
}
fn u64_at(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
}
