//! Mode-correct static x86 metadata, independent of execution/lifting coverage.
use crate::arch::*;
use crate::decode::*;
use crate::{RaxStatus, guard};
use rax_engine::isa::x86_64::instruction_metadata::{self as metadata, Flow, OperandKind};
use std::os::raw::{c_int, c_void};

pub const RAX_INSTRUCTION_INFO_VERSION: u32 = 1;
pub const RAX_INSTRUCTION_BASIC_COMPLETE: u32 = 1;
pub const RAX_INSTRUCTION_OPERANDS_COMPLETE: u32 = 2;
pub const RAX_INSTRUCTION_UNREPRESENTED: u32 = 4;
pub const RAX_OPERAND_REGISTER: u32 = 1;
pub const RAX_OPERAND_MEMORY: u32 = 2;
pub const RAX_OPERAND_IMMEDIATE: u32 = 3;
pub const RAX_OPERAND_TARGET: u32 = 4;
pub const RAX_OPERAND_READ: u32 = 1;
pub const RAX_OPERAND_WRITE: u32 = 2;
pub const RAX_OPERAND_CONDITIONAL: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RaxInstructionOperand {
    pub kind: u32,
    pub access: u32,
    pub width_bits: u32,
    pub address_bits: u32,
    pub reg: [u8; 16],
    pub base: [u8; 16],
    pub index: [u8; 16],
    pub segment: [u8; 8],
    pub scale: u32,
    pub _reserved: u32,
    pub displacement: u64,
    pub value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxInstructionInfo {
    pub struct_size: u32,
    pub abi_version: u32,
    pub decoded: RaxDecoded,
    pub mnemonic: [u8; 32],
    pub flags: u32,
    pub operand_count: u32,
    pub stack_pointer_increment: i32,
    pub _reserved: u32,
    pub operands: [RaxInstructionOperand; 5],
}
impl Default for RaxInstructionInfo {
    fn default() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: RAX_INSTRUCTION_INFO_VERSION,
            decoded: RaxDecoded::zeroed(),
            mnemonic: [0; 32],
            flags: 0,
            operand_count: 0,
            stack_pointer_increment: 0,
            _reserved: 0,
            operands: [RaxInstructionOperand::default(); 5],
        }
    }
}
fn text<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0; N];
    for (d, b) in out.iter_mut().take(N - 1).zip(s.bytes()) {
        *d = b.to_ascii_lowercase();
    }
    out
}
pub(crate) fn bitness(mode: u32) -> Option<u32> {
    if mode & !(RAX_MODE_16 | RAX_MODE_32 | RAX_MODE_64 | RAX_MODE_LITTLE_ENDIAN) != 0 {
        return None;
    }
    match mode & (RAX_MODE_16 | RAX_MODE_32 | RAX_MODE_64) {
        RAX_MODE_16 => Some(16),
        RAX_MODE_32 => Some(32),
        0 | RAX_MODE_64 => Some(64),
        _ => None,
    }
}
pub(crate) fn decode_x86(bits: u32, pc: u64, bytes: &[u8]) -> RaxInstructionInfo {
    let mut out = RaxInstructionInfo::default();
    let decoded = metadata::decode(bits, pc, bytes);
    let Ok(instruction) = decoded else {
        if matches!(decoded, Err(metadata::DecodeFailure::Unsupported)) {
            out.flags = RAX_INSTRUCTION_UNREPRESENTED;
        }
        // Preserve the existing RAX SMIR projection where native metadata is
        // not yet exported. Never decode a legacy mode through the long-mode
        // lifter, and never claim a mnemonic/operand contract from flow alone.
        if bits == 64 && matches!(decoded, Err(metadata::DecodeFailure::Unsupported)) {
            let opts = crate::decode::oracle_options(RaxArch::X86, RAX_MODE_64, pc);
            if let Ok(value) = rax_engine::isa_oracle::decode_to_json(bytes, &opts) {
                crate::decode::fill_from_json(&value, &mut out.decoded);
                if out.decoded.size as usize > bytes.len() || out.decoded.size > 15 {
                    out.decoded = RaxDecoded::zeroed();
                }
            }
        }
        return out;
    };
    let d = &mut out.decoded;
    d.valid = 1;
    d.size = instruction.size;
    d.fallthrough = instruction.fallthrough;
    d.flow = match instruction.flow {
        Flow::Next => RAX_FLOW_FALLTHROUGH,
        Flow::Branch => RAX_FLOW_BRANCH,
        Flow::Conditional => RAX_FLOW_COND_BRANCH,
        Flow::IndirectJump => RAX_FLOW_INDIRECT_JUMP,
        Flow::Call => RAX_FLOW_CALL,
        Flow::IndirectCall => RAX_FLOW_INDIRECT_CALL,
        Flow::Return => RAX_FLOW_RETURN,
        Flow::Trap => RAX_FLOW_TRAP,
        Flow::Syscall => RAX_FLOW_SYSCALL,
        Flow::Unknown => RAX_FLOW_UNKNOWN,
    };
    d.is_indirect = u32::from(matches!(
        instruction.flow,
        Flow::IndirectJump | Flow::IndirectCall
    ));
    if let Some(target) = instruction.target {
        d.target = target;
        d.has_target = 1;
    }
    out.mnemonic = text(&instruction.mnemonic);
    out.flags = RAX_INSTRUCTION_BASIC_COMPLETE;
    if instruction.operands_complete {
        out.flags |= RAX_INSTRUCTION_OPERANDS_COMPLETE;
    }
    out.operand_count = instruction.operands.len() as u32;
    out.stack_pointer_increment = instruction.stack_pointer_increment;
    for (source, dest) in instruction.operands.iter().zip(&mut out.operands) {
        dest.kind = match source.kind {
            OperandKind::Register => RAX_OPERAND_REGISTER,
            OperandKind::Memory => RAX_OPERAND_MEMORY,
            OperandKind::Immediate => RAX_OPERAND_IMMEDIATE,
            OperandKind::Target => RAX_OPERAND_TARGET,
            OperandKind::Unknown => 0,
        };
        dest.access = u32::from(source.read) * RAX_OPERAND_READ
            | u32::from(source.write) * RAX_OPERAND_WRITE
            | u32::from(source.conditional) * RAX_OPERAND_CONDITIONAL;
        dest.width_bits = source.width_bits;
        dest.address_bits = source.address_bits;
        dest.reg = text(&source.reg);
        dest.base = text(&source.base);
        dest.index = text(&source.index);
        dest.segment = text(&source.segment);
        dest.scale = source.scale;
        dest.displacement = source.displacement;
        dest.value = source.value;
    }
    out
}

/// Caller owns readable bytes and writable output; no pointers escape this call.
#[unsafe(no_mangle)]
pub extern "C" fn rax_instruction_info(
    arch: c_int,
    mode: u32,
    pc: u64,
    bytes: *const c_void,
    len: usize,
    out: *mut RaxInstructionInfo,
) -> RaxStatus {
    guard(|| {
        if out.is_null() {
            return RaxStatus::Arg;
        }
        // SAFETY: C contract supplies aligned readable header fields. No larger
        // object is accessed until its declared size and version are checked.
        let (size, version) = unsafe { ((*out).struct_size, (*out).abi_version) };
        if size < size_of::<RaxInstructionInfo>() as u32 || version != RAX_INSTRUCTION_INFO_VERSION
        {
            return RaxStatus::Arg;
        }
        // SAFETY: size negotiation establishes writable v1 object. Caller tails
        // are never read/written. Default initializes every field and reserve.
        unsafe {
            *out = RaxInstructionInfo::default();
        }
        if bytes.is_null() || len == 0 || len > isize::MAX as usize {
            return RaxStatus::Arg;
        }
        if arch != RaxArch::X86 as c_int {
            return RaxStatus::Arch;
        }
        let Some(bits) = bitness(mode) else {
            return RaxStatus::Mode;
        };
        // SAFETY: caller provides len initialized readable bytes, validated to
        // meet Rust's slice-size bound; decoder borrows only during this call.
        let data = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), len.min(15)) };
        let result = decode_x86(bits, pc, data);
        // SAFETY: same checked caller-owned v1 object; no alias retained.
        unsafe {
            *out = result;
        }
        RaxStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode(mode: u32, bytes: &[u8]) -> RaxInstructionInfo {
        let mut out = RaxInstructionInfo::default();
        assert_eq!(
            rax_instruction_info(
                1,
                mode,
                0x1000,
                bytes.as_ptr().cast(),
                bytes.len(),
                &mut out
            ),
            RaxStatus::Ok
        );
        out
    }
    #[test]
    fn loop_operand_prefix_preserves_code_address_width() {
        for bits in [32, 64] {
            for opcode in 0xe0..=0xe3 {
                let x = decode_x86(bits, 0x1_0000, &[0x66, opcode, 2]);
                assert_eq!(x.decoded.valid, 1);
                assert_eq!(
                    (x.decoded.fallthrough, x.decoded.target),
                    (0x1_0003, 0x1_0005)
                );
            }
        }
    }
    #[test]
    fn ret_modes_and_stack_cleanup() {
        for (mode, width) in [(RAX_MODE_16, 2), (RAX_MODE_32, 4), (RAX_MODE_64, 8)] {
            for (bytes, size, cleanup) in [
                (&[0xc3][..], 1, 0),
                (&[0xc2, 0x34, 0x12][..], 3, 0x1234),
                (&[0xf3, 0xc3][..], 2, 0),
            ] {
                let x = decode(mode, bytes);
                assert_eq!(
                    (x.decoded.valid, x.decoded.size, x.decoded.flow),
                    (1, size, RAX_FLOW_RETURN)
                );
                assert_eq!(&x.mnemonic[..4], b"ret\0");
                assert_eq!(x.stack_pointer_increment, width + cleanup);
            }
        }
        assert_eq!(
            decode(RAX_MODE_32, &[0x66, 0xc3]).stack_pointer_increment,
            2
        );
        for b in [0xcb, 0xcf] {
            assert_ne!(&decode(RAX_MODE_32, &[b]).mnemonic[..4], b"ret\0");
        }
    }
    #[test]
    fn mode_changes_encoding_and_relative_wrap() {
        let a = decode(RAX_MODE_32, &[0x40, 0x90]);
        let b = decode(RAX_MODE_64, &[0x40, 0x90]);
        assert_eq!((a.decoded.size, b.decoded.size), (1, 2));
        assert_eq!(&a.mnemonic[..4], b"inc\0");
        let x = decode_x86(32, 0xffff_fffc, &[0xe8, 0, 0, 0, 0]);
        assert_eq!((x.decoded.target, x.decoded.fallthrough), (1, 1));
        assert_eq!(decode(RAX_MODE_32, &[0x66, 0xe8, 0, 0]).decoded.size, 4);
    }
    #[test]
    fn indirect_and_operands() {
        let x = decode(RAX_MODE_64, &[0x41, 0xff, 0xd3]);
        assert_eq!(x.decoded.flow, RAX_FLOW_INDIRECT_CALL);
        assert_eq!(&x.operands[0].reg[..4], b"r11\0");
        let x = decode(RAX_MODE_32, &[0xff, 0x54, 0x8b, 0xfc]);
        assert_eq!(x.decoded.size, 4);
        assert_eq!(
            (
                x.operands[0].kind,
                x.operands[0].address_bits,
                x.operands[0].scale
            ),
            (RAX_OPERAND_MEMORY, 32, 4)
        );
        assert_eq!(&x.operands[0].base[..4], b"ebx\0");
        assert_eq!(&x.operands[0].index[..4], b"ecx\0");
        let x = decode(RAX_MODE_64, &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(
            (x.operands[0].base[0], x.operands[0].displacement),
            (0, 0x1006)
        );
    }
    #[test]
    fn truncated_invalid_and_changed_bytes() {
        for data in [
            &[0xc2][..],
            &[0xe8, 0, 0, 0][..],
            &[0x0f][..],
            &[0x66; 15][..],
            &[0xf0, 0xc3][..],
        ] {
            assert_eq!(decode(RAX_MODE_64, data).decoded.valid, 0);
        }
        assert_eq!(decode(RAX_MODE_64, &[0x90]).decoded.size, 1);
        assert_eq!(decode(RAX_MODE_64, &[0xc3]).decoded.flow, RAX_FLOW_RETURN);
    }
    #[test]
    fn native_prefix_legality_and_complete_buffer_boundaries() {
        for mode in [RAX_MODE_16, RAX_MODE_32, RAX_MODE_64] {
            for count in 0..15 {
                let mut bytes = vec![0x2e; count];
                bytes.push(0xc3);
                let info = decode(mode, &bytes);
                assert_eq!(info.decoded.size as usize, count + 1);
                assert_eq!(info.decoded.flow, RAX_FLOW_RETURN);
                if count > 0 {
                    assert_eq!(decode(mode, &bytes[..count]).decoded.valid, 0);
                }
            }
        }
        for bytes in [
            &[0xd5, 0, 0xe8, 0, 0, 0, 0][..],
            &[0xf0, 0x90][..],
            &[0xf0, 0x01, 0xc0][..],
        ] {
            assert_eq!(decode(RAX_MODE_64, bytes).decoded.valid, 0);
        }
        assert_eq!(decode(RAX_MODE_64, &[0xf0, 0x01, 0x00]).decoded.size, 3);
        let absolute = decode(RAX_MODE_64, &[0xd5, 0, 0xa1, 0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            (
                absolute.decoded.size,
                absolute.decoded.target,
                absolute.decoded.flow
            ),
            (11, 0x100000000, RAX_FLOW_BRANCH)
        );
        let xchg = decode(RAX_MODE_64, &[0x48, 0x87, 0xc3]);
        assert!(
            xchg.operands
                .iter()
                .take(2)
                .all(|op| op.access == RAX_OPERAND_READ | RAX_OPERAND_WRITE)
        );
    }

    #[test]
    fn version_size_and_invalid_modes() {
        let b = [0xc3];
        let mut out = RaxInstructionInfo::default();
        out.struct_size = 8;
        assert_eq!(
            rax_instruction_info(1, 0, 0, b.as_ptr().cast(), 1, &mut out),
            RaxStatus::Arg
        );
        assert_eq!(out.struct_size, 8);
        out = RaxInstructionInfo::default();
        out.abi_version = 99;
        assert_eq!(
            rax_instruction_info(1, 0, 0, b.as_ptr().cast(), 1, &mut out),
            RaxStatus::Arg
        );
        out = RaxInstructionInfo::default();
        for mode in [
            RAX_MODE_16 | RAX_MODE_32,
            RAX_MODE_BIG_ENDIAN,
            RAX_MODE_THUMB,
            1 << 31,
        ] {
            assert_eq!(
                rax_instruction_info(1, mode, 0, b.as_ptr().cast(), 1, &mut out),
                RaxStatus::Mode
            );
        }
        assert_eq!(
            rax_instruction_info(2, 0, 0, b.as_ptr().cast(), 1, &mut out),
            RaxStatus::Arch
        );
        assert_eq!(
            rax_instruction_info(1, 0, 0, b.as_ptr().cast(), usize::MAX, &mut out),
            RaxStatus::Arg
        );
        assert_eq!(size_of::<RaxInstructionOperand>(), 96);
        assert_eq!(size_of::<RaxInstructionInfo>(), 576);
    }
}
