//! rax_decode — static, stateless single-instruction decode (since API 1.2)
//!
//! These exercise the extern "C" rax_decode entry point directly with the same
//! raw-pointer discipline a C caller uses, covering x86-64, AArch64, AArch32
//! (ARM + Thumb) control-flow classification plus argument validation.

use std::os::raw::c_void;
use std::ptr;

use crate::arch::{
    RAX_MODE_16, RAX_MODE_32, RAX_MODE_64, RAX_MODE_ARM, RAX_MODE_THUMB, RAX_MODE_USER, RaxArch,
};
use crate::decode::{
    RAX_FLOW_BRANCH, RAX_FLOW_CALL, RAX_FLOW_COND_BRANCH, RAX_FLOW_FALLTHROUGH,
    RAX_FLOW_INDIRECT_CALL, RAX_FLOW_INDIRECT_JUMP, RAX_FLOW_RETURN, RaxDecoded, rax_decode,
};
use crate::status::RaxStatus;

const X86: i32 = RaxArch::X86 as i32;
const ARM64: i32 = RaxArch::Arm64 as i32;
const ARM: i32 = RaxArch::Arm as i32;

/// A sentinel `RaxDecoded` whose fields are all non-default, so a successful
/// decode must overwrite every field (catches "left untouched" bugs).
fn sentinel() -> RaxDecoded {
    RaxDecoded {
        size: 0xDEAD,
        flow: -1,
        is_indirect: 0xDEAD,
        has_target: 0xDEAD,
        target: 0xDEAD_BEEF,
        fallthrough: 0xDEAD_BEEF,
        valid: 0xDEAD,
        _reserved: 0,
    }
}

/// Decode `bytes` and assert the call itself is well-formed (RAX_OK).
fn decode(arch: i32, mode: u32, pc: u64, bytes: &[u8]) -> RaxDecoded {
    let mut out = sentinel();
    let st = rax_decode(
        arch,
        mode,
        pc,
        bytes.as_ptr() as *const c_void,
        bytes.len(),
        &mut out,
    );
    assert_eq!(st, RaxStatus::Ok, "rax_decode error for {:02x?}", bytes);
    out
}

// ---- x86 16- and 32-bit code (since API 1.5) ----------------------------

#[test]
fn x86_legacy_modes_decode_their_own_encodings() {
    // 40 90: `inc eax ; nop` in 32-bit code, `rex nop` (2 bytes) in 64-bit.
    for mode in [RAX_MODE_32, RAX_MODE_16, RAX_MODE_32 | RAX_MODE_USER] {
        let d = decode(X86, mode, 0x1000, &[0x40, 0x90]);
        assert_eq!(
            (d.valid, d.size, d.flow),
            (1, 1, RAX_FLOW_FALLTHROUGH),
            "mode {mode:#x}"
        );
    }
    assert_eq!(decode(X86, RAX_MODE_64, 0x1000, &[0x40, 0x90]).size, 2);
    // mov ax, imm16 in 16-bit code; mov eax, imm32 in 32-bit code.
    let code = [0xB8, 0x34, 0x12, 0x00, 0x00, 0x90];
    assert_eq!(decode(X86, RAX_MODE_16, 0, &code).size, 3);
    assert_eq!(decode(X86, RAX_MODE_32, 0, &code).size, 5);
}

#[test]
fn x86_legacy_branches_wrap_to_the_operand_size() {
    // jne rel16 in 16-bit code at IP 0xFFF0: 4 bytes, target mod 2^16.
    let d = decode(X86, RAX_MODE_16, 0xFFF0, &[0x0F, 0x85, 0x20, 0x00]);
    assert_eq!((d.size, d.flow), (4, RAX_FLOW_COND_BRANCH));
    assert_eq!((d.target, d.fallthrough), (0x0014, 0xFFF4));
    // Far jumps have no static linear target.
    let d = decode(X86, RAX_MODE_16, 0, &[0xEA, 0xF0, 0xFF, 0x00, 0xF0]);
    assert_eq!(
        (d.size, d.flow, d.has_target),
        (5, RAX_FLOW_INDIRECT_JUMP, 0)
    );
    // call rel32 in 32-bit code.
    let d = decode(X86, RAX_MODE_32, 0x1000, &[0xE8, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!((d.size, d.flow, d.target), (5, RAX_FLOW_CALL, 0x1105));
}

// ---- x86-64 (arch=1, mode=64, pc=0x1000) ------------------------------

#[test]
fn x86_call_rel32() {
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0xE8, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 5);
    assert_eq!(d.flow, RAX_FLOW_CALL);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
    assert_eq!(d.target, 0x1005);
}

#[test]
fn x86_indirect_call() {
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0xFF, 0xD0]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 2);
    assert_eq!(d.flow, RAX_FLOW_INDIRECT_CALL);
    assert_eq!(d.is_indirect, 1);
    assert_eq!(d.has_target, 0);
}

#[test]
fn x86_direct_jmp() {
    // EB FE: jmp .-2 => back to the start of this 2-byte instruction.
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0xEB, 0xFE]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 2);
    assert_eq!(d.flow, RAX_FLOW_BRANCH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
    assert_eq!(d.target, 0x1000);
}

#[test]
fn x86_cond_branch() {
    // 74 05: je .+5 (from end of 2-byte insn) => 0x1007; fallthrough 0x1002.
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0x74, 0x05]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 2);
    assert_eq!(d.flow, RAX_FLOW_COND_BRANCH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
    assert_eq!(d.target, 0x1007);
    assert_eq!(d.fallthrough, 0x1002);
}

#[test]
fn x86_ret() {
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0xC3]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 1);
    assert_eq!(d.flow, RAX_FLOW_RETURN);
}

#[test]
fn x86_indirect_jmp() {
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0xFF, 0xE0]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 2);
    assert_eq!(d.flow, RAX_FLOW_INDIRECT_JUMP);
    assert_eq!(d.is_indirect, 1);
    assert_eq!(d.has_target, 0);
}

#[test]
fn x86_nop_fallthrough() {
    let d = decode(X86, RAX_MODE_64, 0x1000, &[0x90]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 1);
    assert_eq!(d.flow, RAX_FLOW_FALLTHROUGH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 0);
}

// ---- AArch64 (arch=2, mode=little, pc=0x1000) -------------------------

#[test]
fn arm64_bl() {
    // bl #0 (00 00 00 94) => direct call to pc + 0 = 0x1000.
    let d = decode(ARM64, 0, 0x1000, &[0x00, 0x00, 0x00, 0x94]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_CALL);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
    assert_eq!(d.target, 0x1000);
}

#[test]
fn arm64_blr() {
    // blr x0 (00 00 3F D6) => indirect call.
    let d = decode(ARM64, 0, 0x1000, &[0x00, 0x00, 0x3F, 0xD6]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_INDIRECT_CALL);
    assert_eq!(d.is_indirect, 1);
    assert_eq!(d.has_target, 0);
}

#[test]
fn arm64_ret() {
    // ret (C0 03 5F D6).
    let d = decode(ARM64, 0, 0x1000, &[0xC0, 0x03, 0x5F, 0xD6]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_RETURN);
}

#[test]
fn arm64_b() {
    // b #0 (00 00 00 14) => unconditional branch to pc + 0 = 0x1000.
    let d = decode(ARM64, 0, 0x1000, &[0x00, 0x00, 0x00, 0x14]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_BRANCH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
    assert_eq!(d.target, 0x1000);
}

#[test]
fn arm64_nop() {
    // nop (1F 20 03 D5).
    let d = decode(ARM64, 0, 0x1000, &[0x1F, 0x20, 0x03, 0xD5]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_FALLTHROUGH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 0);
}

// ---- AArch32 (arch=3) — viy now relies on arch=3 decoding -------------

#[test]
fn arm32_arm_bl() {
    // ARM state BL #imm (0xEB000000, little-endian bytes 00 00 00 EB):
    // a direct, resolvable call. Target math (PC pipeline offset) is not
    // asserted exactly; the class + direct-vs-indirect is what matters.
    let d = decode(ARM, RAX_MODE_ARM, 0x1000, &[0x00, 0x00, 0x00, 0xEB]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_CALL);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
}

#[test]
fn arm32_arm_b() {
    // ARM state B #imm (0xEA000000, little-endian bytes 00 00 00 EA):
    // an unconditional, resolvable direct branch.
    let d = decode(ARM, RAX_MODE_ARM, 0x1000, &[0x00, 0x00, 0x00, 0xEA]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_BRANCH);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
}

#[test]
fn arm32_thumb_bl() {
    // Thumb-2 BL (32-bit): halfwords F000 F800 => bytes 00 F0 00 F8.
    // A direct, resolvable call; assert the class + direct target.
    let d = decode(ARM, RAX_MODE_THUMB, 0x1000, &[0x00, 0xF0, 0x00, 0xF8]);
    assert_eq!(d.valid, 1);
    assert_eq!(d.size, 4);
    assert_eq!(d.flow, RAX_FLOW_CALL);
    assert_eq!(d.is_indirect, 0);
    assert_eq!(d.has_target, 1);
}

// ---- Argument validation & truncation ---------------------------------

#[test]
fn null_out_rejected() {
    let bytes = [0x90u8];
    let st = rax_decode(
        X86,
        RAX_MODE_64,
        0x1000,
        bytes.as_ptr() as *const c_void,
        bytes.len(),
        ptr::null_mut(),
    );
    assert_eq!(st, RaxStatus::Arg);
}

#[test]
fn null_bytes_rejected() {
    let mut out = sentinel();
    let st = rax_decode(X86, RAX_MODE_64, 0x1000, ptr::null(), 4, &mut out);
    assert_eq!(st, RaxStatus::Arg);
    // A defined (invalid) output is still established.
    assert_eq!(out.valid, 0);
}

#[test]
fn zero_len_rejected() {
    let bytes = [0x90u8];
    let mut out = sentinel();
    let st = rax_decode(
        X86,
        RAX_MODE_64,
        0x1000,
        bytes.as_ptr() as *const c_void,
        0,
        &mut out,
    );
    assert_eq!(st, RaxStatus::Arg);
    assert_eq!(out.valid, 0);
}

#[test]
fn impossible_slice_length_rejected_before_dereference() {
    let bytes = [0x90u8];
    let mut out = sentinel();
    let st = rax_decode(
        X86,
        RAX_MODE_64,
        0x1000,
        bytes.as_ptr().cast::<c_void>(),
        usize::MAX,
        &mut out,
    );
    assert_eq!(st, RaxStatus::Arg);
    assert_eq!(out.valid, 0);
}

#[test]
fn bad_arch_rejected() {
    let bytes = [0x90u8];
    let mut out = sentinel();
    let st = rax_decode(
        99,
        RAX_MODE_64,
        0x1000,
        bytes.as_ptr() as *const c_void,
        bytes.len(),
        &mut out,
    );
    assert_eq!(st, RaxStatus::Arch);
}

#[test]
fn truncated_arm64_is_ok_but_invalid() {
    // Only 2 of the 4 bytes of an AArch64 instruction: well-formed call,
    // but the bytes do not decode.
    let d = decode(ARM64, 0, 0x1000, &[0x00, 0x00]);
    assert_eq!(d.valid, 0);
    assert_eq!(d.size, 0);
}
