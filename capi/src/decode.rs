//! Static, stateless single-instruction decode (`rax_decode`).
//!
//! This is a pure disassembly of one instruction — no engine, no memory map,
//! no execution, no side effects. It wraps the engine's JSON decode oracle
//! [`rax_engine::isa_oracle::decode_to_json`] and projects the rich per-arch
//! JSON down to the small, ABI-stable [`RaxDecoded`] control-flow summary.
//!
//! The oracle emits a top-level `control_flow` object whose `kind` string is
//! the classification we map to `RAX_FLOW_*`. For x86-64 and AArch64 that object
//! comes from the SMIR lifter (`control_flow_json`); for AArch32/Thumb it comes
//! from `arm_control_flow`; for RISC-V from `riscv_control_flow`; for Hexagon
//! from the packet's aggregated effects. Targets are hex strings (`"0x1000"`).

use std::os::raw::{c_int, c_void};
use std::slice;

use serde_json::Value;

use rax_engine::config::Endianness;
use rax_engine::isa_oracle::{ArmState, OracleIsa, OracleOptions, decode_to_json};
use rax_engine::riscv::Xlen;
use rax_engine::smir::SourceArch;

use crate::arch::{RAX_MODE_BIG_ENDIAN, RAX_MODE_THUMB, RaxArch};
use crate::guard;
use crate::status::RaxStatus;

// Control-flow class of a decoded instruction. Mirrors `RAX_FLOW_*` in `rax.h`.
pub const RAX_FLOW_FALLTHROUGH: i32 = 0;
pub const RAX_FLOW_BRANCH: i32 = 1;
pub const RAX_FLOW_COND_BRANCH: i32 = 2;
pub const RAX_FLOW_INDIRECT_JUMP: i32 = 3;
pub const RAX_FLOW_CALL: i32 = 4;
pub const RAX_FLOW_INDIRECT_CALL: i32 = 5;
pub const RAX_FLOW_RETURN: i32 = 6;
pub const RAX_FLOW_TRAP: i32 = 7;
pub const RAX_FLOW_SYSCALL: i32 = 8;
pub const RAX_FLOW_UNKNOWN: i32 = 9;

/// Result of [`rax_decode`]. Mirrors `rax_decoded` in `rax.h` (C layout).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxDecoded {
    /// Instruction length in bytes (0 if `!valid`).
    pub size: u32,
    /// One of `RAX_FLOW_*`.
    pub flow: i32,
    /// 1 if the branch/call target is computed at runtime.
    pub is_indirect: u32,
    /// 1 if `target` holds a resolved direct target.
    pub has_target: u32,
    /// Absolute direct branch/call target (valid when `has_target`).
    pub target: u64,
    /// Not-taken address for a conditional branch.
    pub fallthrough: u64,
    /// 1 if the bytes decoded to a valid instruction.
    pub valid: u32,
    pub _reserved: u32,
}

impl RaxDecoded {
    pub(crate) fn zeroed() -> Self {
        RaxDecoded {
            size: 0,
            flow: RAX_FLOW_FALLTHROUGH,
            is_indirect: 0,
            has_target: 0,
            target: 0,
            fallthrough: 0,
            valid: 0,
            _reserved: 0,
        }
    }
}

/// Parses an oracle hex string like `"0x1000"` (also plain decimal) to `u64`.
fn parse_hexish(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Reads a hex-string field (e.g. `"target"`) from a control-flow object.
fn hex_field(cf: &Value, key: &str) -> Option<u64> {
    parse_hexish(cf.get(key)?)
}

/// Extracts a concrete/direct call target if the call carries one.
///
/// Two shapes occur: `arm_control_flow` / `riscv_control_flow` put the target
/// as a bare hex string on `control_flow.target`; the SMIR path nests a
/// `call_target_json` object there — `{"kind":"direct","addr":"0x.."}` for a
/// resolved guest address, otherwise indirect / a function id with no address.
fn call_direct_target(cf: &Value) -> Option<u64> {
    match cf.get("target") {
        Some(v @ Value::String(_)) => parse_hexish(v),
        Some(obj @ Value::Object(_)) => parse_hexish(obj.get("addr")?),
        _ => None,
    }
}

/// Instruction length from the oracle JSON. Prefers the SMIR lifter's
/// `bytes_consumed` (x86-64/AArch64/RISC-V/Hexagon), then the per-arch
/// `decoded_ops[0].size` (AArch32/Thumb/RISC-V), then a top-level `size`.
/// A size of 0 means "did not actually decode".
fn extract_size(value: &Value) -> u32 {
    if let Some(n) = value
        .get("smir")
        .and_then(|s| s.get("bytes_consumed"))
        .and_then(Value::as_u64)
    {
        if n > 0 {
            return n as u32;
        }
    }
    if let Some(n) = value
        .get("decoded_ops")
        .and_then(|d| d.get(0))
        .and_then(|o| o.get("size"))
        .and_then(Value::as_u64)
    {
        if n > 0 {
            return n as u32;
        }
    }
    if let Some(n) = value.get("size").and_then(Value::as_u64) {
        return n as u32;
    }
    0
}

/// Builds oracle options for an architecture and CPU mode.
pub(crate) fn oracle_options(arch: RaxArch, mode: u32, pc: u64) -> OracleOptions {
    let mut opts = OracleOptions::default();
    opts.pc = pc;
    opts.include_smir = true;
    let big_endian = mode & RAX_MODE_BIG_ENDIAN != 0;
    if big_endian {
        opts.hexagon_endian = Endianness::Big;
    } else {
        opts.hexagon_endian = Endianness::Little;
    }
    match arch {
        RaxArch::X86 => {
            opts.isa = OracleIsa::X86_64;
            opts.smir_source = SourceArch::X86_64;
        }
        RaxArch::Arm64 => {
            opts.isa = OracleIsa::Arm;
            opts.arm_state = ArmState::Aarch64;
            opts.smir_source = SourceArch::Aarch64;
        }
        RaxArch::Arm => {
            opts.isa = OracleIsa::Arm;
            opts.arm_state = if mode & RAX_MODE_THUMB != 0 {
                ArmState::Thumb
            } else {
                ArmState::Aarch32
            };
        }
        RaxArch::CortexM => {
            // Cortex-M is Thumb-only.
            opts.isa = OracleIsa::Arm;
            opts.arm_state = ArmState::Thumb;
        }
        RaxArch::Riscv64 => {
            opts.isa = OracleIsa::RiscV;
            opts.riscv_xlen = Xlen::Rv64;
            opts.smir_source = SourceArch::RiscV64;
        }
        RaxArch::Hexagon => {
            opts.isa = OracleIsa::Hexagon;
            opts.smir_source = SourceArch::Hexagon;
        }
    }
    opts
}

/// Maps a decoded oracle JSON value into the caller's [`RaxDecoded`].
pub(crate) fn fill_from_json(value: &Value, out: &mut RaxDecoded) {
    let size = extract_size(value);
    if size == 0 {
        // The bytes did not decode to a valid instruction.
        *out = RaxDecoded::zeroed();
        return;
    }
    out.size = size;
    out.valid = 1;

    let empty = Value::Null;
    let cf = value.get("control_flow").unwrap_or(&empty);
    let kind = cf.get("kind").and_then(Value::as_str).unwrap_or("unknown");

    match kind {
        "fallthrough" | "next_insn" => out.flow = RAX_FLOW_FALLTHROUGH,
        "branch" | "direct_branch" => {
            out.flow = RAX_FLOW_BRANCH;
            if let Some(t) = hex_field(cf, "target") {
                out.target = t;
                out.has_target = 1;
            }
        }
        "cond_branch" | "cond_branch_reg" => {
            out.flow = RAX_FLOW_COND_BRANCH;
            if let Some(t) = hex_field(cf, "target") {
                out.target = t;
                out.has_target = 1;
            }
            if let Some(f) = hex_field(cf, "fallthrough") {
                out.fallthrough = f;
            }
        }
        "indirect_branch" | "indirect_branch_mem" | "cond_indirect_branch" => {
            out.flow = RAX_FLOW_INDIRECT_JUMP;
            out.is_indirect = 1;
        }
        "call" | "cond_call" => {
            if let Some(t) = call_direct_target(cf) {
                out.flow = RAX_FLOW_CALL;
                out.target = t;
                out.has_target = 1;
            } else {
                out.flow = RAX_FLOW_INDIRECT_CALL;
                out.is_indirect = 1;
            }
        }
        "indirect_call" | "cond_indirect_call" => {
            out.flow = RAX_FLOW_INDIRECT_CALL;
            out.is_indirect = 1;
        }
        "return" | "cond_return" => out.flow = RAX_FLOW_RETURN,
        "trap" | "undefined" => out.flow = RAX_FLOW_TRAP,
        "syscall" => out.flow = RAX_FLOW_SYSCALL,
        // "unknown", "halt", "loop_setup", "packet_multi", ...
        _ => out.flow = RAX_FLOW_UNKNOWN,
    }
}

// ===========================================================================
// FFI: static decode
// ===========================================================================

/// Decodes ONE instruction at virtual address `pc` from `bytes[0..len)` for
/// `arch`/`mode` (same values as `rax_engine_open`), filling `*out`.
///
/// Returns `RAX_OK` when the call is well-formed — inspect `out->valid` to see
/// whether the bytes actually decoded (an undecodable or truncated instruction
/// yields `RAX_OK` with `out->valid == 0`). Returns `RAX_ERR_ARG` for a NULL
/// `out`/`bytes` or `len == 0`, and `RAX_ERR_ARCH` for an unsupported arch.
#[unsafe(no_mangle)]
pub extern "C" fn rax_decode(
    arch: c_int,
    mode: u32,
    pc: u64,
    bytes: *const c_void,
    len: usize,
    out: *mut RaxDecoded,
) -> RaxStatus {
    guard(|| {
        if out.is_null() {
            return RaxStatus::Arg;
        }
        // Establish a defined output before any fallible work.
        unsafe {
            *out = RaxDecoded::zeroed();
        }
        // Rust slices require a length no greater than isize::MAX even for a
        // non-NULL C pointer. Reject it before from_raw_parts so malformed FFI
        // input cannot create an invalid slice.
        if bytes.is_null() || len == 0 || len > isize::MAX as usize {
            return RaxStatus::Arg;
        }
        let arch = match RaxArch::from_i32(arch) {
            Some(a) => a,
            None => return RaxStatus::Arch,
        };

        let slice = unsafe { slice::from_raw_parts(bytes as *const u8, len) };
        if arch == RaxArch::X86 {
            let Some(bits) = crate::instruction_info::bitness(mode) else {
                return RaxStatus::Mode;
            };
            let info = crate::instruction_info::decode_x86(bits, pc, &slice[..slice.len().min(15)]);
            // SAFETY: caller supplied a writable RaxDecoded, validated above.
            unsafe {
                *out = info.decoded;
            }
            return RaxStatus::Ok;
        }
        let opts = oracle_options(arch, mode, pc);

        match decode_to_json(slice, &opts) {
            Ok(value) => {
                let mut d = RaxDecoded::zeroed();
                fill_from_json(&value, &mut d);
                unsafe {
                    *out = d;
                }
                RaxStatus::Ok
            }
            Err(_) => {
                // Undecodable / truncated: well-formed call, invalid bytes.
                RaxStatus::Ok
            }
        }
    })
}
