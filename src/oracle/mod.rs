//! JSON oracle harness for ISA-specific decoders and SMIR lifters.

mod address;
mod call_target;
mod x86_fma;
mod x86_frame;
mod x86_legacy;
mod x86_opmask;

pub use x86_legacy::X86CodeSize;

use call_target::call_target_json;

use serde_json::{Map, Value, json};

use crate::config::{Endianness, HexagonIsa};
use crate::isa::arm::ExecutionState;
use crate::isa::arm::decoder::{Decoder as ArmDecoder, Mnemonic, Operand};
use crate::isa::hexagon::decode::{self as hex_decode, DecodedInsn as HexInsn};
use crate::isa::hexagon::opcode as hex_opcode;
use crate::isa::riscv::decode as rv_decode;
use crate::isa::riscv::{Isa as RvIsa, Op as RvOp, Xlen};
use crate::smir::ir::ops::ArmDpRegShiftKind;
use crate::smir::ir::ops::HexFpOp;
use crate::smir::ir::ops::HexFpRecipKind;
use crate::smir::ir::ops::X86AdxKind;
use crate::smir::ir::ops::X86BlsKind;
use crate::smir::ir::ops::X86CacheControlKind;
use crate::smir::ir::ops::X86CmpxchgOp;
use crate::smir::ir::ops::X86ControlReg;
use crate::smir::ir::ops::X86CountKind;
use crate::smir::ir::ops::X86DebugReg;
use crate::smir::ir::ops::X86DescriptorTable;
use crate::smir::ir::ops::X86DescriptorTableLoadOp;
use crate::smir::ir::ops::X86DescriptorTableStoreOp;
use crate::smir::ir::ops::X86GprOperand;
use crate::smir::ir::ops::X86InvlpgOp;
use crate::smir::ir::ops::X86InvpcidOp;
use crate::smir::ir::ops::X86LmswOp;
use crate::smir::ir::ops::X86LmswSource;
use crate::smir::ir::ops::X86MonitorMwaitOp;
use crate::smir::ir::ops::X86MsrOp;
use crate::smir::ir::ops::X86PackedStringKind;
use crate::smir::ir::ops::X86ReadPmcOp;
use crate::smir::ir::ops::X86ReadTscOp;
use crate::smir::ir::ops::X86SatFpFormat;
use crate::smir::ir::ops::X86SelectorQueryKind;
use crate::smir::ir::ops::X86SelectorQueryOp;
use crate::smir::ir::ops::X86SelectorQuerySource;
use crate::smir::ir::ops::X86SelectorVerifyKind;
use crate::smir::ir::ops::X86SelectorVerifyOp;
use crate::smir::ir::ops::X86SelectorVerifySource;
use crate::smir::ir::ops::X86Sha32Op;
use crate::smir::ir::ops::X86SmswOp;
use crate::smir::ir::ops::X86SmswTarget;
use crate::smir::ir::ops::X86Sse4aBitfieldKind;
use crate::smir::ir::ops::X86StackFlagsKind;
use crate::smir::ir::ops::X86SystemSelector;
use crate::smir::ir::ops::X86SystemSelectorLoadOp;
use crate::smir::ir::ops::X86SystemSelectorSource;
use crate::smir::ir::ops::X86SystemSelectorStoreOp;
use crate::smir::ir::ops::X86SystemSelectorTarget;
use crate::smir::ir::ops::X86TbmKind;
use crate::smir::ir::ops::X86ThreeDNowKind;
use crate::smir::ir::ops::X86WaitPkgOp;
use crate::smir::ir::ops::X86X87CompareSource;
use crate::smir::ir::ops::X86X87Constant;
use crate::smir::ir::ops::X86X87ControlKind;
use crate::smir::ir::ops::X86X87DataKind;
use crate::smir::ir::ops::X86X87EnvWidth;
use crate::smir::ir::ops::X86X87FloatWidth;
use crate::smir::ir::ops::X86X87IntWidth;
use crate::smir::ir::ops::X86XSaveKind;
use crate::smir::ir::ops::X86XaddOp;
use crate::smir::ir::ops::X86XopPackedBitKind;
use crate::smir::ir::ops::{
    X86FarCallOp, X86FarJumpOp, X86FarReturnOp, X86FastSystemTransferKind, X86FastSystemTransferOp,
};
use crate::smir::ir::types::DispSize;
use crate::smir::ir::types::X86AesOp;
use crate::smir::lift::riscv::RiscVExtensions;
use crate::smir::{
    Aarch64Lifter, Address, ArchReg, ArmReg, AtomicOp, Avx10FP16Op, BlockId, CallTarget, Condition,
    ControlFlow, ExtendOp, FenceKind, FlagSet, FlagUpdate, FlatMemory, FpPrecision, FpRoundMode,
    HexagonLifter, HexagonReg, LiftContext, MemWidth, MemoryOrder, OpId, OpKind, OpWidth,
    RiscVLifter, RiscVReg, ShiftOp, SignExtend, SmirBlock, SmirContext, SmirInterpreter,
    SmirLifter, SmirMemory, SmirOp, SourceArch, SrcOperand, Terminator, TrapKind, VLaneOp, VReg,
    VShiftVKind, VecCmpCond, VecElementType, VecPermuteKind, VecReduceOp, VecUnaryOp, VecWidth,
    X86_64Lifter, X86FmaKind, X86FmaOrder, X86FpBinaryOp, X86NarrowMode, X86Reg,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleIsa {
    X86_64,
    Arm,
    Hexagon,
    RiscV,
    Smir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmState {
    Aarch64,
    Aarch32,
    Thumb,
}

impl ArmState {
    pub fn execution_state(self) -> ExecutionState {
        match self {
            ArmState::Aarch64 => ExecutionState::Aarch64,
            ArmState::Aarch32 => ExecutionState::Aarch32,
            ArmState::Thumb => ExecutionState::Thumb,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscVIsaProfile {
    Rv64Gc,
    Rv64I,
    Rv64Imac,
}

impl RiscVIsaProfile {
    pub fn isa(self) -> RvIsa {
        match self {
            RiscVIsaProfile::Rv64Gc => RvIsa::rv64gc(),
            RiscVIsaProfile::Rv64I => RvIsa::rv_i(),
            RiscVIsaProfile::Rv64Imac => RvIsa::imac(),
        }
    }
}

fn riscv_extensions(profile: RiscVIsaProfile) -> RiscVExtensions {
    match profile {
        RiscVIsaProfile::Rv64Gc => RiscVExtensions::rv64gc(),
        RiscVIsaProfile::Rv64I => RiscVExtensions::rv64i(),
        RiscVIsaProfile::Rv64Imac => RiscVExtensions::rv64imac(),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OracleOptions {
    pub isa: OracleIsa,
    pub pc: u64,
    pub arm_state: ArmState,
    pub hexagon_isa: HexagonIsa,
    pub hexagon_endian: Endianness,
    pub riscv_xlen: Xlen,
    pub riscv_isa: RiscVIsaProfile,
    pub smir_source: SourceArch,
    pub include_smir: bool,
    /// The code size of [`OracleIsa::X86_64`] input. The SMIR lifter and
    /// the side-effect summaries model 64-bit code only; 16- and 32-bit code
    /// is decoded for length and control flow.
    pub x86_code_size: X86CodeSize,
}

impl Default for OracleOptions {
    fn default() -> Self {
        OracleOptions {
            isa: OracleIsa::Hexagon,
            pc: 0x1000,
            arm_state: ArmState::Aarch64,
            hexagon_isa: HexagonIsa::V68,
            hexagon_endian: Endianness::Little,
            riscv_xlen: Xlen::Rv64,
            riscv_isa: RiscVIsaProfile::Rv64Gc,
            smir_source: SourceArch::X86_64,
            include_smir: true,
            x86_code_size: X86CodeSize::Bits64,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OracleSeed {
    pub regs: Vec<(String, u64)>,
    pub memory: Vec<OracleMemorySeed>,
    pub memory_size: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct OracleMemorySeed {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

pub const MAX_ORACLE_SEED_MEMORY_SIZE: usize = 16 * 1024 * 1024;

impl OracleSeed {
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let mut seed = OracleSeed::default();

        if let Some(size) = value.get("memory_size") {
            let size = json_usize(size, "memory_size")?;
            validate_seed_memory_size(size, "seed.memory_size")?;
            seed.memory_size = Some(size);
        }

        if let Some(regs) = value.get("regs") {
            let regs = regs
                .as_object()
                .ok_or_else(|| "seed.regs must be a JSON object".to_string())?;
            for (name, raw) in regs {
                seed.regs.push((name.clone(), json_u64(raw, name)?));
            }
        }

        if let Some(memory) = value.get("memory") {
            let memory = memory
                .as_array()
                .ok_or_else(|| "seed.memory must be an array".to_string())?;
            for (idx, item) in memory.iter().enumerate() {
                let obj = item
                    .as_object()
                    .ok_or_else(|| format!("seed.memory[{idx}] must be an object"))?;
                let addr = obj
                    .get("addr")
                    .ok_or_else(|| format!("seed.memory[{idx}].addr is required"))
                    .and_then(|v| json_u64(v, "addr"))?;
                let bytes = if let Some(hex) = obj.get("hex") {
                    parse_hex_bytes(
                        hex.as_str()
                            .ok_or_else(|| format!("seed.memory[{idx}].hex must be a string"))?,
                    )?
                } else if let Some(bytes) = obj.get("bytes") {
                    let arr = bytes
                        .as_array()
                        .ok_or_else(|| format!("seed.memory[{idx}].bytes must be an array"))?;
                    let mut out = Vec::with_capacity(arr.len());
                    for (byte_idx, byte) in arr.iter().enumerate() {
                        let value = json_u64(byte, "byte")?;
                        if value > u8::MAX as u64 {
                            return Err(format!(
                                "seed.memory[{idx}].bytes[{byte_idx}] is larger than 0xff"
                            ));
                        }
                        out.push(value as u8);
                    }
                    out
                } else {
                    return Err(format!(
                        "seed.memory[{idx}] needs either a hex string or bytes array"
                    ));
                };
                seed.memory.push(OracleMemorySeed { addr, bytes });
            }
        }

        Ok(seed)
    }
}

pub fn decode_to_json(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    decode_to_json_with_seed(bytes, opts, None)
}

pub fn decode_to_json_with_seed(
    bytes: &[u8],
    opts: &OracleOptions,
    seed: Option<&OracleSeed>,
) -> Result<Value, String> {
    let mut value = decode_to_json_no_seed(bytes, opts)?;
    if let Some(seed) = seed {
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "side_effects".to_string(),
                smir_side_effects(bytes, opts, seed),
            );
        }
    }
    Ok(value)
}

fn decode_to_json_no_seed(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    match opts.isa {
        OracleIsa::X86_64 => decode_x86(bytes, opts),
        OracleIsa::Arm => decode_arm(bytes, opts),
        OracleIsa::Hexagon => decode_hexagon_packet(bytes, opts),
        OracleIsa::RiscV => decode_riscv(bytes, opts),
        OracleIsa::Smir => Ok(decode_smir_only(bytes, opts)),
    }
}

pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let mut hex = String::new();
    for ch in input.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch);
        } else if ch == 'x' || ch == 'X' {
            if !hex.ends_with('0') {
                return Err(format!("unexpected '{ch}' in byte string"));
            }
            hex.pop();
        } else if ch.is_ascii_whitespace() || matches!(ch, '_' | ',' | ':' | '-') {
            continue;
        } else {
            return Err(format!("unexpected '{ch}' in byte string"));
        }
    }

    if hex.len() % 2 != 0 {
        return Err("hex byte string has an odd number of digits".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for idx in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16)
            .map_err(|e| format!("invalid hex byte at offset {idx}: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn json_u64(value: &Value, field: &str) -> Result<u64, String> {
    if let Some(raw) = value.as_u64() {
        return Ok(raw);
    }
    if let Some(raw) = value.as_i64() {
        if raw >= 0 {
            return Ok(raw as u64);
        }
    }
    if let Some(raw) = value.as_bool() {
        return Ok(u64::from(raw));
    }
    let Some(raw) = value.as_str() else {
        return Err(format!("{field} must be a number, boolean, or string"));
    };
    parse_u64ish(raw).map_err(|e| format!("{field}: {e}"))
}

fn json_usize(value: &Value, field: &str) -> Result<usize, String> {
    let raw = json_u64(value, field)?;
    usize::try_from(raw).map_err(|_| format!("{field} is too large for this host"))
}

fn parse_u64ish(raw: &str) -> Result<u64, String> {
    let s = raw.trim().replace('_', "");
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn decode_x86(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    match opts.x86_code_size {
        X86CodeSize::Bits64 => Ok(decode_x86_64(bytes, opts)),
        size => x86_legacy::decode_json(
            bytes,
            opts.pc,
            size,
            input_json(bytes),
            side_effects_not_run(),
        ),
    }
}

fn decode_x86_64(bytes: &[u8], opts: &OracleOptions) -> Value {
    let prefix = decode_x86_prefix_metadata(bytes);
    let smir = if opts.include_smir {
        lift_smir(SourceArch::X86_64, bytes, opts)
    } else {
        json!({"available": false, "reason": "disabled"})
    };
    let control_flow = smir
        .get("control_flow")
        .cloned()
        .unwrap_or_else(|| json!({"kind": "unknown"}));

    json!({
        "isa": "x86_64",
        "pc": hex_u64(opts.pc),
        "input": input_json(bytes),
        "decoded_ops": [prefix],
        "packet_flags": null,
        "control_flow": control_flow,
        "smir": smir,
        "side_effects": side_effects_not_run(),
    })
}

fn decode_arm(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    let state = opts.arm_state.execution_state();
    let decoder = ArmDecoder::new(state);
    let insn = decoder.decode(bytes).map_err(|e| e.to_string())?;
    let control_flow = arm_control_flow(&insn, opts.pc);
    let smir = if opts.include_smir && opts.arm_state == ArmState::Aarch64 {
        lift_smir(SourceArch::Aarch64, bytes, opts)
    } else {
        json!({
            "available": false,
            "reason": if opts.arm_state == ArmState::Aarch64 { "disabled" } else { "no_smir_lifter_for_arm_state" },
        })
    };

    Ok(json!({
        "isa": "arm",
        "arm_state": format!("{:?}", opts.arm_state).to_lowercase(),
        "pc": hex_u64(opts.pc),
        "input": input_json(bytes),
        "decoded_ops": [{
            "offset": 0,
            "size": insn.size,
            "raw": hex_u32(insn.raw),
            "mnemonic": insn.mnemonic.to_string(),
            "condition": insn.cond.map(|cond| format!("{:?}", cond)),
            "sets_flags": insn.sets_flags,
            "operands": insn.operands.iter().map(|op| format!("{op:?}")).collect::<Vec<_>>(),
            "debug": format!("{insn:?}"),
        }],
        "packet_flags": null,
        "control_flow": control_flow,
        "smir": smir,
        "side_effects": side_effects_not_run(),
    }))
}

fn decode_riscv(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    if bytes.len() < 2 {
        return Err("RISC-V decode needs at least 2 bytes".to_string());
    }

    let isa = opts.riscv_isa.isa();
    let compressed = bytes[0] & 0x03 != 0x03;
    let insn = if compressed {
        let half = u16::from_le_bytes([bytes[0], bytes[1]]);
        rv_decode::decode_compressed(half, opts.riscv_xlen, &isa)
    } else {
        if bytes.len() < 4 {
            return Err("RISC-V 32-bit instruction needs 4 bytes".to_string());
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        rv_decode::decode(word, opts.riscv_xlen, &isa)
    };
    let consumed = insn.len as usize;
    let control_flow = riscv_control_flow(&insn, opts.pc);
    let smir_source = match opts.riscv_xlen {
        Xlen::Rv32 => SourceArch::RiscV32,
        Xlen::Rv64 => SourceArch::RiscV64,
    };
    let smir = if opts.include_smir {
        lift_smir(smir_source, &bytes[..bytes.len().min(consumed)], opts)
    } else {
        json!({"available": false, "reason": "disabled"})
    };

    Ok(json!({
        "isa": "riscv",
        "xlen": opts.riscv_xlen.bits(),
        "pc": hex_u64(opts.pc),
        "input": input_json(bytes),
        "decoded_ops": [{
            "offset": 0,
            "size": insn.len,
            "raw": hex_u32(insn.raw),
            "op": format!("{:?}", insn.op),
            "disasm": insn.to_string(),
            "rd": insn.rd,
            "rs1": insn.rs1,
            "rs2": insn.rs2,
            "rs3": insn.rs3,
            "imm": insn.imm,
            "funct3": insn.funct3,
            "csr": insn.csr,
            "aq": insn.aq,
            "rl": insn.rl,
            "illegal": insn.is_illegal(),
            "debug": format!("{insn:?}"),
        }],
        "packet_flags": null,
        "control_flow": control_flow,
        "smir": smir,
        "side_effects": side_effects_not_run(),
    }))
}

fn decode_hexagon_packet(bytes: &[u8], opts: &OracleOptions) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err("Hexagon packet bytes must be a non-empty multiple of 4".to_string());
    }

    let mut decoded_ops = Vec::new();
    let mut control_effects = Vec::new();
    let mut parse_bits = Vec::new();
    let mut warnings = Vec::new();
    let mut immext = None;
    let mut first_parse = None;
    let mut second_parse = None;
    let mut has_duplex = false;
    let mut end_seen = false;
    let mut consumed_words = 0usize;

    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = word_from_bytes(chunk, opts.hexagon_endian);
        let parse = (word >> 14) & 0x3;
        parse_bits.push(parse);
        if idx == 0 {
            first_parse = Some(parse);
        } else if idx == 1 {
            second_parse = Some(parse);
        }

        let word_pc = opts.pc.wrapping_add((idx * 4) as u64);
        consumed_words = idx + 1;

        if parse == 0 {
            has_duplex = true;
            match hex_decode::decode_duplex(word, opts.hexagon_isa) {
                Some((slot1, slot0)) => {
                    for (slot, sub) in [(1u8, slot1), (0u8, slot0)] {
                        let cf = hex_control_flow(&sub.insn, word_pc, opts.pc, false);
                        if !is_fallthrough(&cf) {
                            control_effects.push(cf.clone());
                        }
                        decoded_ops.push(json!({
                            "offset": idx * 4,
                            "pc": hex_u64(word_pc),
                            "word": hex_u32(word),
                            "parse_bits": parse,
                            "duplex_slot": slot,
                            "opcode": sub.opcode.map(hex_opcode::opcode_name),
                            "op": format!("{:?}", sub.insn),
                            "control_flow": cf,
                        }));
                    }
                }
                None => {
                    decoded_ops.push(json!({
                        "offset": idx * 4,
                        "pc": hex_u64(word_pc),
                        "word": hex_u32(word),
                        "parse_bits": parse,
                        "error": "unknown_duplex",
                    }));
                }
            }
            end_seen = true;
            if consumed_words * 4 != bytes.len() {
                warnings.push("bytes_after_packet_end");
            }
            break;
        }

        let decoded = hex_decode::decode(word, immext, opts.hexagon_isa);
        let fields = hex_fields(word);
        let cf = hex_control_flow(&decoded.insn, word_pc, opts.pc, decoded.used_ext);
        if !is_fallthrough(&cf) {
            control_effects.push(cf.clone());
        }
        decoded_ops.push(json!({
            "offset": idx * 4,
            "pc": hex_u64(word_pc),
            "word": hex_u32(word),
            "parse_bits": parse,
            "opcode": decoded.opcode.map(hex_opcode::opcode_name),
            "op": format!("{:?}", decoded.insn),
            "used_ext": decoded.used_ext,
            "fields": fields,
            "control_flow": cf,
        }));

        immext = match decoded.insn {
            HexInsn::ImmExt { value } => Some(value),
            _ => None,
        };

        if parse == 0x3 {
            end_seen = true;
            if consumed_words * 4 != bytes.len() {
                warnings.push("bytes_after_packet_end");
            }
            break;
        }
    }

    let loop0_end = matches!((first_parse, second_parse), (Some(first), Some(second)) if first == 0b10 && second != 0);
    let loop1_end = matches!((first_parse, second_parse), (Some(first), Some(second)) if second == 0b10 && first != 0);
    let smir = if opts.include_smir {
        lift_smir(SourceArch::Hexagon, &bytes[..consumed_words * 4], opts)
    } else {
        json!({"available": false, "reason": "disabled"})
    };

    Ok(json!({
        "isa": "hexagon",
        "hexagon_isa": format!("{:?}", opts.hexagon_isa),
        "endian": format!("{:?}", opts.hexagon_endian).to_lowercase(),
        "pc": hex_u64(opts.pc),
        "input": input_json(bytes),
        "decoded_ops": decoded_ops,
        "packet_flags": {
            "word_count": consumed_words,
            "parse_bits": parse_bits,
            "end_seen": end_seen,
            "complete": end_seen && consumed_words * 4 == bytes.len(),
            "has_duplex": has_duplex,
            "first_parse": first_parse,
            "second_parse": second_parse,
            "loop0_end": loop0_end,
            "loop1_end": loop1_end,
            "warnings": warnings,
        },
        "control_flow": packet_control_flow(control_effects),
        "smir": smir,
        "side_effects": side_effects_not_run(),
    }))
}

fn decode_smir_only(bytes: &[u8], opts: &OracleOptions) -> Value {
    let smir = lift_smir(opts.smir_source, bytes, opts);
    let decoded_ops = smir
        .get("ops")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let control_flow = smir
        .get("control_flow")
        .cloned()
        .unwrap_or_else(|| json!({"kind": "unknown"}));
    json!({
        "isa": "smir",
        "source_arch": format!("{:?}", opts.smir_source),
        "pc": hex_u64(opts.pc),
        "input": input_json(bytes),
        "decoded_ops": decoded_ops,
        "packet_flags": null,
        "control_flow": control_flow,
        "smir": smir,
        "side_effects": side_effects_not_run(),
    })
}

fn smir_side_effects(bytes: &[u8], opts: &OracleOptions, seed: &OracleSeed) -> Value {
    let Some(source) = side_effect_source(opts) else {
        return json!({
            "available": false,
            "engine": "smir_lifter",
            "reason": "no_smir_side_effect_engine_for_isa",
        });
    };

    let (ops, bytes_consumed) = match lift_side_effect_ops(source, bytes, opts) {
        Ok(result) => result,
        Err(err) => {
            return json!({
                "available": true,
                "engine": "smir_lifter",
                "error": err,
            });
        }
    };

    let memory_layout = match seed_memory_layout(seed) {
        Ok(layout) => layout,
        Err(err) => {
            return json!({
                "available": true,
                "engine": "smir_lifter",
                "error": err,
            });
        }
    };

    let mut ctx = smir_context(source);
    ctx.pc = opts.pc;
    ctx.arch_regs.set_pc(opts.pc);

    let mut watched_regs = Vec::new();
    for (name, value) in &seed.regs {
        let Some(reg) = parse_arch_reg(source, name) else {
            return json!({
                "available": true,
                "engine": "smir_lifter",
                "error": format!("unsupported seed register '{name}' for {source:?}"),
            });
        };
        ctx.write_arch_reg(reg, *value);
        watched_regs.push((name.clone(), reg, ctx.read_arch_reg(reg)));
    }

    let mut memory = FlatMemory::with_base(memory_layout.base, memory_layout.size);
    let mut watched_memory = Vec::new();
    for mem in &seed.memory {
        let offset = (mem.addr - memory_layout.base) as usize;
        memory.load(offset, &mem.bytes);
        let mut before = vec![0u8; mem.bytes.len()];
        if let Err(err) = memory.read(mem.addr, &mut before) {
            return json!({
                "available": true,
                "engine": "smir_lifter",
                "error": format!("failed to read seeded memory: {err}"),
            });
        }
        watched_memory.push((mem.addr, before));
    }

    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: opts.pc,
        phis: vec![],
        ops,
        terminator: Terminator::Trap {
            kind: TrapKind::Breakpoint,
        },
        exec_count: 0,
    };

    let interp = SmirInterpreter::new();
    let exit = interp.execute_block(&mut ctx, &mut memory, &block);

    let mut final_regs = Map::new();
    let mut changed_regs = Map::new();
    for (name, reg, before) in watched_regs {
        let after = ctx.read_arch_reg(reg);
        final_regs.insert(name.clone(), json!(hex_u64(after)));
        if before != after {
            changed_regs.insert(
                name,
                json!({
                    "before": hex_u64(before),
                    "after": hex_u64(after),
                }),
            );
        }
    }

    let mut changed_memory = Vec::new();
    for (addr, before) in watched_memory {
        let mut after = vec![0u8; before.len()];
        if let Err(err) = memory.read(addr, &mut after) {
            return json!({
                "available": true,
                "engine": "smir_lifter",
                "error": format!("failed to read watched memory: {err}"),
            });
        }
        if before != after {
            changed_memory.push(json!({
                "addr": hex_u64(addr),
                "len": before.len(),
                "before_hex": bytes_to_hex(&before),
                "after_hex": bytes_to_hex(&after),
            }));
        }
    }

    json!({
        "available": true,
        "engine": "smir_lifter",
        "source_arch": format!("{source:?}"),
        "bytes_consumed": bytes_consumed,
        "exit": format!("{exit:?}"),
        "changed_regs": changed_regs,
        "final_regs": final_regs,
        "changed_memory": changed_memory,
        "memory_base": hex_u64(memory_layout.base),
        "memory_size": memory_layout.size,
    })
}

fn side_effect_source(opts: &OracleOptions) -> Option<SourceArch> {
    match opts.isa {
        OracleIsa::X86_64 if opts.x86_code_size == X86CodeSize::Bits64 => Some(SourceArch::X86_64),
        OracleIsa::X86_64 => None,
        OracleIsa::Arm if opts.arm_state == ArmState::Aarch64 => Some(SourceArch::Aarch64),
        OracleIsa::Arm => None,
        OracleIsa::Hexagon => Some(SourceArch::Hexagon),
        OracleIsa::RiscV => Some(match opts.riscv_xlen {
            Xlen::Rv32 => SourceArch::RiscV32,
            Xlen::Rv64 => SourceArch::RiscV64,
        }),
        OracleIsa::Smir => Some(opts.smir_source),
    }
}

fn lift_side_effect_ops(
    source: SourceArch,
    bytes: &[u8],
    opts: &OracleOptions,
) -> Result<(Vec<crate::smir::SmirOp>, usize), String> {
    let mut ctx = LiftContext::new(source);
    let mut ops = Vec::new();
    let consumed;

    match source {
        SourceArch::X86_64 => {
            let result = X86_64Lifter::new()
                .lift_insn(opts.pc, bytes, &mut ctx)
                .map_err(|e| e.to_string())?;
            consumed = result.bytes_consumed;
            ops = result.ops;
        }
        SourceArch::Aarch64 => {
            let result = Aarch64Lifter::new()
                .lift_insn(opts.pc, bytes, &mut ctx)
                .map_err(|e| e.to_string())?;
            consumed = result.bytes_consumed;
            ops = result.ops;
        }
        SourceArch::Hexagon => {
            if bytes.is_empty() || bytes.len() % 4 != 0 {
                return Err("Hexagon side-effect bytes must be a non-empty multiple of 4".into());
            }
            let mut lifter = HexagonLifter::new(opts.hexagon_isa);
            let mut pc = opts.pc;
            let mut total = 0usize;
            for chunk in bytes.chunks_exact(4) {
                let word = word_from_bytes(chunk, opts.hexagon_endian);
                let parse = (word >> 14) & 0x3;
                if parse == 0 {
                    return Err(
                        "Hexagon duplex packet side effects are not supported by the SMIR word lifter"
                            .to_string(),
                    );
                }
                let word_bytes = word.to_le_bytes();
                let result = lifter
                    .lift_insn(pc, &word_bytes, &mut ctx)
                    .map_err(|e| e.to_string())?;
                ops.extend(result.ops);
                total += 4;
                pc = pc.wrapping_add(4);
                if parse == 0x3 {
                    break;
                }
            }
            consumed = total;
        }
        SourceArch::RiscV64 => {
            let result = RiscVLifter::new_rv64(riscv_extensions(opts.riscv_isa))
                .lift_insn(opts.pc, bytes, &mut ctx)
                .map_err(|e| e.to_string())?;
            consumed = result.bytes_consumed;
            ops = result.ops;
        }
        SourceArch::RiscV32 => {
            let result = RiscVLifter::new_rv32(riscv_extensions(opts.riscv_isa))
                .lift_insn(opts.pc, bytes, &mut ctx)
                .map_err(|e| e.to_string())?;
            consumed = result.bytes_consumed;
            ops = result.ops;
        }
        other => return Err(format!("no SMIR side-effect lifter for {other:?}")),
    }

    for (idx, op) in ops.iter_mut().enumerate() {
        op.id = OpId(idx as u16);
    }

    Ok((ops, consumed))
}

fn smir_context(source: SourceArch) -> SmirContext {
    match source {
        SourceArch::X86_64 => SmirContext::new_x86_64(),
        SourceArch::Aarch64 => SmirContext::new_aarch64(),
        SourceArch::Hexagon => SmirContext::new_hexagon(),
        SourceArch::RiscV64 => SmirContext::new_riscv(),
        SourceArch::RiscV32 => {
            let mut ctx = SmirContext::new_riscv();
            ctx.source_arch = SourceArch::RiscV32;
            ctx
        }
        _ => SmirContext::new_x86_64(),
    }
}

struct MemoryLayout {
    base: u64,
    size: usize,
}

fn seed_memory_layout(seed: &OracleSeed) -> Result<MemoryLayout, String> {
    if let Some(size) = seed.memory_size {
        validate_seed_memory_size(size, "seed.memory_size")?;
    }

    if seed.memory.is_empty() {
        return Ok(MemoryLayout {
            base: 0,
            size: seed.memory_size.unwrap_or(0x10000),
        });
    }

    let base = seed.memory.iter().map(|mem| mem.addr).min().unwrap();
    let max_end = seed.memory.iter().try_fold(base, |max_end, mem| {
        let len = u64::try_from(mem.bytes.len())
            .map_err(|_| "seed memory entry length does not fit in u64".to_string())?;
        let end = mem
            .addr
            .checked_add(len)
            .ok_or_else(|| "seed memory entry address range overflows u64".to_string())?;
        Ok::<_, String>(max_end.max(end))
    })?;
    let needed_u64 = max_end
        .checked_sub(base)
        .ok_or_else(|| "invalid seed memory layout".to_string())?;
    let needed = usize::try_from(needed_u64)
        .map_err(|_| format!("seeded memory span {needed_u64} does not fit in host usize"))?;
    validate_seed_memory_size(needed, "seeded memory span")?;
    let size = seed.memory_size.unwrap_or(needed.max(0x1000));
    if size < needed {
        return Err(format!(
            "seed.memory_size {size} is smaller than seeded memory span {needed}"
        ));
    }
    Ok(MemoryLayout { base, size })
}

fn validate_seed_memory_size(size: usize, field: &str) -> Result<(), String> {
    if size > MAX_ORACLE_SEED_MEMORY_SIZE {
        return Err(format!(
            "{field} {size} exceeds oracle seed memory limit {MAX_ORACLE_SEED_MEMORY_SIZE}"
        ));
    }
    Ok(())
}

fn parse_arch_reg(source: SourceArch, name: &str) -> Option<ArchReg> {
    let lower = name.trim().to_ascii_lowercase();
    match source {
        SourceArch::X86_64 => parse_x86_reg(&lower).map(ArchReg::X86),
        SourceArch::Aarch64 => parse_arm_reg(&lower).map(ArchReg::Arm),
        SourceArch::Hexagon => parse_hexagon_reg(&lower).map(ArchReg::Hexagon),
        SourceArch::RiscV64 | SourceArch::RiscV32 => parse_riscv_reg(&lower).map(ArchReg::RiscV),
        _ => None,
    }
}

fn parse_x86_reg(name: &str) -> Option<X86Reg> {
    match name {
        "rax" | "eax" | "ax" | "al" => Some(X86Reg::Rax),
        "rcx" | "ecx" | "cx" | "cl" => Some(X86Reg::Rcx),
        "rdx" | "edx" | "dx" | "dl" => Some(X86Reg::Rdx),
        "rbx" | "ebx" | "bx" | "bl" => Some(X86Reg::Rbx),
        "rsp" | "esp" | "sp" => Some(X86Reg::Rsp),
        "rbp" | "ebp" | "bp" => Some(X86Reg::Rbp),
        "rsi" | "esi" | "si" => Some(X86Reg::Rsi),
        "rdi" | "edi" | "di" => Some(X86Reg::Rdi),
        "rip" | "eip" | "pc" => Some(X86Reg::Rip),
        "rflags" | "eflags" | "flags" => Some(X86Reg::Rflags),
        "fs_base" | "fsbase" => Some(X86Reg::FsBase),
        "gs_base" | "gsbase" => Some(X86Reg::GsBase),
        "kernel_gs_base" | "kernelgsbase" => Some(X86Reg::KernelGsBase),
        "pkru" => Some(X86Reg::Pkru),
        _ => {
            let idx = name.strip_prefix('r')?.parse::<u8>().ok()?;
            (8..=15).contains(&idx).then(|| X86Reg::gpr(idx))
        }
    }
}

fn parse_arm_reg(name: &str) -> Option<ArmReg> {
    match name {
        "sp" => Some(ArmReg::Sp),
        "pc" => Some(ArmReg::Pc),
        "nzcv" | "flags" => Some(ArmReg::Nzcv),
        _ => {
            let idx = name
                .strip_prefix('x')
                .or_else(|| name.strip_prefix('w'))?
                .parse::<u8>()
                .ok()?;
            (idx <= 30).then_some(ArmReg::X(idx))
        }
    }
}

fn parse_hexagon_reg(name: &str) -> Option<HexagonReg> {
    match name {
        "pc" => Some(HexagonReg::Pc),
        "gp" => Some(HexagonReg::Gp),
        "lr" => Some(HexagonReg::Lr),
        "sp" => Some(HexagonReg::Sp),
        "fp" => Some(HexagonReg::Fp),
        "lc0" => Some(HexagonReg::Lc0),
        "lc1" => Some(HexagonReg::Lc1),
        "sa0" => Some(HexagonReg::Sa0),
        "sa1" => Some(HexagonReg::Sa1),
        "usr" => Some(HexagonReg::Usr),
        _ if name.starts_with('r') => {
            let idx = name.strip_prefix('r')?.parse::<u8>().ok()?;
            (idx <= 31).then_some(HexagonReg::R(idx))
        }
        _ if name.starts_with('p') => {
            let idx = name.strip_prefix('p')?.parse::<u8>().ok()?;
            (idx <= 3).then_some(HexagonReg::P(idx))
        }
        _ if name.starts_with('m') => {
            let idx = name.strip_prefix('m')?.parse::<u8>().ok()?;
            (idx <= 1).then_some(HexagonReg::M(idx))
        }
        _ if name.starts_with("cs") => {
            let idx = name.strip_prefix("cs")?.parse::<u8>().ok()?;
            (idx <= 1).then_some(HexagonReg::Cs(idx))
        }
        _ => None,
    }
}

fn parse_riscv_reg(name: &str) -> Option<RiscVReg> {
    match name {
        "pc" => Some(RiscVReg::Pc),
        "zero" => Some(RiscVReg::X(0)),
        "ra" => Some(RiscVReg::X(1)),
        "sp" => Some(RiscVReg::X(2)),
        "gp" => Some(RiscVReg::X(3)),
        "tp" => Some(RiscVReg::X(4)),
        "fp" | "s0" => Some(RiscVReg::X(8)),
        _ if name.starts_with('x') => {
            let idx = name.strip_prefix('x')?.parse::<u8>().ok()?;
            (idx <= 31).then_some(RiscVReg::X(idx))
        }
        _ if name.starts_with('f') => {
            let idx = name.strip_prefix('f')?.parse::<u8>().ok()?;
            (idx <= 31).then_some(RiscVReg::F(idx))
        }
        _ if name.starts_with('a') => {
            let idx = name.strip_prefix('a')?.parse::<u8>().ok()?;
            (idx <= 7).then_some(RiscVReg::X(10 + idx))
        }
        _ if name.starts_with('t') => {
            let idx = name.strip_prefix('t')?.parse::<u8>().ok()?;
            match idx {
                0..=2 => Some(RiscVReg::X(5 + idx)),
                3..=6 => Some(RiscVReg::X(28 + (idx - 3))),
                _ => None,
            }
        }
        _ if name.starts_with('s') => {
            let idx = name.strip_prefix('s')?.parse::<u8>().ok()?;
            match idx {
                1 => Some(RiscVReg::X(9)),
                2..=11 => Some(RiscVReg::X(16 + (idx - 2))),
                _ => None,
            }
        }
        _ => None,
    }
}

fn lift_smir(source: SourceArch, bytes: &[u8], opts: &OracleOptions) -> Value {
    let mut ctx = LiftContext::new(source);
    let result = match source {
        SourceArch::X86_64 => X86_64Lifter::new().lift_insn(opts.pc, bytes, &mut ctx),
        SourceArch::Aarch64 => Aarch64Lifter::new().lift_insn(opts.pc, bytes, &mut ctx),
        SourceArch::Hexagon => {
            HexagonLifter::new(opts.hexagon_isa).lift_insn(opts.pc, bytes, &mut ctx)
        }
        SourceArch::RiscV64 => RiscVLifter::new_rv64(riscv_extensions(opts.riscv_isa))
            .lift_insn(opts.pc, bytes, &mut ctx),
        SourceArch::RiscV32 => RiscVLifter::new_rv32(riscv_extensions(opts.riscv_isa))
            .lift_insn(opts.pc, bytes, &mut ctx),
        other => {
            return json!({
                "available": false,
                "source_arch": format!("{other:?}"),
                "reason": "no_lifter",
            });
        }
    };

    match result {
        Ok(result) => {
            let ops = result.ops.iter().map(smir_op_json).collect::<Vec<_>>();
            let control_flow = control_flow_json(&result.control_flow);
            // Lifters may model architectural writes by rebinding an
            // architecture register to a fresh SSA VReg instead of putting the
            // architecture register directly in `OpKind::dests()`. Publish
            // that final mapping as additive oracle metadata so stateless
            // effect consumers can recover those writes. RISC-V, x86-64, and
            // AArch64 use explicit architecture destinations; Hexagon still
            // uses this binding path. Sort by stable textual register name;
            // VRegAllocator is backed by a HashMap and has no iteration-order
            // guarantee.
            let mut arch_outputs = ctx
                .vreg_alloc
                .arch_bindings()
                .into_iter()
                .map(|(reg, value)| {
                    json!({
                        "reg": VReg::Arch(reg).oracle_json(),
                        "value": value.oracle_json(),
                    })
                })
                .collect::<Vec<_>>();
            arch_outputs.sort_by(|a, b| {
                let key = |v: &Value| {
                    let r = &v["reg"];
                    format!(
                        "{}:{}",
                        r.get("arch").and_then(Value::as_str).unwrap_or(""),
                        r.get("name").and_then(Value::as_str).unwrap_or("")
                    )
                };
                key(a).cmp(&key(b))
            });
            json!({
                "available": true,
                "source_arch": format!("{source:?}"),
                "bytes_consumed": result.bytes_consumed,
                "ops": ops,
                "arch_outputs": arch_outputs,
                "control_flow": control_flow,
                "branch_targets": result.branch_targets.iter().map(|target| hex_u64(*target)).collect::<Vec<_>>(),
                "ends_block": result.control_flow.ends_block(),
                "ends_function": result.control_flow.ends_function(),
            })
        }
        Err(err) => json!({
            "available": true,
            "source_arch": format!("{source:?}"),
            "error": err.to_string(),
            "debug": format!("{err:?}"),
        }),
    }
}

trait OracleJson {
    fn oracle_json(&self) -> Value;
}

impl<T: OracleJson + ?Sized> OracleJson for &T {
    fn oracle_json(&self) -> Value {
        (*self).oracle_json()
    }
}

impl<T: OracleJson> OracleJson for Option<T> {
    fn oracle_json(&self) -> Value {
        self.as_ref()
            .map(OracleJson::oracle_json)
            .unwrap_or(Value::Null)
    }
}

impl<T: OracleJson> OracleJson for Vec<T> {
    fn oracle_json(&self) -> Value {
        Value::Array(self.iter().map(OracleJson::oracle_json).collect())
    }
}

macro_rules! number_json {
    ($($ty:ty),* $(,)?) => {
        $(
            impl OracleJson for $ty {
                fn oracle_json(&self) -> Value {
                    json!(*self)
                }
            }
        )*
    };
}

number_json!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

impl OracleJson for bool {
    fn oracle_json(&self) -> Value {
        json!(*self)
    }
}

impl OracleJson for X86SmswTarget {
    fn oracle_json(&self) -> Value {
        match self {
            X86SmswTarget::Register { dst, width } => json!({
                "kind": "register",
                "dst": dst.oracle_json(),
                "width": width.oracle_json(),
            }),
            X86SmswTarget::Memory { addr } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
            }),
        }
    }
}

impl OracleJson for X86SystemSelectorTarget {
    fn oracle_json(&self) -> Value {
        match self {
            X86SystemSelectorTarget::Register { dst, width } => json!({
                "kind": "register",
                "dst": dst.oracle_json(),
                "width": width.oracle_json(),
            }),
            X86SystemSelectorTarget::Memory { addr } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
                "width": "B2",
            }),
            X86SystemSelectorTarget::Stack {
                stack_pointer,
                width,
            } => json!({
                "kind": "stack",
                "stack_pointer": stack_pointer.oracle_json(),
                "width": width.oracle_json(),
                "commit": "after_write",
            }),
        }
    }
}

impl OracleJson for X86SystemSelectorSource {
    fn oracle_json(&self) -> serde_json::Value {
        match self {
            X86SystemSelectorSource::Register { src } => json!({
                "kind": "register",
                "src": src.oracle_json(),
                "width": "W16",
            }),
            X86SystemSelectorSource::Memory {
                addr,
                width,
                stack_segment,
            } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
                "width": width.oracle_json(),
                "stack_segment": stack_segment,
            }),
            X86SystemSelectorSource::Stack {
                stack_pointer,
                width,
            } => json!({
                "kind": "stack",
                "stack_pointer": stack_pointer.oracle_json(),
                "width": width.oracle_json(),
                "commit": "after_selector_load",
            }),
            X86SystemSelectorSource::FarPointer {
                addr,
                dst,
                offset_width,
                stack_segment,
            } => json!({
                "kind": "far_pointer",
                "addr": addr.oracle_json(),
                "dst": dst.oracle_json(),
                "offset_width": offset_width.oracle_json(),
                "selector_width": "B2",
                "stack_segment": stack_segment,
                "commit": "after_selector_load",
            }),
        }
    }
}

impl OracleJson for X86SelectorVerifySource {
    fn oracle_json(&self) -> Value {
        match self {
            X86SelectorVerifySource::Register { src } => json!({
                "kind": "register",
                "src": src.oracle_json(),
                "width": "W16",
            }),
            X86SelectorVerifySource::Memory {
                addr,
                stack_segment,
            } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
                "width": "B2",
                "stack_segment": stack_segment,
            }),
        }
    }
}

impl OracleJson for X86SelectorQuerySource {
    fn oracle_json(&self) -> Value {
        match self {
            X86SelectorQuerySource::Register { src } => json!({
                "kind": "register",
                "src": src.oracle_json(),
                "width": "W16",
            }),
            X86SelectorQuerySource::Memory {
                addr,
                stack_segment,
            } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
                "width": "B2",
                "stack_segment": stack_segment,
            }),
        }
    }
}

impl OracleJson for X86LmswSource {
    fn oracle_json(&self) -> Value {
        match self {
            X86LmswSource::Register { src } => json!({
                "kind": "register",
                "src": src.oracle_json(),
                "width": "W16",
            }),
            X86LmswSource::Memory { addr } => json!({
                "kind": "memory",
                "addr": addr.oracle_json(),
                "width": "B2",
            }),
        }
    }
}

macro_rules! debug_name_json {
    ($($ty:ty),* $(,)?) => {
        $(
            impl OracleJson for $ty {
                fn oracle_json(&self) -> Value {
                    json!(debug_name(self))
                }
            }
        )*
    };
}

debug_name_json!(
    ArmDpRegShiftKind,
    X86DescriptorTable,
    X86SystemSelector,
    X86SelectorQueryKind,
    X86SelectorVerifyKind,
    X86StackFlagsKind,
    OpWidth,
    MemWidth,
    SignExtend,
    DispSize,
    ShiftOp,
    ExtendOp,
    MemoryOrder,
    FenceKind,
    AtomicOp,
    FpPrecision,
    FpRoundMode,
    VecWidth,
    X86SatFpFormat,
    VecElementType,
    VecCmpCond,
    VShiftVKind,
    VLaneOp,
    VecUnaryOp,
    VecReduceOp,
    VecPermuteKind,
    X86AesOp,
    X86PackedStringKind,
    X86Sha32Op,
    Avx10FP16Op,
    X86FpBinaryOp,
    X86FmaKind,
    X86FmaOrder,
    X86NarrowMode,
    Condition,
    HexFpOp,
    HexFpRecipKind,
    X86AdxKind,
    X86Sse4aBitfieldKind,
    X86CacheControlKind,
    X86ControlReg,
    X86DebugReg,
    X86FastSystemTransferKind,
    X86BlsKind,
    X86TbmKind,
    X86XopPackedBitKind,
    X86CountKind,
    X86ThreeDNowKind,
    X86X87Constant,
    X86X87CompareSource,
    X86X87ControlKind,
    X86X87DataKind,
    X86X87EnvWidth,
    X86X87IntWidth,
    X86X87FloatWidth,
    X86XSaveKind,
);

impl OracleJson for FlagSet {
    fn oracle_json(&self) -> Value {
        let mut names = Vec::new();
        for (name, flag) in [
            ("cf", FlagSet::CF),
            ("zf", FlagSet::ZF),
            ("sf", FlagSet::SF),
            ("of", FlagSet::OF),
            ("pf", FlagSet::PF),
            ("af", FlagSet::AF),
        ] {
            if self.contains(flag) {
                names.push(name);
            }
        }
        json!({
            "mask": self.0,
            "names": names,
        })
    }
}

impl OracleJson for FlagUpdate {
    fn oracle_json(&self) -> Value {
        match self {
            FlagUpdate::None => json!({"mode": "none", "set": FlagSet::EMPTY.oracle_json()}),
            FlagUpdate::All => json!({"mode": "all", "set": self.as_set().oracle_json()}),
            FlagUpdate::Specific(set) => json!({"mode": "specific", "set": set.oracle_json()}),
        }
    }
}

impl OracleJson for VReg {
    fn oracle_json(&self) -> Value {
        match self {
            VReg::Virtual(id) => json!({
                "kind": "virtual",
                "id": id.0,
            }),
            VReg::Arch(reg) => {
                let mut obj = arch_reg_json(reg);
                obj.insert("kind".to_string(), json!("arch"));
                Value::Object(obj)
            }
            VReg::Imm(value) => json!({
                "kind": "imm",
                "value": value,
                "hex": hex_i64(*value),
            }),
        }
    }
}

impl OracleJson for X86GprOperand {
    fn oracle_json(&self) -> Value {
        json!({
            "reg": self.vreg().oracle_json(),
            "high_byte": self.high_byte,
        })
    }
}

impl OracleJson for SrcOperand {
    fn oracle_json(&self) -> Value {
        match self {
            SrcOperand::Reg(reg) => json!({
                "kind": "reg",
                "reg": reg.oracle_json(),
            }),
            SrcOperand::Imm(value) => json!({
                "kind": "imm",
                "value": value,
                "hex": hex_i64(*value),
            }),
            SrcOperand::Imm64(value) => json!({
                "kind": "imm64",
                "value": value,
                "hex": hex_i64(*value),
            }),
            SrcOperand::Shifted { reg, shift, amount } => json!({
                "kind": "shifted",
                "reg": reg.oracle_json(),
                "shift": shift.oracle_json(),
                "amount": amount,
            }),
            SrcOperand::Extended { reg, extend, shift } => json!({
                "kind": "extended",
                "reg": reg.oracle_json(),
                "extend": extend.oracle_json(),
                "shift": shift,
            }),
        }
    }
}

fn smir_op_json(op: &SmirOp) -> Value {
    let kind = smir_op_kind_json(&op.kind);
    let opcode = kind
        .get("opcode")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    json!({
        "id": op.id.0,
        "guest_pc": hex_u64(op.guest_pc),
        "opcode": opcode,
        "kind": kind,
        "writes": op.kind.dests().iter().map(OracleJson::oracle_json).collect::<Vec<_>>(),
        "memory": {
            "reads": op.kind.reads_memory(),
            "writes": op.kind.writes_memory(),
        },
        "side_effects": op.kind.has_side_effects(),
        "x86_hint": op.x86_hint.map(|hint| debug_name(&hint)),
    })
}

fn smir_op_kind_json(kind: &OpKind) -> Value {
    macro_rules! op_json {
        ($opcode:literal $(, $field:ident)*) => {{
            let mut obj = Map::new();
            obj.insert("opcode".to_string(), json!($opcode));
            $(
                obj.insert(stringify!($field).to_string(), $field.oracle_json());
            )*
            Value::Object(obj)
        }};
    }

    match kind {
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("add", dst, src1, src2, width, flags),
        OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("sub", dst, src1, src2, width, flags),
        OpKind::Adc {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("adc", dst, src1, src2, width, flags),
        OpKind::Sbb {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("sbb", dst, src1, src2, width, flags),
        OpKind::Neg {
            dst,
            src,
            width,
            flags,
        } => op_json!("neg", dst, src, width, flags),
        OpKind::Inc {
            dst,
            src,
            width,
            flags,
        } => op_json!("inc", dst, src, width, flags),
        OpKind::Dec {
            dst,
            src,
            width,
            flags,
        } => op_json!("dec", dst, src, width, flags),
        OpKind::Cmp { src1, src2, width } => op_json!("cmp", src1, src2, width),
        OpKind::MulU {
            dst_lo,
            dst_hi,
            src1,
            src2,
            width,
            flags,
        } => op_json!("mul_u", dst_lo, dst_hi, src1, src2, width, flags),
        OpKind::MulS {
            dst_lo,
            dst_hi,
            src1,
            src2,
            width,
            flags,
        } => op_json!("mul_s", dst_lo, dst_hi, src1, src2, width, flags),
        OpKind::MulAdd {
            dst,
            acc,
            src1,
            src2,
            width,
        } => op_json!("mul_add", dst, acc, src1, src2, width),
        OpKind::MulSub {
            dst,
            acc,
            src1,
            src2,
            width,
        } => op_json!("mul_sub", dst, acc, src1, src2, width),
        OpKind::DivU {
            quot,
            rem,
            src1,
            src2,
            width,
            flags,
        } => op_json!("div_u", quot, rem, src1, src2, width, flags),
        OpKind::DivS {
            quot,
            rem,
            src1,
            src2,
            width,
            flags,
        } => op_json!("div_s", quot, rem, src1, src2, width, flags),
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("and", dst, src1, src2, width, flags),
        OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("or", dst, src1, src2, width, flags),
        OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("xor", dst, src1, src2, width, flags),
        OpKind::Not { dst, src, width } => op_json!("not", dst, src, width),
        OpKind::Test { src1, src2, width } => op_json!("test", src1, src2, width),
        OpKind::AndNot {
            dst,
            src1,
            src2,
            width,
            flags,
        } => op_json!("and_not", dst, src1, src2, width, flags),
        OpKind::Shl {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("shl", dst, src, amount, width, flags),
        OpKind::Shr {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("shr", dst, src, amount, width, flags),
        OpKind::Sar {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("sar", dst, src, amount, width, flags),
        OpKind::Shld {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("shld", dst, src, amount, width, flags),
        OpKind::Shrd {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("shrd", dst, src, amount, width, flags),
        OpKind::X86NddDoubleShift {
            dst,
            base,
            fill,
            amount,
            width,
            left,
            flags,
        } => op_json!(
            "x86_ndd_double_shift",
            dst,
            base,
            fill,
            amount,
            width,
            left,
            flags
        ),
        OpKind::Rol {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("rol", dst, src, amount, width, flags),
        OpKind::Ror {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("ror", dst, src, amount, width, flags),
        OpKind::ArmRegShift {
            dst,
            src,
            amount,
            shift,
            width,
            flags,
        } => op_json!("arm_reg_shift", dst, src, amount, shift, width, flags),
        OpKind::ArmDpRegShift {
            kind,
            dst,
            rn,
            rm,
            rs,
            shift,
            flags,
        } => op_json!("arm_dp_reg_shift", kind, dst, rn, rm, rs, shift, flags),
        OpKind::Rcl {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("rcl", dst, src, amount, width, flags),
        OpKind::Rcr {
            dst,
            src,
            amount,
            width,
            flags,
        } => op_json!("rcr", dst, src, amount, width, flags),
        OpKind::Bt { src, index, width } => op_json!("bt", src, index, width),
        OpKind::Bts {
            dst,
            src,
            index,
            width,
        } => op_json!("bts", dst, src, index, width),
        OpKind::Btr {
            dst,
            src,
            index,
            width,
        } => op_json!("btr", dst, src, index, width),
        OpKind::Btc {
            dst,
            src,
            index,
            width,
        } => op_json!("btc", dst, src, index, width),
        OpKind::Bsf {
            dst,
            src,
            width,
            flags,
        } => op_json!("bsf", dst, src, width, flags),
        OpKind::Bsr {
            dst,
            src,
            width,
            flags,
        } => op_json!("bsr", dst, src, width, flags),
        OpKind::Bextr {
            dst,
            src,
            control,
            width,
            flags,
        } => op_json!("bextr", dst, src, control, width, flags),
        OpKind::Bzhi {
            dst,
            src,
            index,
            width,
            flags,
        } => op_json!("bzhi", dst, src, index, width, flags),
        OpKind::X86Bls {
            dst,
            src,
            width,
            kind,
            flags,
        } => op_json!("x86_bls", dst, src, width, kind, flags),
        OpKind::X86Tbm {
            dst,
            src,
            width,
            kind,
            flags,
        } => op_json!("x86_tbm", dst, src, width, kind, flags),
        OpKind::X86Adx {
            dst,
            src1,
            src2,
            width,
            kind,
            flags,
        } => op_json!("x86_adx", dst, src1, src2, width, kind, flags),
        OpKind::Pdep {
            dst,
            src,
            mask,
            width,
        } => op_json!("pdep", dst, src, mask, width),
        OpKind::Pext {
            dst,
            src,
            mask,
            width,
        } => op_json!("pext", dst, src, mask, width),
        OpKind::Clz { dst, src, width } => op_json!("clz", dst, src, width),
        OpKind::Ctz { dst, src, width } => op_json!("ctz", dst, src, width),
        OpKind::Popcnt { dst, src, width } => op_json!("popcnt", dst, src, width),
        OpKind::X86Count {
            dst,
            src,
            width,
            kind,
            flags,
        } => op_json!("x86_count", dst, src, width, kind, flags),
        OpKind::Bswap { dst, src, width } => op_json!("bswap", dst, src, width),
        OpKind::Rbit { dst, src, width } => op_json!("rbit", dst, src, width),
        OpKind::Bfx {
            dst,
            src,
            lsb,
            width_bits,
            sign_extend,
            op_width,
        } => op_json!("bfx", dst, src, lsb, width_bits, sign_extend, op_width),
        OpKind::Bfi {
            dst,
            dst_in,
            src,
            lsb,
            width_bits,
            op_width,
        } => op_json!("bfi", dst, dst_in, src, lsb, width_bits, op_width),
        OpKind::Mov { dst, src, width } => op_json!("mov", dst, src, width),
        OpKind::CMove {
            dst,
            src,
            cond,
            width,
        } => op_json!("cmove", dst, src, cond, width),
        OpKind::Select {
            dst,
            cond,
            src_true,
            src_false,
            width,
        } => op_json!("select", dst, cond, src_true, src_false, width),
        OpKind::ZeroExtend {
            dst,
            src,
            from_width,
            to_width,
        } => op_json!("zero_extend", dst, src, from_width, to_width),
        OpKind::SignExtend {
            dst,
            src,
            from_width,
            to_width,
        } => op_json!("sign_extend", dst, src, from_width, to_width),
        OpKind::Cwd { dst, src, width } => op_json!("cwd", dst, src, width),
        OpKind::Truncate {
            dst,
            src,
            from_width,
            to_width,
        } => op_json!("truncate", dst, src, from_width, to_width),
        OpKind::Lea { dst, addr } => op_json!("lea", dst, addr),
        OpKind::X86Lea { dst, addr, width } => op_json!("x86_lea", dst, addr, width),
        OpKind::Xchg { reg1, reg2, width } => op_json!("xchg", reg1, reg2, width),
        OpKind::X86Xadd(X86XaddOp {
            dst,
            src,
            width,
            flags,
        }) => op_json!("x86_xadd", dst, src, width, flags),
        OpKind::X86Cmpxchg(X86CmpxchgOp {
            dst,
            src,
            width,
            flags,
        }) => op_json!("x86_cmpxchg", dst, src, width, flags),
        OpKind::Load {
            dst,
            addr,
            width,
            sign,
        } => op_json!("load", dst, addr, width, sign),
        OpKind::Store { src, addr, width } => op_json!("store", src, addr, width),
        OpKind::PredLoad {
            dst,
            cond,
            addr,
            width,
            signed,
        } => op_json!("pred_load", dst, cond, addr, width, signed),
        OpKind::PredStore {
            src,
            cond,
            addr,
            width,
        } => op_json!("pred_store", src, cond, addr, width),
        OpKind::RepStos {
            dst,
            src,
            count,
            width,
        } => op_json!("rep_stos", dst, src, count, width),
        OpKind::RepMovs {
            dst,
            src,
            count,
            width,
        } => op_json!("rep_movs", dst, src, count, width),
        OpKind::LoadPair {
            dst1,
            dst2,
            addr,
            width,
        } => op_json!("load_pair", dst1, dst2, addr, width),
        OpKind::StorePair {
            src1,
            src2,
            addr,
            width,
        } => op_json!("store_pair", src1, src2, addr, width),
        OpKind::AtomicLoad {
            dst,
            addr,
            width,
            order,
        } => op_json!("atomic_load", dst, addr, width, order),
        OpKind::AtomicStore {
            src,
            addr,
            width,
            order,
        } => op_json!("atomic_store", src, addr, width, order),
        OpKind::AtomicRmw {
            dst,
            addr,
            src,
            op,
            width,
            order,
        } => op_json!("atomic_rmw", dst, addr, src, op, width, order),
        OpKind::Cas {
            dst,
            success,
            addr,
            expected,
            new_val,
            width,
            order,
        } => op_json!("cas", dst, success, addr, expected, new_val, width, order),
        OpKind::CasPair {
            dst_lo,
            dst_hi,
            success,
            addr,
            expected_lo,
            expected_hi,
            new_lo,
            new_hi,
            order,
            failure_order,
        } => op_json!(
            "cas_pair",
            dst_lo,
            dst_hi,
            success,
            addr,
            expected_lo,
            expected_hi,
            new_lo,
            new_hi,
            order,
            failure_order
        ),
        OpKind::AtomicCmpXadd {
            dst_old,
            addr,
            cmp,
            add,
            cond,
            width,
            order,
        } => op_json!(
            "atomic_cmpxadd",
            dst_old,
            addr,
            cmp,
            add,
            cond,
            width,
            order
        ),
        OpKind::LoadExclusive { dst, addr, width } => op_json!("load_exclusive", dst, addr, width),
        OpKind::StoreExclusive {
            status,
            src,
            addr,
            width,
        } => op_json!("store_exclusive", status, src, addr, width),
        OpKind::ClearExclusive => op_json!("clear_exclusive"),
        OpKind::Prefetch { addr, write } => op_json!("prefetch", addr, write),
        OpKind::Fence { kind } => op_json!("fence", kind),
        OpKind::FAdd {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fadd", dst, src1, src2, precision),
        OpKind::FSub {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fsub", dst, src1, src2, precision),
        OpKind::FMul {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fmul", dst, src1, src2, precision),
        OpKind::FDiv {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fdiv", dst, src1, src2, precision),
        OpKind::FFma {
            dst,
            src1,
            src2,
            src3,
            precision,
        } => op_json!("ffma", dst, src1, src2, src3, precision),
        OpKind::FAbs {
            dst,
            src,
            precision,
        } => op_json!("fabs", dst, src, precision),
        OpKind::FNeg {
            dst,
            src,
            precision,
        } => op_json!("fneg", dst, src, precision),
        OpKind::FSqrt {
            dst,
            src,
            precision,
        } => op_json!("fsqrt", dst, src, precision),
        OpKind::FMin {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fmin", dst, src1, src2, precision),
        OpKind::FMax {
            dst,
            src1,
            src2,
            precision,
        } => op_json!("fmax", dst, src1, src2, precision),
        OpKind::FCmp {
            src1,
            src2,
            precision,
        } => op_json!("fcmp", src1, src2, precision),
        OpKind::X86FpCompare {
            src1,
            src2,
            elem,
            signaling,
            suppress_exceptions,
        } => op_json!(
            "x86_fp_compare",
            src1,
            src2,
            elem,
            signaling,
            suppress_exceptions
        ),
        OpKind::X86VectorFpCompare {
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            predicate,
            scalar,
            mask_destination,
            zero_upper,
            suppress_exceptions,
        } => op_json!(
            "x86_vector_fp_compare",
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            predicate,
            scalar,
            mask_destination,
            zero_upper,
            suppress_exceptions
        ),
        OpKind::X86GetExponent {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_get_exponent",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86GetMantissa {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_get_mantissa",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86RoundScale {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_round_scale",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86Reduce {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_reduce",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86Range {
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_range",
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86FixupImm {
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_fixup_imm",
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            imm,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86Exp2 {
            dst,
            src,
            mask,
            elem,
            width,
            lanes,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_exp2",
            dst,
            src,
            mask,
            elem,
            width,
            lanes,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86Recip14 {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
        } => op_json!(
            "x86_recip14",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing
        ),
        OpKind::X86Rsqrt14 {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
        } => op_json!(
            "x86_rsqrt14",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing
        ),
        OpKind::X86RecipFp16 {
            dst,
            merge,
            src,
            mask,
            width,
            lanes,
            scalar,
            mask_zeroing,
        } => op_json!(
            "x86_recip_fp16",
            dst,
            merge,
            src,
            mask,
            width,
            lanes,
            scalar,
            mask_zeroing
        ),
        OpKind::X86RsqrtFp16 {
            dst,
            merge,
            src,
            mask,
            width,
            lanes,
            scalar,
            mask_zeroing,
        } => op_json!(
            "x86_rsqrt_fp16",
            dst,
            merge,
            src,
            mask,
            width,
            lanes,
            scalar,
            mask_zeroing
        ),
        OpKind::X86Recip28 {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_recip28",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86Rsqrt28 {
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions,
        } => op_json!(
            "x86_rsqrt28",
            dst,
            merge,
            src,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            suppress_exceptions
        ),
        OpKind::X86ScaleF {
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_scale_f",
            dst,
            src1,
            src2,
            mask,
            elem,
            width,
            lanes,
            scalar,
            mask_zeroing,
            round,
            suppress_exceptions
        ),
        OpKind::X86FpToInt {
            dst,
            src,
            elem,
            int_width,
            signed,
            truncate,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_fp_to_int",
            dst,
            src,
            elem,
            int_width,
            signed,
            truncate,
            round,
            suppress_exceptions
        ),
        OpKind::X86ScalarFpToIntSat {
            dst,
            src,
            elem,
            int_width,
            signed,
            suppress_exceptions,
        } => op_json!(
            "x86_scalar_fp_to_int_sat",
            dst,
            src,
            elem,
            int_width,
            signed,
            suppress_exceptions
        ),
        OpKind::X86IntToFp {
            dst,
            merge,
            src,
            elem,
            int_width,
            signed,
            round,
            suppress_exceptions,
            zero_upper,
        } => op_json!(
            "x86_int_to_fp",
            dst,
            merge,
            src,
            elem,
            int_width,
            signed,
            round,
            suppress_exceptions,
            zero_upper
        ),
        OpKind::X86FpConvert {
            dst,
            merge,
            src,
            mask,
            from,
            to,
            mask_zeroing,
            round,
            suppress_exceptions,
            zero_upper,
        } => op_json!(
            "x86_fp_convert",
            dst,
            merge,
            src,
            mask,
            from,
            to,
            mask_zeroing,
            round,
            suppress_exceptions,
            zero_upper
        ),
        OpKind::X86PackedFpConvert {
            dst,
            src,
            mask,
            from,
            to,
            lanes,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
            report_fp16_denormal,
        } => op_json!(
            "x86_packed_fp_convert",
            dst,
            src,
            mask,
            from,
            to,
            lanes,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
            report_fp16_denormal
        ),
        OpKind::X86PackedIntToFp {
            dst,
            src,
            mask,
            int_elem,
            fp_elem,
            signed,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_packed_int_to_fp",
            dst,
            src,
            mask,
            int_elem,
            fp_elem,
            signed,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions
        ),
        OpKind::X86PackedFpToInt {
            dst,
            src,
            mask,
            fp_elem,
            int_elem,
            signed,
            truncate,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_packed_fp_to_int",
            dst,
            src,
            mask,
            fp_elem,
            int_elem,
            signed,
            truncate,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions
        ),
        OpKind::X86PackedIntToFp16 {
            dst,
            src,
            mask,
            int_elem,
            signed,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_packed_int_to_fp16",
            dst,
            src,
            mask,
            int_elem,
            signed,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions
        ),
        OpKind::X86PackedFp16ToInt {
            dst,
            src,
            mask,
            int_elem,
            signed,
            truncate,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_packed_fp16_to_int",
            dst,
            src,
            mask,
            int_elem,
            signed,
            truncate,
            lanes,
            src_width,
            dst_width,
            mask_zeroing,
            zero_upper,
            round,
            suppress_exceptions
        ),
        OpKind::X86PackedFpConvertStore {
            addr,
            src,
            mask,
            lanes,
            round,
        } => op_json!("x86_packed_fp_convert_store", addr, src, mask, lanes, round),
        OpKind::X86LoadMxcsr {
            addr,
            requires_apx,
            next_pc,
        } => op_json!("x86_load_mxcsr", addr, requires_apx, next_pc),
        OpKind::X86StoreMxcsr { addr, requires_apx } => {
            op_json!("x86_store_mxcsr", addr, requires_apx)
        }
        OpKind::X86CacheControl { addr, kind } => op_json!("x86_cache_control", addr, kind),
        OpKind::X86CheckAlignment { addr, alignment } => {
            op_json!("x86_check_alignment", addr, alignment)
        }
        OpKind::X86CheckAlignmentAc {
            addr,
            access_size,
            alignment,
            stack_segment,
            natural_alignment,
        } => op_json!(
            "x86_check_alignment_ac",
            addr,
            access_size,
            alignment,
            stack_segment,
            natural_alignment
        ),
        OpKind::X86X87Control { kind, addr } => op_json!("x86_x87_control", kind, addr),
        OpKind::X86X87Data {
            kind,
            addr,
            st,
            fop,
        } => op_json!("x86_x87_data", kind, addr, st, fop),
        OpKind::X86FxSave { addr, rex_w } => op_json!("x86_fxsave", addr, rex_w),
        OpKind::X86FxRstor { addr, rex_w } => op_json!("x86_fxrstor", addr, rex_w),
        OpKind::X86XSave {
            addr,
            rex_w,
            kind,
            src_low,
            src_high,
        } => op_json!("x86_xsave", addr, rex_w, kind, src_low, src_high),
        OpKind::X86XRstor {
            addr,
            rex_w,
            supervisor,
            src_low,
            src_high,
        } => op_json!("x86_xrstor", addr, rex_w, supervisor, src_low, src_high),
        OpKind::X86Cmpxchg8b16b {
            addr,
            wide,
            locked,
            compare_lo,
            compare_hi,
            new_lo,
            new_hi,
            dst_lo,
            dst_hi,
        } => op_json!(
            "x86_cmpxchg8b16b",
            addr,
            wide,
            locked,
            compare_lo,
            compare_hi,
            new_lo,
            new_hi,
            dst_lo,
            dst_hi
        ),
        OpKind::X86Random { dst, width, seed } => op_json!("x86_random", dst, width, seed),
        OpKind::X86ReadPid { dst } => op_json!("x86_read_pid", dst),
        OpKind::X86XGetBv {
            dst_low,
            dst_high,
            selector,
        } => op_json!("x86_xgetbv", dst_low, dst_high, selector),
        OpKind::X86XSetBv {
            selector,
            src_low,
            src_high,
        } => op_json!("x86_xsetbv", selector, src_low, src_high),
        OpKind::X86Clts => op_json!("x86_clts"),
        OpKind::X86Msr(X86MsrOp {
            eax,
            ecx,
            edx,
            write,
            next_pc,
        }) => op_json!("x86_msr", eax, ecx, edx, write, next_pc),
        OpKind::X86ReadControl { dst, control } => {
            op_json!("x86_read_control", dst, control)
        }
        OpKind::X86Smsw(X86SmswOp {
            target,
            requires_apx,
        }) => op_json!("x86_smsw", target, requires_apx),
        OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
            selector,
            target,
            requires_apx,
        }) => op_json!("x86_system_selector_store", selector, target, requires_apx),
        OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
            selector,
            source,
            requires_apx,
            next_pc,
        }) => op_json!(
            "x86_system_selector_load",
            selector,
            source,
            requires_apx,
            next_pc
        ),
        OpKind::X86SelectorVerify(X86SelectorVerifyOp {
            kind,
            source,
            requires_apx,
            next_pc,
        }) => op_json!("x86_selector_verify", kind, source, requires_apx, next_pc),
        OpKind::X86SelectorQuery(X86SelectorQueryOp {
            kind,
            dst,
            source,
            width,
            requires_apx,
            next_pc,
        }) => op_json!(
            "x86_selector_query",
            kind,
            dst,
            source,
            width,
            requires_apx,
            next_pc
        ),
        OpKind::X86FarJump(X86FarJumpOp {
            addr,
            target,
            offset_width,
            requires_apx,
            stack_segment,
            next_pc,
        }) => op_json!(
            "x86_far_jump",
            addr,
            target,
            offset_width,
            requires_apx,
            stack_segment,
            next_pc
        ),
        OpKind::X86FarCall(X86FarCallOp {
            addr,
            target,
            offset_width,
            requires_apx,
            stack_segment,
            next_pc,
        }) => op_json!(
            "x86_far_call",
            addr,
            target,
            offset_width,
            requires_apx,
            stack_segment,
            next_pc
        ),
        OpKind::X86FarReturn(X86FarReturnOp {
            target,
            offset_width,
            pop_bytes,
            requires_apx,
            next_pc,
        }) => op_json!(
            "x86_far_return",
            target,
            offset_width,
            pop_bytes,
            requires_apx,
            next_pc
        ),
        OpKind::X86FastSystemTransfer(X86FastSystemTransferOp {
            kind,
            target,
            stack_pointer,
            return_target,
            return_stack_pointer,
            operand64,
            next_pc,
        }) => op_json!(
            "x86_fast_system_transfer",
            kind,
            target,
            stack_pointer,
            return_target,
            return_stack_pointer,
            operand64,
            next_pc
        ),
        OpKind::X86Lmsw(X86LmswOp {
            source,
            requires_apx,
            next_pc,
        }) => op_json!("x86_lmsw", source, requires_apx, next_pc),
        OpKind::X86DescriptorTableStore(X86DescriptorTableStoreOp {
            addr,
            table,
            requires_apx,
        }) => op_json!("x86_descriptor_table_store", addr, table, requires_apx),
        OpKind::X86DescriptorTableLoad(X86DescriptorTableLoadOp {
            addr,
            table,
            requires_apx,
            next_pc,
        }) => op_json!(
            "x86_descriptor_table_load",
            addr,
            table,
            requires_apx,
            next_pc
        ),
        OpKind::X86Invlpg(X86InvlpgOp {
            addr,
            requires_apx,
            next_pc,
        }) => op_json!("x86_invlpg", addr, requires_apx, next_pc),
        OpKind::X86Invpcid(X86InvpcidOp {
            invpcid_type,
            addr,
            requires_apx,
            stack_segment,
            next_pc,
        }) => op_json!(
            "x86_invpcid",
            invpcid_type,
            addr,
            requires_apx,
            stack_segment,
            next_pc
        ),
        OpKind::X86WriteControl {
            src,
            control,
            next_pc,
        } => op_json!("x86_write_control", src, control, next_pc),
        OpKind::X86ReadDebug { dst, debug } => {
            op_json!("x86_read_debug", dst, debug)
        }
        OpKind::X86WriteDebug { src, debug } => {
            op_json!("x86_write_debug", src, debug)
        }
        OpKind::X86FsGsBase {
            operand,
            base,
            write,
            width,
            requires_apx,
        } => op_json!("x86_fsgsbase", operand, base, write, width, requires_apx),
        OpKind::X86SwapGs {
            gs_base,
            kernel_gs_base,
        } => op_json!("x86_swapgs", gs_base, kernel_gs_base),
        OpKind::X86MonitorMwait(X86MonitorMwaitOp {
            rcx,
            hint,
            addr,
            stack_segment,
        }) => {
            op_json!("x86_monitor_mwait", rcx, hint, addr, stack_segment)
        }
        OpKind::X86WaitPkg(X86WaitPkgOp::Umonitor {
            addr,
            stack_segment,
        }) => op_json!("x86_waitpkg_umonitor", addr, stack_segment),
        OpKind::X86WaitPkg(X86WaitPkgOp::Umwait {
            control,
            deadline_low,
            deadline_high,
        }) => op_json!("x86_waitpkg_umwait", control, deadline_low, deadline_high),
        OpKind::X86WaitPkg(X86WaitPkgOp::Tpause {
            control,
            deadline_low,
            deadline_high,
        }) => op_json!("x86_waitpkg_tpause", control, deadline_low, deadline_high),
        OpKind::X86Pkru {
            eax,
            ecx,
            edx,
            pkru,
            write,
        } => op_json!("x86_pkru", eax, ecx, edx, pkru, write),
        OpKind::X86Cpuid {
            dst_eax,
            dst_ebx,
            dst_ecx,
            dst_edx,
            leaf,
            subleaf,
        } => op_json!(
            "x86_cpuid",
            dst_eax,
            dst_ebx,
            dst_ecx,
            dst_edx,
            leaf,
            subleaf
        ),
        OpKind::FConvert { dst, src, from, to } => op_json!("fconvert", dst, src, from, to),
        OpKind::HexFp {
            dst,
            src1,
            src2,
            op,
        } => op_json!("hexfp", dst, src1, src2, op),
        OpKind::HexFp3 {
            dst,
            src1,
            src2,
            src3,
            negate_product,
            lib,
        } => op_json!("hexfp3", dst, src1, src2, src3, negate_product, lib),
        OpKind::HexFpRecip {
            dst,
            pred,
            src1,
            src2,
            kind,
        } => op_json!("hexfp_recip", dst, pred, src1, src2, kind),
        OpKind::IntToFp {
            dst,
            src,
            int_width,
            fp_precision,
            signed,
        } => op_json!("int_to_fp", dst, src, int_width, fp_precision, signed),
        OpKind::FpToInt {
            dst,
            src,
            fp_precision,
            int_width,
            signed,
            round,
        } => op_json!(
            "fp_to_int",
            dst,
            src,
            fp_precision,
            int_width,
            signed,
            round
        ),
        OpKind::FRound {
            dst,
            src,
            precision,
            mode,
        } => op_json!("fround", dst, src, precision, mode),
        OpKind::X86Round {
            dst,
            merge,
            src,
            elem,
            width,
            lanes,
            scalar_source,
            zero_upper,
            mode,
            suppress_precision,
        } => op_json!(
            "x86_round",
            dst,
            merge,
            src,
            elem,
            width,
            lanes,
            scalar_source,
            zero_upper,
            mode,
            suppress_precision
        ),
        OpKind::X86DotProduct {
            dst,
            src1,
            src2,
            elem,
            width,
            imm,
        } => op_json!("x86_dot_product", dst, src1, src2, elem, width, imm),
        OpKind::VAdd {
            dst,
            src1,
            src2,
            elem,
            lanes,
        } => op_json!("vadd", dst, src1, src2, elem, lanes),
        OpKind::VSub {
            dst,
            src1,
            src2,
            elem,
            lanes,
        } => op_json!("vsub", dst, src1, src2, elem, lanes),
        OpKind::VAddSubSat {
            dst,
            src1,
            src2,
            elem,
            lanes,
            subtract,
            signed,
        } => op_json!(
            "vaddsub_sat",
            dst,
            src1,
            src2,
            elem,
            lanes,
            subtract,
            signed
        ),
        OpKind::VMax {
            dst,
            src1,
            src2,
            elem,
            lanes,
        } => op_json!("vmax", dst, src1, src2, elem, lanes),
        OpKind::VX86MinMax {
            dst,
            src1,
            src2,
            elem,
            lanes,
            min,
        } => op_json!("vx86_minmax", dst, src1, src2, elem, lanes, min),
        OpKind::VMul {
            dst,
            src1,
            src2,
            elem,
            lanes,
        } => op_json!("vmul", dst, src1, src2, elem, lanes),
        OpKind::VDiv {
            dst,
            src1,
            src2,
            elem,
            lanes,
        } => op_json!("vdiv", dst, src1, src2, elem, lanes),
        OpKind::VUnary {
            dst,
            src,
            elem,
            lanes,
            op,
        } => op_json!("vunary", dst, src, elem, lanes, op),
        OpKind::X86Sqrt {
            dst,
            src,
            elem,
            lanes,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_sqrt",
            dst,
            src,
            elem,
            lanes,
            round,
            suppress_exceptions
        ),
        OpKind::X86FpBinary {
            dst,
            src1,
            src2,
            mask,
            elem,
            lanes,
            op,
            round,
            suppress_exceptions,
        } => op_json!(
            "x86_fp_binary",
            dst,
            src1,
            src2,
            mask,
            elem,
            lanes,
            op,
            round,
            suppress_exceptions
        ),
        OpKind::VReduce {
            dst,
            src,
            elem,
            lanes,
            op,
        } => op_json!("vreduce", dst, src, elem, lanes, op),
        OpKind::VFMinMaxNm {
            dst,
            src1,
            src2,
            elem,
            lanes,
            min,
        } => op_json!("vfminmaxnm", dst, src1, src2, elem, lanes, min),
        OpKind::VPermute2 {
            dst,
            src1,
            src2,
            elem,
            lanes,
            kind,
        } => op_json!("vpermute2", dst, src1, src2, elem, lanes, kind),
        OpKind::VTableLookup {
            dst,
            table,
            num_tables,
            index,
            lanes,
            is_tbx,
        } => op_json!("vtbl", dst, table, num_tables, index, lanes, is_tbx),
        OpKind::VAnd {
            dst,
            src1,
            src2,
            width,
        } => op_json!("vand", dst, src1, src2, width),
        OpKind::VAndNot {
            dst,
            src1,
            src2,
            width,
        } => op_json!("vandnot", dst, src1, src2, width),
        OpKind::VOr {
            dst,
            src1,
            src2,
            width,
        } => op_json!("vor", dst, src1, src2, width),
        OpKind::VXor {
            dst,
            src1,
            src2,
            width,
        } => op_json!("vxor", dst, src1, src2, width),
        OpKind::VBitSelect {
            dst,
            mask,
            src_true,
            src_false,
            width,
        } => op_json!("vbitselect", dst, mask, src_true, src_false, width),
        OpKind::VLane {
            dst,
            src1,
            src2,
            elem,
            lanes,
            op,
            signed,
            set_ovf,
        } => op_json!("vlane", dst, src1, src2, elem, lanes, op, signed, set_ovf),
        OpKind::VWidenMul {
            dst_lo,
            dst_hi,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            acc,
        } => op_json!(
            "vwiden_mul",
            dst_lo,
            dst_hi,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            acc
        ),
        OpKind::VWidenExt {
            dst_lo,
            dst_hi,
            src,
            src_elem,
            signed,
            interleave,
        } => op_json!(
            "vwiden_ext",
            dst_lo,
            dst_hi,
            src,
            src_elem,
            signed,
            interleave
        ),
        OpKind::VWidenAddSub {
            dst_lo,
            dst_hi,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            sub,
            acc,
        } => op_json!(
            "vwiden_add_sub",
            dst_lo,
            dst_hi,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            sub,
            acc
        ),
        OpKind::VLaneUnary {
            dst,
            src,
            elem,
            lanes,
            op,
            signed,
        } => op_json!("vlane_unary", dst, src, elem, lanes, op, signed),
        OpKind::VNavg {
            dst,
            src1,
            src2,
            elem,
            lanes,
            signed,
        } => op_json!("vnavg", dst, src1, src2, elem, lanes, signed),
        OpKind::VShiftAcc {
            dst,
            src,
            amount,
            shift,
            elem,
            lanes,
        } => op_json!("vshift_acc", dst, src, amount, shift, elem, lanes),
        OpKind::VPack {
            dst,
            src1,
            src2,
            elem,
            odd,
        } => op_json!("vpack", dst, src1, src2, elem, odd),
        OpKind::VPackSat {
            dst,
            src1,
            src2,
            src_elem,
            to_unsigned,
            src_lanes,
            block_lanes,
        } => op_json!(
            "vpack_sat",
            dst,
            src1,
            src2,
            src_elem,
            to_unsigned,
            src_lanes,
            block_lanes
        ),
        OpKind::VLut16 {
            dst_lo,
            dst_hi,
            src_idx,
            table,
            sel,
            nomatch,
            oracc,
        } => op_json!(
            "vlut16", dst_lo, dst_hi, src_idx, table, sel, nomatch, oracc
        ),
        OpKind::VLut {
            dst,
            src_idx,
            table,
            sel,
            nomatch,
            oracc,
        } => op_json!("vlut", dst, src_idx, table, sel, nomatch, oracc),
        OpKind::VDelta {
            dst,
            src,
            control,
            ascending,
        } => op_json!("vdelta", dst, src, control, ascending),
        OpKind::VShuffVdd {
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            amount,
        } => op_json!("vshuff_vdd", dst_lo, dst_hi, src_lo, src_hi, amount),
        OpKind::VDealB4W { dst, src1, src2 } => op_json!("vdeal_b4w", dst, src1, src2),
        OpKind::VAlign {
            dst,
            src1,
            src2,
            amount,
            left,
        } => op_json!("valign", dst, src1, src2, amount, left),
        OpKind::VShuffle2 {
            dst,
            src,
            elem,
            deal,
        } => op_json!("vshuffle2", dst, src, elem, deal),
        OpKind::VShuffleEO {
            dst,
            src1,
            src2,
            elem,
            odd,
        } => op_json!("vshuffle_eo", dst, src1, src2, elem, odd),
        OpKind::VShuffleEOPair { .. } => op_json!("vshuffle_eo_pair"),
        OpKind::VShuffleDeal { .. } => op_json!("vshuffle_deal"),
        OpKind::VDealVdd { .. } => op_json!("vdeal_vdd"),
        OpKind::VUnpackOAcc { .. } => op_json!("vunpack_o_acc"),
        OpKind::VInsertWordR { .. } => op_json!("vinsert_word_r"),
        OpKind::VExtractWord { .. } => op_json!("vextract_word"),
        OpKind::VLut4 { .. } => op_json!("vlut4"),
        OpKind::VRotr { .. } => op_json!("vrotr"),
        OpKind::VAddSubMixedSat { .. } => op_json!("vaddsub_mixed_sat"),
        OpKind::VSetPredQ { .. } => op_json!("vset_pred_q"),
        OpKind::VShuffEqQ { .. } => op_json!("vshuffeq_q"),
        OpKind::VMpaHhSat { .. } => op_json!("vmpa_hh_sat"),
        OpKind::VMpyHsatAcc { .. } => op_json!("vmpy_hsat_acc"),
        OpKind::VAsrInto { .. } => op_json!("vasr_into"),
        OpKind::V6Mpy { .. } => op_json!("v6mpy"),
        OpKind::VCmpToQ {
            dst,
            src1,
            src2,
            cond,
            elem,
            lanes,
            accumulate,
        } => op_json!("vcmp_to_q", dst, src1, src2, cond, elem, lanes, accumulate),
        OpKind::VQFromVAndR {
            dst,
            src1,
            src2,
            oracc,
        } => {
            op_json!("vq_from_v_and_r", dst, src1, src2, oracc)
        }
        OpKind::VMaskZero {
            dst,
            mask_q,
            src,
            negate,
            oracc,
        } => op_json!("vmask_zero", dst, mask_q, src, negate, oracc),
        OpKind::VLaneCond { .. } => op_json!("vlane_cond"),
        OpKind::VCarry { .. } => op_json!("vcarry"),
        OpKind::VSwap { .. } => op_json!("vswap"),
        OpKind::VCondMove { .. } => op_json!("vcond_move"),
        OpKind::VPrefixSumQ { .. } => op_json!("vprefix_sum_q"),
        OpKind::VHist { .. } => op_json!("vhist"),
        OpKind::VBlend {
            dst,
            mask_q,
            src_true,
            src_false,
        } => op_json!("vblend", dst, mask_q, src_true, src_false),
        OpKind::VShiftV {
            dst,
            src,
            amount,
            elem,
            lanes,
            kind,
        } => op_json!("vshift_v", dst, src, amount, elem, lanes, kind),
        OpKind::VMulShiftSat {
            dst,
            src1,
            src2,
            src_elem,
            lanes,
            signed1,
            signed2,
            shift_left,
            round,
            sat_bits,
            out_shift,
        } => op_json!(
            "vmul_shift_sat",
            dst,
            src1,
            src2,
            src_elem,
            lanes,
            signed1,
            signed2,
            shift_left,
            round,
            sat_bits,
            out_shift
        ),
        OpKind::VNarrowShiftSat {
            dst,
            src_lo,
            src_hi,
            src_elem,
            amount,
            arith,
            round,
            sat,
            set_ovf,
        } => op_json!(
            "vnarrow_shift_sat",
            dst,
            src_lo,
            src_hi,
            src_elem,
            amount,
            arith,
            round,
            sat,
            set_ovf
        ),
        OpKind::VSatDW {
            dst,
            src_lo,
            src_hi,
        } => op_json!("vsat_dw", dst, src_lo, src_hi),
        OpKind::VNarrowShiftV {
            dst,
            src_lo,
            src_hi,
            amount,
            src_elem,
            arith,
            round,
        } => op_json!(
            "vnarrow_shift_v",
            dst,
            src_lo,
            src_hi,
            amount,
            src_elem,
            arith,
            round
        ),
        OpKind::VMulSubLane {
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd,
            signed1,
            signed2,
            acc,
        } => op_json!(
            "vmul_sub_lane",
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd,
            signed1,
            signed2,
            acc
        ),
        OpKind::VMulSubLaneFrac {
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd,
            signed1,
            signed2,
            shl1,
            rnd,
            shift,
            sat,
            acc,
            rnd2,
        } => op_json!(
            "vmul_sub_lane_frac",
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd,
            signed1,
            signed2,
            shl1,
            rnd,
            shift,
            sat,
            acc,
            rnd2
        ),
        OpKind::VMulSubLaneSh {
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd1,
            odd2,
            signed1,
            signed2,
            shl,
        } => op_json!(
            "vmul_sub_lane_sh",
            dst,
            src1,
            src2,
            out_elem,
            sub_elem,
            odd1,
            odd2,
            signed1,
            signed2,
            shl
        ),
        OpKind::VMulWord64Pair {
            dst_lo,
            dst_hi,
            src1,
            src2,
            mode,
        } => op_json!("vmul_word64_pair", dst_lo, dst_hi, src1, src2, mode),
        OpKind::VMulEvenWiden {
            dst,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            acc,
        } => op_json!(
            "vmul_even_widen",
            dst,
            src1,
            src2,
            src_elem,
            signed1,
            signed2,
            acc
        ),
        OpKind::VPairPairReduceMul {
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2_lo,
            src2_hi,
            narrow_elem,
            out_elem,
            signed1,
            signed2,
        } => op_json!(
            "vpair_pair_reduce_mul",
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2_lo,
            src2_hi,
            narrow_elem,
            out_elem,
            signed1,
            signed2
        ),
        OpKind::VPairReduceMul {
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            pair_elem,
            rt_elem,
            out_elem,
            signed1,
            signed2,
            acc,
        } => op_json!(
            "vpair_reduce_mul",
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            pair_elem,
            rt_elem,
            out_elem,
            signed1,
            signed2,
            acc
        ),
        OpKind::VSlideReduceMul {
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            src_elem,
            rt_elem,
            out_elem,
            mode,
            signed1,
            signed2,
            sat,
            set_ovf,
            acc,
        } => op_json!(
            "vslide_reduce_mul",
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            src_elem,
            rt_elem,
            out_elem,
            mode,
            signed1,
            signed2,
            sat,
            set_ovf,
            acc
        ),
        OpKind::VRotReduceMulPair {
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            src_elem,
            rt_elem,
            out_elem,
            imm,
            mode,
            signed1,
            signed2,
            acc,
            abs_diff,
        } => op_json!(
            "vrot_reduce_mul_pair",
            dst_lo,
            dst_hi,
            src_lo,
            src_hi,
            src2,
            src_elem,
            rt_elem,
            out_elem,
            imm,
            mode,
            signed1,
            signed2,
            acc,
            abs_diff
        ),
        OpKind::VReduceMul {
            dst,
            src1,
            src2,
            src1_elem,
            src2_elem,
            out_elem,
            taps,
            signed1,
            signed2,
            sat,
            set_ovf,
            acc,
        } => op_json!(
            "vreduce_mul",
            dst,
            src1,
            src2,
            src1_elem,
            src2_elem,
            out_elem,
            taps,
            signed1,
            signed2,
            sat,
            set_ovf,
            acc
        ),
        OpKind::VShift {
            dst,
            src,
            amount,
            shift,
            elem,
            lanes,
        } => op_json!("vshift", dst, src, amount, shift, elem, lanes),
        OpKind::VCmp {
            dst,
            src1,
            src2,
            cond,
            elem,
            lanes,
        } => op_json!("vcmp", dst, src1, src2, cond, elem, lanes),
        OpKind::VMov { dst, src, width } => op_json!("vmov", dst, src, width),
        OpKind::VInsertLane {
            dst,
            vec,
            scalar,
            lane,
            elem,
        } => op_json!("vinsert_lane", dst, vec, scalar, lane, elem),
        OpKind::VExtractLane {
            dst,
            vec,
            lane,
            elem,
            sign,
        } => op_json!("vextract_lane", dst, vec, lane, elem, sign),
        OpKind::VShuffle {
            dst,
            src1,
            src2,
            indices,
            elem,
            lanes,
        } => op_json!("vshuffle", dst, src1, src2, indices, elem, lanes),
        OpKind::VInterleave {
            dst,
            src1,
            src2,
            elem,
            lanes,
            block_lanes,
            high,
        } => op_json!(
            "vinterleave",
            dst,
            src1,
            src2,
            elem,
            lanes,
            block_lanes,
            high
        ),
        OpKind::VByteShuffle {
            dst,
            src,
            control,
            lanes,
            block_lanes,
        } => op_json!("vbyte_shuffle", dst, src, control, lanes, block_lanes),
        OpKind::VHorizontalBin {
            dst,
            src1,
            src2,
            elem,
            lanes,
            block_lanes,
            subtract,
            saturating,
        } => op_json!(
            "vhorizontal_bin",
            dst,
            src1,
            src2,
            elem,
            lanes,
            block_lanes,
            subtract,
            saturating
        ),
        OpKind::VLoad { dst, addr, width } => op_json!("vload", dst, addr, width),
        OpKind::PredVLoad {
            dst,
            cond,
            addr,
            width,
        } => op_json!("pred_vload", dst, cond, addr, width),
        OpKind::VStore { src, addr, width } => op_json!("vstore", src, addr, width),
        OpKind::X86Enter(op) => x86_frame::enter_json(op),
        OpKind::X86StackFlags(op) => x86_frame::stack_flags_json(op),
        OpKind::X86Leave(op) => x86_frame::leave_json(op),
        OpKind::IoIn { dst, port, width } => op_json!("io_in", dst, port, width),
        OpKind::IoOut { port, value, width } => op_json!("io_out", port, value, width),
        OpKind::VBroadcast {
            dst,
            scalar,
            elem,
            lanes,
        } => op_json!("vbroadcast", dst, scalar, elem, lanes),
        OpKind::VMin {
            dst,
            src1,
            src2,
            elem,
            lanes,
            signed,
        } => op_json!("vmin", dst, src1, src2, elem, lanes, signed),
        OpKind::VFma {
            dst,
            src1,
            src2,
            acc,
            elem,
            lanes,
            negate_product,
            negate_acc,
        } => op_json!(
            "vfma",
            dst,
            src1,
            src2,
            acc,
            elem,
            lanes,
            negate_product,
            negate_acc
        ),
        OpKind::X86Fma(op) => x86_fma::op_json(op),
        OpKind::X86FP16Fma {
            dst,
            src1,
            src2,
            src3,
            mask,
            kind,
            order,
            round,
            lanes,
        } => op_json!(
            "x86_fp16_fma",
            dst,
            src1,
            src2,
            src3,
            mask,
            kind,
            order,
            round,
            lanes
        ),
        OpKind::X86FP16Complex {
            dst,
            src1,
            src2,
            mask,
            width,
            pairs,
            scalar,
            mask_zeroing,
            accumulate,
            conjugate,
            round,
        } => op_json!(
            "x86_fp16_complex",
            dst,
            src1,
            src2,
            mask,
            width,
            pairs,
            scalar,
            mask_zeroing,
            accumulate,
            conjugate,
            round
        ),
        OpKind::X86FourFma {
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask,
            scalar,
            negate_product,
            mask_zeroing,
        } => op_json!(
            "x86_four_fma",
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask,
            scalar,
            negate_product,
            mask_zeroing
        ),
        OpKind::X86FourDotProduct {
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask,
            saturating,
            mask_zeroing,
        } => op_json!(
            "x86_four_dot_product",
            dst,
            src0,
            src1,
            src2,
            src3,
            mem,
            mask,
            saturating,
            mask_zeroing
        ),
        OpKind::VDotProduct {
            dst,
            acc,
            src1,
            src2,
            mask,
            src_elem,
            acc_elem,
            width,
            src1_unsigned,
            saturate,
            zeroing,
        } => op_json!(
            "vdot_product",
            dst,
            acc,
            src1,
            src2,
            mask,
            src_elem,
            acc_elem,
            width,
            src1_unsigned,
            saturate,
            zeroing
        ),
        OpKind::VMultiplyAdd52 {
            dst,
            acc,
            src1,
            src2,
            mask,
            width,
            high,
            zeroing,
        } => op_json!(
            "vmultiply_add52",
            dst,
            acc,
            src1,
            src2,
            mask,
            width,
            high,
            zeroing
        ),
        OpKind::VPopcnt {
            dst,
            src,
            mask,
            elem,
            width,
            zeroing,
        } => op_json!("vpopcnt", dst, src, mask, elem, width, zeroing),
        OpKind::VLeadingZeros {
            dst,
            src,
            mask,
            elem,
            width,
            zeroing,
        } => op_json!("vleading_zeros", dst, src, mask, elem, width, zeroing),
        OpKind::VConflict {
            dst,
            src,
            mask,
            elem,
            width,
            zeroing,
        } => op_json!("vconflict", dst, src, mask, elem, width, zeroing),
        OpKind::VPermute {
            dst,
            src1,
            src2,
            indices,
            elem,
            width,
            overwrite_table,
        } => op_json!(
            "vpermute",
            dst,
            src1,
            src2,
            indices,
            elem,
            width,
            overwrite_table
        ),
        OpKind::X86PermuteBytesWords {
            dst,
            table1,
            table2,
            indices,
            mask,
            elem,
            width,
            overwrite_table,
            zeroing,
        } => op_json!(
            "x86_permute_bytes_words",
            dst,
            table1,
            table2,
            indices,
            mask,
            elem,
            width,
            overwrite_table,
            zeroing
        ),
        OpKind::VShuffleBitQM {
            dst,
            src,
            indices,
            mask,
            width,
        } => op_json!("vshuffle_bit_qm", dst, src, indices, mask, width),
        OpKind::VCompress {
            dst,
            src,
            mask,
            elem,
            width,
            zeroing,
        } => op_json!("vcompress", dst, src, mask, elem, width, zeroing),
        OpKind::VExpand {
            dst,
            src,
            mask,
            elem,
            width,
            zeroing,
        } => op_json!("vexpand", dst, src, mask, elem, width, zeroing),
        OpKind::X86NarrowInt {
            dst,
            src,
            mask,
            src_elem,
            dst_elem,
            width,
            mode,
            zeroing,
        } => op_json!(
            "x86_narrow_int",
            dst,
            src,
            mask,
            src_elem,
            dst_elem,
            width,
            mode,
            zeroing
        ),
        OpKind::VDotProductBF16 {
            dst,
            acc,
            src1,
            src2,
            mask,
            width,
            zeroing,
        } => op_json!(
            "vdot_product_bf16",
            dst,
            acc,
            src1,
            src2,
            mask,
            width,
            zeroing
        ),
        OpKind::VCvtFP32ToBF16 {
            dst,
            src1,
            src2,
            mask,
            width,
            zeroing,
        } => op_json!("vcvt_fp32_to_bf16", dst, src1, src2, mask, width, zeroing),
        OpKind::VCvtBF16ToFP32 { dst, src, width } => {
            op_json!("vcvt_bf16_to_fp32", dst, src, width)
        }
        OpKind::VFP16Arith {
            dst,
            src1,
            src2,
            mask,
            op,
            round,
            width,
            lanes,
            zeroing,
        } => op_json!(
            "vfp16_arith",
            dst,
            src1,
            src2,
            mask,
            op,
            round,
            width,
            lanes,
            zeroing
        ),
        OpKind::VCvtFpToIntSat {
            dst,
            src,
            mask,
            fp_elem,
            int_elem,
            width,
            signed,
            truncate,
            round,
            zeroing,
            suppress_exceptions,
        } => op_json!(
            "vcvt_fp_to_int_sat",
            dst,
            src,
            mask,
            fp_elem,
            int_elem,
            width,
            signed,
            truncate,
            round,
            zeroing,
            suppress_exceptions
        ),
        OpKind::VMinMax {
            dst,
            src1,
            src2,
            elem,
            width,
            imm,
        } => op_json!("vmin_max", dst, src1, src2, elem, width, imm),
        OpKind::VMpsadbw {
            dst,
            src1,
            src2,
            mask,
            width,
            imm,
            zeroing,
        } => op_json!("vmpsadbw", dst, src1, src2, mask, width, imm, zeroing),
        OpKind::VSadBytes {
            dst,
            src1,
            src2,
            width,
        } => op_json!("vsad_bytes", dst, src1, src2, width),
        OpKind::X86Phminposuw { dst, src } => op_json!("x86_phminposuw", dst, src),
        OpKind::X86MovMask {
            dst,
            src,
            elem,
            lanes,
            dst_width,
        } => op_json!("x86_mov_mask", dst, src, elem, lanes, dst_width),
        OpKind::X86MovdQ {
            dst,
            src,
            width,
            zero_upper,
        } => op_json!("x86_movd_q", dst, src, width, zero_upper),
        OpKind::X86Aes {
            dst,
            src1,
            src2,
            width,
            op,
            imm,
        } => op_json!("x86_aes", dst, src1, src2, width, op, imm),
        OpKind::X86Sha32 {
            dst,
            src1,
            src2,
            wk,
            op,
            imm,
        } => op_json!("x86_sha32", dst, src1, src2, wk, op, imm),
        OpKind::X86PackedStringCompare {
            dst,
            src1,
            src2,
            len1,
            len2,
            length_width,
            kind,
            imm,
            zero_upper,
        } => op_json!(
            "x86_packed_string_compare",
            dst,
            src1,
            src2,
            len1,
            len2,
            length_width,
            kind,
            imm,
            zero_upper
        ),
        OpKind::X86Sha512Msg1 { dst, src } => op_json!("x86_sha512_msg1", dst, src),
        OpKind::X86Sha512Msg2 { dst, src } => op_json!("x86_sha512_msg2", dst, src),
        OpKind::X86Sha512Rounds2 { dst, state, wk } => {
            op_json!("x86_sha512_rounds2", dst, state, wk)
        }
        OpKind::X86Sm3Msg1 {
            dst, src1, src2, ..
        } => op_json!("x86_sm3_msg1", dst, src1, src2),
        OpKind::X86Sm3Msg2 {
            dst, src1, src2, ..
        } => op_json!("x86_sm3_msg2", dst, src1, src2),
        OpKind::X86Sm3Rounds2 {
            dst,
            state,
            words,
            imm,
        } => op_json!("x86_sm3_rounds2", dst, state, words, imm),
        OpKind::X86Sm4 {
            dst,
            src1,
            src2,
            width,
            key_schedule,
        } => op_json!("x86_sm4", dst, src1, src2, width, key_schedule),
        OpKind::X86Convert16ToFp32 {
            dst,
            src,
            width,
            fp16,
            odd,
            broadcast,
        } => op_json!(
            "x86_convert_16_to_fp32",
            dst,
            src,
            width,
            fp16,
            odd,
            broadcast
        ),
        OpKind::X86PackedShiftImm {
            dst,
            src,
            width,
            elem,
            shift,
            amount,
            byte_lane,
        } => op_json!(
            "x86_packed_shift_imm",
            dst,
            src,
            width,
            elem,
            shift,
            amount,
            byte_lane
        ),
        OpKind::X86PackedAlignRight {
            dst,
            high,
            low,
            width,
            amount,
        } => op_json!("x86_packed_align_right", dst, high, low, width, amount),
        OpKind::X86PackedShuffleImm {
            dst,
            src,
            width,
            elem,
            imm,
            high_words,
        } => op_json!(
            "x86_packed_shuffle_imm",
            dst,
            src,
            width,
            elem,
            imm,
            high_words
        ),
        OpKind::X86ThreeDNow {
            dst,
            src1,
            src2,
            kind,
        } => op_json!("x86_three_d_now", dst, src1, src2, kind),
        OpKind::X86PackedShift {
            dst,
            src,
            count,
            width,
            elem,
            shift,
        } => op_json!("x86_packed_shift", dst, src, count, width, elem, shift),
        OpKind::X86PackedShiftVariable {
            dst,
            src,
            count,
            mask,
            width,
            elem,
            shift,
            zeroing,
        } => op_json!(
            "x86_packed_shift_variable",
            dst,
            src,
            count,
            mask,
            width,
            elem,
            shift,
            zeroing
        ),
        OpKind::X86PackedRotate {
            dst,
            src,
            count,
            mask,
            amount,
            width,
            elem,
            left,
            zeroing,
        } => op_json!(
            "x86_packed_rotate",
            dst,
            src,
            count,
            mask,
            amount,
            width,
            elem,
            left,
            zeroing
        ),
        OpKind::X86XopPackedBit {
            dst,
            src,
            count,
            elem,
            kind,
        } => op_json!("x86_xop_packed_bit", dst, src, count, elem, kind),
        OpKind::X86TernaryLogic {
            dst,
            src1,
            src2,
            src3,
            mask,
            imm,
            width,
            elem,
            zeroing,
        } => op_json!(
            "x86_ternary_logic",
            dst,
            src1,
            src2,
            src3,
            mask,
            imm,
            width,
            elem,
            zeroing
        ),
        OpKind::X86PackedFunnelShift {
            dst,
            src,
            fill,
            count,
            mask,
            amount,
            width,
            elem,
            left,
            zeroing,
        } => op_json!(
            "x86_packed_funnel_shift",
            dst,
            src,
            fill,
            count,
            mask,
            amount,
            width,
            elem,
            left,
            zeroing
        ),
        OpKind::X86MultiShiftQB {
            dst,
            control,
            source,
            mask,
            width,
            zeroing,
        } => op_json!(
            "x86_multishift_qb",
            dst,
            control,
            source,
            mask,
            width,
            zeroing
        ),
        OpKind::VDotProductExt {
            dst,
            acc,
            src1,
            src2,
            src_elem,
            acc_elem,
            width,
            src1_signed,
            src2_signed,
            saturate,
        } => op_json!(
            "vdot_product_ext",
            dst,
            acc,
            src1,
            src2,
            src_elem,
            acc_elem,
            width,
            src1_signed,
            src2_signed,
            saturate
        ),
        OpKind::ReadFlags { dst } => op_json!("read_flags", dst),
        OpKind::WriteFlags { src } => op_json!("write_flags", src),
        OpKind::SetCF { value } => op_json!("set_cf", value),
        OpKind::SetDF { value } => op_json!("set_df", value),
        OpKind::SetAC { value } => op_json!("set_ac", value),
        OpKind::X86RequireApx => op_json!("x86_require_apx"),
        OpKind::X86RequireSse4a => op_json!("x86_require_sse4a"),
        OpKind::X86RequireTbm => op_json!("x86_require_tbm"),
        OpKind::X86RequireXop => op_json!("x86_require_xop"),
        OpKind::X86Sse4aBitfield {
            dst,
            source,
            kind,
            length,
            index,
        } => op_json!("x86_sse4a_bitfield", dst, source, kind, length, index),
        OpKind::X86Sse4aMovntStore { src, addr, width } => {
            op_json!("x86_sse4a_movnt_store", src, addr, width)
        }
        OpKind::X86Cli {
            requires_apx,
            next_pc,
        } => op_json!("x86_cli", requires_apx, next_pc),
        OpKind::X86Sti {
            requires_apx,
            next_pc,
        } => op_json!("x86_sti", requires_apx, next_pc),
        OpKind::CmcCF => op_json!("cmc_cf"),
        OpKind::MaterializeFlags => op_json!("materialize_flags"),
        OpKind::X86XTest => op_json!("x86_xtest"),
        OpKind::TestCondition { dst, cond } => op_json!("test_condition", dst, cond),
        OpKind::SetCC { dst, cond, width } => op_json!("set_cc", dst, cond, width),
        OpKind::Syscall { num, args } => op_json!("syscall", num, args),
        OpKind::Swi { imm } => op_json!("swi", imm),
        OpKind::ReadSysReg { dst, reg } => op_json!("read_sys_reg", dst, reg),
        OpKind::WriteSysReg { reg, src } => op_json!("write_sys_reg", reg, src),
        OpKind::X86ReadTsc(X86ReadTscOp {
            dst_lo,
            dst_hi,
            dst_aux,
        }) => op_json!("x86_read_tsc", dst_lo, dst_hi, dst_aux),
        OpKind::X86ReadPmc(X86ReadPmcOp {
            dst_lo,
            dst_hi,
            selector,
        }) => op_json!("x86_read_pmc", dst_lo, dst_hi, selector),
        OpKind::X86Opmask(op) => op_json!("x86_opmask", op),
        OpKind::Nop => op_json!("nop"),
        OpKind::Undefined { opcode } => {
            let mut obj = Map::new();
            obj.insert("opcode".to_string(), json!("undefined"));
            obj.insert("raw_opcode".to_string(), opcode.oracle_json());
            Value::Object(obj)
        }
        OpKind::Breakpoint => op_json!("breakpoint"),
        OpKind::BidirShift { .. } => op_json!("bidir_shift"),
        OpKind::SatN { .. } => op_json!("sat_n"),
        OpKind::ClMul { .. } => op_json!("clmul"),
        OpKind::Crc32C {
            dst,
            crc,
            data,
            data_width,
        } => op_json!("crc32c", dst, crc, data, data_width),
        OpKind::CmpyW128Sat { .. } => op_json!("cmpy_w128_sat"),
        OpKind::SatOrigShl { .. } => op_json!("sat_orig_shl"),
        OpKind::HexFpDf {
            dst,
            src1,
            src2,
            src3,
            ..
        } => op_json!("hexfp_df", dst, src1, src2, src3),
        OpKind::HexFpScFma {
            dst,
            src1,
            src2,
            src3,
            scale,
        } => op_json!("hexfp_sc_fma", dst, src1, src2, src3, scale),
        OpKind::HexCabacDecBin {
            dst,
            pred,
            src1,
            src2,
        } => op_json!("hex_cabac_decbin", dst, pred, src1, src2),
        OpKind::HexTlbMatch { dst, src1, src2 } => op_json!("hex_tlbmatch", dst, src1, src2),
        OpKind::RvFp {
            dst,
            fcsr_dst,
            src1,
            src2,
            src3,
            fcsr_src,
            ..
        } => op_json!("rv_fp", dst, fcsr_dst, src1, src2, src3, fcsr_src),
        OpKind::RvIntCrypto {
            dst, src1, src2, ..
        } => op_json!("rv_int_crypto", dst, src1, src2),
        OpKind::RvVector { rs1, rs2, .. } => op_json!("rv_vector", rs1, rs2),
        OpKind::X86String {
            accumulator,
            src_index,
            dst_index,
            count,
            ..
        } => op_json!("x86_string", accumulator, src_index, dst_index, count),
    }
}

fn arch_reg_json(reg: &ArchReg) -> Map<String, Value> {
    let mut obj = Map::new();
    match reg {
        ArchReg::X86(reg) => {
            obj.insert("arch".to_string(), json!("x86_64"));
            obj.insert("name".to_string(), json!(x86_reg_name(reg)));
        }
        ArchReg::Arm(reg) => {
            obj.insert("arch".to_string(), json!("aarch64"));
            obj.insert("name".to_string(), json!(arm_reg_name(reg)));
        }
        ArchReg::Hexagon(reg) => {
            obj.insert("arch".to_string(), json!("hexagon"));
            obj.insert("name".to_string(), json!(hexagon_reg_name(reg)));
        }
        ArchReg::RiscV(reg) => {
            obj.insert("arch".to_string(), json!("riscv"));
            obj.insert("name".to_string(), json!(riscv_reg_name(reg)));
        }
    }
    obj
}

fn x86_reg_name(reg: &X86Reg) -> String {
    match reg {
        X86Reg::Rax => "rax".to_string(),
        X86Reg::Rcx => "rcx".to_string(),
        X86Reg::Rdx => "rdx".to_string(),
        X86Reg::Rbx => "rbx".to_string(),
        X86Reg::Rsp => "rsp".to_string(),
        X86Reg::Rbp => "rbp".to_string(),
        X86Reg::Rsi => "rsi".to_string(),
        X86Reg::Rdi => "rdi".to_string(),
        X86Reg::R8 => "r8".to_string(),
        X86Reg::R9 => "r9".to_string(),
        X86Reg::R10 => "r10".to_string(),
        X86Reg::R11 => "r11".to_string(),
        X86Reg::R12 => "r12".to_string(),
        X86Reg::R13 => "r13".to_string(),
        X86Reg::R14 => "r14".to_string(),
        X86Reg::R15 => "r15".to_string(),
        X86Reg::R16 => "r16".to_string(),
        X86Reg::R17 => "r17".to_string(),
        X86Reg::R18 => "r18".to_string(),
        X86Reg::R19 => "r19".to_string(),
        X86Reg::R20 => "r20".to_string(),
        X86Reg::R21 => "r21".to_string(),
        X86Reg::R22 => "r22".to_string(),
        X86Reg::R23 => "r23".to_string(),
        X86Reg::R24 => "r24".to_string(),
        X86Reg::R25 => "r25".to_string(),
        X86Reg::R26 => "r26".to_string(),
        X86Reg::R27 => "r27".to_string(),
        X86Reg::R28 => "r28".to_string(),
        X86Reg::R29 => "r29".to_string(),
        X86Reg::R30 => "r30".to_string(),
        X86Reg::R31 => "r31".to_string(),
        X86Reg::Rip => "rip".to_string(),
        X86Reg::Rflags => "rflags".to_string(),
        X86Reg::FsBase => "fs_base".to_string(),
        X86Reg::GsBase => "gs_base".to_string(),
        X86Reg::KernelGsBase => "kernel_gs_base".to_string(),
        X86Reg::Pkru => "pkru".to_string(),
        X86Reg::Mm(n) => format!("mm{n}"),
        X86Reg::Xmm(n) => format!("xmm{n}"),
        X86Reg::Ymm(n) => format!("ymm{n}"),
        X86Reg::Zmm(n) => format!("zmm{n}"),
        X86Reg::K(n) => format!("k{n}"),
    }
}

fn arm_reg_name(reg: &ArmReg) -> String {
    match reg {
        ArmReg::X(n) => format!("x{n}"),
        ArmReg::Sp => "sp".to_string(),
        ArmReg::Pc => "pc".to_string(),
        ArmReg::Nzcv => "nzcv".to_string(),
        ArmReg::V(n) => format!("v{n}"),
        ArmReg::Fpcr => "fpcr".to_string(),
        ArmReg::Fpsr => "fpsr".to_string(),
        ArmReg::SysReg(reg) => format!("sysreg_{reg:#x}"),
    }
}

fn hexagon_reg_name(reg: &HexagonReg) -> String {
    match reg {
        HexagonReg::R(n) => format!("r{n}"),
        HexagonReg::P(n) => format!("p{n}"),
        HexagonReg::Pc => "pc".to_string(),
        HexagonReg::Gp => "gp".to_string(),
        HexagonReg::Lr => "lr".to_string(),
        HexagonReg::Sp => "sp".to_string(),
        HexagonReg::Fp => "fp".to_string(),
        HexagonReg::Lc0 => "lc0".to_string(),
        HexagonReg::Lc1 => "lc1".to_string(),
        HexagonReg::Sa0 => "sa0".to_string(),
        HexagonReg::Sa1 => "sa1".to_string(),
        HexagonReg::Usr => "usr".to_string(),
        HexagonReg::V(n) => format!("v{n}"),
        HexagonReg::Q(n) => format!("q{n}"),
        HexagonReg::M(n) => format!("m{n}"),
        HexagonReg::Cs(n) => format!("cs{n}"),
    }
}

fn riscv_reg_name(reg: &RiscVReg) -> String {
    match reg {
        RiscVReg::X(n) => format!("x{n}"),
        RiscVReg::F(n) => format!("f{n}"),
        RiscVReg::V(n) => format!("v{n}"),
        RiscVReg::Pc => "pc".to_string(),
        RiscVReg::Csr(reg) => format!("csr_{reg:#x}"),
    }
}

fn debug_name(value: &impl std::fmt::Debug) -> String {
    format!("{value:?}")
}

fn decode_x86_prefix_metadata(bytes: &[u8]) -> Value {
    let mut cursor = 0usize;
    let mut prefixes = Vec::new();
    while cursor < bytes.len() {
        let b = bytes[cursor];
        let name = match b {
            0x26 => "es",
            0x2e => "cs",
            0x36 => "ss",
            0x3e => "ds",
            0x64 => "fs",
            0x65 => "gs",
            0x66 => "operand_size",
            0x67 => "address_size",
            0xf0 => "lock",
            0xf2 => "repne",
            0xf3 => "rep",
            0x40..=0x4f => "rex",
            _ => break,
        };
        prefixes.push(json!({"byte": hex_u8(b), "name": name}));
        cursor += 1;
    }

    let opcode = if cursor < bytes.len() {
        let first = bytes[cursor];
        if first == 0x0f && cursor + 1 < bytes.len() {
            let second = bytes[cursor + 1];
            if matches!(second, 0x38 | 0x3a) && cursor + 2 < bytes.len() {
                vec![first, second, bytes[cursor + 2]]
            } else {
                vec![first, second]
            }
        } else if matches!(first, 0xc4 | 0xc5 | 0x62) {
            let prefix_len = if first == 0xc5 {
                2
            } else if first == 0xc4 {
                3
            } else {
                4
            };
            let opcode_idx = cursor + prefix_len;
            if opcode_idx < bytes.len() {
                bytes[cursor..=opcode_idx].to_vec()
            } else {
                bytes[cursor..].to_vec()
            }
        } else {
            vec![first]
        }
    } else {
        Vec::new()
    };

    json!({
        "offset": 0,
        "prefixes": prefixes,
        "opcode_offset": cursor,
        "opcode_bytes": opcode.iter().map(|b| hex_u8(*b)).collect::<Vec<_>>(),
        "debug": "x86_64 prefix/opcode metadata; semantic decode is in smir",
    })
}

fn arm_control_flow(insn: &crate::isa::arm::DecodedInsn, pc: u64) -> Value {
    match insn.mnemonic {
        Mnemonic::B => direct_label_cf("branch", insn, pc, insn.size),
        Mnemonic::BL => direct_label_cf("call", insn, pc, insn.size),
        Mnemonic::BCC | Mnemonic::CBZ | Mnemonic::CBNZ | Mnemonic::TBZ | Mnemonic::TBNZ => {
            let target = insn
                .operands
                .iter()
                .find_map(label_operand)
                .map(|offset| (pc as i64).wrapping_add(offset) as u64);
            json!({
                "kind": "cond_branch",
                "target": target.map(hex_u64),
                "fallthrough": hex_u64(pc + insn.size as u64),
                "condition": insn.cond.map(|cond| format!("{cond:?}")),
            })
        }
        Mnemonic::BX | Mnemonic::BR => json!({"kind": "indirect_branch"}),
        Mnemonic::BLX | Mnemonic::BLR => json!({"kind": "indirect_call"}),
        Mnemonic::RET => json!({"kind": "return"}),
        Mnemonic::SVC => json!({"kind": "syscall"}),
        Mnemonic::BRK => json!({"kind": "trap", "trap": "breakpoint"}),
        Mnemonic::HLT => json!({"kind": "trap", "trap": "halt"}),
        Mnemonic::UDF | Mnemonic::UNDEFINED => json!({"kind": "trap", "trap": "undefined"}),
        _ => fallthrough_json(pc + insn.size as u64),
    }
}

fn direct_label_cf(kind: &str, insn: &crate::isa::arm::DecodedInsn, pc: u64, size: u8) -> Value {
    let target = insn
        .operands
        .iter()
        .find_map(label_operand)
        .map(|offset| (pc as i64).wrapping_add(offset) as u64);
    json!({
        "kind": kind,
        "target": target.map(hex_u64),
        "fallthrough": if kind == "call" { Some(hex_u64(pc + size as u64)) } else { None },
    })
}

fn label_operand(op: &Operand) -> Option<i64> {
    match op {
        Operand::Label(offset) => Some(*offset),
        _ => None,
    }
}

fn riscv_control_flow(insn: &crate::isa::riscv::Insn, pc: u64) -> Value {
    match insn.op {
        RvOp::Jal => json!({
            "kind": if insn.rd == 1 || insn.rd == 5 { "call" } else { "branch" },
            "target": hex_u64((pc as i64).wrapping_add(insn.imm) as u64),
            "fallthrough": hex_u64(pc + insn.len as u64),
        }),
        RvOp::Jalr => json!({
            "kind": if insn.rd == 1 || insn.rd == 5 { "indirect_call" } else { "indirect_branch" },
            "base_reg": insn.rs1,
            "offset": insn.imm,
            "fallthrough": hex_u64(pc + insn.len as u64),
        }),
        RvOp::Beq | RvOp::Bne | RvOp::Blt | RvOp::Bge | RvOp::Bltu | RvOp::Bgeu => json!({
            "kind": "cond_branch",
            "condition": format!("{:?}", insn.op),
            "target": hex_u64((pc as i64).wrapping_add(insn.imm) as u64),
            "fallthrough": hex_u64(pc + insn.len as u64),
        }),
        RvOp::Ecall => json!({"kind": "syscall"}),
        RvOp::Ebreak => json!({"kind": "trap", "trap": "breakpoint"}),
        RvOp::Mret | RvOp::Sret => json!({"kind": "return"}),
        RvOp::Wfi => json!({"kind": "halt"}),
        RvOp::Illegal => json!({"kind": "trap", "trap": "illegal"}),
        _ => fallthrough_json(pc + insn.len as u64),
    }
}

fn hex_control_flow(insn: &HexInsn, pc: u64, packet_pc: u64, used_ext: bool) -> Value {
    let pcrel_base = if used_ext { packet_pc } else { pc };
    match insn {
        HexInsn::Jump { offset } => json!({
            "kind": "branch",
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
        }),
        HexInsn::JumpCond {
            offset,
            pred,
            sense,
            pred_new,
        } => json!({
            "kind": "cond_branch",
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
            "fallthrough": hex_u64(pc + 4),
            "predicate": pred,
            "sense": sense,
            "pred_new": pred_new,
        }),
        HexInsn::JumpReg { src } => json!({"kind": "indirect_branch", "reg": format!("r{src}")}),
        HexInsn::JumpRegCond {
            src,
            pred,
            sense,
            pred_new,
        } => json!({
            "kind": "cond_indirect_branch",
            "reg": format!("r{src}"),
            "fallthrough": hex_u64(pc + 4),
            "predicate": pred,
            "sense": sense,
            "pred_new": pred_new,
        }),
        HexInsn::JumpRegZero { src, kind, offset } => json!({
            "kind": "cond_branch",
            "condition": format!("{kind:?}"),
            "src": format!("r{src}"),
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
            "fallthrough": hex_u64(pc + 4),
        }),
        HexInsn::JumpSet { dst, value, offset } => json!({
            "kind": "branch",
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
            "writes": format!("r{dst} = {value:?}"),
        }),
        HexInsn::Call { offset, pred } => json!({
            "kind": if pred.is_some() { "cond_call" } else { "call" },
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
            "fallthrough": hex_u64(pc + 4),
            "predicate": pred.map(|p| format!("{p:?}")),
        }),
        HexInsn::CallReg { src, pred } => json!({
            "kind": if pred.is_some() { "cond_indirect_call" } else { "indirect_call" },
            "reg": format!("r{src}"),
            "fallthrough": hex_u64(pc + 4),
            "predicate": pred.map(|p| format!("{p:?}")),
        }),
        HexInsn::DeallocReturn { pred, .. } => json!({
            "kind": if pred.is_some() { "cond_return" } else { "return" },
            "predicate": pred.map(|p| format!("{p:?}")),
        }),
        HexInsn::CompoundCmpJump {
            kind,
            src1,
            src2,
            sense,
            new_value,
            offset,
            write_pred,
        } => json!({
            "kind": "cond_branch",
            "condition": format!("{kind:?}"),
            "src1": src1,
            "src2": src2,
            "sense": sense,
            "new_value": new_value,
            "write_pred": write_pred,
            "target": hex_u64((pcrel_base as i64).wrapping_add(*offset as i64) as u64),
            "fallthrough": hex_u64(pc + 4),
        }),
        HexInsn::Trap0 => json!({"kind": "syscall", "trap": "trap0"}),
        HexInsn::LoopStartReg {
            loop_id,
            start_offset,
            count_reg,
            lpcfg,
        } => json!({
            "kind": "loop_setup",
            "loop_id": loop_id,
            "start": hex_u64((pcrel_base as i64).wrapping_add(*start_offset as i64) as u64),
            "count_reg": count_reg,
            "lpcfg": lpcfg,
        }),
        HexInsn::LoopStartImm {
            loop_id,
            start_offset,
            count,
            lpcfg,
        } => json!({
            "kind": "loop_setup",
            "loop_id": loop_id,
            "start": hex_u64((pcrel_base as i64).wrapping_add(*start_offset as i64) as u64),
            "count": count,
            "lpcfg": lpcfg,
        }),
        HexInsn::Unknown(_) => json!({"kind": "unknown"}),
        _ => fallthrough_json(pc + 4),
    }
}

fn packet_control_flow(effects: Vec<Value>) -> Value {
    if effects.is_empty() {
        json!({"kind": "fallthrough"})
    } else if effects.len() == 1 {
        effects.into_iter().next().unwrap()
    } else {
        json!({"kind": "packet_multi", "effects": effects})
    }
}

fn control_flow_json(cf: &ControlFlow) -> Value {
    match cf {
        ControlFlow::Fallthrough | ControlFlow::NextInsn => json!({"kind": "fallthrough"}),
        ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
            json!({"kind": "branch", "target": hex_u64(*target)})
        }
        ControlFlow::CondBranch {
            cond,
            target,
            fallthrough,
        } => json!({
            "kind": "cond_branch",
            "condition": format!("{cond:?}"),
            "target": hex_u64(*target),
            "fallthrough": hex_u64(*fallthrough),
        }),
        ControlFlow::CondBranchReg {
            cond,
            taken,
            not_taken,
        } => json!({
            "kind": "cond_branch_reg",
            "condition_reg": format!("{cond:?}"),
            "condition_value": cond.oracle_json(),
            "target": hex_u64(*taken),
            "fallthrough": hex_u64(*not_taken),
        }),
        ControlFlow::IndirectBranch { target } => {
            json!({
                "kind": "indirect_branch",
                "target": format!("{target:?}"),
                "target_value": target.oracle_json(),
            })
        }
        ControlFlow::IndirectBranchMem { addr } => {
            json!({
                "kind": "indirect_branch_mem",
                "addr": format!("{addr:?}"),
                "address": addr.oracle_json(),
            })
        }
        ControlFlow::Call { target } => json!({"kind": "call", "target": call_target_json(target)}),
        ControlFlow::Return => json!({"kind": "return"}),
        ControlFlow::Trap { kind } => json!({"kind": "trap", "trap": format!("{kind:?}")}),
        ControlFlow::Syscall => json!({"kind": "syscall"}),
    }
}

fn hex_fields(word: u32) -> Value {
    let Some(decoded) = hex_opcode::decode_word(word) else {
        return Value::Array(Vec::new());
    };
    let fields = decoded
        .fields
        .iter()
        .map(|field| {
            let letter = char::from(field.letter).to_string();
            let value = decoded.field(field.letter);
            json!({
                "letter": letter,
                "bits": field.bits,
                "value": value.map(|v| v.value),
                "width": value.map(|v| v.bits),
            })
        })
        .collect::<Vec<_>>();
    Value::Array(fields)
}

fn word_from_bytes(bytes: &[u8], endian: Endianness) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match endian {
        Endianness::Little => u32::from_le_bytes(arr),
        Endianness::Big => u32::from_be_bytes(arr),
    }
}

fn is_fallthrough(cf: &Value) -> bool {
    cf.get("kind").and_then(Value::as_str) == Some("fallthrough")
}

fn fallthrough_json(next_pc: u64) -> Value {
    json!({"kind": "fallthrough", "next_pc": hex_u64(next_pc)})
}

fn side_effects_not_run() -> Value {
    json!({
        "available": false,
        "reason": "no_seeded_execution_requested",
    })
}

fn input_json(bytes: &[u8]) -> Value {
    json!({
        "len": bytes.len(),
        "hex": bytes_to_hex(bytes),
        "bytes": bytes.iter().map(|b| hex_u8(*b)).collect::<Vec<_>>(),
    })
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_u8(value: u8) -> String {
    format!("0x{value:02x}")
}

fn hex_u32(value: u32) -> String {
    format!("0x{value:08x}")
}

fn hex_i64(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        hex_u64(value as u64)
    }
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}
