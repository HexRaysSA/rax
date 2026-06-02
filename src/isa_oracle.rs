//! JSON oracle harness for ISA-specific decoders and SMIR lifters.

use serde_json::{json, Map, Value};

use crate::arm::decoder::{Decoder as ArmDecoder, Mnemonic, Operand};
use crate::arm::ExecutionState;
use crate::backend::emulator::hexagon::decode::{self as hex_decode, DecodedInsn as HexInsn};
use crate::backend::emulator::hexagon::opcode as hex_opcode;
use crate::config::{Endianness, HexagonIsa};
use crate::riscv::decode as rv_decode;
use crate::riscv::{Isa as RvIsa, Op as RvOp, Xlen};
use crate::smir::lift::riscv::RiscVExtensions;
use crate::smir::{
    Aarch64Lifter, ArchReg, ArmReg, BlockId, CallTarget, ControlFlow, FlatMemory, HexagonLifter,
    HexagonReg, LiftContext, OpId, RiscVLifter, RiscVReg, SmirBlock, SmirContext, SmirInterpreter,
    SmirLifter, SmirMemory, SourceArch, Terminator, TrapKind, X86Reg, X86_64Lifter,
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

impl OracleSeed {
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let mut seed = OracleSeed::default();

        if let Some(size) = value.get("memory_size") {
            seed.memory_size = Some(json_usize(size, "memory_size")?);
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
        OracleIsa::X86_64 => Ok(decode_x86(bytes, opts)),
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

fn decode_x86(bytes: &[u8], opts: &OracleOptions) -> Value {
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
                        let cf = hex_control_flow(&sub.insn, word_pc);
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
        let cf = hex_control_flow(&decoded.insn, word_pc);
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
        OracleIsa::X86_64 => Some(SourceArch::X86_64),
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
    if seed.memory.is_empty() {
        return Ok(MemoryLayout {
            base: 0,
            size: seed.memory_size.unwrap_or(0x10000),
        });
    }

    let base = seed.memory.iter().map(|mem| mem.addr).min().unwrap();
    let max_end = seed
        .memory
        .iter()
        .map(|mem| mem.addr.saturating_add(mem.bytes.len() as u64))
        .max()
        .unwrap();
    let needed = max_end
        .checked_sub(base)
        .ok_or_else(|| "invalid seed memory layout".to_string())? as usize;
    let size = seed.memory_size.unwrap_or(needed.max(0x1000));
    if size < needed {
        return Err(format!(
            "seed.memory_size {size} is smaller than seeded memory span {needed}"
        ));
    }
    Ok(MemoryLayout { base, size })
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
            let ops = result
                .ops
                .iter()
                .map(|op| {
                    json!({
                        "id": op.id.0,
                        "guest_pc": hex_u64(op.guest_pc),
                        "kind": format!("{:?}", op.kind),
                        "x86_hint": op.x86_hint.map(|hint| format!("{hint:?}")),
                        "debug": format!("{op:?}"),
                    })
                })
                .collect::<Vec<_>>();
            let control_flow = control_flow_json(&result.control_flow);
            json!({
                "available": true,
                "source_arch": format!("{source:?}"),
                "bytes_consumed": result.bytes_consumed,
                "ops": ops,
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

fn arm_control_flow(insn: &crate::arm::DecodedInsn, pc: u64) -> Value {
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

fn direct_label_cf(kind: &str, insn: &crate::arm::DecodedInsn, pc: u64, size: u8) -> Value {
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

fn riscv_control_flow(insn: &crate::riscv::Insn, pc: u64) -> Value {
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

fn hex_control_flow(insn: &HexInsn, pc: u64) -> Value {
    match insn {
        HexInsn::Jump { offset } => json!({
            "kind": "branch",
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
        }),
        HexInsn::JumpCond {
            offset,
            pred,
            sense,
            pred_new,
        } => json!({
            "kind": "cond_branch",
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
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
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
            "fallthrough": hex_u64(pc + 4),
        }),
        HexInsn::JumpSet { dst, value, offset } => json!({
            "kind": "branch",
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
            "writes": format!("r{dst} = {value:?}"),
        }),
        HexInsn::Call { offset, pred } => json!({
            "kind": if pred.is_some() { "cond_call" } else { "call" },
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
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
            "target": hex_u64((pc as i64).wrapping_add(*offset as i64) as u64),
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
            "start": hex_u64((pc as i64).wrapping_add(*start_offset as i64) as u64),
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
            "start": hex_u64((pc as i64).wrapping_add(*start_offset as i64) as u64),
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
            "target": hex_u64(*taken),
            "fallthrough": hex_u64(*not_taken),
        }),
        ControlFlow::IndirectBranch { target } => {
            json!({"kind": "indirect_branch", "target": format!("{target:?}")})
        }
        ControlFlow::IndirectBranchMem { addr } => {
            json!({"kind": "indirect_branch_mem", "addr": format!("{addr:?}")})
        }
        ControlFlow::Call { target } => json!({"kind": "call", "target": call_target_json(target)}),
        ControlFlow::Return => json!({"kind": "return"}),
        ControlFlow::Trap { kind } => json!({"kind": "trap", "trap": format!("{kind:?}")}),
        ControlFlow::Syscall => json!({"kind": "syscall"}),
    }
}

fn call_target_json(target: &CallTarget) -> Value {
    match target {
        CallTarget::Direct(id) => json!({"kind": "direct_function", "id": id.0}),
        CallTarget::GuestAddr(addr) => json!({"kind": "direct", "addr": hex_u64(*addr)}),
        CallTarget::Indirect(reg) => json!({"kind": "indirect", "reg": format!("{reg:?}")}),
        CallTarget::IndirectMem(addr) => {
            json!({"kind": "indirect_mem", "addr": format!("{addr:?}")})
        }
        CallTarget::Runtime(func) => json!({"kind": "runtime", "func": format!("{func:?}")}),
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

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}
