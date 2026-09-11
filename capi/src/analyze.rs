//! Stateless, pointer-free instruction-effect analysis (`rax_analyze`).
//!
//! This module projects one SMIR lift into a compact C ABI.  The ABI never
//! exposes Rust allocation or enum layout: the summary and every effect record
//! are fixed-size `repr(C)` values with explicit versions and reserved space.
//! Variable-length effects use a caller-owned array and a two-call size query.

use std::collections::{HashMap, HashSet};
use std::os::raw::{c_int, c_void};
use std::slice;

use serde_json::Value;

use rax_engine::isa_oracle::decode_to_json;

use crate::arch::{RAX_MODE_64, RaxArch, normalize_mode};
use crate::decode::{RaxDecoded, fill_from_json, oracle_options};
use crate::guard;
use crate::status::RaxStatus;

pub const RAX_ANALYSIS_ABI_VERSION: u32 = 1;

pub const RAX_ANALYSIS_VALID: u32 = 1 << 0;
pub const RAX_ANALYSIS_HAS_SMIR: u32 = 1 << 1;
pub const RAX_ANALYSIS_COMPLETE: u32 = 1 << 2;
pub const RAX_ANALYSIS_PARTIAL: u32 = 1 << 3;
pub const RAX_ANALYSIS_UNSUPPORTED: u32 = 1 << 4;
pub const RAX_ANALYSIS_TRUNCATED: u32 = 1 << 5;

pub const RAX_EFFECT_REGISTER: u16 = 1;
pub const RAX_EFFECT_MEMORY: u16 = 2;

pub const RAX_EFFECT_READ: u32 = 1 << 0;
pub const RAX_EFFECT_WRITE: u32 = 1 << 1;
pub const RAX_EFFECT_CONDITIONAL: u32 = 1 << 2;
pub const RAX_EFFECT_ATOMIC: u32 = 1 << 3;
pub const RAX_EFFECT_REPEATED: u32 = 1 << 4;
pub const RAX_EFFECT_ORDERED: u32 = 1 << 5;
pub const RAX_EFFECT_IMPLICIT: u32 = 1 << 6;
pub const RAX_EFFECT_ADDRESS_COMPLETE: u32 = 1 << 7;
pub const RAX_EFFECT_VALUE_COMPLETE: u32 = 1 << 8;

pub const RAX_VALUE_UNKNOWN: u32 = 0;
pub const RAX_VALUE_CONSTANT: u32 = 1;
pub const RAX_VALUE_REGISTER: u32 = 2;

pub const RAX_ADDRESS_NONE: u32 = 0;
pub const RAX_ADDRESS_UNKNOWN: u32 = 1;
pub const RAX_ADDRESS_ABSOLUTE: u32 = 2;
pub const RAX_ADDRESS_REGISTER: u32 = 3;
pub const RAX_ADDRESS_BASE_DISP: u32 = 4;
pub const RAX_ADDRESS_BASE_INDEX_DISP: u32 = 5;
pub const RAX_ADDRESS_PC_RELATIVE: u32 = 6;
pub const RAX_ADDRESS_GP_RELATIVE: u32 = 7;
pub const RAX_ADDRESS_SEGMENT_RELATIVE: u32 = 8;

// Architecture-neutral condition-code bits.  On x86 N/V are SF/OF; on ARM
// they are N/V.  P and A are x86-only.  DF is kept separate from arithmetic
// flags because string operations may read it implicitly.
pub const RAX_FLAG_C: u32 = 1 << 0;
pub const RAX_FLAG_Z: u32 = 1 << 1;
pub const RAX_FLAG_N: u32 = 1 << 2;
pub const RAX_FLAG_V: u32 = 1 << 3;
pub const RAX_FLAG_P: u32 = 1 << 4;
pub const RAX_FLAG_A: u32 = 1 << 5;
pub const RAX_FLAG_D: u32 = 1 << 6;
pub const RAX_FLAG_ARITHMETIC: u32 =
    RAX_FLAG_C | RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_V | RAX_FLAG_P | RAX_FLAG_A;
pub const RAX_FLAG_NZCV: u32 = RAX_FLAG_C | RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_V;

const REG_INVALID: i32 = -1;

/// Fixed ABI summary for one instruction.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxAnalysis {
    pub struct_size: u32,
    pub abi_version: u32,
    pub decoded: RaxDecoded,
    pub flags: u32,
    /// Number of records copied to the caller's array.
    pub effect_count: u32,
    /// Full number of records required for a lossless result.
    pub required_effect_count: u32,
    pub flags_read: u32,
    pub flags_written: u32,
    pub flags_undefined: u32,
    pub smir_op_count: u32,
    pub _reserved0: u32,
    pub _reserved: [u64; 4],
}

impl RaxAnalysis {
    pub(crate) fn zeroed() -> Self {
        Self {
            struct_size: size_of_u32::<Self>(),
            abi_version: RAX_ANALYSIS_ABI_VERSION,
            decoded: RaxDecoded::zeroed(),
            flags: 0,
            effect_count: 0,
            required_effect_count: 0,
            flags_read: 0,
            flags_written: 0,
            flags_undefined: 0,
            smir_op_count: 0,
            _reserved0: 0,
            _reserved: [0; 4],
        }
    }
}

/// One normalized register or memory effect.  All register identifiers are the
/// stable architecture-specific `RAX_*` ids from `rax.h`; `-1` means absent.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RaxAnalysisEffect {
    pub struct_size: u32,
    pub abi_version: u16,
    pub kind: u16,
    pub access: u32,
    pub reg: i32,
    pub width_bits: u32,
    pub value_kind: u32,
    pub source_reg: i32,
    pub address_kind: u32,
    pub base_reg: i32,
    pub index_reg: i32,
    pub segment_reg: i32,
    pub scale: u32,
    pub value: u64,
    pub address: u64,
    pub displacement: i64,
    pub _reserved: [u64; 2],
}

impl RaxAnalysisEffect {
    pub(crate) fn empty(kind: u16, access: u32) -> Self {
        Self {
            struct_size: size_of_u32::<Self>(),
            abi_version: RAX_ANALYSIS_ABI_VERSION as u16,
            kind,
            access,
            reg: REG_INVALID,
            width_bits: 0,
            value_kind: RAX_VALUE_UNKNOWN,
            source_reg: REG_INVALID,
            address_kind: RAX_ADDRESS_NONE,
            base_reg: REG_INVALID,
            index_reg: REG_INVALID,
            segment_reg: REG_INVALID,
            scale: 0,
            value: 0,
            address: 0,
            displacement: 0,
            _reserved: [0; 2],
        }
    }
}

const fn size_of_u32<T>() -> u32 {
    // Both ABI structs are intentionally far below u32::MAX.
    std::mem::size_of::<T>() as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Symbolic {
    Unknown,
    Constant(u64),
    Register(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum VKey {
    Virtual(u32),
    Arch(i32),
}

struct Analyzer {
    arch: RaxArch,
    pc: u64,
    values: HashMap<u32, Symbolic>,
    widths: HashMap<u32, u32>,
    effects: Vec<RaxAnalysisEffect>,
    seen: HashSet<RaxAnalysisEffect>,
    flags_read: u32,
    flags_written: u32,
    flags_undefined: u32,
    complete: bool,
}

impl Analyzer {
    fn new(arch: RaxArch, pc: u64) -> Self {
        Self {
            arch,
            pc,
            values: HashMap::new(),
            widths: HashMap::new(),
            effects: Vec::new(),
            seen: HashSet::new(),
            flags_read: 0,
            flags_written: 0,
            flags_undefined: 0,
            complete: true,
        }
    }

    fn push(&mut self, effect: RaxAnalysisEffect) {
        if self.seen.insert(effect) {
            self.effects.push(effect);
        }
    }

    fn symbolic(&mut self, value: &Value) -> Symbolic {
        let Some(kind) = value.get("kind").and_then(Value::as_str) else {
            return Symbolic::Unknown;
        };
        match kind {
            "imm" | "imm64" => integer(value.get("value"))
                .map_or(Symbolic::Unknown, |v| Symbolic::Constant(v as u64)),
            "arch" => match stable_reg_id(self.arch, value) {
                Some(reg) => Symbolic::Register(reg),
                None => {
                    self.complete = false;
                    Symbolic::Unknown
                }
            },
            "virtual" => value
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
                .and_then(|id| self.values.get(&id).copied())
                .unwrap_or(Symbolic::Unknown),
            "reg" => value
                .get("reg")
                .map(|v| self.symbolic(v))
                .unwrap_or(Symbolic::Unknown),
            "shifted" if value.get("amount").and_then(Value::as_u64) == Some(0) => value
                .get("reg")
                .map(|v| self.symbolic(v))
                .unwrap_or(Symbolic::Unknown),
            // A shifted or extended register is still a register *read*, but
            // it is not a direct register value result. collect_vregs() has
            // already preserved the read effect; keep value provenance honest.
            "shifted" | "extended" => Symbolic::Unknown,
            _ => Symbolic::Unknown,
        }
    }

    fn key(&mut self, value: &Value) -> Option<VKey> {
        match value.get("kind").and_then(Value::as_str)? {
            "virtual" => value
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
                .map(VKey::Virtual),
            "arch" => match stable_reg_id(self.arch, value) {
                Some(reg) => Some(VKey::Arch(reg)),
                None => {
                    self.complete = false;
                    None
                }
            },
            _ => None,
        }
    }

    fn register_read(&mut self, reg: i32) {
        let mut effect = RaxAnalysisEffect::empty(RAX_EFFECT_REGISTER, RAX_EFFECT_READ);
        effect.reg = reg;
        effect.width_bits = natural_reg_width(self.arch, reg);
        self.push(effect);
    }

    fn register_write(&mut self, reg: i32, width_bits: u32, value: Symbolic) {
        let mut effect = RaxAnalysisEffect::empty(RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE);
        effect.reg = reg;
        effect.width_bits = if width_bits == 0 {
            natural_reg_width(self.arch, reg)
        } else {
            width_bits
        };
        match value {
            Symbolic::Constant(value) => {
                effect.value_kind = RAX_VALUE_CONSTANT;
                effect.value = mask_width(value, effect.width_bits);
                effect.access |= RAX_EFFECT_VALUE_COMPLETE;
            }
            Symbolic::Register(source) => {
                effect.value_kind = RAX_VALUE_REGISTER;
                effect.source_reg = source;
                effect.access |= RAX_EFFECT_VALUE_COMPLETE;
            }
            Symbolic::Unknown => {}
        }
        self.push(effect);
    }

    fn analyze_op(&mut self, op: &Value) {
        let kind = op.get("kind").unwrap_or(&Value::Null);
        let opcode = op
            .get("opcode")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let writes = op
            .get("writes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        // Every destination appears once in `kind` and once in `writes`.
        // Removing one occurrence per destination from the recursively found
        // VRegs leaves precisely the source occurrences, including a true
        // read-modify-write where the same architectural register appears twice.
        let mut occurrences = Vec::new();
        collect_vregs(kind, &mut occurrences);
        for write in &writes {
            if let Some(key) = self.key(write)
                && let Some(index) = occurrences
                    .iter()
                    .position(|candidate| self.key(candidate) == Some(key))
            {
                occurrences.remove(index);
            }
        }
        for source in occurrences {
            if let Symbolic::Register(reg) = self.symbolic(source) {
                self.register_read(reg);
            }
        }

        self.analyze_flags(opcode, kind);
        self.analyze_memory(opcode, op, kind);

        let width = operation_width_bits(kind, opcode);
        let inferred = self.infer_result(opcode, kind, width);
        let primary = kind.get("dst").and_then(|dst| self.key(dst));

        for write in writes {
            let Some(key) = self.key(&write) else {
                continue;
            };
            let value = if Some(key) == primary {
                inferred
            } else {
                Symbolic::Unknown
            };
            match key {
                VKey::Virtual(id) => {
                    self.values.insert(id, value);
                    self.widths.insert(id, width);
                }
                VKey::Arch(reg) => self.register_write(reg, width, value),
            }
        }

        // These SMIR bridge ops intentionally hide broad machine state behind
        // an opaque executor.  Report all explicit effects but never claim the
        // register/memory list is complete.
        if matches!(opcode, "rv_vector" | "v_hist") {
            self.complete = false;
        }
    }

    fn analyze_flags(&mut self, opcode: &str, kind: &Value) {
        if let Some(mask) = kind
            .get("flags")
            .and_then(|f| f.get("set"))
            .and_then(|s| s.get("mask"))
            .and_then(Value::as_u64)
        {
            self.flags_written |= mask as u32 & RAX_FLAG_ARITHMETIC;
        }
        match opcode {
            "adc" | "sbb" | "rcl" | "rcr" | "cmc_cf" => self.flags_read |= RAX_FLAG_C,
            "read_flags" => self.flags_read |= RAX_FLAG_ARITHMETIC | RAX_FLAG_D,
            "write_flags" => self.flags_written |= RAX_FLAG_ARITHMETIC | RAX_FLAG_D,
            "set_cf" => self.flags_written |= RAX_FLAG_C,
            "set_df" => self.flags_written |= RAX_FLAG_D,
            "rep_stos" | "rep_movs" => self.flags_read |= RAX_FLAG_D,
            _ => {}
        }
        if self.arch == RaxArch::X86 {
            match opcode {
                "cmp" | "test" => self.flags_written |= RAX_FLAG_ARITHMETIC,
                "bt" | "bts" | "btr" | "btc" => {
                    self.flags_written |= RAX_FLAG_C;
                    self.flags_undefined |=
                        RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_V | RAX_FLAG_P | RAX_FLAG_A;
                }
                "bsf" | "bsr" => {
                    self.flags_written |= RAX_FLAG_Z;
                    self.flags_undefined |=
                        RAX_FLAG_C | RAX_FLAG_N | RAX_FLAG_V | RAX_FLAG_P | RAX_FLAG_A;
                }
                "mul_u" | "mul_s" => {
                    self.flags_undefined |= RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_P | RAX_FLAG_A;
                }
                "div_u" | "div_s" => self.flags_undefined |= RAX_FLAG_ARITHMETIC,
                "bextr" => self.flags_undefined |= RAX_FLAG_N | RAX_FLAG_P | RAX_FLAG_A,
                "bzhi" => self.flags_undefined |= RAX_FLAG_P | RAX_FLAG_A,
                _ => {}
            }
        }
        if matches!(opcode, "test_condition" | "setcc" | "cmove" | "select") {
            if let Some(cond) = kind.get("cond").and_then(Value::as_str) {
                self.flags_read |= condition_flags(cond);
            }
        }
    }

    fn analyze_memory(&mut self, opcode: &str, op: &Value, kind: &Value) {
        let reads = op
            .get("memory")
            .and_then(|m| m.get("reads"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let writes = op
            .get("memory")
            .and_then(|m| m.get("writes"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !reads && !writes {
            return;
        }

        let mut access = 0;
        if reads {
            access |= RAX_EFFECT_READ;
        }
        if writes {
            access |= RAX_EFFECT_WRITE;
        }
        if opcode.starts_with("pred_") || kind.get("cond").is_some() {
            access |= RAX_EFFECT_CONDITIONAL;
        }
        if opcode.starts_with("atomic_")
            || matches!(
                opcode,
                "cas" | "load_exclusive" | "store_exclusive" | "atomic_cmpxadd"
            )
        {
            access |= RAX_EFFECT_ATOMIC;
        }
        if opcode.starts_with("rep_") {
            access |= RAX_EFFECT_REPEATED;
        }
        if kind.get("order").is_some() {
            access |= RAX_EFFECT_ORDERED;
        }

        let mut effect = RaxAnalysisEffect::empty(RAX_EFFECT_MEMORY, access);
        effect.width_bits = memory_width_bits(kind, opcode);
        if effect.width_bits == 0 {
            self.complete = false;
        }
        if let Some(addr) = kind.get("addr") {
            if self.fill_address(addr, &mut effect) {
                effect.access |= RAX_EFFECT_ADDRESS_COMPLETE;
                self.address_register_reads(&effect);
            } else {
                self.complete = false;
            }
        } else {
            effect.address_kind = RAX_ADDRESS_UNKNOWN;
            self.complete = false;
        }

        if writes {
            let source = kind
                .get("src")
                .or_else(|| kind.get("value"))
                .map(|value| self.symbolic(value))
                .unwrap_or(Symbolic::Unknown);
            match source {
                Symbolic::Constant(value) => {
                    effect.value_kind = RAX_VALUE_CONSTANT;
                    effect.value = mask_width(value, effect.width_bits);
                    effect.access |= RAX_EFFECT_VALUE_COMPLETE;
                }
                Symbolic::Register(reg) => {
                    effect.value_kind = RAX_VALUE_REGISTER;
                    effect.source_reg = reg;
                    effect.access |= RAX_EFFECT_VALUE_COMPLETE;
                }
                Symbolic::Unknown => {}
            }
        }
        self.push(effect);
    }

    fn fill_address(&mut self, addr: &Value, out: &mut RaxAnalysisEffect) -> bool {
        let Some(kind) = addr.get("kind").and_then(Value::as_str) else {
            out.address_kind = RAX_ADDRESS_UNKNOWN;
            return false;
        };
        match kind {
            "absolute" => {
                let Some(value) = parse_hexish(addr.get("addr")) else {
                    out.address_kind = RAX_ADDRESS_UNKNOWN;
                    return false;
                };
                out.address_kind = RAX_ADDRESS_ABSOLUTE;
                out.address = value;
                true
            }
            "pc_relative" => {
                let Some(offset) = integer(addr.get("offset")) else {
                    return false;
                };
                let base = parse_hexish(addr.get("base")).unwrap_or(self.pc);
                out.address_kind = RAX_ADDRESS_PC_RELATIVE;
                out.displacement = offset;
                out.address = base.wrapping_add_signed(offset);
                true
            }
            "gp_relative" => {
                let Some(offset) = integer(addr.get("offset")) else {
                    return false;
                };
                let gp = stable_named_reg(self.arch, "gp").unwrap_or(REG_INVALID);
                if gp == REG_INVALID {
                    return false;
                }
                out.address_kind = RAX_ADDRESS_GP_RELATIVE;
                out.base_reg = gp;
                out.displacement = offset;
                true
            }
            "direct" => match addr.get("reg").map(|v| self.symbolic(v)) {
                Some(Symbolic::Register(reg)) => {
                    out.address_kind = RAX_ADDRESS_REGISTER;
                    out.base_reg = reg;
                    true
                }
                Some(Symbolic::Constant(value)) => {
                    out.address_kind = RAX_ADDRESS_ABSOLUTE;
                    out.address = value;
                    true
                }
                _ => false,
            },
            "base_offset" => {
                let Some(offset) = integer(addr.get("offset")) else {
                    return false;
                };
                out.displacement = offset;
                match addr.get("base").map(|v| self.symbolic(v)) {
                    Some(Symbolic::Register(reg)) => {
                        out.address_kind = RAX_ADDRESS_BASE_DISP;
                        out.base_reg = reg;
                        true
                    }
                    Some(Symbolic::Constant(value)) => {
                        out.address_kind = RAX_ADDRESS_ABSOLUTE;
                        out.address = value.wrapping_add_signed(offset);
                        true
                    }
                    _ => false,
                }
            }
            "base_index_scale" => {
                let disp = integer(addr.get("disp")).unwrap_or(0);
                let scale = addr
                    .get("scale")
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(1);
                let base = addr
                    .get("base")
                    .filter(|value| !value.is_null())
                    .map(|v| self.symbolic(v))
                    .unwrap_or(Symbolic::Constant(0));
                let index = addr
                    .get("index")
                    .map(|v| self.symbolic(v))
                    .unwrap_or(Symbolic::Unknown);
                out.displacement = disp;
                out.scale = scale;
                match (base, index) {
                    (Symbolic::Register(base), Symbolic::Register(index)) => {
                        out.address_kind = RAX_ADDRESS_BASE_INDEX_DISP;
                        out.base_reg = base;
                        out.index_reg = index;
                        true
                    }
                    (Symbolic::Constant(base), Symbolic::Register(index)) if base == 0 => {
                        out.address_kind = RAX_ADDRESS_BASE_INDEX_DISP;
                        out.index_reg = index;
                        true
                    }
                    (Symbolic::Constant(base), Symbolic::Constant(index)) => {
                        out.address_kind = RAX_ADDRESS_ABSOLUTE;
                        out.address = base
                            .wrapping_add(index.wrapping_mul(scale as u64))
                            .wrapping_add_signed(disp);
                        true
                    }
                    _ => false,
                }
            }
            "segment_rel" => {
                let segment = addr
                    .get("segment")
                    .map(|v| self.symbolic(v))
                    .unwrap_or(Symbolic::Unknown);
                let base = addr
                    .get("base")
                    .filter(|value| !value.is_null())
                    .map(|v| self.symbolic(v))
                    .unwrap_or(Symbolic::Constant(0));
                let index = addr
                    .get("index")
                    .filter(|value| !value.is_null())
                    .map(|v| self.symbolic(v))
                    .unwrap_or(Symbolic::Constant(0));
                let Symbolic::Register(segment_reg) = segment else {
                    return false;
                };
                out.address_kind = RAX_ADDRESS_SEGMENT_RELATIVE;
                out.segment_reg = segment_reg;
                out.displacement = integer(addr.get("disp")).unwrap_or(0);
                out.scale = addr
                    .get("scale")
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(1);
                if let Symbolic::Register(reg) = base {
                    out.base_reg = reg;
                } else if base != Symbolic::Constant(0) {
                    return false;
                }
                if let Symbolic::Register(reg) = index {
                    out.index_reg = reg;
                } else if index != Symbolic::Constant(0) {
                    return false;
                }
                true
            }
            _ => {
                out.address_kind = RAX_ADDRESS_UNKNOWN;
                false
            }
        }
    }

    fn address_register_reads(&mut self, address: &RaxAnalysisEffect) {
        for reg in [address.segment_reg, address.base_reg, address.index_reg] {
            if reg != REG_INVALID {
                self.register_read(reg);
            }
        }
    }

    fn infer_result(&mut self, opcode: &str, kind: &Value, width: u32) -> Symbolic {
        let src = |this: &mut Self, name: &str| {
            kind.get(name)
                .map(|value| this.symbolic(value))
                .unwrap_or(Symbolic::Unknown)
        };
        let result = match opcode {
            "mov" | "vmov" => src(self, "src"),
            "zero_extend" | "truncate" => match src(self, "src") {
                Symbolic::Constant(value) => Symbolic::Constant(mask_width(value, width)),
                value @ Symbolic::Register(_)
                    if width_name_bits(kind.get("from_width")) == Some(width) =>
                {
                    value
                }
                _ => Symbolic::Unknown,
            },
            "sign_extend" => match src(self, "src") {
                Symbolic::Constant(value) => {
                    let from = width_name_bits(kind.get("from_width")).unwrap_or(width);
                    Symbolic::Constant(sign_extend(value, from, width))
                }
                value @ Symbolic::Register(_)
                    if width_name_bits(kind.get("from_width")) == Some(width) =>
                {
                    value
                }
                _ => Symbolic::Unknown,
            },
            "add" | "sub" | "and" | "or" | "xor" => {
                let lhs = src(self, "src1");
                let rhs = src(self, "src2");
                infer_binary(opcode, lhs, rhs, width)
            }
            "not" => match src(self, "src") {
                Symbolic::Constant(value) => Symbolic::Constant(mask_width(!value, width)),
                _ => Symbolic::Unknown,
            },
            "neg" => match src(self, "src") {
                Symbolic::Constant(value) => {
                    Symbolic::Constant(mask_width((0u64).wrapping_sub(value), width))
                }
                _ => Symbolic::Unknown,
            },
            "lea" => kind
                .get("addr")
                .map(|addr| self.symbolic_address(addr))
                .unwrap_or(Symbolic::Unknown),
            _ => Symbolic::Unknown,
        };
        match result {
            Symbolic::Constant(value) => Symbolic::Constant(mask_width(value, width)),
            other => other,
        }
    }

    fn symbolic_address(&mut self, addr: &Value) -> Symbolic {
        match addr.get("kind").and_then(Value::as_str) {
            Some("absolute") => parse_hexish(addr.get("addr"))
                .map(Symbolic::Constant)
                .unwrap_or(Symbolic::Unknown),
            Some("pc_relative") => integer(addr.get("offset"))
                .map(|offset| {
                    Symbolic::Constant(
                        parse_hexish(addr.get("base"))
                            .unwrap_or(self.pc)
                            .wrapping_add_signed(offset),
                    )
                })
                .unwrap_or(Symbolic::Unknown),
            Some("direct") => addr
                .get("reg")
                .map(|value| self.symbolic(value))
                .unwrap_or(Symbolic::Unknown),
            Some("base_offset") => {
                let base = addr
                    .get("base")
                    .map(|value| self.symbolic(value))
                    .unwrap_or(Symbolic::Unknown);
                let offset = integer(addr.get("offset")).unwrap_or(0);
                match (base, offset) {
                    (Symbolic::Register(reg), 0) => Symbolic::Register(reg),
                    (Symbolic::Constant(value), offset) => {
                        Symbolic::Constant(value.wrapping_add_signed(offset))
                    }
                    _ => Symbolic::Unknown,
                }
            }
            _ => Symbolic::Unknown,
        }
    }

    fn analyze_control_flow(&mut self, smir: &Value) {
        let cf = smir.get("control_flow").unwrap_or(&Value::Null);
        let kind = cf.get("kind").and_then(Value::as_str).unwrap_or("unknown");
        match kind {
            "cond_branch" => {
                if let Some(cond) = cf.get("condition").and_then(Value::as_str) {
                    self.flags_read |= condition_flags(cond);
                }
            }
            "cond_branch_reg" => {
                if let Some(value) = cf.get("condition_value")
                    && let Symbolic::Register(reg) = self.symbolic(value)
                {
                    self.register_read(reg);
                }
            }
            "indirect_branch" => {
                if let Some(value) = cf.get("target_value")
                    && let Symbolic::Register(reg) = self.symbolic(value)
                {
                    self.register_read(reg);
                }
            }
            "indirect_branch_mem" => {
                // This is an instruction fetch through a computed memory
                // address. Model the dereference explicitly even when the
                // lifter did not need a separate Load op.
                let mut effect = RaxAnalysisEffect::empty(
                    RAX_EFFECT_MEMORY,
                    RAX_EFFECT_READ | RAX_EFFECT_IMPLICIT,
                );
                effect.width_bits = pointer_width(self.arch);
                if let Some(addr) = cf.get("address") {
                    if self.fill_address(addr, &mut effect) {
                        effect.access |= RAX_EFFECT_ADDRESS_COMPLETE;
                        self.address_register_reads(&effect);
                    } else {
                        self.complete = false;
                    }
                } else {
                    effect.address_kind = RAX_ADDRESS_UNKNOWN;
                    self.complete = false;
                }
                self.push(effect);
            }
            "call" => {
                if let Some(target) = cf.get("target") {
                    match target.get("kind").and_then(Value::as_str) {
                        Some("indirect") => {
                            if let Some(value) = target.get("reg_value")
                                && let Symbolic::Register(reg) = self.symbolic(value)
                            {
                                self.register_read(reg);
                            }
                        }
                        Some("indirect_mem") => {
                            let mut effect = RaxAnalysisEffect::empty(
                                RAX_EFFECT_MEMORY,
                                RAX_EFFECT_READ | RAX_EFFECT_IMPLICIT,
                            );
                            effect.width_bits = pointer_width(self.arch);
                            if let Some(addr) = target.get("address") {
                                if self.fill_address(addr, &mut effect) {
                                    effect.access |= RAX_EFFECT_ADDRESS_COMPLETE;
                                    self.address_register_reads(&effect);
                                } else {
                                    self.complete = false;
                                }
                            } else {
                                self.complete = false;
                            }
                            self.push(effect);
                        }
                        _ => {}
                    }
                }
                // The x86 SMIR call terminator intentionally carries control
                // flow only; materialize its architectural near-call stack
                // effects here so a COMPLETE result is not missing the push.
                // Address expressions are relative to pre-instruction values.
                if self.arch == RaxArch::X86 {
                    let rsp = 0x0100 + 4;
                    self.register_read(rsp);
                    self.register_write(rsp, 64, Symbolic::Unknown);
                    let mut effect = RaxAnalysisEffect::empty(
                        RAX_EFFECT_MEMORY,
                        RAX_EFFECT_WRITE
                            | RAX_EFFECT_IMPLICIT
                            | RAX_EFFECT_ADDRESS_COMPLETE
                            | RAX_EFFECT_VALUE_COMPLETE,
                    );
                    effect.width_bits = 64;
                    effect.address_kind = RAX_ADDRESS_BASE_DISP;
                    effect.base_reg = rsp;
                    effect.displacement = -8;
                    effect.value_kind = RAX_VALUE_CONSTANT;
                    let size = smir
                        .get("bytes_consumed")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    effect.value = self.pc.wrapping_add(size);
                    self.push(effect);
                }
            }
            // Exception entry and host/runtime service effects depend on
            // privileged machine state that a stateless single-instruction
            // lift does not carry. Keep the useful decode but never advertise
            // a complete effect set for these terminators.
            "syscall" | "trap" => self.complete = false,
            _ => {}
        }
    }

    fn apply_arch_outputs(&mut self, smir: &Value) {
        let Some(outputs) = smir.get("arch_outputs").and_then(Value::as_array) else {
            self.complete = false;
            return;
        };
        for output in outputs {
            let Some(reg) = output
                .get("reg")
                .and_then(|value| stable_reg_id(self.arch, value))
            else {
                self.complete = false;
                continue;
            };
            let value = output
                .get("value")
                .map(|value| self.symbolic(value))
                .unwrap_or(Symbolic::Unknown);
            let width = output
                .get("value")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
                .and_then(|id| self.widths.get(&id).copied())
                .unwrap_or_else(|| natural_reg_width(self.arch, reg));
            self.register_write(reg, width, value);
        }
    }
}

fn collect_vregs<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_vregs(value, out);
            }
        }
        Value::Object(object) => {
            if matches!(
                object.get("kind").and_then(Value::as_str),
                Some("arch" | "virtual" | "imm")
            ) {
                out.push(value);
                return;
            }
            for value in object.values() {
                collect_vregs(value, out);
            }
        }
        _ => {}
    }
}

fn integer(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| value.as_u64().map(|v| v as i64))
}

fn parse_hexish(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}

fn width_name_bits(value: Option<&Value>) -> Option<u32> {
    let name = value?.as_str()?;
    name.strip_prefix('W')?.parse().ok()
}

fn operation_width_bits(kind: &Value, opcode: &str) -> u32 {
    width_name_bits(kind.get("width"))
        .or_else(|| memory_width_name_bits(kind.get("width")))
        .or_else(|| width_name_bits(kind.get("to_width")))
        .unwrap_or_else(|| if opcode.starts_with('v') { 0 } else { 64 })
}

fn memory_width_name_bits(value: Option<&Value>) -> Option<u32> {
    let name = value?.as_str()?;
    if let Some(bytes) = name.strip_prefix('B') {
        return bytes.parse::<u32>().ok()?.checked_mul(8);
    }
    name.strip_prefix('V')?.parse().ok()
}

fn memory_width_bits(kind: &Value, opcode: &str) -> u32 {
    let mut width = memory_width_name_bits(kind.get("width"))
        .or_else(|| width_name_bits(kind.get("width")))
        .unwrap_or(0);
    if matches!(opcode, "load_pair" | "store_pair") {
        width = width.saturating_mul(2);
    }
    width
}

fn mask_width(value: u64, width: u32) -> u64 {
    match width {
        0 | 64.. => value,
        bits => value & ((1u64 << bits) - 1),
    }
}

fn sign_extend(value: u64, from: u32, to: u32) -> u64 {
    if from == 0 || from >= 64 {
        return mask_width(value, to);
    }
    let shift = 64 - from;
    mask_width((((value << shift) as i64) >> shift) as u64, to)
}

fn infer_binary(opcode: &str, lhs: Symbolic, rhs: Symbolic, width: u32) -> Symbolic {
    if opcode == "xor" && lhs == rhs && lhs != Symbolic::Unknown {
        return Symbolic::Constant(0);
    }
    match (lhs, rhs) {
        (Symbolic::Constant(a), Symbolic::Constant(b)) => Symbolic::Constant(mask_width(
            match opcode {
                "add" => a.wrapping_add(b),
                "sub" => a.wrapping_sub(b),
                "and" => a & b,
                "or" => a | b,
                "xor" => a ^ b,
                _ => return Symbolic::Unknown,
            },
            width,
        )),
        (reg @ Symbolic::Register(_), Symbolic::Constant(0))
            if matches!(opcode, "add" | "sub" | "or" | "xor") =>
        {
            reg
        }
        (reg @ Symbolic::Register(_), Symbolic::Constant(mask))
            if opcode == "and" && mask_width(mask, width) == mask_width(u64::MAX, width) =>
        {
            reg
        }
        _ => Symbolic::Unknown,
    }
}

fn condition_flags(condition: &str) -> u32 {
    match condition.to_ascii_lowercase().as_str() {
        "eq" | "ne" | "e" | "z" | "nz" => RAX_FLAG_Z,
        "ult" | "uge" | "b" | "ae" | "cs" | "cc" | "lo" | "hs" => RAX_FLAG_C,
        "ule" | "ugt" | "be" | "a" | "ls" | "hi" => RAX_FLAG_C | RAX_FLAG_Z,
        "slt" | "sge" | "l" | "ge" | "lt" => RAX_FLAG_N | RAX_FLAG_V,
        "sle" | "sgt" | "le" | "g" | "gt" => RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_V,
        "negative" | "positive" | "mi" | "pl" | "s" | "ns" => RAX_FLAG_N,
        "overflow" | "nooverflow" | "vs" | "vc" | "o" | "no" => RAX_FLAG_V,
        "parity" | "noparity" | "p" | "np" => RAX_FLAG_P,
        "always" | "al" => 0,
        // An unfamiliar architectural condition is still known to consume
        // condition codes. Conservatively report the common arithmetic set.
        _ => RAX_FLAG_NZCV,
    }
}

fn stable_reg_id(arch: RaxArch, value: &Value) -> Option<i32> {
    let value_arch = value.get("arch").and_then(Value::as_str)?;
    let expected = match arch {
        RaxArch::X86 => "x86_64",
        RaxArch::Arm64 => "aarch64",
        RaxArch::Riscv64 => "riscv",
        RaxArch::Hexagon => "hexagon",
        RaxArch::Arm | RaxArch::CortexM => return None,
    };
    if value_arch != expected {
        return None;
    }
    stable_named_reg(arch, value.get("name")?.as_str()?)
}

fn suffix_index(name: &str, prefix: &str, limit: u32) -> Option<i32> {
    let index: u32 = name.strip_prefix(prefix)?.parse().ok()?;
    (index < limit).then_some(index as i32)
}

fn stable_named_reg(arch: RaxArch, name: &str) -> Option<i32> {
    match arch {
        RaxArch::X86 => {
            let gprs = [
                "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
                "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
            ];
            if let Some(index) = gprs.iter().position(|candidate| *candidate == name) {
                return Some(0x0100 + index as i32);
            }
            match name {
                "rip" => Some(0x0010),
                "rflags" => Some(0x0012),
                "fs_base" => Some(0x1009),
                "gs_base" => Some(0x100a),
                _ => suffix_index(name, "xmm", 32)
                    .map(|index| 0x0b00 + index)
                    .or_else(|| suffix_index(name, "ymm", 32).map(|index| 0x0c00 + index))
                    .or_else(|| suffix_index(name, "zmm", 32).map(|index| 0x0d00 + index))
                    .or_else(|| suffix_index(name, "k", 8).map(|index| 0x0e00 + index)),
            }
        }
        RaxArch::Arm64 => match name {
            "sp" => Some(0x0010),
            "pc" => Some(0x0011),
            "nzcv" => Some(0x0012),
            "fpcr" => Some(0x0020),
            "fpsr" => Some(0x0021),
            _ => suffix_index(name, "x", 31)
                .map(|index| 0x0100 + index)
                .or_else(|| suffix_index(name, "v", 32).map(|index| 0x0200 + index)),
        },
        RaxArch::Riscv64 => match name {
            "pc" => Some(0x0011),
            "fcsr" | "csr_0x3" => Some(0x0023),
            _ => suffix_index(name, "x", 32)
                .map(|index| 0x0100 + index)
                .or_else(|| suffix_index(name, "f", 32).map(|index| 0x0200 + index)),
        },
        RaxArch::Hexagon => match name {
            "pc" => Some(0x0300 + 9),
            "gp" => Some(0x0300 + 11),
            "lr" => Some(0x0100 + 31),
            "sp" => Some(0x0100 + 29),
            "fp" => Some(0x0100 + 30),
            "lc0" => Some(0x0300 + 1),
            "lc1" => Some(0x0300 + 3),
            "sa0" => Some(0x0300),
            "sa1" => Some(0x0300 + 2),
            "usr" => Some(0x0300 + 8),
            _ => suffix_index(name, "r", 32)
                .map(|index| 0x0100 + index)
                .or_else(|| suffix_index(name, "v", 32).map(|index| 0x0200 + index))
                .or_else(|| suffix_index(name, "m", 2).map(|index| 0x0300 + 6 + index))
                .or_else(|| suffix_index(name, "cs", 2).map(|index| 0x0300 + 12 + index))
                .or_else(|| suffix_index(name, "p", 4).map(|index| 0x0400 + index))
                .or_else(|| suffix_index(name, "q", 4).map(|index| 0x0500 + index)),
        },
        RaxArch::Arm | RaxArch::CortexM => None,
    }
}

fn natural_reg_width(arch: RaxArch, reg: i32) -> u32 {
    let family = reg & !0xff;
    match arch {
        RaxArch::X86 => match reg {
            0x0010 | 0x0012 | 0x1009 | 0x100a => 64,
            _ => match family {
                0x0100 => 64,
                0x0b00 => 128,
                0x0c00 => 256,
                0x0d00 => 512,
                0x0e00 => 64,
                _ => 0,
            },
        },
        RaxArch::Arm64 => match reg {
            0x0010..=0x0021 => 64,
            _ if family == 0x0100 => 64,
            _ if family == 0x0200 => 128,
            _ => 0,
        },
        RaxArch::Riscv64 => match reg {
            0x0011 => 64,
            0x0023 => 32,
            _ if family == 0x0100 || family == 0x0200 => 64,
            _ => 0,
        },
        RaxArch::Hexagon => match family {
            0x0100 | 0x0300 => 32,
            0x0200 => 1024,
            0x0400 => 8,
            0x0500 => 128,
            _ => 0,
        },
        RaxArch::Arm | RaxArch::CortexM => 0,
    }
}

fn pointer_width(arch: RaxArch) -> u32 {
    match arch {
        RaxArch::X86 | RaxArch::Arm64 | RaxArch::Riscv64 => 64,
        RaxArch::Hexagon | RaxArch::Arm | RaxArch::CortexM => 32,
    }
}

/// Analyze one instruction without creating or mutating an emulation engine.
///
/// `out_effect_count` always receives the number of records required. Passing
/// `effects == NULL, effect_cap == 0` is the size-query form and succeeds.
/// A non-NULL undersized array receives a deterministic prefix and returns
/// `RAX_ERR_BOUNDS`; the summary carries `RAX_ANALYSIS_TRUNCATED`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_analyze(
    arch: c_int,
    mode: u32,
    pc: u64,
    bytes: *const c_void,
    len: usize,
    out: *mut RaxAnalysis,
    effects: *mut RaxAnalysisEffect,
    effect_cap: usize,
    out_effect_count: *mut usize,
) -> RaxStatus {
    guard(|| {
        if out.is_null() || out_effect_count.is_null() {
            return RaxStatus::Arg;
        }
        unsafe {
            *out = RaxAnalysis::zeroed();
            *out_effect_count = 0;
        }
        if bytes.is_null()
            || len == 0
            || len > isize::MAX as usize
            || (effects.is_null() && effect_cap != 0)
        {
            return RaxStatus::Arg;
        }
        let arch = match RaxArch::from_i32(arch) {
            Some(arch) => arch,
            None => return RaxStatus::Arch,
        };
        if arch == RaxArch::X86 && crate::instruction_info::bitness(mode).is_none() {
            return RaxStatus::Mode;
        }
        let mode = match normalize_mode(arch, mode) {
            Some(mode) => mode,
            None => return RaxStatus::Mode,
        };

        let input = unsafe { slice::from_raw_parts(bytes.cast::<u8>(), len) };
        let opts = oracle_options(arch, mode, pc);
        let value = match decode_to_json(input, &opts) {
            Ok(value) => value,
            Err(_) => Value::Null,
        };

        let mut summary = RaxAnalysis::zeroed();
        if arch == RaxArch::X86 {
            let bits = crate::instruction_info::bitness(mode).unwrap();
            summary.decoded =
                crate::instruction_info::decode_x86(bits, pc, &input[..input.len().min(15)])
                    .decoded;
        } else {
            fill_from_json(&value, &mut summary.decoded);
        }
        if summary.decoded.valid != 0 {
            summary.flags |= RAX_ANALYSIS_VALID;
        }

        let rich_arch = matches!(
            arch,
            RaxArch::X86 | RaxArch::Arm64 | RaxArch::Riscv64 | RaxArch::Hexagon
        ) && (arch != RaxArch::X86 || mode & RAX_MODE_64 != 0);
        let smir = value.get("smir").unwrap_or(&Value::Null);
        let available = smir
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let lift_size_matches =
            smir.get("bytes_consumed").and_then(Value::as_u64) == Some(summary.decoded.size as u64);
        let lift_ok = available
            && smir.get("error").is_none()
            && summary.decoded.valid != 0
            && lift_size_matches;
        let mut analyzer = Analyzer::new(arch, pc);

        if rich_arch && lift_ok {
            summary.flags |= RAX_ANALYSIS_HAS_SMIR;
            let ops = smir
                .get("ops")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            summary.smir_op_count = u32::try_from(ops.len()).unwrap_or(u32::MAX);
            for op in ops {
                analyzer.analyze_op(op);
            }
            analyzer.analyze_control_flow(smir);
            analyzer.apply_arch_outputs(smir);
            if analyzer.complete {
                summary.flags |= RAX_ANALYSIS_COMPLETE;
            } else {
                summary.flags |= RAX_ANALYSIS_PARTIAL;
            }
        } else {
            summary.flags |= RAX_ANALYSIS_UNSUPPORTED;
            if summary.decoded.valid != 0 {
                summary.flags |= RAX_ANALYSIS_PARTIAL;
            }
        }

        summary.flags_read = analyzer.flags_read;
        summary.flags_written = analyzer.flags_written;
        summary.flags_undefined = analyzer.flags_undefined;
        let required = analyzer.effects.len();
        summary.required_effect_count = u32::try_from(required).unwrap_or(u32::MAX);
        unsafe {
            *out_effect_count = required;
        }

        let copied = effect_cap.min(required);
        if copied != 0 {
            // A nonzero cap with NULL was rejected above.
            unsafe {
                std::ptr::copy_nonoverlapping(analyzer.effects.as_ptr(), effects, copied);
            }
        }
        summary.effect_count = u32::try_from(copied).unwrap_or(u32::MAX);
        let truncated = !effects.is_null() && effect_cap < required;
        if truncated {
            summary.flags |= RAX_ANALYSIS_TRUNCATED;
        }
        unsafe {
            *out = summary;
        }
        if truncated {
            RaxStatus::Bounds
        } else {
            RaxStatus::Ok
        }
    })
}
