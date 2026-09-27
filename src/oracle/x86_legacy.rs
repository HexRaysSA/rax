//! Length and control flow of 16- and 32-bit x86 instructions (real,
//! virtual-8086, and protected mode), from the Intel SDM Vol. 2 chapter 2
//! instruction format and Appendix A opcode maps. The SMIR x86 lifter models
//! 64-bit mode only, so these modes are decoded without semantics.
//!
//! Differences from 64-bit mode: 0x40-0x4F are INC/DEC, not REX; the
//! default operand and address size is the code size, toggled by 0x66 and
//! 0x67; ModR/M may use 16-bit addressing; the opcodes invalid in 64-bit mode
//! (PUSH/POP of segment registers, BCD adjusts, PUSHA/POPA, BOUND, ARPL,
//! LES/LDS, far CALL/JMP with a pointer, INTO, SALC, 0x82) are valid; C4/C5
//! and 0x62 start VEX and EVEX when the next byte has ModR/M.mod = 11, and
//! 0x8F starts XOP when its map field is 8 or more (in real and virtual-8086
//! mode these encodings are #UD either way; 16-bit protected mode decodes
//! them).
//!
//! Reserved opcodes of the 0F 38 and 0F 3A maps, and opcodes whose
//! validity depends on the mandatory prefix, decode by their encoding length
//! without a validity check.

use serde_json::{Value, json};

/// The default operand and address size of x86 code: the code segment's
/// L and D bits (64-bit mode, 32-bit protected mode, or 16-bit real,
/// virtual-8086, or protected mode).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum X86CodeSize {
    Bits16,
    Bits32,
    #[default]
    Bits64,
}

/// Architectural limit on an instruction's length (SDM Vol. 2, 2.3.11).
const MAX_LEN: usize = 15;

/// How an instruction transfers control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    Fallthrough,
    /// JMP with a relative displacement.
    Branch(u64),
    /// Jcc (flags), or LOOP/JCXZ (`register` = true).
    CondBranch {
        target: u64,
        register: bool,
    },
    /// CALL with a relative displacement.
    Call(u64),
    /// JMP through a register or memory, or a far JMP.
    IndirectBranch,
    /// CALL through a register or memory, or a far CALL.
    IndirectCall,
    /// RET, RETF.
    Return,
    /// SYSENTER, SYSCALL.
    Syscall,
    /// An instruction that raises an exception or stops: INT n, INT3,
    /// INTO, INT1, IRET, HLT, UD0/UD1/UD2, and undefined encodings.
    Trap(&'static str),
}

/// A decoded instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Insn {
    pub len: usize,
    /// The opcode bytes after the prefixes, as hex (`"0f 85"`).
    pub opcode: String,
    pub operand_size: u32,
    pub address_size: u32,
    pub flow: Flow,
}

/// Immediate operand of an opcode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Imm {
    None,
    /// 8 bits.
    B,
    /// 16 bits.
    W,
    /// The operand size (16 or 32 bits).
    Z,
    /// A far pointer: offset of the operand size, then a 16-bit selector.
    Far,
    /// A memory offset of the address size (MOV moffs).
    Moffs,
    /// ENTER: 16 then 8 bits.
    WB,
    /// A relative branch displacement of 8 bits.
    Rel8,
    /// A relative branch displacement of the operand size.
    RelZ,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, String> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| format!("truncated after {} bytes", self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Result<u8, String> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| format!("truncated after {} bytes", self.pos))
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        if self.pos + n > self.bytes.len() {
            return Err(format!("truncated after {} bytes", self.bytes.len()));
        }
        self.pos += n;
        Ok(())
    }

    /// A little-endian signed value of `n` bytes.
    fn signed(&mut self, n: usize) -> Result<i64, String> {
        let start = self.pos;
        self.skip(n)?;
        let mut v: u64 = 0;
        for (i, b) in self.bytes[start..start + n].iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
        let shift = 64 - 8 * n as u32;
        Ok(((v << shift) as i64) >> shift)
    }

    /// Consumes a ModR/M byte and its SIB and displacement; returns the
    /// ModR/M byte.
    fn modrm(&mut self, address_size: u32) -> Result<u8, String> {
        let m = self.byte()?;
        let (mode, rm) = (m >> 6, m & 7);
        if mode == 3 {
            return Ok(m);
        }
        let disp = if address_size == 16 {
            match mode {
                0 if rm == 6 => 2,
                0 => 0,
                1 => 1,
                _ => 2,
            }
        } else {
            let base = if rm == 4 { self.byte()? & 7 } else { rm };
            match mode {
                0 if base == 5 => 4,
                0 => 0,
                1 => 1,
                _ => 4,
            }
        };
        self.skip(disp)?;
        Ok(m)
    }
}

/// Decodes one instruction of `code_size` (16 or 32) bits at `pc`, the
/// instruction's offset in its code segment.
pub(crate) fn decode(bytes: &[u8], pc: u64, code_size: u32) -> Result<Insn, String> {
    assert!(code_size == 16 || code_size == 32);
    let mut r = Reader { bytes, pos: 0 };
    let (mut opsize_override, mut addrsize_override) = (false, false);
    let mut mandatory = 0u8;
    loop {
        match r.peek()? {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0xF0 => {}
            0x66 => opsize_override = true,
            0x67 => addrsize_override = true,
            b @ (0xF2 | 0xF3) => mandatory = b,
            _ => break,
        }
        r.pos += 1;
        if r.pos >= MAX_LEN {
            return Err("more than 15 bytes of prefixes".to_string());
        }
    }
    let toggle = |overridden: bool| match (code_size, overridden) {
        (16, false) | (32, true) => 16,
        _ => 32,
    };
    let operand_size = toggle(opsize_override);
    let address_size = toggle(addrsize_override);
    let opcode_start = r.pos;
    let flow = decode_opcode(
        &mut r,
        operand_size,
        address_size,
        opsize_override,
        mandatory,
    )?;
    if r.pos > MAX_LEN {
        return Err(format!("{} bytes exceed the 15-byte limit", r.pos));
    }
    let opcode = bytes[opcode_start..r.pos.min(opcode_start + 3)]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let len = r.pos;
    let next = pc.wrapping_add(len as u64);
    let ip_mask = if operand_size == 16 {
        0xFFFF
    } else {
        0xFFFF_FFFF
    };
    let target = |rel: i64| next.wrapping_add(rel as u64) & ip_mask;
    let flow = match flow {
        Pending::Done(flow) => flow,
        Pending::Rel(kind, rel) => match kind {
            RelKind::Jmp => Flow::Branch(target(rel)),
            RelKind::Call => Flow::Call(target(rel)),
            RelKind::Jcc => Flow::CondBranch {
                target: target(rel),
                register: false,
            },
            RelKind::Loop => Flow::CondBranch {
                target: target(rel),
                register: true,
            },
        },
    };
    Ok(Insn {
        len,
        opcode,
        operand_size,
        address_size,
        flow,
    })
}

#[derive(Clone, Copy)]
enum RelKind {
    Jmp,
    Call,
    Jcc,
    Loop,
}

/// A flow whose relative target needs the final length.
enum Pending {
    Done(Flow),
    Rel(RelKind, i64),
}

fn immediate(
    r: &mut Reader,
    imm: Imm,
    operand_size: u32,
    address_size: u32,
) -> Result<Option<i64>, String> {
    let z = operand_size as usize / 8;
    match imm {
        Imm::None => {}
        Imm::B => r.skip(1)?,
        Imm::W => r.skip(2)?,
        Imm::Z => r.skip(z)?,
        Imm::Far => r.skip(z + 2)?,
        Imm::Moffs => r.skip(address_size as usize / 8)?,
        Imm::WB => r.skip(3)?,
        Imm::Rel8 => return r.signed(1).map(Some),
        Imm::RelZ => return r.signed(z).map(Some),
    }
    Ok(None)
}

const UNDEFINED: Pending = Pending::Done(Flow::Trap("undefined"));

fn decode_opcode(
    r: &mut Reader,
    operand_size: u32,
    address_size: u32,
    opsize_override: bool,
    mandatory: u8,
) -> Result<Pending, String> {
    let op = r.byte()?;
    let fall = Pending::Done(Flow::Fallthrough);
    let modrm = |r: &mut Reader| r.modrm(address_size);
    let imm = |r: &mut Reader, kind: Imm| immediate(r, kind, operand_size, address_size);
    let next_is_register_form = |r: &Reader| r.peek().map(|b| b >> 6 == 3);
    match op {
        0x0F => return two_byte(r, operand_size, address_size, opsize_override, mandatory),
        0xC4 | 0xC5 if next_is_register_form(r)? => {
            return vex(r, op, operand_size, address_size);
        }
        0x62 if next_is_register_form(r)? => {
            return evex(r, operand_size, address_size);
        }
        0x8F if r.peek()? & 0x1F >= 8 => {
            return xop(r, operand_size, address_size);
        }
        _ => {}
    }
    Ok(match op {
        // ALU groups: r/m forms, AL/eAX immediates, and the one-byte
        // segment pushes, pops, and BCD adjusts.
        0x00..=0x3F => {
            match op & 7 {
                0..=3 => {
                    modrm(r)?;
                }
                4 => imm(r, Imm::B).map(|_| ())?,
                5 => imm(r, Imm::Z).map(|_| ())?,
                _ => {}
            }
            fall
        }
        0x40..=0x61
        | 0x90..=0x99
        | 0x9B..=0x9F
        | 0xA4..=0xA7
        | 0xAA..=0xAF
        | 0xC9
        | 0xD6
        | 0xD7
        | 0xEC..=0xEF
        | 0xF5
        | 0xF8..=0xFD => fall,
        0x62 | 0xC4 | 0xC5 | 0x8D => {
            // BOUND, LES, LDS, LEA: memory operand only.
            if modrm(r)? >> 6 == 3 { UNDEFINED } else { fall }
        }
        0x63 | 0x84..=0x8B | 0xD0..=0xD3 | 0xD8..=0xDF => {
            modrm(r)?;
            fall
        }
        0x8C | 0x8E => {
            // MOV to or from a segment register: ES, CS, SS, DS, FS, GS,
            // and never a load of CS.
            let sreg = (modrm(r)? >> 3) & 7;
            if sreg > 5 || (op == 0x8E && sreg == 1) {
                UNDEFINED
            } else {
                fall
            }
        }
        0x68 => {
            imm(r, Imm::Z)?;
            fall
        }
        0x69 | 0x81 => {
            modrm(r)?;
            imm(r, Imm::Z)?;
            fall
        }
        0x6A | 0xA8 | 0xB0..=0xB7 | 0xE4..=0xE7 | 0xD4 | 0xD5 => {
            imm(r, Imm::B)?;
            fall
        }
        0x6B | 0x80 | 0x82 | 0x83 | 0xC0 | 0xC1 => {
            modrm(r)?;
            imm(r, Imm::B)?;
            fall
        }
        0x6C..=0x6F => fall,
        0x70..=0x7F => Pending::Rel(RelKind::Jcc, imm(r, Imm::Rel8)?.unwrap()),
        0x8F => {
            // POP r/m: /0 only.
            if (modrm(r)? >> 3) & 7 != 0 {
                UNDEFINED
            } else {
                fall
            }
        }
        0x9A => {
            imm(r, Imm::Far)?;
            Pending::Done(Flow::IndirectCall)
        }
        0xA0..=0xA3 => {
            imm(r, Imm::Moffs)?;
            fall
        }
        0xA9 | 0xB8..=0xBF => {
            imm(r, Imm::Z)?;
            fall
        }
        0xC2 | 0xCA => {
            imm(r, Imm::W)?;
            Pending::Done(Flow::Return)
        }
        0xC3 | 0xCB => Pending::Done(Flow::Return),
        0xC6 | 0xC7 => {
            let m = r.peek()?;
            if m == 0xF8 {
                // XABORT imm8 / XBEGIN rel16/32.
                r.byte()?;
                if op == 0xC6 {
                    imm(r, Imm::B)?;
                    fall
                } else {
                    Pending::Rel(RelKind::Jcc, imm(r, Imm::RelZ)?.unwrap())
                }
            } else {
                let m = modrm(r)?;
                imm(r, if op == 0xC6 { Imm::B } else { Imm::Z })?;
                if (m >> 3) & 7 != 0 { UNDEFINED } else { fall }
            }
        }
        0xC8 => {
            imm(r, Imm::WB)?;
            fall
        }
        0xCC => Pending::Done(Flow::Trap("int3")),
        0xCD => {
            imm(r, Imm::B)?;
            Pending::Done(Flow::Trap("int"))
        }
        0xCE => Pending::Done(Flow::Trap("into")),
        0xCF => Pending::Done(Flow::Trap("iret")),
        0xE0..=0xE3 => Pending::Rel(RelKind::Loop, imm(r, Imm::Rel8)?.unwrap()),
        0xE8 => Pending::Rel(RelKind::Call, imm(r, Imm::RelZ)?.unwrap()),
        0xE9 => Pending::Rel(RelKind::Jmp, imm(r, Imm::RelZ)?.unwrap()),
        0xEA => {
            imm(r, Imm::Far)?;
            Pending::Done(Flow::IndirectBranch)
        }
        0xEB => Pending::Rel(RelKind::Jmp, imm(r, Imm::Rel8)?.unwrap()),
        0xF1 => Pending::Done(Flow::Trap("int1")),
        0xF4 => Pending::Done(Flow::Trap("halt")),
        0xF6 | 0xF7 => {
            // TEST r/m, imm (/0, /1) carries an immediate.
            let m = modrm(r)?;
            if (m >> 3) & 7 < 2 {
                imm(r, if op == 0xF6 { Imm::B } else { Imm::Z })?;
            }
            fall
        }
        0xFE => {
            if (modrm(r)? >> 3) & 7 > 1 {
                UNDEFINED
            } else {
                fall
            }
        }
        0xFF => {
            let m = modrm(r)?;
            let register = m >> 6 == 3;
            match (m >> 3) & 7 {
                2 => Pending::Done(Flow::IndirectCall),
                3 if !register => Pending::Done(Flow::IndirectCall),
                4 => Pending::Done(Flow::IndirectBranch),
                5 if !register => Pending::Done(Flow::IndirectBranch),
                0 | 1 | 6 => fall,
                _ => UNDEFINED,
            }
        }
        // Prefixes were consumed before the opcode; 0x0F is handled above.
        _ => UNDEFINED,
    })
}

/// The two-byte opcode map (0F xx), including the 0F 38 and 0F 3A maps.
fn two_byte(
    r: &mut Reader,
    operand_size: u32,
    address_size: u32,
    opsize_override: bool,
    mandatory: u8,
) -> Result<Pending, String> {
    let op = r.byte()?;
    let fall = Pending::Done(Flow::Fallthrough);
    let modrm = |r: &mut Reader| r.modrm(address_size);
    let imm = |r: &mut Reader, kind: Imm| immediate(r, kind, operand_size, address_size);
    Ok(match op {
        0x38 => {
            r.byte()?;
            modrm(r)?;
            fall
        }
        0x3A => {
            r.byte()?;
            modrm(r)?;
            imm(r, Imm::B)?;
            fall
        }
        0x00 => {
            if (modrm(r)? >> 3) & 7 > 5 {
                UNDEFINED
            } else {
                fall
            }
        }
        // Memory operands only.
        0x0D | 0x13 | 0x17 | 0x2B | 0xB2 | 0xB4 | 0xB5 | 0xC3 | 0xE7 => {
            if modrm(r)? >> 6 == 3 {
                UNDEFINED
            } else {
                fall
            }
        }
        // Register operands only.
        0x50 | 0xD7 | 0xF7 => {
            if modrm(r)? >> 6 != 3 {
                UNDEFINED
            } else {
                fall
            }
        }
        0x01..=0x03
        | 0x10..=0x12
        | 0x14..=0x16
        | 0x18..=0x1F
        | 0x28..=0x2A
        | 0x2C..=0x2F
        | 0x40..=0x4F
        | 0x51..=0x6F
        | 0x74..=0x76
        | 0x7C..=0x7F
        | 0x90..=0x9F
        | 0xA3
        | 0xA5
        | 0xAB
        | 0xAD
        | 0xAE
        | 0xAF
        | 0xB0
        | 0xB1
        | 0xB3
        | 0xB6
        | 0xB7
        | 0xBB..=0xBF
        | 0xC0
        | 0xC1
        | 0xC7
        | 0xD0..=0xD6
        | 0xD8..=0xE6
        | 0xE8..=0xF6
        | 0xF8..=0xFE => {
            modrm(r)?;
            fall
        }
        // VIA PadLock (MONTMUL, XSHA*, XSTORE, XCRYPT*): register form.
        0xA6 | 0xA7 => {
            if modrm(r)? >> 6 != 3 {
                UNDEFINED
            } else {
                fall
            }
        }
        // MOV to or from control and debug registers: the ModR/M byte
        // always names registers.
        0x20..=0x23 => {
            r.byte()?;
            fall
        }
        0x0F => {
            // 3DNow!: ModR/M, then the opcode suffix byte.
            modrm(r)?;
            imm(r, Imm::B)?;
            fall
        }
        0x71..=0x73 => {
            // Groups 12-14: register operands only.
            let m = modrm(r)?;
            imm(r, Imm::B)?;
            if m >> 6 != 3 { UNDEFINED } else { fall }
        }
        0xC5 => {
            // PEXTRW: register operands only.
            let m = modrm(r)?;
            imm(r, Imm::B)?;
            if m >> 6 != 3 { UNDEFINED } else { fall }
        }
        0x70 | 0xA4 | 0xAC | 0xC2 | 0xC4 | 0xC6 => {
            modrm(r)?;
            imm(r, Imm::B)?;
            fall
        }
        0x78 if (opsize_override || mandatory == 0xF2) && r.peek()? >> 6 == 3 => {
            // EXTRQ / INSERTQ with immediates (SSE4a).
            modrm(r)?;
            imm(r, Imm::W)?;
            fall
        }
        0x78 | 0x79 => {
            modrm(r)?;
            fall
        }
        0xBA => {
            let m = modrm(r)?;
            imm(r, Imm::B)?;
            if (m >> 3) & 7 < 4 { UNDEFINED } else { fall }
        }
        0xB8 => {
            // POPCNT needs F3; the bare form is the Itanium JMPE.
            modrm(r)?;
            if mandatory == 0xF3 { fall } else { UNDEFINED }
        }
        0x80..=0x8F => Pending::Rel(RelKind::Jcc, imm(r, Imm::RelZ)?.unwrap()),
        0x05 | 0x34 => Pending::Done(Flow::Syscall),
        0x07 | 0x35 => Pending::Done(Flow::IndirectBranch),
        0x06
        | 0x08
        | 0x09
        | 0x0E
        | 0x30..=0x33
        | 0x37
        | 0x77
        | 0xA0..=0xA2
        | 0xA8..=0xAA
        | 0xC8..=0xCF => fall,
        0x0B => Pending::Done(Flow::Trap("ud2")),
        0xB9 | 0xFF => {
            modrm(r)?;
            Pending::Done(Flow::Trap("ud"))
        }
        _ => UNDEFINED,
    })
}

/// A VEX-encoded instruction; `op` is C4 (three-byte) or C5 (two-byte).
fn vex(r: &mut Reader, op: u8, operand_size: u32, address_size: u32) -> Result<Pending, String> {
    let map = if op == 0xC5 {
        r.byte()?;
        1
    } else {
        let map = r.byte()? & 0x1F;
        r.byte()?;
        map
    };
    let opcode = r.byte()?;
    match map {
        1 if opcode == 0x77 => {}
        1 => {
            r.modrm(address_size)?;
            if matches!(opcode, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6) {
                immediate(r, Imm::B, operand_size, address_size)?;
            }
        }
        2 => {
            r.modrm(address_size)?;
        }
        3 => {
            r.modrm(address_size)?;
            immediate(r, Imm::B, operand_size, address_size)?;
        }
        _ => return Ok(UNDEFINED),
    }
    Ok(Pending::Done(Flow::Fallthrough))
}

/// An EVEX-encoded instruction (four-byte prefix 62 P0 P1 P2).
fn evex(r: &mut Reader, operand_size: u32, address_size: u32) -> Result<Pending, String> {
    let map = r.byte()? & 7;
    r.skip(2)?;
    let opcode = r.byte()?;
    r.modrm(address_size)?;
    let has_imm = match map {
        1 => matches!(opcode, 0x70..=0x73 | 0xC2 | 0xC4..=0xC6),
        3 => true,
        2 | 5 | 6 => false,
        _ => return Ok(UNDEFINED),
    };
    if has_imm {
        immediate(r, Imm::B, operand_size, address_size)?;
    }
    Ok(Pending::Done(Flow::Fallthrough))
}

/// An AMD XOP-encoded instruction (8F with map 8, 9, or 0xA).
fn xop(r: &mut Reader, operand_size: u32, address_size: u32) -> Result<Pending, String> {
    let map = r.byte()? & 0x1F;
    r.skip(2)?;
    r.modrm(address_size)?;
    match map {
        8 => immediate(r, Imm::B, operand_size, address_size).map(|_| ())?,
        9 => {}
        0xA => r.skip(4)?,
        _ => return Ok(UNDEFINED),
    }
    Ok(Pending::Done(Flow::Fallthrough))
}

/// The oracle record of one 16- or 32-bit instruction; `input` and
/// `side_effects` are the record's shared fields. There is no SMIR lift.
pub(crate) fn decode_json(
    bytes: &[u8],
    pc: u64,
    size: X86CodeSize,
    input: Value,
    side_effects: Value,
) -> Result<Value, String> {
    let code_size = match size {
        X86CodeSize::Bits16 => 16,
        X86CodeSize::Bits32 => 32,
        X86CodeSize::Bits64 => return Err("64-bit code is decoded by the SMIR lifter".into()),
    };
    let insn = decode(bytes, pc, code_size)?;
    Ok(json!({
        "isa": "x86",
        "code_size": code_size,
        "pc": format!("{pc:#x}"),
        "input": input,
        "decoded_ops": [{
            "offset": 0,
            "size": insn.len,
            "opcode": insn.opcode,
            "operand_size": insn.operand_size,
            "address_size": insn.address_size,
        }],
        "packet_flags": null,
        "control_flow": control_flow_json(&insn, pc),
        "smir": {"available": false, "reason": "x86_smir_models_64_bit_code_only"},
        "side_effects": side_effects,
    }))
}

/// The oracle JSON control-flow summary of `flow`, in the shape the 64-bit
/// SMIR summaries use.
pub(crate) fn control_flow_json(insn: &Insn, pc: u64) -> Value {
    let hex = |v: u64| format!("{v:#x}");
    let fallthrough = pc.wrapping_add(insn.len as u64);
    match insn.flow {
        Flow::Fallthrough => json!({"kind": "fallthrough"}),
        Flow::Branch(t) => json!({"kind": "branch", "target": hex(t)}),
        Flow::CondBranch { target, register } => json!({
            "kind": if register { "cond_branch_reg" } else { "cond_branch" },
            "target": hex(target),
            "fallthrough": hex(fallthrough),
        }),
        Flow::Call(t) => json!({"kind": "call", "target": hex(t)}),
        Flow::IndirectBranch => json!({"kind": "indirect_branch"}),
        Flow::IndirectCall => json!({"kind": "indirect_call"}),
        Flow::Return => json!({"kind": "return"}),
        Flow::Syscall => json!({"kind": "syscall"}),
        Flow::Trap(what) => json!({"kind": "trap", "trap": what}),
    }
}

#[cfg(test)]
#[path = "x86_legacy_tests.rs"]
mod tests;
