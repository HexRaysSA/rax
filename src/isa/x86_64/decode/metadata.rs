//! Stateless metadata from the native RAX prefix/operand decoder.
//!
//! Execution dispatch owns instruction semantics. This projection owns no CPU
//! state and consumes only provided instruction bytes. Unknown encodings remain
//! explicitly unsupported instead of acquiring fabricated lengths or mnemonics.
use super::Decoder;
use crate::isa::x86_64::cpu::InsnContext;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Flow {
    #[default]
    Next,
    Branch,
    Conditional,
    IndirectJump,
    Call,
    IndirectCall,
    Return,
    Trap,
    Syscall,
    Unknown,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OperandKind {
    #[default]
    Unknown,
    Register,
    Memory,
    Immediate,
    Target,
}
#[derive(Clone, Debug, Default)]
pub struct Operand {
    pub kind: OperandKind,
    pub read: bool,
    pub write: bool,
    pub conditional: bool,
    pub width_bits: u32,
    pub address_bits: u32,
    pub reg: String,
    pub base: String,
    pub index: String,
    pub segment: String,
    pub scale: u32,
    pub displacement: u64,
    pub value: u64,
    pub ip_relative: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Instruction {
    pub size: u32,
    pub mnemonic: String,
    pub flow: Flow,
    pub target: Option<u64>,
    pub fallthrough: u64,
    pub operands: Vec<Operand>,
    pub operands_complete: bool,
    pub stack_pointer_increment: i32,
}
fn mask(value: u64, bits: u32) -> u64 {
    if bits == 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    }
}
fn register(index: u8, size: u8, rex: bool) -> String {
    let names = match size {
        1 if !rex => &["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"][..],
        1 => &["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"][..],
        2 => &["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"][..],
        4 => &["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][..],
        _ => &["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][..],
    };
    if index < 8 {
        names[index as usize].into()
    } else {
        format!(
            "r{index}{}",
            match size {
                1 => "b",
                2 => "w",
                4 => "d",
                _ => "",
            }
        )
    }
}
fn reg_operand(index: u8, size: u8, rex: bool, read: bool, write: bool) -> Operand {
    Operand {
        kind: OperandKind::Register,
        reg: register(index, size, rex),
        width_bits: size as u32 * 8,
        read,
        write,
        ..Default::default()
    }
}
fn immediate(ctx: &mut InsnContext, size: u8, signed: bool) -> Option<Operand> {
    let value = ctx.consume_imm(size).ok()?;
    let value = if signed && size < 8 {
        ((value << (64 - size * 8)) as i64 >> (64 - size * 8)) as u64
    } else {
        value
    };
    Some(Operand {
        kind: OperandKind::Immediate,
        value,
        width_bits: size as u32 * 8,
        read: true,
        ..Default::default()
    })
}

// The same mode and prefix rules as the native decoder's ModR/M path. The
// projection retains the address expression; it does not read guest registers.
fn modrm(
    ctx: &mut InsnContext,
    address_bits: u32,
    width: u8,
    long_mode: bool,
) -> Option<(u8, Operand, Operand)> {
    let byte = ctx.consume_u8().ok()?;
    let mode = byte >> 6;
    let group = (byte >> 3) & 7;
    let reg = reg_operand(
        group | ctx.any_rex_r(),
        width,
        ctx.has_any_rex(),
        true,
        false,
    );
    let rm_index = (byte & 7) | ctx.any_rex_b();
    if mode == 3 {
        return Some((
            group,
            reg,
            reg_operand(rm_index, width, ctx.has_any_rex(), true, false),
        ));
    }
    let mut rm = Operand {
        kind: OperandKind::Memory,
        width_bits: width as u32 * 8,
        address_bits,
        scale: 1,
        read: true,
        ..Default::default()
    };
    let mut stack_segment = false;
    let raw_rm = byte & 7;
    let displacement;
    if address_bits == 16 {
        let (base, index) = match raw_rm {
            0 => ("bx", "si"),
            1 => ("bx", "di"),
            2 => ("bp", "si"),
            3 => ("bp", "di"),
            4 => ("si", ""),
            5 => ("di", ""),
            6 if mode == 0 => ("", ""),
            6 => ("bp", ""),
            _ => ("bx", ""),
        };
        rm.base = base.into();
        rm.index = index.into();
        stack_segment = base == "bp";
        displacement = if mode == 0 && raw_rm == 6 {
            2
        } else if mode == 1 {
            1
        } else if mode == 2 {
            2
        } else {
            0
        };
    } else {
        displacement = if mode == 1 {
            1
        } else if mode == 2 {
            4
        } else {
            0
        };
        if raw_rm == 4 {
            let sib = ctx.consume_u8().ok()?;
            rm.scale = 1 << (sib >> 6);
            let index = ((sib >> 3) & 7)
                | if ctx.has_rex2() {
                    ctx.rex2_x()
                } else {
                    ctx.rex.map_or(0, |r| if r & 2 != 0 { 8 } else { 0 })
                };
            if index != 4 {
                rm.index = register(index, (address_bits / 8) as u8, true);
            }
            let base = (sib & 7) | ctx.any_rex_b();
            if mode == 0 && (sib & 7) == 5 {
                rm.displacement = ctx.consume_u32().ok()? as i32 as i64 as u64;
            } else {
                rm.base = register(base, (address_bits / 8) as u8, true);
                stack_segment = base & 7 == 4 || base & 7 == 5;
            }
        } else if mode == 0 && raw_rm == 5 {
            rm.ip_relative = long_mode;
            rm.displacement = ctx.consume_u32().ok()? as i32 as i64 as u64;
        } else {
            rm.base = register(rm_index, (address_bits / 8) as u8, true);
            stack_segment = rm_index & 7 == 4 || rm_index & 7 == 5;
        }
    }
    if displacement != 0 {
        rm.displacement = immediate(ctx, displacement, true)?.value;
    }
    rm.segment = match ctx.segment_override {
        Some(0x26) => "es",
        Some(0x2e) => "cs",
        Some(0x36) => "ss",
        Some(0x3e) => "ds",
        Some(0x64) => "fs",
        Some(0x65) => "gs",
        _ if stack_segment => "ss",
        _ => "ds",
    }
    .into();
    Some((group, reg, rm))
}
fn read_write(mut op: Operand, read: bool, write: bool) -> Operand {
    op.read = read;
    op.write = write;
    op
}
const ALU: [&str; 8] = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const JCC: [&str; 16] = [
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge",
    "jle", "jg",
];
const SETCC: [&str; 16] = [
    "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta", "sets", "setns", "setp",
    "setnp", "setl", "setge", "setle", "setg",
];
impl Instruction {
    /// Evaluate a legacy SETcc byte from a captured RFLAGS image.
    pub fn setcc_value(&self, rflags: u64) -> Option<u8> {
        let code = SETCC.iter().position(|name| *name == self.mnemonic)?;
        Some(u8::from(crate::isa::x86_64::flags::condition_holds(
            rflags, code as u8,
        )))
    }

    /// Evaluate the register selection of a legacy CMOVcc. Its source is always read.
    pub fn cmov_condition(&self, rflags: u64) -> Option<bool> {
        let code = CMOV.iter().position(|name| *name == self.mnemonic)?;
        Some(crate::isa::x86_64::flags::condition_holds(
            rflags, code as u8,
        ))
    }
}
const CMOV: [&str; 16] = [
    "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova", "cmovs", "cmovns",
    "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
];

/// Decode without execution. Bitness is the guest code-segment default, never
/// the host width. Failure means invalid/truncated or not represented by this
/// metadata projection; it does not revoke native execution coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeFailure {
    Invalid,
    Unsupported,
}
pub fn decode(bits: u32, pc: u64, bytes: &[u8]) -> Result<Instruction, DecodeFailure> {
    let mut unsupported = false;
    decode_inner(bits, pc, bytes, &mut unsupported).ok_or(if unsupported {
        DecodeFailure::Unsupported
    } else {
        DecodeFailure::Invalid
    })
}
fn decode_inner(bits: u32, pc: u64, bytes: &[u8], unsupported: &mut bool) -> Option<Instruction> {
    if !matches!(bits, 16 | 32 | 64) || bytes.is_empty() {
        return None;
    }
    let mut buffer = [0; 15];
    let len = bytes.len().min(15);
    buffer[..len].copy_from_slice(&bytes[..len]);
    let mut ctx = Decoder::decode_prefixes(buffer, len, false, bits == 64).ok()?;
    let prefix_len = ctx.cursor;
    let lock = bytes[..prefix_len].contains(&0xf0);
    let width = if bits == 64 && ctx.any_rex_w() {
        8
    } else if ctx.operand_size_override {
        if bits == 16 { 4 } else { 2 }
    } else if bits == 16 {
        2
    } else {
        4
    };
    let near = if bits == 64 {
        if ctx.operand_size_override { 2 } else { 8 }
    } else {
        width
    };
    let address_bits = if ctx.address_size_override {
        if bits == 16 {
            32
        } else if bits == 32 {
            16
        } else {
            32
        }
    } else {
        bits
    };
    let rex = ctx.has_any_rex();
    let opcode = if ctx.rex2.is_some_and(|p| p.m) {
        0x0f
    } else {
        ctx.consume_u8().ok()?
    };
    if let Some(rex2) = ctx.rex2 {
        let effective = if rex2.m { ctx.peek_u8().ok()? } else { opcode };
        let following = bytes.get(ctx.cursor + usize::from(rex2.m)).copied();
        if super::rex2_reserved_opcode_len(rex2.m, effective, following).is_some() {
            return None;
        }
    }
    if lock && !super::X86_64Vcpu::lock_is_legal(&ctx, opcode) {
        return None;
    }
    let mut out = Instruction {
        operands_complete: true,
        ..Default::default()
    };
    let mut relative = None;
    let mut branch_bits = bits;
    let mut lockable = false;
    match opcode {
        0xc4 | 0xc5 if bits == 64 || ctx.peek_u8().ok()? & 0xc0 == 0xc0 => {
            vex::decode_xmm_transfer(&mut ctx, opcode, bits, address_bits, &mut out, unsupported)?;
        }
        0xc3 | 0xc2 | 0xcb | 0xca | 0xcf => {
            out.mnemonic = match opcode {
                0xc3 | 0xc2 => "ret",
                0xcb | 0xca => "retf",
                _ => "iret",
            }
            .into();
            out.flow = Flow::Return;
            if opcode == 0xc2 || opcode == 0xca {
                out.operands.push(immediate(&mut ctx, 2, false)?);
            }
            if opcode == 0xc3 || opcode == 0xc2 {
                out.stack_pointer_increment =
                    near as i32 + out.operands.first().map_or(0, |o| o.value as i32);
            } else {
                out.operands_complete = false;
            }
        }
        0xe8 | 0xe9 | 0xeb | 0x70..=0x7f | 0xe0..=0xe3 => {
            out.mnemonic = match opcode {
                0xe8 => "call",
                0xe9 | 0xeb => "jmp",
                0x70..=0x7f => JCC[(opcode & 15) as usize],
                0xe0 => "loopne",
                0xe1 => "loope",
                0xe2 => "loop",
                _ if address_bits == 16 => "jcxz",
                _ if address_bits == 32 => "jecxz",
                _ => "jrcxz",
            }
            .into();
            out.flow = match opcode {
                0xe8 => Flow::Call,
                0xe9 | 0xeb => Flow::Branch,
                _ => Flow::Conditional,
            };
            let imm_width = if opcode == 0xe8 || opcode == 0xe9 {
                near.min(4)
            } else {
                1
            };
            relative = Some(immediate(&mut ctx, imm_width, true)?.value);
            // LOOP/JCXZ select their counter through address size; 66 does
            // not narrow their instruction pointer like the near Jcc family.
            branch_bits = if (0xe0..=0xe3).contains(&opcode) {
                bits
            } else {
                near as u32 * 8
            };
            if opcode == 0xe8 {
                out.stack_pointer_increment = -(near as i32);
            }
        }
        0xfe | 0xff => {
            let group = (ctx.peek_u8().ok()? >> 3) & 7;
            let operand_width = if opcode == 0xfe {
                1
            } else if (2..=6).contains(&group) {
                near
            } else {
                width
            };
            let (_, _, rm) = modrm(&mut ctx, address_bits, operand_width, bits == 64)?;
            if (opcode == 0xfe && group > 1) || group == 7 {
                return None;
            }
            out.mnemonic = match group {
                0 => "inc",
                1 => "dec",
                2 => "call",
                3 => "callf",
                4 => "jmp",
                5 => "jmpf",
                _ => "push",
            }
            .into();
            out.flow = match group {
                2 | 3 => Flow::IndirectCall,
                4 | 5 => Flow::IndirectJump,
                _ => Flow::Next,
            };
            if group == 2 || group == 6 {
                out.stack_pointer_increment = -(near as i32);
            }
            lockable = group <= 1 && rm.kind == OperandKind::Memory;
            out.operands.push(read_write(rm, true, group <= 1));
            if group == 3 || group == 5 {
                out.operands_complete = false;
            }
        }
        0x40..=0x4f if bits != 64 => {
            out.mnemonic = if opcode < 0x48 { "inc" } else { "dec" }.into();
            out.operands
                .push(reg_operand(opcode & 7, width, rex, true, true));
        }
        0x90..=0x97 => {
            let reg = (opcode & 7) | ctx.any_rex_b();
            if reg == 0 {
                out.mnemonic = if ctx.rep_prefix == Some(0xf3) {
                    "pause"
                } else {
                    "nop"
                }
                .into();
            } else {
                out.mnemonic = "xchg".into();
                out.operands = vec![
                    reg_operand(0, width, rex, true, true),
                    reg_operand(reg, width, rex, true, true),
                ];
            }
        }
        0xb0..=0xbf => {
            let size = if opcode < 0xb8 { 1 } else { width };
            out.mnemonic = "mov".into();
            out.operands.push(reg_operand(
                (opcode & 7) | ctx.any_rex_b(),
                size,
                rex,
                false,
                true,
            ));
            out.operands.push(immediate(&mut ctx, size, false)?);
        }
        0x00..=0x3f if opcode & 7 <= 5 => {
            out.mnemonic = ALU[(opcode >> 3) as usize].into();
            let size = if opcode & 1 == 0 { 1 } else { width };
            let writes = opcode >> 3 != 7;
            if opcode & 7 >= 4 {
                out.operands.push(reg_operand(0, size, rex, true, writes));
                out.operands
                    .push(immediate(&mut ctx, size.min(4), size == 8)?);
            } else {
                let (_, reg, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
                lockable = writes && opcode & 2 == 0 && rm.kind == OperandKind::Memory;
                out.operands = if opcode & 2 != 0 {
                    vec![read_write(reg, true, writes), rm]
                } else {
                    vec![read_write(rm, true, writes), reg]
                };
            }
        }
        0x80..=0x83 => {
            if opcode == 0x82 && bits == 64 {
                return None;
            }
            let size = if opcode == 0x80 || opcode == 0x82 {
                1
            } else {
                width
            };
            let (group, _, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
            out.mnemonic = ALU[group as usize].into();
            lockable = group != 7 && rm.kind == OperandKind::Memory;
            out.operands.push(read_write(rm, true, group != 7));
            out.operands.push(immediate(
                &mut ctx,
                if opcode == 0x81 { size.min(4) } else { 1 },
                opcode == 0x83 || size == 8,
            )?);
        }
        0x84..=0x8e => {
            let size = if matches!(opcode, 0x84 | 0x86 | 0x88 | 0x8a) {
                1
            } else if opcode == 0x8c || opcode == 0x8e {
                2
            } else {
                width
            };
            let (_, reg, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
            out.mnemonic = match opcode {
                0x84 | 0x85 => "test",
                0x86 | 0x87 => "xchg",
                0x8d => "lea",
                _ => "mov",
            }
            .into();
            let rm_first = matches!(opcode, 0x84..=0x89 | 0x8c | 0x8e);
            let writes = opcode != 0x84 && opcode != 0x85;
            let reads = matches!(opcode, 0x84..=0x87);
            lockable = matches!(opcode, 0x86 | 0x87) && rm.kind == OperandKind::Memory;
            if opcode == 0x8d && rm.kind != OperandKind::Memory {
                return None;
            }
            out.operands = if rm_first {
                vec![
                    read_write(rm, reads, writes),
                    read_write(reg, true, matches!(opcode, 0x86 | 0x87)),
                ]
            } else {
                vec![
                    read_write(reg, false, true),
                    read_write(rm, opcode != 0x8d, false),
                ]
            };
            if opcode == 0x8c || opcode == 0x8e {
                out.operands_complete = false;
            }
        }
        0xc6 | 0xc7 => {
            let size = if opcode == 0xc6 { 1 } else { width };
            let (group, _, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
            if group != 0 {
                return None;
            }
            out.mnemonic = "mov".into();
            out.operands.push(read_write(rm, false, true));
            out.operands
                .push(immediate(&mut ctx, size.min(4), size == 8)?);
        }
        0x50..=0x5f => {
            let pop = opcode >= 0x58;
            out.mnemonic = if pop { "pop" } else { "push" }.into();
            out.operands.push(reg_operand(
                (opcode & 7) | ctx.any_rex_b(),
                near,
                rex,
                !pop,
                pop,
            ));
            out.stack_pointer_increment = if pop { near as i32 } else { -(near as i32) };
        }
        0x68 | 0x6a => {
            out.mnemonic = "push".into();
            out.operands.push(immediate(
                &mut ctx,
                if opcode == 0x6a { 1 } else { near.min(4) },
                true,
            )?);
            out.stack_pointer_increment = -(near as i32);
        }
        0x8f => {
            let (group, _, rm) = modrm(&mut ctx, address_bits, near, bits == 64)?;
            if group != 0 {
                return None;
            }
            out.mnemonic = "pop".into();
            out.operands.push(read_write(rm, false, true));
            out.stack_pointer_increment = near as i32;
        }
        0x69 | 0x6b => {
            let (_, reg, rm) = modrm(&mut ctx, address_bits, width, bits == 64)?;
            out.mnemonic = "imul".into();
            out.operands = vec![
                read_write(reg, false, true),
                rm,
                immediate(
                    &mut ctx,
                    if opcode == 0x6b { 1 } else { width.min(4) },
                    true,
                )?,
            ];
        }
        0xc0 | 0xc1 | 0xd0..=0xd3 => {
            let size = if opcode & 1 == 0 { 1 } else { width };
            let (group, _, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
            out.mnemonic =
                ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"][group as usize].into();
            out.operands.push(read_write(rm, true, true));
            if opcode == 0xc0 || opcode == 0xc1 {
                out.operands.push(immediate(&mut ctx, 1, false)?);
            } else if opcode >= 0xd2 {
                out.operands.push(reg_operand(1, 1, rex, true, false));
            } else {
                out.operands.push(Operand {
                    kind: OperandKind::Immediate,
                    value: 1,
                    read: true,
                    ..Default::default()
                });
            }
        }
        0xf6 | 0xf7 => {
            let size = if opcode == 0xf6 { 1 } else { width };
            let (group, _, rm) = modrm(&mut ctx, address_bits, size, bits == 64)?;
            out.mnemonic =
                ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"][group as usize].into();
            lockable = (group == 2 || group == 3) && rm.kind == OperandKind::Memory;
            out.operands
                .push(read_write(rm, true, group == 2 || group == 3));
            if group <= 1 {
                out.operands
                    .push(immediate(&mut ctx, size.min(4), size == 8)?);
            }
        }
        0xa8 | 0xa9 => {
            let size = if opcode == 0xa8 { 1 } else { width };
            out.mnemonic = "test".into();
            out.operands = vec![
                reg_operand(0, size, rex, true, false),
                immediate(&mut ctx, size.min(4), size == 8)?,
            ];
        }
        0x0f => decode_0f(
            &mut ctx,
            address_bits,
            width,
            near,
            &mut out,
            &mut relative,
            &mut branch_bits,
            &mut lockable,
            unsupported,
        )?,
        _ => fixed_legacy(
            &mut ctx,
            opcode,
            bits,
            width,
            near,
            address_bits,
            &mut out,
            unsupported,
        )?,
    }
    if lock && !lockable {
        return None;
    }
    out.size = ctx.cursor as u32;
    if out.size == 0 || out.size > 15 || out.size as usize > len {
        return None;
    }
    out.fallthrough = mask(pc.wrapping_add(out.size as u64), branch_bits);
    if let Some(disp) = relative {
        let target = mask(
            pc.wrapping_add(out.size as u64).wrapping_add(disp),
            branch_bits,
        );
        out.target = Some(target);
        out.operands.push(Operand {
            kind: OperandKind::Target,
            value: target,
            read: true,
            ..Default::default()
        });
    }
    for operand in &mut out.operands {
        if operand.ip_relative {
            operand.displacement = pc
                .wrapping_add(out.size as u64)
                .wrapping_add(operand.displacement);
            operand.ip_relative = false;
        }
    }
    Some(out)
}

#[path = "metadata_legacy.rs"]
mod legacy;
#[path = "metadata_vex.rs"]
mod vex;
use legacy::{decode_0f, fixed_legacy};

fn packed_uniform_shift_mnemonics(
    map: u8,
    prefix: u8,
    opcode: u8,
) -> Option<(&'static str, &'static str)> {
    Some(match (map, prefix, opcode) {
        (1, 1, 0xf1) => ("psllw", "vpsllw"),
        (1, 1, 0xf2) => ("pslld", "vpslld"),
        (1, 1, 0xf3) => ("psllq", "vpsllq"),
        (1, 1, 0xd1) => ("psrlw", "vpsrlw"),
        (1, 1, 0xd2) => ("psrld", "vpsrld"),
        (1, 1, 0xd3) => ("psrlq", "vpsrlq"),
        (1, 1, 0xe1) => ("psraw", "vpsraw"),
        (1, 1, 0xe2) => ("psrad", "vpsrad"),
        _ => return None,
    })
}

fn packed_immediate_shuffle_mnemonics(
    map: u8,
    prefix: u8,
    opcode: u8,
) -> Option<(&'static str, &'static str)> {
    Some(match (map, prefix, opcode) {
        (1, 0, 0xc6) => ("shufps", "vshufps"),
        (1, 1, 0xc6) => ("shufpd", "vshufpd"),
        (3, 1, 0x0f) => ("palignr", "vpalignr"),
        _ => return None,
    })
}

fn packed_unary_shuffle_mnemonics(prefix: u8) -> Option<(&'static str, &'static str)> {
    Some(match prefix {
        1 => ("pshufd", "vpshufd"),
        2 => ("pshufhw", "vpshufhw"),
        3 => ("pshuflw", "vpshuflw"),
        _ => return None,
    })
}

fn packed_binary_mnemonics(
    map: u8,
    prefix: u8,
    opcode: u8,
) -> Option<(&'static str, &'static str)> {
    Some(match (map, prefix, opcode) {
        (1, 0, 0x54) => ("andps", "vandps"),
        (1, 0, 0x55) => ("andnps", "vandnps"),
        (1, 0, 0x56) => ("orps", "vorps"),
        (1, 0, 0x57) => ("xorps", "vxorps"),
        (1, 1, 0x54) => ("andpd", "vandpd"),
        (1, 1, 0x55) => ("andnpd", "vandnpd"),
        (1, 1, 0x56) => ("orpd", "vorpd"),
        (1, 1, 0x57) => ("xorpd", "vxorpd"),
        (1, 1, 0xdb) => ("pand", "vpand"),
        (1, 1, 0xdf) => ("pandn", "vpandn"),
        (1, 1, 0xeb) => ("por", "vpor"),
        (1, 1, 0xef) => ("pxor", "vpxor"),
        (2, 1, 0x00) => ("pshufb", "vpshufb"),
        (2, 1, 0x01) => ("phaddw", "vphaddw"),
        (2, 1, 0x02) => ("phaddd", "vphaddd"),
        (2, 1, 0x03) => ("phaddsw", "vphaddsw"),
        (2, 1, 0x05) => ("phsubw", "vphsubw"),
        (2, 1, 0x06) => ("phsubd", "vphsubd"),
        (2, 1, 0x07) => ("phsubsw", "vphsubsw"),
        (1, 1, 0x60) => ("punpcklbw", "vpunpcklbw"),
        (1, 1, 0x61) => ("punpcklwd", "vpunpcklwd"),
        (1, 1, 0x62) => ("punpckldq", "vpunpckldq"),
        (1, 1, 0x6c) => ("punpcklqdq", "vpunpcklqdq"),
        (1, 1, 0x68) => ("punpckhbw", "vpunpckhbw"),
        (1, 1, 0x69) => ("punpckhwd", "vpunpckhwd"),
        (1, 1, 0x6a) => ("punpckhdq", "vpunpckhdq"),
        (1, 1, 0x6d) => ("punpckhqdq", "vpunpckhqdq"),
        (1, 1, 0x63) => ("packsswb", "vpacksswb"),
        (1, 1, 0x6b) => ("packssdw", "vpackssdw"),
        (1, 1, 0x67) => ("packuswb", "vpackuswb"),
        (2, 1, 0x2b) => ("packusdw", "vpackusdw"),
        (1, 1, 0x74) => ("pcmpeqb", "vpcmpeqb"),
        (1, 1, 0x75) => ("pcmpeqw", "vpcmpeqw"),
        (1, 1, 0x76) => ("pcmpeqd", "vpcmpeqd"),
        (2, 1, 0x29) => ("pcmpeqq", "vpcmpeqq"),
        (1, 1, 0x64) => ("pcmpgtb", "vpcmpgtb"),
        (1, 1, 0x65) => ("pcmpgtw", "vpcmpgtw"),
        (1, 1, 0x66) => ("pcmpgtd", "vpcmpgtd"),
        (2, 1, 0x37) => ("pcmpgtq", "vpcmpgtq"),
        (1, 1, 0xfc) => ("paddb", "vpaddb"),
        (1, 1, 0xfd) => ("paddw", "vpaddw"),
        (1, 1, 0xfe) => ("paddd", "vpaddd"),
        (1, 1, 0xd4) => ("paddq", "vpaddq"),
        (1, 1, 0xf8) => ("psubb", "vpsubb"),
        (1, 1, 0xf9) => ("psubw", "vpsubw"),
        (1, 1, 0xfa) => ("psubd", "vpsubd"),
        (1, 1, 0xfb) => ("psubq", "vpsubq"),
        (1, 1, 0xec) => ("paddsb", "vpaddsb"),
        (1, 1, 0xed) => ("paddsw", "vpaddsw"),
        (1, 1, 0xdc) => ("paddusb", "vpaddusb"),
        (1, 1, 0xdd) => ("paddusw", "vpaddusw"),
        (1, 1, 0xe8) => ("psubsb", "vpsubsb"),
        (1, 1, 0xe9) => ("psubsw", "vpsubsw"),
        (1, 1, 0xd8) => ("psubusb", "vpsubusb"),
        (1, 1, 0xd9) => ("psubusw", "vpsubusw"),
        (1, 1, 0xe0) => ("pavgb", "vpavgb"),
        (1, 1, 0xe3) => ("pavgw", "vpavgw"),
        (1, 1, 0xf6) => ("psadbw", "vpsadbw"),
        (2, 1, 0x38) => ("pminsb", "vpminsb"),
        (1, 1, 0xda) => ("pminub", "vpminub"),
        (1, 1, 0xea) => ("pminsw", "vpminsw"),
        (2, 1, 0x3a) => ("pminuw", "vpminuw"),
        (2, 1, 0x39) => ("pminsd", "vpminsd"),
        (2, 1, 0x3b) => ("pminud", "vpminud"),
        (2, 1, 0x3c) => ("pmaxsb", "vpmaxsb"),
        (1, 1, 0xde) => ("pmaxub", "vpmaxub"),
        (1, 1, 0xee) => ("pmaxsw", "vpmaxsw"),
        (2, 1, 0x3e) => ("pmaxuw", "vpmaxuw"),
        (2, 1, 0x3d) => ("pmaxsd", "vpmaxsd"),
        (2, 1, 0x3f) => ("pmaxud", "vpmaxud"),
        (1, 1, 0xd5) => ("pmullw", "vpmullw"),
        (1, 1, 0xe5) => ("pmulhw", "vpmulhw"),
        (1, 1, 0xe4) => ("pmulhuw", "vpmulhuw"),
        (1, 1, 0xf4) => ("pmuludq", "vpmuludq"),
        (1, 1, 0xf5) => ("pmaddwd", "vpmaddwd"),
        (2, 1, 0x40) => ("pmulld", "vpmulld"),
        (2, 1, 0x28) => ("pmuldq", "vpmuldq"),
        (2, 1, 0x0b) => ("pmulhrsw", "vpmulhrsw"),
        (2, 1, 0x04) => ("pmaddubsw", "vpmaddubsw"),
        _ => return None,
    })
}
