use super::*;

pub(super) fn fixed_legacy(
    ctx: &mut InsnContext,
    op: u8,
    bits: u32,
    width: u8,
    near: u8,
    address_bits: u32,
    out: &mut Instruction,
    unsupported: &mut bool,
) -> Option<()> {
    out.mnemonic = match op {
        0x06 | 0x0e | 0x16 | 0x1e if bits != 64 => "push",
        0x07 | 0x17 | 0x1f if bits != 64 => "pop",
        0x27 if bits != 64 => "daa",
        0x2f if bits != 64 => "das",
        0x37 if bits != 64 => "aaa",
        0x3f if bits != 64 => "aas",
        0x60 if bits != 64 => "pusha",
        0x61 if bits != 64 => "popa",
        0x98 => match width {
            2 => "cbw",
            4 => "cwde",
            _ => "cdqe",
        },
        0x99 => match width {
            2 => "cwd",
            4 => "cdq",
            _ => "cqo",
        },
        0x9b => "wait",
        0x9c => "pushf",
        0x9d => "popf",
        0x9e => "sahf",
        0x9f => "lahf",
        0xc9 => "leave",
        0xcc => "int3",
        0xce if bits != 64 => "into",
        0xd6 if bits != 64 => "salc",
        0xd7 => "xlat",
        0xf1 => "int1",
        0xf4 => "hlt",
        0xf5 => "cmc",
        0xf8 => "clc",
        0xf9 => "stc",
        0xfa => "cli",
        0xfb => "sti",
        0xfc => "cld",
        0xfd => "std",
        0x6c => "insb",
        0x6d => {
            if width == 2 {
                "insw"
            } else {
                "insd"
            }
        }
        0x6e => "outsb",
        0x6f => {
            if width == 2 {
                "outsw"
            } else {
                "outsd"
            }
        }
        0xa4 => "movsb",
        0xa5 => match width {
            2 => "movsw",
            4 => "movsd",
            _ => "movsq",
        },
        0xa6 => "cmpsb",
        0xa7 => match width {
            2 => "cmpsw",
            4 => "cmpsd",
            _ => "cmpsq",
        },
        0xaa => "stosb",
        0xab => match width {
            2 => "stosw",
            4 => "stosd",
            _ => "stosq",
        },
        0xac => "lodsb",
        0xad => match width {
            2 => "lodsw",
            4 => "lodsd",
            _ => "lodsq",
        },
        0xae => "scasb",
        0xaf => match width {
            2 => "scasw",
            4 => "scasd",
            _ => "scasq",
        },
        0xec | 0xed => "in",
        0xee | 0xef => "out",
        0xe4 | 0xe5 | 0xe6 | 0xe7 => {
            out.operands.push(immediate(ctx, 1, false)?);
            if op < 0xe6 { "in" } else { "out" }
        }
        0xcd => {
            out.operands.push(immediate(ctx, 1, false)?);
            "int"
        }
        0xd4 | 0xd5 if bits != 64 => {
            out.operands.push(immediate(ctx, 1, false)?);
            if op == 0xd4 { "aam" } else { "aad" }
        }
        0xc8 => {
            out.operands.push(immediate(ctx, 2, false)?);
            out.operands.push(immediate(ctx, 1, false)?);
            "enter"
        }
        0x9a | 0xea if bits != 64 => {
            out.operands.push(immediate(ctx, width, false)?);
            out.operands.push(immediate(ctx, 2, false)?);
            out.flow = if op == 0x9a { Flow::Call } else { Flow::Branch };
            if op == 0x9a { "callf" } else { "jmpf" }
        }
        0xa0..=0xa3 => {
            if ctx.has_rex2() {
                if op != 0xa1 {
                    return None;
                }
                out.mnemonic = "jmpabs".into();
                out.flow = Flow::Branch;
                out.target = Some(ctx.consume_u64().ok()?);
                out.operands.push(Operand {
                    kind: OperandKind::Target,
                    value: out.target.unwrap(),
                    width_bits: 64,
                    read: true,
                    ..Default::default()
                });
                return Some(());
            }
            let size = if op & 1 == 0 { 1 } else { width };
            let address = immediate(ctx, (address_bits / 8) as u8, false)?.value;
            let mem = Operand {
                kind: OperandKind::Memory,
                width_bits: size as u32 * 8,
                address_bits,
                displacement: address,
                read: op < 0xa2,
                write: op >= 0xa2,
                segment: match ctx.segment_override {
                    Some(0x64) => "fs",
                    Some(0x65) => "gs",
                    _ => "ds",
                }
                .into(),
                ..Default::default()
            };
            let reg = reg_operand(0, size, ctx.has_any_rex(), op >= 0xa2, op < 0xa2);
            out.operands = if op < 0xa2 {
                vec![reg, mem]
            } else {
                vec![mem, reg]
            };
            "mov"
        }
        0x63 => {
            let (_, reg, rm) = modrm(
                ctx,
                address_bits,
                if bits == 64 { 4 } else { 2 },
                bits == 64,
            )?;
            out.operands = vec![reg, rm];
            out.operands_complete = false;
            if bits == 64 { "movsxd" } else { "arpl" }
        }
        0xc4 | 0xc5 | 0x62 if bits != 64 => {
            if ctx.peek_u8().ok()? & 0xc0 == 0xc0 {
                *unsupported = true;
                return None;
            }
            let (_, reg, rm) = modrm(ctx, address_bits, width, bits == 64)?;
            if rm.kind != OperandKind::Memory {
                return None;
            }
            out.operands = vec![reg, rm];
            out.operands_complete = false;
            match op {
                0xc4 => "les",
                0xc5 => "lds",
                _ => "bound",
            }
        }
        _ => {
            *unsupported = true;
            return None;
        }
    }
    .into();
    if matches!(op, 0xcc | 0xcd | 0xce | 0xf1 | 0xf4) {
        out.flow = Flow::Trap;
    }
    if matches!(op, 0x9c) {
        out.stack_pointer_increment = -(near as i32);
    }
    if matches!(op, 0x9d) {
        out.stack_pointer_increment = near as i32;
    }
    if matches!(op,0x06|0x07|0x0e|0x16|0x17|0x1e|0x1f|0x60|0x61|0x6c..=0x6f|0xa4..=0xa7|0xaa..=0xaf|0xec..=0xef|0xd7|0x9a|0xea)
    {
        out.operands_complete = false;
    }
    Some(())
}

pub(super) fn decode_0f(
    ctx: &mut InsnContext,
    address_bits: u32,
    width: u8,
    near: u8,
    out: &mut Instruction,
    relative: &mut Option<u64>,
    branch_bits: &mut u32,
    lockable: &mut bool,
    unsupported: &mut bool,
) -> Option<()> {
    let op = ctx.consume_u8().ok()?;
    let rex = ctx.has_any_rex();
    out.mnemonic = match op {
        0x80..=0x8f => {
            *relative = Some(immediate(ctx, near.min(4), true)?.value);
            *branch_bits = near as u32 * 8;
            out.flow = Flow::Conditional;
            JCC[(op & 15) as usize]
        }
        0x90..=0x9f => {
            let (_, _, rm) = modrm(ctx, address_bits, 1, *branch_bits == 64)?;
            out.operands.push(read_write(rm, false, true));
            SETCC[(op & 15) as usize]
        }
        0x40..=0x4f => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            let mut dst = read_write(reg, true, true);
            dst.conditional = true;
            out.operands = vec![dst, rm];
            CMOV[(op & 15) as usize]
        }
        0xc8..=0xcf => {
            out.operands.push(reg_operand(
                (op & 7) | ctx.any_rex_b(),
                width,
                rex,
                true,
                true,
            ));
            "bswap"
        }
        0xb6 | 0xb7 | 0xbe | 0xbf => {
            let m = ctx.peek_u8().ok()?;
            let (_, mut reg, rm) = modrm(
                ctx,
                address_bits,
                if op & 1 == 0 { 1 } else { 2 },
                *branch_bits == 64,
            )?;
            reg.reg = register(((m >> 3) & 7) | ctx.any_rex_r(), width, rex);
            reg.width_bits = width as u32 * 8;
            out.operands = vec![read_write(reg, false, true), rm];
            if op < 0xbe { "movzx" } else { "movsx" }
        }
        0xaf => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.operands = vec![read_write(reg, true, true), rm];
            "imul"
        }
        0xa3 | 0xab | 0xb3 | 0xbb => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            *lockable = op != 0xa3 && rm.kind == OperandKind::Memory;
            out.operands = vec![read_write(rm, true, op != 0xa3), reg];
            match op {
                0xa3 => "bt",
                0xab => "bts",
                0xb3 => "btr",
                _ => "btc",
            }
        }
        0xba => {
            let (group, _, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            if group < 4 {
                return None;
            }
            *lockable = group != 4 && rm.kind == OperandKind::Memory;
            out.operands = vec![read_write(rm, true, group != 4), immediate(ctx, 1, false)?];
            ["bt", "bts", "btr", "btc"][(group - 4) as usize]
        }
        0xa4 | 0xa5 | 0xac | 0xad => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.operands = vec![read_write(rm, true, true), reg];
            out.operands.push(if op & 1 == 0 {
                immediate(ctx, 1, false)?
            } else {
                reg_operand(1, 1, rex, true, false)
            });
            if op < 0xac { "shld" } else { "shrd" }
        }
        0xbc | 0xbd => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.operands = vec![read_write(reg, false, true), rm];
            match (op, ctx.rep_prefix) {
                (0xbc, Some(0xf3)) => "tzcnt",
                (0xbd, Some(0xf3)) => "lzcnt",
                (0xbc, _) => "bsf",
                _ => "bsr",
            }
        }
        0xb8 if ctx.rep_prefix == Some(0xf3) => {
            let (_, reg, rm) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.operands = vec![read_write(reg, false, true), rm];
            "popcnt"
        }
        0xb0 | 0xb1 | 0xc0 | 0xc1 => {
            let (_, reg, rm) = modrm(
                ctx,
                address_bits,
                if op & 1 == 0 { 1 } else { width },
                *branch_bits == 64,
            )?;
            *lockable = rm.kind == OperandKind::Memory;
            out.operands = vec![
                read_write(rm, true, true),
                read_write(reg, true, op >= 0xc0),
            ];
            if op < 0xc0 { "cmpxchg" } else { "xadd" }
        }
        0x1f => {
            let (group, _, _) = modrm(ctx, address_bits, width, *branch_bits == 64)?;
            if group != 0 {
                return None;
            }
            "nop"
        }
        0x05 => {
            out.flow = Flow::Syscall;
            "syscall"
        }
        0x07 => {
            out.flow = Flow::Syscall;
            "sysret"
        }
        0x34 => {
            out.flow = Flow::Syscall;
            "sysenter"
        }
        0x35 => {
            out.flow = Flow::Syscall;
            "sysexit"
        }
        0x0b => {
            out.flow = Flow::Trap;
            "ud2"
        }
        0xb9 => {
            modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.flow = Flow::Trap;
            "ud1"
        }
        0xff => {
            modrm(ctx, address_bits, width, *branch_bits == 64)?;
            out.flow = Flow::Trap;
            "ud0"
        }
        0x06 => "clts",
        0x08 => "invd",
        0x09 => "wbinvd",
        0x0e => "femms",
        0x30 => "wrmsr",
        0x31 => "rdtsc",
        0x32 => "rdmsr",
        0x33 => "rdpmc",
        0x37 => "getsec",
        0x77 => "emms",
        0xa2 => "cpuid",
        0xaa => "rsm",
        0xa0 | 0xa8 => {
            out.operands_complete = false;
            "push"
        }
        0xa1 | 0xa9 => {
            out.operands_complete = false;
            "pop"
        }
        0x1e if ctx.rep_prefix == Some(0xf3) => match ctx.consume_u8().ok()? {
            0xfa => "endbr64",
            0xfb => "endbr32",
            _ => return None,
        },
        _ => {
            *unsupported = true;
            return None;
        }
    }
    .into();
    Some(())
}
