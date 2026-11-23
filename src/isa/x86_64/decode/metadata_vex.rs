//! Stateless projection of AVX XMM transfer encodings.
use super::*;

pub(super) fn decode_xmm_transfer(
    ctx: &mut InsnContext,
    lead: u8,
    bits: u32,
    address_bits: u32,
    out: &mut Instruction,
    unsupported: &mut bool,
) -> Option<()> {
    // Intel SDM Vol. 2A 2.3.2-2.3.5. The raw bytes catch a REX prefix
    // discarded by the generic prefix parser when another prefix followed it.
    if ctx.bytes[..ctx.cursor - 1]
        .iter()
        .any(|byte| !matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x67))
    {
        return None;
    }
    let vex = ctx.consume_u8().ok()?;
    let (extensions, flags) = if lead == 0xc4 {
        let flags = ctx.consume_u8().ok()?;
        if vex & 0x1f != 1 {
            *unsupported = true;
            return None;
        }
        ((!vex >> 5) & 7, flags)
    } else {
        ((!vex >> 5) & 4, vex & 0x7f)
    };
    let opcode = ctx.consume_u8().ok()?;
    let wide = bits == 64 && flags & 0x80 != 0;
    let (load, size, vector_rm) = match (flags & 3, opcode) {
        (1, 0x6e) => (true, if wide { 8 } else { 4 }, false),
        (1, 0x7e) => (false, if wide { 8 } else { 4 }, false),
        (2, 0x7e) => (true, 8, true),
        (1, 0xd6) => (false, 8, true),
        (1 | 2, 0x6f | 0x7f) => (opcode == 0x6f, 16, true),
        _ => {
            *unsupported = true;
            return None;
        }
    };
    if flags & 0x78 != 0x78 {
        // These encodings reserve the inverted vvvv field.
        return None;
    }
    if flags & 4 != 0 {
        // L=1 is reserved for the scalar forms and selects YMM for full moves.
        *unsupported = size == 16;
        return None;
    }
    ctx.rex = (bits == 64).then_some(0x40 | extensions);
    let raw_rm = ctx.peek_u8().ok()? & 7;
    let (group, _, mut rm) = modrm(ctx, address_bits, size, bits == 64)?;
    if vector_rm && rm.kind == OperandKind::Register {
        rm.width_bits = 128;
        rm.reg = format!("xmm{}", raw_rm | ctx.any_rex_b());
    }
    let xmm = Operand {
        kind: OperandKind::Register,
        reg: format!("xmm{}", group | ctx.any_rex_r()),
        width_bits: 128,
        read: !load,
        write: load,
        ..Operand::default()
    };
    out.operands = if load {
        vec![xmm, rm]
    } else {
        vec![read_write(rm, false, true), xmm]
    };
    out.mnemonic = match size {
        16 if flags & 3 == 1 => "vmovdqa",
        16 => "vmovdqu",
        8 => "vmovq",
        _ => "vmovd",
    }
    .into();
    Some(())
}
