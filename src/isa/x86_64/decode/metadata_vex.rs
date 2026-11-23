//! Stateless projection of AVX vector transfer encodings.
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
    let (load, mut size, vector_rm) = match (flags & 3, opcode) {
        (1, 0x6e) => (true, if wide { 8 } else { 4 }, false),
        (1, 0x7e) => (false, if wide { 8 } else { 4 }, false),
        (2, 0x7e) => (true, 8, true),
        (1, 0xd6) => (false, 8, true),
        (0 | 1, 0x10 | 0x11 | 0x28 | 0x29) => (opcode & 1 == 0, 16, true),
        (2, 0x10 | 0x11) => (opcode == 0x10, 4, true),
        (3, 0x10 | 0x11) => (opcode == 0x10, 8, true),
        (1 | 2, 0x6f | 0x7f) => (opcode == 0x6f, 16, true),
        _ => {
            *unsupported = true;
            return None;
        }
    };
    let scalar_float = matches!(opcode, 0x10 | 0x11) && matches!(size, 4 | 8);
    let modrm_byte = ctx.peek_u8().ok()?;
    if scalar_float && modrm_byte >> 6 == 3 {
        // The three-register form uses vvvv and merges two sources.
        *unsupported = true;
        return None;
    }
    if flags & 0x78 != 0x78 {
        // These encodings reserve the inverted vvvv field.
        return None;
    }
    if flags & 4 != 0 {
        if size != 16 {
            // Scalar floating moves use the canonical L=0 encoding.
            *unsupported = scalar_float;
            return None;
        }
        size = 32;
    }
    ctx.rex = (bits == 64).then_some(0x40 | extensions);
    let raw_rm = modrm_byte & 7;
    let (group, _, mut rm) = modrm(ctx, address_bits, size, bits == 64)?;
    let (bank, register_width) = if size == 32 {
        ("ymm", 256)
    } else {
        ("xmm", 128)
    };
    if vector_rm && rm.kind == OperandKind::Register {
        rm.width_bits = register_width;
        rm.reg = format!("{bank}{}", raw_rm | ctx.any_rex_b());
    }
    let vector = Operand {
        kind: OperandKind::Register,
        reg: format!("{bank}{}", group | ctx.any_rex_r()),
        width_bits: register_width,
        read: !load,
        write: load,
        ..Operand::default()
    };
    out.operands = if load {
        vec![vector, rm]
    } else {
        vec![read_write(rm, false, true), vector]
    };
    out.mnemonic = match (opcode, size, flags & 3) {
        (0x10 | 0x11, 4, 2) => "vmovss",
        (0x10 | 0x11, 8, 3) => "vmovsd",
        (0x10 | 0x11, 16 | 32, 0) => "vmovups",
        (0x10 | 0x11, 16 | 32, 1) => "vmovupd",
        (0x28 | 0x29, 16 | 32, 0) => "vmovaps",
        (0x28 | 0x29, 16 | 32, 1) => "vmovapd",
        (_, 16 | 32, 1) => "vmovdqa",
        (_, 16 | 32, _) => "vmovdqu",
        (_, 8, _) => "vmovq",
        _ => "vmovd",
    }
    .into();
    Some(())
}
