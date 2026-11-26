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
    let (extensions, flags, map) = if lead == 0xc4 {
        let flags = ctx.consume_u8().ok()?;
        let map = vex & 0x1f;
        if !matches!(map, 1..=3) {
            *unsupported = true;
            return None;
        }
        ((!vex >> 5) & 7, flags, map)
    } else {
        ((!vex >> 5) & 4, vex & 0x7f, 1)
    };
    let opcode = ctx.consume_u8().ok()?;
    let streaming_load = (map, flags & 3, opcode) == (2, 1, 0x2a);
    let uniform_shift = packed_uniform_shift_mnemonics(map, flags & 3, opcode);
    let immediate_shuffle = match (map, flags & 0x87, opcode) {
        (3, 1 | 5, 0x02) => Some("vpblendd"),
        (3, 5, 0x06) => Some("vperm2f128"),
        (3, 5, 0x46) => Some("vperm2i128"),
        _ => packed_immediate_shuffle_mnemonics(map, flags & 3, opcode).map(|(_, vex)| vex),
    };
    let carryless_multiply = ((map, flags & 3, opcode) == (3, 1, 0x44)).then_some("vpclmulqdq");
    let register_blend = match (map, flags & 0x83, opcode) {
        (3, 1, 0x4a) => Some("vblendvps"),
        (3, 1, 0x4b) => Some("vblendvpd"),
        (3, 1, 0x4c) => Some("vpblendvb"),
        _ => None,
    };
    let unary_shuffle = match (map, flags & 0x87, opcode) {
        (3, 0x85, 0x00) => Some("vpermq"),
        (3, 0x85, 0x01) => Some("vpermpd"),
        (3, 1 | 5, 0x04) => Some("vpermilps"),
        (3, 1 | 5, 0x05) => Some("vpermilpd"),
        (1, _, 0x70) => packed_unary_shuffle_mnemonics(flags & 3).map(|(_, vex)| vex),
        _ => None,
    };
    let indexed_permutation = match (map, flags & 0x87, opcode) {
        (2, 1 | 5, 0x0c) => Some("vpermilps"),
        (2, 1 | 5, 0x0d) => Some("vpermilpd"),
        (2, 5, 0x16) => Some("vpermps"),
        (2, 5, 0x36) => Some("vpermd"),
        _ => None,
    };
    let absolute = if map == 2 && flags & 3 == 1 {
        packed_absolute_mnemonics(opcode).map(|(_, vex)| vex)
    } else {
        None
    };
    let aes_transform = match (map, flags & 3, opcode) {
        (2, 1, 0xdb) => Some(("vaesimc", false)),
        (3, 1, 0xdf) => Some(("vaeskeygenassist", true)),
        _ => None,
    };
    let widening = if map == 2 && flags & 3 == 1 {
        packed_widening(opcode).map(|(_, name, source_size)| (name, source_size))
    } else {
        None
    };
    // Intel SDM Vol. 2C, VPSLLVD/Q, VPSRAVD, VPSRLVD/Q.
    let variable_shift = match (map, flags & 3, flags & 0x80 != 0, opcode) {
        (2, 1, false, 0x45) => Some("vpsrlvd"),
        (2, 1, true, 0x45) => Some("vpsrlvq"),
        (2, 1, false, 0x46) => Some("vpsravd"),
        (2, 1, false, 0x47) => Some("vpsllvd"),
        (2, 1, true, 0x47) => Some("vpsllvq"),
        _ => None,
    };
    let binary = uniform_shift
        .or_else(|| packed_binary_mnemonics(map, flags & 3, opcode))
        .map(|(_, vex)| vex)
        .or(variable_shift)
        .or(indexed_permutation)
        .or(immediate_shuffle)
        .or(carryless_multiply)
        .or(register_blend);
    let bit_test = match (map, flags & 3, opcode) {
        (2, 1, 0x17) => Some("vptest"),
        (2, 1, 0x0e) if flags & 0x80 == 0 => Some("vtestps"),
        (2, 1, 0x0f) if flags & 0x80 == 0 => Some("vtestpd"),
        _ => None,
    };
    let wide = bits == 64 && flags & 0x80 != 0;
    let (load, mut size, vector_rm) = match (flags & 3, opcode) {
        _ if binary.is_some()
            || bit_test.is_some()
            || unary_shuffle.is_some()
            || absolute.is_some()
            || widening.is_some()
            || aes_transform.is_some()
            || streaming_load =>
        {
            (true, 16, true)
        }
        _ if map != 1 => {
            *unsupported = true;
            return None;
        }
        (1, 0x6e) => (true, if wide { 8 } else { 4 }, false),
        (1, 0x7e) => (false, if wide { 8 } else { 4 }, false),
        (2, 0x7e) => (true, 8, true),
        (1, 0xd6) => (false, 8, true),
        (0 | 1, 0x10 | 0x11 | 0x28 | 0x29) => (opcode & 1 == 0, 16, true),
        (0 | 1, 0x12 | 0x13 | 0x16 | 0x17) => (opcode & 1 == 0, 8, true),
        (0 | 1, 0x2b) | (1, 0xe7) => (false, 16, true),
        (2, 0x10 | 0x11) => (opcode == 0x10, 4, true),
        (3, 0x10 | 0x11) => (opcode == 0x10, 8, true),
        (1 | 2, 0x6f | 0x7f) => (opcode == 0x6f, 16, true),
        _ => {
            *unsupported = true;
            return None;
        }
    };
    let scalar_float = matches!(opcode, 0x10 | 0x11) && matches!(size, 4 | 8);
    let lane_move = map == 1 && matches!(opcode, 0x12 | 0x13 | 0x16 | 0x17);
    let modrm_byte = ctx.peek_u8().ok()?;
    if scalar_float && modrm_byte >> 6 == 3 {
        // The three-register form uses vvvv and merges two sources.
        *unsupported = true;
        return None;
    }
    if lane_move && modrm_byte >> 6 == 3 {
        *unsupported = load && flags & 3 == 0;
        return None;
    }
    let explicit_source = lane_move && load || binary.is_some();
    let vvvv = !flags >> 3 & 15;
    if explicit_source && bits != 64 && vvvv >= 8 || !explicit_source && vvvv != 0 {
        return None;
    }
    if flags & 4 != 0 {
        if size != 16 || aes_transform.is_some() {
            // Scalar floating moves and the AES transforms require L=0.
            *unsupported = scalar_float;
            return None;
        }
        size = 32;
    }
    ctx.rex = (bits == 64).then_some(0x40 | extensions);
    let raw_rm = modrm_byte & 7;
    // Uniform shifts always encode an XMM or m128 count, including VEX.256.
    let rm_size = if let Some((_, source_size)) = widening {
        source_size * (size / 16)
    } else if uniform_shift.is_some() {
        16
    } else {
        size
    };
    let (group, _, mut rm) = modrm(ctx, address_bits, rm_size, bits == 64)?;
    if (streaming_load || map == 1 && matches!(opcode, 0x2b | 0xe7))
        && rm.kind != OperandKind::Memory
    {
        return None;
    }
    let (bank, register_width) = if size == 32 {
        ("ymm", 256)
    } else {
        ("xmm", 128)
    };
    if vector_rm && rm.kind == OperandKind::Register {
        let (rm_bank, rm_width) = if uniform_shift.is_some() || widening.is_some() {
            ("xmm", 128)
        } else {
            (bank, register_width)
        };
        rm.width_bits = rm_width;
        rm.reg = format!("{rm_bank}{}", raw_rm | ctx.any_rex_b());
    }
    let vector = Operand {
        kind: OperandKind::Register,
        reg: format!("{bank}{}", group | ctx.any_rex_r()),
        width_bits: register_width,
        read: !load || bit_test.is_some(),
        write: load && bit_test.is_none(),
        ..Operand::default()
    };
    out.operands = if explicit_source {
        let source = Operand {
            reg: format!("{bank}{vvvv}"),
            read: true,
            write: false,
            ..vector.clone()
        };
        vec![vector, source, rm]
    } else if load {
        vec![vector, rm]
    } else {
        vec![read_write(rm, false, true), vector]
    };
    if immediate_shuffle.is_some()
        || carryless_multiply.is_some()
        || unary_shuffle.is_some()
        || aes_transform.is_some_and(|(_, immediate)| immediate)
    {
        out.operands.push(immediate(ctx, 1, false)?);
    }
    if register_blend.is_some() {
        let mask = (ctx.consume_u8().ok()? >> 4) & if bits == 64 { 15 } else { 7 };
        out.operands.push(Operand {
            kind: OperandKind::Register,
            reg: format!("{bank}{mask}"),
            width_bits: register_width,
            read: true,
            ..Operand::default()
        });
    }
    out.mnemonic = match (opcode, size, flags & 3) {
        _ if let Some(name) = bit_test => name,
        _ if let Some(name) = binary => name,
        _ if let Some(name) = unary_shuffle.or(absolute) => name,
        _ if let Some((name, _)) = widening => name,
        _ if let Some((name, _)) = aes_transform => name,
        _ if streaming_load => "vmovntdqa",
        (0x10 | 0x11, 4, 2) => "vmovss",
        (0x10 | 0x11, 8, 3) => "vmovsd",
        (0x10 | 0x11, 16 | 32, 0) => "vmovups",
        (0x10 | 0x11, 16 | 32, 1) => "vmovupd",
        (0x12 | 0x13, 8, 0) => "vmovlps",
        (0x12 | 0x13, 8, 1) => "vmovlpd",
        (0x16 | 0x17, 8, 0) => "vmovhps",
        (0x16 | 0x17, 8, 1) => "vmovhpd",
        (0x28 | 0x29, 16 | 32, 0) => "vmovaps",
        (0x28 | 0x29, 16 | 32, 1) => "vmovapd",
        (0x2b, 16 | 32, 0) => "vmovntps",
        (0x2b, 16 | 32, 1) => "vmovntpd",
        (0xe7, 16 | 32, 1) => "vmovntdq",
        (_, 16 | 32, 1) => "vmovdqa",
        (_, 16 | 32, _) => "vmovdqu",
        (_, 8, _) => "vmovq",
        _ => "vmovd",
    }
    .into();
    Some(())
}
