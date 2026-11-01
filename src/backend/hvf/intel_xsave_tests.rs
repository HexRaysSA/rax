use super::*;

fn layout() -> Layout {
    Layout {
        mask: 7,
        size: 832,
        components: vec![Component {
            bit: 2,
            size: 256,
            offset: 576,
            align64: false,
        }],
        mxcsr_mask: 0xffbf,
    }
}
fn image(layout: &Layout) -> Vec<u8> {
    let mut bytes = vec![0; layout.size as usize];
    bytes[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&layout.mxcsr_mask.to_le_bytes());
    bytes
}

#[test]
fn projects_first_and_last_xmm_and_ymm_lanes() {
    let layout = layout();
    let mut bytes = image(&layout);
    bytes[512..520].copy_from_slice(&7u64.to_le_bytes());
    for (offset, value) in [
        (160, 0x1122u64),
        (408, 0x3344),
        (576, 0x5566),
        (824, 0x7788),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut registers = Registers::default();
    layout.project(&bytes, &mut registers).unwrap();
    assert_eq!(registers.xmm[0][0], 0x1122);
    assert_eq!(registers.xmm[15][1], 0x3344);
    assert_eq!(registers.ymm_high[0][0], 0x5566);
    assert_eq!(registers.ymm_high[15][1], 0x7788);
}

#[test]
fn init_components_ignore_stale_bytes() {
    let layout = layout();
    let mut bytes = image(&layout);
    bytes[160..416].fill(0xa5);
    bytes[576..832].fill(0x5a);
    let mut registers = Registers::default();
    let emulator = layout.project(&bytes, &mut registers).unwrap();
    assert_eq!(registers.xmm, [[0; 2]; 16]);
    assert_eq!(registers.ymm_high, [[0; 2]; 16]);
    assert_eq!(emulator.mxcsr, 0x1f80);
    assert_eq!(emulator.fpu.control_word, 0x037f);
    assert_eq!(emulator.fpu.tag_word, 0xffff);
}

#[test]
fn x87_logical_slots_recover_physical_registers_and_full_tags() {
    let layout = layout();
    let mut bytes = image(&layout);
    bytes[512..520].copy_from_slice(&3u64.to_le_bytes());
    bytes[2..4].copy_from_slice(&(3u16 << 11).to_le_bytes());
    bytes[4] = (1 << 3) | (1 << 4);
    bytes[32..40].copy_from_slice(&(1u64 << 63).to_le_bytes());
    bytes[40..42].copy_from_slice(&0x3fffu16.to_le_bytes());
    let mut registers = Registers::default();
    let emulator = layout.project(&bytes, &mut registers).unwrap();
    assert_eq!(emulator.fpu.top, 3);
    assert_eq!(emulator.fpu.tag_word, 0xfd3f);
    assert_eq!(emulator.fpu.st[3][7], 0x80);
    assert_eq!(&emulator.fpu.st[3][8..], &[0xff, 0x3f]);
    assert_eq!(registers.mm[3], 1 << 63);
    assert_eq!(registers.mm[4], 0);
}

#[test]
fn preserves_unprojected_host_component_during_register_overlay() {
    let mut layout = layout();
    layout.size = 1024;
    layout.mask |= 1 << 62;
    layout.components.push(Component {
        bit: 62,
        size: 64,
        offset: 960,
        align64: true,
    });
    let mut bytes = image(&layout);
    bytes[512..520].copy_from_slice(&(7u64 | (1 << 62)).to_le_bytes());
    bytes[960..1024].fill(0x5a);
    let mut registers = Registers::default();
    registers.xmm[15] = [0x1234, 0x5678];
    let changed = layout.overlay(&bytes, &registers).unwrap();
    assert_eq!(&changed[960..1024], &[0x5a; 64]);
    assert_eq!(&bytes[400..416], &[0; 16]);
    assert_eq!(u64_at(&changed, 400), 0x1234);
    assert_eq!(u64_at(&changed, 408), 0x5678);
}

#[test]
fn compacted_images_keep_opaque_components_when_normalized() {
    let mut layout = layout();
    layout.size = 1024;
    layout.mask |= 1 << 62;
    layout.components.push(Component {
        bit: 62,
        size: 64,
        offset: 960,
        align64: true,
    });
    let mut bytes = image(&layout);
    let present = 7u64 | (1 << 62);
    bytes[512..520].copy_from_slice(&present.to_le_bytes());
    bytes[520..528].copy_from_slice(&(COMPACTED | present).to_le_bytes());
    bytes[832..896].fill(0x6b);
    let changed = layout.overlay(&bytes, &Registers::default()).unwrap();
    assert_eq!(u64_at(&changed, 520), 0);
    assert_eq!(&changed[960..1024], &[0x6b; 64]);
}

#[test]
fn rejects_malformed_headers_and_reserved_mxcsr_bits() {
    let layout = layout();
    for (offset, value) in [(512, 8u64), (520, 7), (528, 1)] {
        let mut bytes = image(&layout);
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(layout.validate_image(&bytes).is_err());
    }
    let mut bytes = image(&layout);
    bytes[512..520].copy_from_slice(&3u64.to_le_bytes());
    bytes[24..28].copy_from_slice(&0x1_0000u32.to_le_bytes());
    assert!(layout.validate_image(&bytes).is_err());
    assert!(layout.validate_image(&bytes[..831]).is_err());
}

#[test]
fn rejects_overlapping_or_unsupported_component_tables() {
    let mut layout = layout();
    layout.components[0].offset = 512;
    assert!(layout.validate().is_err());
    layout.components[0].offset = 576;
    layout.mask |= 1 << 9;
    assert!(layout.validate().is_err());
    layout.components.push(Component {
        bit: 9,
        size: 8,
        offset: 600,
        align64: false,
    });
    assert!(layout.validate().is_err());
}

#[test]
fn unsupported_public_banks_are_rejected_without_changing_the_source() {
    let layout = layout();
    let bytes = image(&layout);
    let original = bytes.clone();
    let mut registers = Registers::default();
    registers.r16 = 1;
    assert!(layout.overlay(&bytes, &registers).is_err());
    registers.r16 = 0;
    registers.zmm_ext[15][7] = 1;
    assert!(layout.overlay(&bytes, &registers).is_err());
    assert_eq!(bytes, original);
}

#[test]
fn emulator_overlay_round_trips_exact_x87_state_at_every_top() {
    let layout = layout();
    let original = image(&layout);
    for top in 0..8 {
        let mut emulator = EmulatorState::default();
        emulator.fpu.top = top;
        emulator.fpu.status_word = u16::from(top) << 11;
        emulator.fpu.control_word = 0x0b7f;
        emulator.fpu.tag_word = 0xffff;
        emulator.fpu.instr_ptr = 0xffff_8000_1234_5678;
        emulator.fpu.data_ptr = 0xffff_8000_8765_4321;
        emulator.fpu.last_opcode = 0x5ab;
        emulator.mxcsr = 0x5f81;
        for (physical, value) in emulator.fpu.st.iter_mut().enumerate() {
            value[..8].copy_from_slice(&((1u64 << 63) | physical as u64).to_le_bytes());
            value[8..].copy_from_slice(&(0x3fffu16 + physical as u16).to_le_bytes());
            emulator.fpu.tag_word &= !(3 << (2 * physical));
        }
        let changed = layout.overlay_emulator(&original, &emulator).unwrap();
        let projected = layout.project(&changed, &mut Registers::default()).unwrap();
        assert_eq!(
            crate::codec::serialize(&projected.fpu).unwrap(),
            crate::codec::serialize(&emulator.fpu).unwrap()
        );
        assert_eq!(projected.mxcsr, emulator.mxcsr);
        assert_eq!(&changed[160..416], &original[160..416]);
        assert_eq!(&changed[576..832], &original[576..832]);
    }
}

#[test]
fn emulator_overlay_rejects_unrepresentable_tags_and_controls_without_source_changes() {
    let layout = layout();
    let bytes = image(&layout);
    let original = bytes.clone();
    let default = EmulatorState::default();
    for invalid in 0..5 {
        let mut emulator = default.clone();
        match invalid {
            0 => emulator.fpu.top = 8,
            1 => emulator.fpu.status_word = 1 << 11,
            2 => emulator.fpu.last_opcode = 0x800,
            3 => emulator.fpu.tag_word &= !3, // zero value with a nonzero-value tag
            4 => emulator.pkru = 1,
            _ => unreachable!(),
        }
        assert!(
            layout.overlay_emulator(&bytes, &emulator).is_err(),
            "case {invalid}"
        );
        assert_eq!(bytes, original);
    }
}

#[test]
fn pkru_overlay_preserves_other_extended_components() {
    let mut layout = layout();
    layout.size = 896;
    layout.mask |= 1 << 9;
    layout.components.push(Component {
        bit: 9,
        size: 8,
        offset: 832,
        align64: false,
    });
    let mut bytes = image(&layout);
    bytes[512..520].copy_from_slice(&7u64.to_le_bytes());
    bytes[576..832].fill(0xa7);
    let mut emulator = EmulatorState::default();
    emulator.pkru = 0x1234_5678;
    let changed = layout.overlay_emulator(&bytes, &emulator).unwrap();
    let projected = layout.project(&changed, &mut Registers::default()).unwrap();
    assert_eq!(projected.pkru, 0x1234_5678);
    assert_eq!(&changed[576..832], &[0xa7; 256]);
}

#[test]
fn standard_mxcsr_is_independent_of_the_sse_in_use_bit() {
    let layout = layout();
    let mut bytes = image(&layout);
    bytes[24..28].copy_from_slice(&0x5f81u32.to_le_bytes());
    let emulator = layout.project(&bytes, &mut Registers::default()).unwrap();
    assert_eq!(emulator.mxcsr, 0x5f81);
    let changed = layout.overlay(&bytes, &Registers::default()).unwrap();
    assert_eq!(u32_at(&changed, 24), 0x5f81);
    bytes[24..28].copy_from_slice(&0x1_0000u32.to_le_bytes());
    assert!(layout.validate_image(&bytes).is_err());
}

#[test]
fn emulator_overlay_materializes_initial_xmm_and_compacted_mxcsr() {
    let layout = layout();
    let mut bytes = image(&layout);
    bytes[520..528].copy_from_slice(&(COMPACTED | 7).to_le_bytes());
    bytes[160..416].fill(0xa5);
    bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    let emulator = layout.project(&bytes, &mut Registers::default()).unwrap();
    assert_eq!(emulator.mxcsr, 0x1f80);
    let changed = layout.overlay_emulator(&bytes, &emulator).unwrap();
    assert_eq!(u32_at(&changed, 24), 0x1f80);
    assert_eq!(&changed[160..416], &[0; 256]);
}
