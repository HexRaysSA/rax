//! Qualified hardware translations remain valid after guest table replacement.
use super::*;

#[test]
fn first_page_uses_the_exit_gpa_after_data_pte_replacement() {
    for (code, qualification) in [
        (&[0x48, 0x8b, 0x07][..], 0x181),
        (&[0x48, 0x89, 0x07][..], 0x182),
        (&[0x48, 0x03, 0x07][..], 0x181),
        (&[0x48, 0x01, 0x07][..], 0x183),
        (&[0x48, 0x0f, 0xab, 0x07][..], 0x183),
    ] {
        for entry in [0xa001u64, 0xc001, 0, 0x8000_0000_0000_a001] {
            let (mut context, mut memory, mut exit) = paged_fixture(code, 0xb000);
            context.registers[7] = 0x2800;
            context.registers[0] = 2;
            exit.linear = 0x2800;
            exit.physical = 0xa800;
            exit.qualification = qualification;
            memory.bytes(0x4010, &entry.to_le_bytes());
            let before = memory.bytes.clone();
            let plan = prepare(&context, &mut memory, exit).unwrap();
            assert_eq!(plan.linear, 0x2800);
            assert_eq!(plan.physical, 0xa800);
            assert_eq!(memory.bytes, before, "planning cannot mutate guest RAM");
        }
    }
}

#[test]
fn first_page_and_following_page_have_distinct_translation_sources() {
    let (context, mut memory, exit) = paged_fixture(&[0x48, 0x8b, 7], 0xb000);
    // The first data PTE changes after the recorded access. The next page still
    // resolves to the represented contiguous continuation at GPA0xb000.
    memory.bytes(0x4010, &0xc001u64.to_le_bytes());
    let plan = prepare(&context, &mut memory, exit).unwrap();
    assert_eq!(plan.physical, 0xafff);
    let Action::Read(input) = plan.action else {
        panic!("expected read")
    };
    assert_eq!(input.size, 8);
    memory.bytes(0x4018, &0xd001u64.to_le_bytes());
    assert!(
        prepare(&context, &mut memory, exit)
            .unwrap_err()
            .contains("noncontiguous")
    );
}

#[test]
fn recorded_ranges_reject_bad_offsets_width_and_ram_targets() {
    for size in [1u8, 2, 4, 8] {
        let code: &[u8] = match size {
            1 => &[0x8a, 7],
            2 => &[0x66, 0x8b, 7],
            4 => &[0x8b, 7],
            _ => &[0x48, 0x8b, 7],
        };
        let (context, mut memory, exit) = fixture(code);
        let mut invalid = exit;
        invalid.physical += 1;
        assert!(
            prepare(&context, &mut memory, invalid)
                .unwrap_err()
                .contains("offsets")
        );
        invalid = exit;
        invalid.physical |= 1 << context.paging.physical_bits;
        assert!(
            prepare(&context, &mut memory, invalid)
                .unwrap_err()
                .contains("width")
        );
        let mut last_context = context;
        last_context.registers[7] |= 0xfff;
        invalid = exit;
        invalid.linear = last_context.registers[7];
        invalid.physical = (1 << context.paging.physical_bits) - 1;
        let last_byte = prepare(&last_context, &mut memory, invalid);
        if size == 1 {
            assert!(last_byte.is_ok());
        } else {
            assert!(last_byte.unwrap_err().contains("width"));
        }
        invalid = exit;
        invalid.physical = (1 << context.paging.physical_bits) - 0x1000;
        memory.bytes(invalid.physical, &[0]);
        assert!(
            prepare(&context, &mut memory, invalid)
                .unwrap_err()
                .contains("RAM")
        );
    }
}

#[test]
fn recorded_metadata_does_not_bypass_linear_address_admission() {
    let (mut context, mut memory, mut exit) = fixture(&[0x48, 0x8b, 7]);
    context.registers[7] = 0x0000_8000_0000_0000;
    exit.linear = context.registers[7];
    assert!(
        prepare(&context, &mut memory, exit)
            .unwrap_err()
            .contains("noncanonical")
    );

    let (mut context, mut memory, mut exit) = fixture(&[0x48, 0x8b, 7]);
    context.paging.cr0 = 0;
    context.paging.efer = 0;
    exit.physical -= 0x1000;
    assert!(
        prepare(&context, &mut memory, exit)
            .unwrap_err()
            .contains("nonpaged")
    );
}
