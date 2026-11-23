//! XLAT's unsigned accumulator index and byte-sized device continuation.
use super::*;

#[test]
fn xlat_device_input_uses_the_selected_address_size_and_segment() {
    const AL: u64 = 0xf0;
    const ORIGINAL: u64 = 0x1234_5678_9abc_de00 | AL;
    const FLAGS: u64 = 0x0ed7;
    for (bits, code, base, segment, wrapped) in [
        (64, &[0xd7][..], 0xfee0_0000 - AL, 3, false),
        (64, &[0x4f, 0xd7], 0xfee0_0000 - AL, 3, false),
        (64, &[0x64, 0x67, 0xd7], 0x1234_5678_ffff_ff20, 4, true),
        (64, &[0x65, 0x67, 0xd7], 0x1234_5678_ffff_ff20, 5, true),
        (32, &[0xd7], 0x1234_5678_ffff_ff20, 3, true),
        (32, &[0x26, 0x67, 0xd7], 0x1234_5678_1234_ff20, 0, true),
        (16, &[0x66, 0xd7], 0x1234_5678_1234_ff20, 3, true),
        (16, &[0x36, 0x67, 0xd7], 0x1234_5678_ffff_ff20, 2, true),
    ] {
        let (mut context, mut ram, exit) = fixture(code);
        context.code_bits = bits;
        context.registers[0] = ORIGINAL;
        context.registers[3] = base;
        context.segments[segment] = if wrapped { exit.linear - 0x10 } else { 0x1000 };
        context.rflags = FLAGS;
        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, code.len() as u64);
        assert!(!ram.reads.iter().any(|&(addr, _)| addr == exit.physical));
        let Action::Read(input) = plan.action else {
            panic!("XLAT requires one device input");
        };
        let mut pending = mmio::InputState::default();
        pending.begin(input).unwrap();
        let saved = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor(), Some((1, None)));
        let mut host = CompletionHost {
            value: ORIGINAL,
            flags: FLAGS,
            ..Default::default()
        };
        restored.complete(&mut host, &[0x39]);
        assert_eq!(restored.ready(), Ok(()));
        assert_eq!(host.value, (ORIGINAL & !0xff) | 0x39);
        assert_eq!(host.flags, FLAGS);
        assert_eq!(host.index, 0);
        assert_eq!(host.length, code.len() as u64);
        assert_eq!(host.calls, ["gpr", "finish"]);
    }
}

#[test]
fn xlat_rejects_lock_and_inconsistent_exit_records() {
    for (code, qualification, displacement, mapped) in [
        (&[0xf0, 0xd7][..], 0x181, 0, false),
        (&[0xd7][..], 0x182, 0, false),
        (&[0xd7][..], 0x183, 0, false),
        (&[0xd7][..], 0x181, 1, false),
        (&[0xd7][..], 0x181, 0, true),
    ] {
        let (mut context, mut ram, mut exit) = fixture(code);
        context.registers[3] = exit.linear - (context.registers[0] & 0xff);
        exit.qualification = qualification;
        exit.linear += displacement;
        exit.physical += displacement;
        if mapped {
            ram.bytes(exit.physical, &[0x12]);
        }
        assert!(prepare(&context, &mut ram, exit).is_err());
        assert!(!ram.reads.iter().any(|&(addr, _)| addr == exit.physical));
    }
}
