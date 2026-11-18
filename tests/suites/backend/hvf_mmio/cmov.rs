//! Memory-source CMOVcc and pending Intel HVF reads.
use super::*;
use isa::x86_64::flags::bits::{CF, OF, PF, SF, ZF};

#[test]
fn cmov_always_reads_and_retires_once_for_every_condition_and_width() {
    let device = 0x1020_3040_5060_7080u64;
    for pattern in 0..32 {
        let [of, cf, zf, sf, pf] = std::array::from_fn(|bit| pattern & (1 << bit) != 0);
        let flags = [OF, CF, ZF, SF, PF];
        let rflags = flags.iter().enumerate().fold(2, |flags, (index, mask)| {
            flags
                | if pattern & (1 << index) != 0 {
                    *mask
                } else {
                    0
                }
        });
        let conditions = [of, cf, zf, cf || zf, sf, pf, sf != of, zf || sf != of];
        for cc in 0..16u8 {
            let selected = conditions[usize::from(cc / 2)] ^ (cc % 2 != 0);
            let code = [0x0f, 0x40 | cc, 0x07];
            for (prefix, size) in [(&[0x66][..], 2), (&[][..], 4), (&[0x48][..], 8)] {
                let encoding = [prefix, &code].concat();
                let (mut context, mut ram, exit) = fixture(&encoding);
                context.rflags = rflags;
                let plan = prepare(&context, &mut ram, exit).unwrap();
                assert_eq!((plan.physical, plan.linear), (exit.physical, exit.linear));
                let Action::Read(input) = plan.action else {
                    panic!("CMOVcc must produce a device read");
                };
                let original = context.registers[0];
                let expected = match (size, selected) {
                    (2, true) => (original & !0xffff) | (device & 0xffff),
                    (4, true) => device & 0xffff_ffff,
                    (8, true) => device,
                    (4, false) => original & 0xffff_ffff,
                    _ => original,
                };
                let mut pending = mmio::InputState::default();
                pending.begin(input).unwrap();
                let encoded = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&encoded).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor().unwrap().0, size as u8);
                let mut host = CompletionHost {
                    value: original,
                    flags: rflags,
                    ..Default::default()
                };
                restored.complete(&mut host, &device.to_le_bytes()[..size]);
                assert_eq!(restored.ready(), Ok(()));
                assert_eq!((host.value, host.flags), (expected, rflags));
                assert_eq!(host.length, encoding.len() as u64);
                assert_eq!(host.index, 0);
                let expected_calls = if selected || size == 4 {
                    &["gpr", "finish"][..]
                } else {
                    &["finish"][..]
                };
                assert_eq!(host.calls, expected_calls);
            }
        }
    }
}

#[test]
fn false_cmov32_clears_the_upper_half_only_in_ia32e() {
    for (code_bits, ia32e, code) in [
        (16, false, &[0x66, 0x0f, 0x44, 0x07][..]),
        (32, false, &[0x0f, 0x44, 0x07][..]),
        (16, true, &[0x66, 0x0f, 0x44, 0x07][..]),
        (32, true, &[0x0f, 0x44, 0x07][..]),
    ] {
        let (mut context, mut ram, exit) = fixture(code);
        context.code_bits = code_bits;
        if !ia32e {
            context.paging.cr0 = 1;
            context.paging.efer = 0;
        }
        if code_bits == 16 {
            context.segments[3] = exit.linear - 0x200;
            context.registers[3] = 0x200;
        }
        let plan = prepare(&context, &mut ram, exit).unwrap();
        let Action::Read(input) = plan.action else {
            panic!("false CMOVcc must produce an input");
        };
        assert_eq!(
            input.extension,
            Extension::Unselected { clear_upper: ia32e }
        );
        assert_eq!(input.size, 4);
    }
}

#[test]
fn false_cmov_rejects_wrong_address_direction_or_reply_before_retirement() {
    for code in [&[0xf0, 0x0f, 0x44, 0x07][..], &[0x0f, 0x44, 0xc7][..]] {
        let (context, mut ram, exit) = fixture(code);
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
    let (context, mut ram, exit) = fixture(&[0x0f, 0x44, 0x07]);
    for invalid in [
        ExitRecord {
            qualification: 0x182,
            ..exit
        },
        ExitRecord {
            linear: exit.linear + 1,
            ..exit
        },
        ExitRecord {
            physical: exit.physical + 1,
            ..exit
        },
    ] {
        assert!(prepare(&context, &mut ram, invalid).is_err());
    }
    let Action::Read(input) = prepare(&context, &mut ram, exit).unwrap().action else {
        panic!("false CMOVcc must produce an input");
    };
    let mut pending = mmio::InputState::default();
    let mut host = CompletionHost::default();
    pending.begin(input).unwrap();
    pending.complete(&mut host, &[0; 3]);
    assert!(pending.ready().is_err());
    assert!(host.calls.is_empty());
}
