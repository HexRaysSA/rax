use super::*;
use devices::bus::MmioRmwOp;

#[path = "../../../../tools/hvf/mmio_rmw_compare.rs"]
mod reference;

#[test]
fn independent_qemu_rmw_records_preserve_all_registers_memory_and_defined_flags() {
    let cases = include_bytes!("../../../fixtures/hvf/mmio-rmw-v1/cases.bin");
    let records = include_bytes!("../../../fixtures/hvf/mmio-rmw-v1/records.bin");
    assert_eq!(reference::compare(cases, records), (9320, 0));
}

#[test]
fn compatibility_widths_and_addr32_override_preserve_effective_addresses() {
    for bits in [16, 32, 64] {
        let code = if bits == 64 {
            &[0x67, 0xf0, 0x01, 0x0f][..]
        } else {
            &[0x01, 0x0f]
        };
        let (mut context, mut memory, mut record) = fixture(code);
        context.code_bits = bits;
        context.registers[1] = 1;
        if bits == 16 {
            context.registers[3] = 0;
            context.segments[3] = record.linear;
        } else if bits == 64 {
            context.registers[7] |= 0xffff_1234_0000_0000;
        }
        record.qualification = 0x182;
        let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
            panic!()
        };
        let size = if bits == 16 { 2 } else { 4 };
        assert_eq!(input.size, size);
        let old = u64::MAX.to_le_bytes();
        let mut new = old[..usize::from(size)].to_vec();
        input.operation.apply(&mut new).unwrap();
        assert_eq!(new, vec![0; usize::from(size)]);
        assert_eq!(
            input
                .completion(&old[..usize::from(size)])
                .unwrap()
                .1
                .unwrap()
                & 0x8d5,
            0x55
        );
    }
}

fn rmw_plan(code: &[u8]) -> (Context, mmio::RmwInput) {
    let (context, mut memory, mut record) = fixture(code);
    record.qualification = 0x183;
    let plan = prepare(&context, &mut memory, record).unwrap();
    let Action::Rmw(input) = plan.action else {
        panic!("expected RMW")
    };
    (context, input)
}

#[test]
fn exchange_aliases_preserve_flags_and_only_replace_the_named_register_part() {
    for code in [
        &[0x86, 0x27][..],
        &[0x66, 0x87, 0x07],
        &[0x87, 0x07],
        &[0x48, 0x87, 0x07],
    ] {
        let (context, input) = rmw_plan(code);
        let data = 0x89ab_cdef_0123_4580u64.to_le_bytes();
        let (register, flags, length) = input.completion(&data[..usize::from(input.size)]).unwrap();
        let part = if input.size == 1 {
            RegisterPart::parse("ah").unwrap()
        } else {
            RegisterPart {
                index: 0,
                bits: u32::from(input.size) * 8,
                shift: 0,
            }
        };
        assert_eq!(
            register,
            Some((
                0,
                part.merge(context.registers[0], u64::from_le_bytes(data))
            ))
        );
        assert_eq!(flags, None);
        assert_eq!(length, code.len() as u64);
    }
}

#[test]
fn cmpxchg_success_preserves_accumulator_and_failure_zero_extends_eax() {
    for equal in [false, true] {
        let (mut context, mut memory, mut record) = fixture(&[0xf0, 0x0f, 0xb1, 0x0f]);
        context.registers[0] = 0xfeed_face_1234_5678;
        context.registers[1] = 0xaaaa_bbbb_8765_4321;
        record.qualification = 0x182;
        let plan = prepare(&context, &mut memory, record).unwrap();
        let Action::Rmw(input) = plan.action else {
            panic!()
        };
        let old = if equal { 0x1234_5678u32 } else { 0x1122_3344 };
        let mut written = old.to_le_bytes();
        input.operation.apply(&mut written).unwrap();
        assert_eq!(
            written,
            if equal { 0x8765_4321u32 } else { old }.to_le_bytes()
        );
        let (register, flags, _) = input.completion(&old.to_le_bytes()).unwrap();
        assert_eq!(
            register,
            if equal {
                None
            } else {
                Some((0, u64::from(old)))
            }
        );
        assert_eq!(flags.unwrap() & (1 << 6) != 0, equal);
    }
}

#[test]
fn carry_borrow_and_increment_boundaries_preserve_control_flags() {
    for size in [1u8, 2, 4, 8] {
        let prefix: Vec<u8> = match size {
            2 => vec![0x66],
            8 => vec![0x48],
            _ => vec![],
        };
        for (opcode, old, source, carry, expected, arithmetic) in [
            (0x00, u64::MAX, 1, false, 0, 0x55u64),
            (0x10, u64::MAX, 1, true, 1, 0x11),
            (0x28, 0, 1, false, u64::MAX, 0x95),
            (0x18, 0, u64::MAX, true, 0, 0x55),
        ] {
            let mut code = prefix.clone();
            code.extend_from_slice(&[opcode + u8::from(size != 1), 0x0f]);
            let (mut context, mut memory, mut record) = fixture(&code);
            context.registers[1] = source;
            context.rflags = 2 | (1 << 9) | (1 << 10) | (1 << 16) | u64::from(carry);
            record.qualification = 0x183;
            let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
                panic!()
            };
            let data = old.to_le_bytes();
            let mut written = data[..usize::from(size)].to_vec();
            input.operation.apply(&mut written).unwrap();
            assert_eq!(written, expected.to_le_bytes()[..usize::from(size)]);
            let (register, flags, _) = input.completion(&data[..usize::from(size)]).unwrap();
            assert_eq!(register, None);
            let flags = flags.unwrap();
            assert_eq!(flags & 0x8d5, arithmetic, "size={size},opcode={opcode:#x}");
            assert_eq!(flags & !0x8d5, context.rflags & !0x8d5);
        }
        for (group, old, expected) in [(0u8, u64::MAX, 0u64), (1, 0, u64::MAX)] {
            let mut code = prefix.clone();
            code.extend_from_slice(&[if size == 1 { 0xfe } else { 0xff }, 7 | (group << 3)]);
            let (mut context, mut memory, mut record) = fixture(&code);
            context.rflags = 3;
            record.qualification = 0x182;
            let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
                panic!()
            };
            let data = old.to_le_bytes();
            let mut written = data[..usize::from(size)].to_vec();
            input.operation.apply(&mut written).unwrap();
            assert_eq!(written, expected.to_le_bytes()[..usize::from(size)]);
            assert_eq!(
                input
                    .completion(&data[..usize::from(size)])
                    .unwrap()
                    .1
                    .unwrap()
                    & 1,
                1
            );
        }
    }
}

#[test]
fn register_bit_strings_use_signed_word_offsets_and_immediates_stay_within_the_operand() {
    for (bits, prefix) in [(16i64, vec![0x66]), (32, vec![]), (64, vec![0x48])] {
        for (value, delta, bit) in [
            (u64::MAX, -(bits / 8), bits - 1),
            (bits as u64, bits / 8, 0),
        ] {
            let mut code = prefix.clone();
            code.extend_from_slice(&[0x0f, 0xab, 0x0f]);
            let (mut context, mut memory, mut record) = fixture(&code);
            context.registers[1] = value;
            record.qualification = 0x183;
            record.linear = record.linear.wrapping_add(delta as i64 as u64);
            record.physical = record.linear;
            let plan = prepare(&context, &mut memory, record).unwrap();
            let Action::Rmw(input) = plan.action else {
                panic!()
            };
            assert_eq!(input.operation, MmioRmwOp::BitSet(bit as u8));
            assert_eq!(input.size, (bits / 8) as u8);
        }
        let mut code = prefix;
        code.extend_from_slice(&[0x0f, 0xba, 0x2f, 0xff]);
        let (_, input) = rmw_plan(&code);
        assert_eq!(input.operation, MmioRmwOp::BitSet((bits - 1) as u8));
    }
}

#[test]
fn xadd_completion_failures_are_terminal_at_every_sdk_publication_stage() {
    let (_, input) = rmw_plan(&[0x0f, 0xc1, 0x0f]);
    for (failure, expected_calls) in [
        ("gpr", vec!["gpr"]),
        ("writeflags", vec!["gpr", "writeflags"]),
        ("finish", vec!["gpr", "writeflags", "finish"]),
    ] {
        let mut pending = mmio::InputState::default();
        pending.begin_rmw(input.clone()).unwrap();
        let mut host = CompletionHost {
            fail: Some(failure),
            ..Default::default()
        };
        pending.complete(&mut host, &0x1234_5678u32.to_le_bytes());
        assert_eq!(host.calls, expected_calls);
        assert!(pending.ready().is_err());
        assert!(pending.begin_rmw(input.clone()).is_err());
        pending.complete(&mut host, &0x1234_5678u32.to_le_bytes());
        assert_eq!(host.calls, expected_calls);
    }
    let mut pending = mmio::InputState::default();
    pending.begin_rmw(input).unwrap();
    let mut host = CompletionHost::default();
    pending.complete(&mut host, &[1, 2, 3]);
    assert!(host.calls.is_empty());
    assert!(pending.ready().is_err());
}

#[test]
fn successful_rmw_completion_publishes_once_and_excludes_an_overlapping_read() {
    let (_, input) = rmw_plan(&[0x0f, 0xc1, 0x0f]);
    let mut pending = mmio::InputState::default();
    pending.begin_rmw(input).unwrap();
    assert!(pending.begin(super::pending()).is_err());
    let mut host = CompletionHost::default();
    pending.complete(&mut host, &0x7654_3210u32.to_le_bytes());
    assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
    assert_eq!((host.index, host.value, host.length), (1, 0x7654_3210, 3));
    assert!(pending.ready().is_ok());
}
