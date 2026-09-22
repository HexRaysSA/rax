//! x87 part 2 tests

use super::*;
use crate::smir::interpret::tests::*;
use crate::smir::interpret::*;

#[test]
fn lifted_x87_fist_fistp_fisttp_round_range_fault_and_pop_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let n15 = raw(0xC000_0000_0000_0000, 0xBFFF);

    for (name, rc, source, expected, expected_c1) in [
        ("nearest +1.5", 0u16, p15, 2i16, true),
        ("nearest -1.5", 0, n15, -2, true),
        ("down +1.5", 1, p15, 1, false),
        ("down -1.5", 1, n15, -2, true),
        ("up +1.5", 2, p15, 2, true),
        ("up -1.5", 2, n15, -1, false),
        ("truncate +1.5", 3, p15, 1, false),
        ("truncate -1.5", 3, n15, -1, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xDF, 0x10], &mut ctx, &mut memory); // FIST m16int
        let mut stored = [0u8; 2];
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(i16::from_le_bytes(stored), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}");
            assert_ne!(x86.x87.status_word & 0x0020, 0, "{name}: PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}");
        }
    }

    // FISTTP ignores FCW.RC, truncates, clears C1, and pops.
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x300);
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word = (x86.x87.control_word & !0x0C00) | 0x0800; // round up
        x86.x87.set_logical_raw(0, n15);
        x86.x87.status_word |= 0x0200;
    }
    execute_lifted_x86(&[0xDF, 0x08], &mut ctx, &mut memory);
    let mut word = [0u8; 2];
    memory.read(0x100, &mut word).unwrap();
    assert_eq!(i16::from_le_bytes(word), -1);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0220, 0x0020);
    }

    // Exact signed minima are valid at every destination width.
    for (bytes, source, expected, len) in [
        (
            &[0xDF, 0x18][..],
            raw(0x8000_0000_0000_0000, 0xC00E),
            (i16::MIN as u16 as u64).to_le_bytes(),
            2usize,
        ),
        (
            &[0xDB, 0x18][..],
            raw(0x8000_0000_0000_0000, 0xC01E),
            (i32::MIN as u32 as u64).to_le_bytes(),
            4,
        ),
        (
            &[0xDF, 0x38][..],
            raw(0x8000_0000_0000_0000, 0xC03E),
            (i64::MIN as u64).to_le_bytes(),
            8,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw(0, source);
        }
        memory.write(0x100, &[0; 8]).unwrap();
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        let mut actual = [0u8; 8];
        memory.read(0x100, &mut actual[..len]).unwrap();
        assert_eq!(&actual[..len], &expected[..len], "{bytes:02X?}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1, "{bytes:02X?}");
            assert_eq!(x86.x87.status_word & 0x0021, 0, "{bytes:02X?}");
        }
    }

    // Masked invalid conversion stores integer indefinite; pop behavior
    // follows the selected opcode.
    let qnan = raw(0xC000_0000_0000_1234, 0x7FFF);
    for (bytes, len, pops) in [
        (&[0xDF, 0x10][..], 2usize, false),
        (&[0xDB, 0x18][..], 4, true),
        (&[0xDF, 0x38][..], 8, true),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw_tagged(0, qnan, 2);
        }
        memory.write(0x100, &[0; 8]).unwrap();
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        let mut actual = [0u8; 8];
        memory.read(0x100, &mut actual[..len]).unwrap();
        let indefinite = (1u64 << (len * 8 - 1)).to_le_bytes();
        assert_eq!(&actual[..len], &indefinite[..len], "{bytes:02X?}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_ne!(x86.x87.status_word & 1, 0);
            assert_eq!(x86.x87.top(), u8::from(pops));
        }
    }

    // Positive 32768 is out of range for m16int and uses the same masked
    // invalid response.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87
            .set_logical_raw(0, raw(0x8000_0000_0000_0000, 0x400E));
    }
    execute_lifted_x86(&[0xDF, 0x10], &mut ctx, &mut memory);
    memory.read(0x100, &mut word).unwrap();
    assert_eq!(u16::from_le_bytes(word), 0x8000);

    // Unmasked invalid suppresses both store and pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
        x86.x87.set_logical_raw_tagged(0, qnan, 2);
    }
    memory.write(0x100, &[0xA5; 8]).unwrap();
    execute_lifted_x86(&[0xDF, 0x38], &mut ctx, &mut memory);
    let mut qword = [0u8; 8];
    memory.read(0x100, &mut qword).unwrap();
    assert_eq!(qword, [0xA5; 8]);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x8081, 0x8081);
    }

    // Unmasked precision still stores and pops the rounded result while
    // asserting the pending summary.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
        x86.x87.set_logical_raw(0, p15);
    }
    execute_lifted_x86(&[0xDB, 0x18], &mut ctx, &mut memory);
    let mut dword = [0u8; 4];
    memory.read(0x100, &mut dword).unwrap();
    assert_eq!(i32::from_le_bytes(dword), 2);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }

    // A partial write fault commits no status, environment, tag, or pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_logical_raw(0, p15);
        x86.x87.data_ptr = 0xCAFE;
    }
    let before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x104);
    let exit = execute_lifted_x86(&[0xDF, 0x38], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_frndint_exact_rounding_special_values_and_exception_masks() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }

    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let n15 = raw(0xC000_0000_0000_0000, 0xBFFF);
    let p1 = raw(0x8000_0000_0000_0000, 0x3FFF);
    let n1 = raw(0x8000_0000_0000_0000, 0xBFFF);
    let p2 = raw(0x8000_0000_0000_0000, 0x4000);
    let n2 = raw(0x8000_0000_0000_0000, 0xC000);

    for (name, rc, source, expected, expected_c1) in [
        ("nearest +1.5", 0u16, p15, p2, true),
        ("nearest -1.5", 0, n15, n2, true),
        ("down +1.5", 1, p15, p1, false),
        ("down -1.5", 1, n15, n2, true),
        ("up +1.5", 2, p15, p2, true),
        ("up -1.5", 2, n15, n1, false),
        ("truncate +1.5", 3, p15, p1, false),
        ("truncate -1.5", 3, n15, n1, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
            x86.x87.data_ptr = 0xCAFE;
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.regs[0], expected, "{name}");
            assert_eq!(x86.x87.top(), 0, "{name}: no pop");
            assert_eq!(x86.x87.status_word & 0x0020, 0x0020, "{name}: PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x01FC, "{name}: FOP");
            assert_eq!(x86.x87.data_ptr, 0xCAFE, "{name}: FDP unchanged");
        }
        ctx.flags.materialize_all();
        assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7, "{name}: RFLAGS");
    }

    // Ties round to even, including signed zero; already-integral values
    // beyond every host integer width remain bit-for-bit unchanged.
    for (name, source, expected) in [
        ("+0.5 tie", raw(0x8000_0000_0000_0000, 0x3FFE), raw(0, 0)),
        (
            "-0.5 tie",
            raw(0x8000_0000_0000_0000, 0xBFFE),
            raw(0, 0x8000),
        ),
        (
            "huge integral",
            raw(0x8000_0000_0001_2345, 0x404F),
            raw(0x8000_0000_0001_2345, 0x404F),
        ),
        ("negative zero", raw(0, 0x8000), raw(0, 0x8000)),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.regs[0], expected, "{name}");
            assert_eq!(
                x86.x87.status_word & 0x0221,
                if name.contains("tie") { 0x0020 } else { 0 },
                "{name}"
            );
        }
    }

    let qnan = raw(0xC123_4567_89AB_CDEF, 0xFFFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quieted_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    let infinity = raw(0x8000_0000_0000_0000, 0xFFFF);
    for (name, source, expected, expected_ie) in [
        ("quiet NaN", qnan, qnan, false),
        ("signaling NaN", snan, quieted_snan, true),
        (
            "unsupported",
            unsupported,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
        ("infinity", infinity, infinity, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.regs[0], expected, "{name}");
            assert_eq!(x86.x87.status_word & 1 != 0, expected_ie, "{name}: IE");
            assert_eq!(x86.x87.status_word & 0x0220, 0, "{name}: no PE/C1");
        }
    }

    // Masked #D permits rounding and subsequent #P accrual. Unmasked #D
    // has higher priority and suppresses the result and #P.
    let denormal = raw(1, 0);
    for source in [denormal, raw(0x8000_0000_0000_0001, 0)] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.regs[0], raw(0, 0));
            assert_eq!(x86.x87.status_word & 0x0022, 0x0022);
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word &= !0x0002;
        x86.x87.set_logical_raw(0, denormal);
    }
    execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[0], denormal);
        assert_eq!(x86.x87.status_word & 0x80A2, 0x8082);
    }

    // Unmasked #IA suppresses quieting/replacement. Unmasked #P is a
    // post-computation exception and therefore retains the rounded result.
    for source in [snan, unsupported] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word &= !0x0001;
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.regs[0], source);
            assert_eq!(x86.x87.status_word & 0x80A1, 0x8081);
        }
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
        x86.x87.set_logical_raw(0, p15);
    }
    execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[0], p2);
        assert_eq!(x86.x87.status_word & 0x82A0, 0x82A0);
    }

    // A masked empty-stack source installs indefinite without changing
    // TOP. With IM clear, both tag and payload remain unchanged.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.regs[0], crate::smir::X86X87State::INDEFINITE);
        assert_eq!(x86.x87.physical_tag(0), 2);
        assert_eq!(x86.x87.status_word & 0x8241, 0x0041);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
        x86.x87.regs[0] = p1;
    }
    execute_lifted_x86(&[0xD9, 0xFC], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[0], p1);
        assert_eq!(x86.x87.physical_tag(0), 3);
        assert_eq!(x86.x87.status_word & 0x82C1, 0x80C1);
    }
}
#[test]
fn lifted_x87_fxtract_exact_decomposition_special_values_and_stack_faults() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn results(ctx: &SmirContext) -> ([u8; 10], [u8; 10]) {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => (
                x86.x87.regs[x86.x87.physical_index(0)],
                x86.x87.regs[x86.x87.physical_index(1)],
            ),
            _ => unreachable!(),
        }
    }

    let p6 = raw(0xC000_0000_0000_0000, 0x4001);
    let n6 = raw(0xC000_0000_0000_0000, 0xC001);
    let p2 = raw(0x8000_0000_0000_0000, 0x4000);
    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let n15 = raw(0xC000_0000_0000_0000, 0xBFFF);
    for (name, source, significand, exponent) in [
        ("positive six", p6, p15, p2),
        ("negative six", n6, n15, p2),
        (
            "maximum normal exponent",
            raw(0xFEDC_BA98_7654_3210, 0x7FFE),
            raw(0xFEDC_BA98_7654_3210, 0x3FFF),
            SmirInterpreter::x86_x87_from_i64(16_383),
        ),
        (
            "minimum true denormal",
            raw(1, 0),
            raw(0x8000_0000_0000_0000, 0x3FFF),
            SmirInterpreter::x86_x87_from_i64(-16_445),
        ),
        (
            "pseudo-denormal",
            raw(0x8000_0000_0000_0001, 0),
            raw(0x8000_0000_0000_0001, 0x3FFF),
            SmirInterpreter::x86_x87_from_i64(-16_382),
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.data_ptr = 0xCAFE;
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
        assert_eq!(results(&ctx), (significand, exponent), "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 7, "{name}: push");
            assert_eq!(
                x86.x87.status_word & 0x0002,
                if source[8] == 0 && source[9] & 0x7F == 0 {
                    0x0002
                } else {
                    0
                },
                "{name}: DE"
            );
            assert_eq!(x86.x87.status_word & 0x0261, 0, "{name}: IE/PE/C1");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x01F4, "{name}: FOP");
            assert_eq!(x86.x87.data_ptr, 0xCAFE, "{name}: FDP unchanged");
        }
        ctx.flags.materialize_all();
        assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7, "{name}: RFLAGS");
    }

    let pzero = raw(0, 0);
    let nzero = raw(0, 0x8000);
    let negative_infinity = raw(0x8000_0000_0000_0000, 0xFFFF);
    let positive_infinity = raw(0x8000_0000_0000_0000, 0x7FFF);
    let qnan = raw(0xC123_4567_89AB_CDEF, 0xFFFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, source, expected, exceptions) in [
        (
            "positive zero",
            pzero,
            (pzero, negative_infinity),
            0x0004u16,
        ),
        ("negative zero", nzero, (nzero, negative_infinity), 0x0004),
        (
            "negative infinity",
            negative_infinity,
            (negative_infinity, positive_infinity),
            0,
        ),
        ("quiet NaN", qnan, (qnan, qnan), 0),
        ("signaling NaN", snan, (quiet_snan, quiet_snan), 0x0001),
        (
            "unsupported",
            unsupported,
            (
                crate::smir::X86X87State::INDEFINITE,
                crate::smir::X86X87State::INDEFINITE,
            ),
            0x0001,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
        assert_eq!(results(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 7, "{name}: push");
            assert_eq!(x86.x87.status_word & 0x0007, exceptions, "{name}");
            assert_eq!(x86.x87.status_word & 0x0260, 0, "{name}: no PE/C1");
        }
    }

    // Invalid, denormal, and zero-divide are pre-computation exceptions:
    // clearing the corresponding mask suppresses the push and both writes.
    for (name, source, mask, exception) in [
        ("SNaN", snan, 0x0001u16, 0x0001u16),
        ("denormal", raw(1, 0), 0x0002, 0x0002),
        ("zero", pzero, 0x0004, 0x0004),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !mask;
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        let before = match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.clone(),
            _ => unreachable!(),
        };
        execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), before.top(), "{name}: no push");
            assert_eq!(x86.x87.regs, before.regs, "{name}: operands unchanged");
            assert_eq!(x86.x87.tag_word, before.tag_word, "{name}: tags unchanged");
            assert_eq!(
                x86.x87.status_word & (0x8080 | exception),
                0x8080 | exception
            );
            assert_eq!(x86.x87.status_word & 0x0060, 0, "{name}: no SF/PE");
        }
    }

    // Masked stack underflow/overflow push two indefinite values. The
    // unmasked forms preserve TOP, tags, and operands; C1 distinguishes
    // overflow from underflow.
    for (name, overflow, expected_c1) in [("underflow", false, false), ("overflow", true, true)] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if overflow {
            if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                x86.x87.set_logical_raw(0, p6);
                x86.x87.set_logical_raw(7, p15);
            }
        }
        execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
        assert_eq!(
            results(&ctx),
            (
                crate::smir::X86X87State::INDEFINITE,
                crate::smir::X86X87State::INDEFINITE,
            ),
            "{name}"
        );
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 7, "{name}: masked push");
            assert_eq!(x86.x87.status_word & 0x0041, 0x0041, "{name}: IE/SF");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }

        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !1;
            if overflow {
                x86.x87.set_logical_raw(0, p6);
                x86.x87.set_logical_raw(7, p15);
            }
        }
        let before = match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.clone(),
            _ => unreachable!(),
        };
        execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), before.top(), "{name}: unmasked no push");
            assert_eq!(x86.x87.regs, before.regs, "{name}: operands unchanged");
            assert_eq!(x86.x87.tag_word, before.tag_word, "{name}: tags unchanged");
            assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1, "{name}: pending #IS");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }
    }
}
#[test]
fn lifted_x87_fscale_exact_scaling_rounding_exceptions_and_reconstruction() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn seed(ctx: &mut SmirContext, st0: [u8; 10], st1: [u8; 10]) {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, st0);
            x86.x87.set_logical_raw(1, st1);
        }
    }
    fn st0(ctx: &SmirContext) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(0)],
            _ => unreachable!(),
        }
    }

    let one = SmirInterpreter::x86_x87_from_i64(1);
    let two = SmirInterpreter::x86_x87_from_i64(2);
    let minus_one = SmirInterpreter::x86_x87_from_i64(-1);
    let minus_64 = SmirInterpreter::x86_x87_from_i64(-64);
    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let p6 = raw(0xC000_0000_0000_0000, 0x4001);
    let p375 = raw(0xC000_0000_0000_0000, 0x3FFD);
    let p25 = raw(0xA000_0000_0000_0000, 0x4000);
    let n25 = raw(0xA000_0000_0000_0000, 0xC000);

    for (name, value, scale, expected) in [
        ("positive integral scale", p15, two, p6),
        ("fraction truncates toward zero", p15, p25, p6),
        ("negative fraction truncates toward zero", p15, n25, p375),
        ("zero scale", p15, raw(0, 0x8000), p15),
        (
            "PC does not narrow significand",
            raw(0x8000_0000_0000_0001, 0x3FFF),
            one,
            raw(0x8000_0000_0000_0001, 0x4000),
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !0x0300; // PC=24, irrelevant to FSCALE
            x86.x87.data_ptr = 0xCAFE;
        }
        seed(&mut ctx, value, scale);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}: no pop");
            assert_eq!(x86.x87.status_word & 0x023F, 0, "{name}: exact");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x01FD, "{name}: FOP");
            assert_eq!(x86.x87.data_ptr, 0xCAFE, "{name}: FDP unchanged");
        }
        ctx.flags.materialize_all();
        assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7, "{name}: RFLAGS");
    }

    // Masked overflow selects infinity or maximum finite according to RC;
    // C1 identifies the magnitude increment.
    let max = raw(u64::MAX, 0x7FFE);
    let nmax = raw(u64::MAX, 0xFFFE);
    let pinf = raw(0x8000_0000_0000_0000, 0x7FFF);
    let ninf = raw(0x8000_0000_0000_0000, 0xFFFF);
    for (name, rc, value, expected, expected_c1) in [
        ("nearest +overflow", 0u16, max, pinf, true),
        ("nearest -overflow", 0, nmax, ninf, true),
        ("down +overflow", 1, max, max, false),
        ("down -overflow", 1, nmax, ninf, true),
        ("up +overflow", 2, max, pinf, true),
        ("up -overflow", 2, nmax, nmax, false),
        ("zero +overflow", 3, max, max, false),
        ("zero -overflow", 3, nmax, nmax, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, value, one);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0028, 0x0028, "{name}: OE/PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }
    }

    // Half a minimum subnormal exercises every RC direction and signed
    // zero. An exactly representable denormal does not raise UE or PE.
    let min_normal = raw(0x8000_0000_0000_0000, 0x0001);
    let nmin_normal = raw(0x8000_0000_0000_0000, 0x8001);
    let pzero = raw(0, 0);
    let nzero = raw(0, 0x8000);
    let pmin_subnormal = raw(1, 0);
    let nmin_subnormal = raw(1, 0x8000);
    for (name, rc, value, expected, expected_c1) in [
        ("nearest +half-min", 0u16, min_normal, pzero, false),
        ("nearest -half-min", 0, nmin_normal, nzero, false),
        ("down +half-min", 1, min_normal, pzero, false),
        ("down -half-min", 1, nmin_normal, nmin_subnormal, true),
        ("up +half-min", 2, min_normal, pmin_subnormal, true),
        ("up -half-min", 2, nmin_normal, nzero, false),
        ("zero +half-min", 3, min_normal, pzero, false),
        ("zero -half-min", 3, nmin_normal, nzero, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, value, minus_64);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0030, 0x0030, "{name}: UE/PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    seed(&mut ctx, min_normal, minus_one);
    execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), raw(0x4000_0000_0000_0000, 0));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0030, 0, "exact tiny result");
    }

    // A denormal in either position raises DE. A masked denormal ST(0) is
    // normalized when scaling permits it; a denormal ST(1) truncates to 0.
    for (name, value, scale, expected) in [
        (
            "denormal destination",
            raw(0x4000_0000_0000_0000, 0),
            one,
            min_normal,
        ),
        ("denormal scale factor", one, raw(1, 0), one),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        seed(&mut ctx, value, scale);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0032, 0x0002, "{name}: DE only");
        }
    }

    // Unmasked register-result overflow/underflow stores Intel's exponent-
    // biased response rather than suppressing the destination write.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0008;
    }
    seed(&mut ctx, max, one);
    execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), raw(u64::MAX, 0x1FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x82A8, 0x80A8);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0010;
    }
    seed(&mut ctx, min_normal, minus_64);
    execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), raw(0x8000_0000_0000_0000, 0x5FC1));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x82B0, 0x80B0);
    }

    // Scaling beyond the +/-24,576 unmasked-response bias saturates to
    // signed infinity/zero. PM independently requests ES/B even when the
    // corresponding range exception remains masked.
    for (name, scale, unmask, expected, expected_flags) in [
        (
            "massive unmasked overflow",
            SmirInterpreter::x86_x87_from_i64(50_000),
            0x0008u16,
            pinf,
            0x80A8u16,
        ),
        (
            "massive unmasked underflow",
            SmirInterpreter::x86_x87_from_i64(-50_000),
            0x0010,
            pzero,
            0x80B0,
        ),
        (
            "masked overflow with PM clear",
            SmirInterpreter::x86_x87_from_i64(50_000),
            0x0020,
            pinf,
            0x82A8,
        ),
        (
            "masked underflow with PM clear",
            SmirInterpreter::x86_x87_from_i64(-50_000),
            0x0020,
            pzero,
            0x80B0,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word &= !unmask;
        }
        seed(&mut ctx, one, scale);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x82B8, expected_flags, "{name}");
        }
    }

    // Infinity, zero, NaN, and unsupported matrices do not report range
    // exceptions; invalid combinations use canonical indefinite.
    let qnan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, value, scale, expected, expected_ie) in [
        ("finite times +infinity", one, pinf, pinf, false),
        ("finite times -infinity", one, ninf, pzero, false),
        (
            "zero times +infinity",
            pzero,
            pinf,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
        (
            "infinity times -infinity",
            pinf,
            ninf,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
        ("quiet NaN scale factor", one, qnan, qnan, false),
        ("signaling NaN scale factor", one, snan, quiet_snan, true),
        (
            "unsupported scale factor",
            one,
            unsupported,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        seed(&mut ctx, value, scale);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 1 != 0, expected_ie, "{name}: IE");
            assert_eq!(x86.x87.status_word & 0x0238, 0, "{name}: no range/PE/C1");
        }
    }

    // Unmasked invalid/denormal and unmasked stack faults suppress ST(0),
    // while their masked forms replace it with indefinite as applicable.
    for (name, value, scale, mask, exception) in [
        ("invalid", one, snan, 0x0001u16, 0x0001u16),
        ("denormal", one, raw(1, 0), 0x0002, 0x0002),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !mask;
        }
        seed(&mut ctx, value, scale);
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), value, "{name}: result suppressed");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                x86.x87.status_word & (0x8080 | exception),
                0x8080 | exception
            );
        }
    }
    for missing_st0 in [true, false] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            if missing_st0 {
                x86.x87.set_logical_raw(1, one);
            } else {
                x86.x87.set_logical_raw(0, one);
            }
        }
        execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), crate::smir::X86X87State::INDEFINITE);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word &= !1;
        x86.x87.set_logical_raw(0, one);
    }
    execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), one);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }

    // The documented FXTRACT/FSCALE composition reconstructs the original
    // binary80 value exactly without changing the extracted exponent.
    let mut ctx = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87
            .set_logical_raw(0, raw(0xFEDC_BA98_7654_3210, 0xC123));
    }
    execute_lifted_x86(&[0xD9, 0xF4], &mut ctx, &mut memory);
    let exponent_before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(1)],
        _ => unreachable!(),
    };
    execute_lifted_x86(&[0xD9, 0xFD], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), raw(0xFEDC_BA98_7654_3210, 0xC123));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[x86.x87.physical_index(1)], exponent_before);
    }
}
#[test]
fn lifted_x87_fsqrt_exact_pc_rc_special_and_exception_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn st0(ctx: &SmirContext) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(0)],
            _ => unreachable!(),
        }
    }

    let two = raw(0x8000_0000_0000_0000, 0x4000);
    for (name, pc, rc, expected, expected_c1) in [
        (
            "PC24 nearest",
            0u16,
            0u16,
            raw(0xB504_F300_0000_0000, 0x3FFF),
            false,
        ),
        ("PC24 down", 0, 1, raw(0xB504_F300_0000_0000, 0x3FFF), false),
        ("PC24 up", 0, 2, raw(0xB504_F400_0000_0000, 0x3FFF), true),
        ("PC24 zero", 0, 3, raw(0xB504_F300_0000_0000, 0x3FFF), false),
        (
            "reserved PC nearest",
            1,
            0,
            raw(0xB504_F333_F9DE_6484, 0x3FFF),
            false,
        ),
        (
            "reserved PC up",
            1,
            2,
            raw(0xB504_F333_F9DE_6485, 0x3FFF),
            true,
        ),
        (
            "PC53 nearest",
            2,
            0,
            raw(0xB504_F333_F9DE_6800, 0x3FFF),
            true,
        ),
        ("PC53 down", 2, 1, raw(0xB504_F333_F9DE_6000, 0x3FFF), false),
        ("PC53 up", 2, 2, raw(0xB504_F333_F9DE_6800, 0x3FFF), true),
        ("PC53 zero", 2, 3, raw(0xB504_F333_F9DE_6000, 0x3FFF), false),
        (
            "PC64 nearest",
            3,
            0,
            raw(0xB504_F333_F9DE_6484, 0x3FFF),
            false,
        ),
        ("PC64 down", 3, 1, raw(0xB504_F333_F9DE_6484, 0x3FFF), false),
        ("PC64 up", 3, 2, raw(0xB504_F333_F9DE_6485, 0x3FFF), true),
        ("PC64 zero", 3, 3, raw(0xB504_F333_F9DE_6484, 0x3FFF), false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            x86.x87.data_ptr = 0xCAFE;
            x86.x87.set_logical_raw(0, two);
        }
        execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0020, 0x0020, "{name}: PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
            assert_eq!(x86.x87.top(), 0, "{name}: no pop");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x01FA, "{name}: FOP");
            assert_eq!(x86.x87.data_ptr, 0xCAFE, "{name}: FDP unchanged");
        }
        ctx.flags.materialize_all();
        assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7, "{name}: RFLAGS");
    }

    // Perfect squares are exact across exponent parity and PC settings.
    for (name, source, expected) in [
        (
            "four",
            raw(0x8000_0000_0000_0000, 0x4001),
            raw(0x8000_0000_0000_0000, 0x4000),
        ),
        (
            "quarter",
            raw(0x8000_0000_0000_0000, 0x3FFD),
            raw(0x8000_0000_0000_0000, 0x3FFE),
        ),
        (
            "maximum exact power",
            raw(0x8000_0000_0000_0000, 0x7FFD),
            raw(0x8000_0000_0000_0000, 0x5FFE),
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !0x0300; // PC24 must still be exact
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x023F, 0, "{name}: exact");
        }
    }

    // Denormals normalize before the root. The minimum denormal has an odd
    // true exponent; a pseudo-denormal just above minimum normal rounds to
    // exactly 2^-8191 while retaining DE and PE.
    for (name, source, expected, expected_flags) in [
        (
            "minimum denormal",
            raw(1, 0),
            raw(0xB504_F333_F9DE_6484, 0x1FE0),
            0x0022u16,
        ),
        (
            "pseudo-denormal",
            raw(0x8000_0000_0000_0001, 0),
            raw(0x8000_0000_0000_0000, 0x2000),
            0x0022,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x023F, expected_flags, "{name}");
        }
    }

    let nzero = raw(0, 0x8000);
    let pinf = raw(0x8000_0000_0000_0000, 0x7FFF);
    let ninf = raw(0x8000_0000_0000_0000, 0xFFFF);
    let negative = raw(0x8000_0000_0000_0000, 0xBFFF);
    let qnan = raw(0xC123_4567_89AB_CDEF, 0xFFFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, source, expected, expected_ie) in [
        ("negative zero", nzero, nzero, false),
        ("positive infinity", pinf, pinf, false),
        (
            "negative infinity",
            ninf,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
        (
            "negative finite",
            negative,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
        ("quiet NaN", qnan, qnan, false),
        ("signaling NaN", snan, quiet_snan, true),
        (
            "unsupported",
            unsupported,
            crate::smir::X86X87State::INDEFINITE,
            true,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 1 != 0, expected_ie, "{name}: IE");
            assert_eq!(
                x86.x87.status_word & 0x023E,
                0,
                "{name}: no other exception/C1"
            );
        }
    }

    // Invalid and denormal are pre-computation exceptions and suppress the
    // destination when unmasked. Precision is post-computation and commits.
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    for (name, source, mask, exception) in [
        ("invalid", negative, 0x0001u16, 0x0001u16),
        ("denormal", raw(1, 0), 0x0002, 0x0002),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word &= !mask;
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
        assert_eq!(st0(&ctx), source, "{name}: suppressed");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(
                x86.x87.status_word & (0x8080 | exception),
                0x8080 | exception
            );
            assert_eq!(x86.x87.status_word & 0x0020, 0, "{name}: no PE");
        }
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
        x86.x87.set_logical_raw(0, two);
    }
    execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), raw(0xB504_F333_F9DE_6484, 0x3FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }

    // Empty-stack masked response installs indefinite; IM clear suppresses
    // the write while retaining the original empty tag and payload.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
    assert_eq!(st0(&ctx), crate::smir::X86X87State::INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
        assert_eq!(x86.x87.physical_tag(0), 2);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
        x86.x87.regs[0] = two;
    }
    execute_lifted_x86(&[0xD9, 0xFA], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[0], two);
        assert_eq!(x86.x87.physical_tag(0), 3);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }
}
#[test]
fn lifted_x87_fmul_fmulp_fimul_exact_rounding_range_fault_and_pop_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn seed(ctx: &mut SmirContext, st0: [u8; 10], st1: [u8; 10]) {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, st0);
            x86.x87.set_logical_raw(1, st1);
        }
    }
    fn logical(ctx: &SmirContext, st: u8) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(st)],
            _ => unreachable!(),
        }
    }

    let one = SmirInterpreter::x86_x87_from_i64(1);
    let two = SmirInterpreter::x86_x87_from_i64(2);
    let four = SmirInterpreter::x86_x87_from_i64(4);
    let six = SmirInterpreter::x86_x87_from_i64(6);
    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let a = raw(0x8000_0000_0000_0001, 0x3FFF);

    // Exact-product rounding is verified at every PC and RC setting against
    // the native binary80 patterns. Reserved PC=01 follows 64-bit precision.
    for (name, pc, rc, expected, expected_c1) in [
        (
            "PC24 nearest",
            0u16,
            0u16,
            raw(0x8000_0000_0000_0000, 0x3FFF),
            false,
        ),
        ("PC24 down", 0, 1, raw(0x8000_0000_0000_0000, 0x3FFF), false),
        ("PC24 up", 0, 2, raw(0x8000_0100_0000_0000, 0x3FFF), true),
        ("PC24 zero", 0, 3, raw(0x8000_0000_0000_0000, 0x3FFF), false),
        (
            "reserved PC nearest",
            1,
            0,
            raw(0x8000_0000_0000_0002, 0x3FFF),
            false,
        ),
        (
            "reserved PC up",
            1,
            2,
            raw(0x8000_0000_0000_0003, 0x3FFF),
            true,
        ),
        (
            "PC53 nearest",
            2,
            0,
            raw(0x8000_0000_0000_0000, 0x3FFF),
            false,
        ),
        ("PC53 down", 2, 1, raw(0x8000_0000_0000_0000, 0x3FFF), false),
        ("PC53 up", 2, 2, raw(0x8000_0000_0000_0800, 0x3FFF), true),
        ("PC53 zero", 2, 3, raw(0x8000_0000_0000_0000, 0x3FFF), false),
        (
            "PC64 nearest",
            3,
            0,
            raw(0x8000_0000_0000_0002, 0x3FFF),
            false,
        ),
        ("PC64 down", 3, 1, raw(0x8000_0000_0000_0002, 0x3FFF), false),
        ("PC64 up", 3, 2, raw(0x8000_0000_0000_0003, 0x3FFF), true),
        ("PC64 zero", 3, 3, raw(0x8000_0000_0000_0002, 0x3FFF), false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            x86.x87.data_ptr = 0xCAFE;
        }
        seed(&mut ctx, a, a);
        execute_lifted_x86(&[0xD8, 0xC9], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        assert_eq!(logical(&ctx, 1), a, "{name}: source unchanged");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0020, 0x0020, "{name}: PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
            assert_eq!(x86.x87.top(), 0, "{name}: no pop");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x00C9, "{name}: FOP");
            assert_eq!(x86.x87.data_ptr, 0xCAFE, "{name}: FDP unchanged");
        }
        ctx.flags.materialize_all();
        assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7, "{name}: RFLAGS");
    }

    // Register direction and FMULP write-before-pop behavior are distinct.
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.set_logical_raw(0, p15);
        x86.x87.set_logical_raw(3, four);
    }
    execute_lifted_x86(&[0xD8, 0xCB], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), six);
    assert_eq!(logical(&ctx, 3), four);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_logical_raw(0, p15);
        x86.x87.set_logical_raw(3, four);
    }
    execute_lifted_x86(&[0xDC, 0xCB], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), p15);
    assert_eq!(logical(&ctx, 3), six);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_logical_raw(0, two);
        x86.x87.set_logical_raw(1, two);
    }
    execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(logical(&ctx, 0), four);
        assert_eq!(x86.x87.last_opcode, 0x06C9);
    }

    // Every memory format is read completely before state changes. Integer
    // sources are converted exactly, including negative signed values.
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    for (name, bytes, source, expected, fop) in [
        (
            "FMUL m32fp",
            &[0xD8, 0x08][..],
            4.0f32.to_bits().to_le_bytes().to_vec(),
            six,
            0x0008u16,
        ),
        (
            "FMUL m64fp",
            &[0xDC, 0x08][..],
            4.0f64.to_bits().to_le_bytes().to_vec(),
            six,
            0x0408,
        ),
        (
            "FIMUL m16int",
            &[0xDE, 0x08][..],
            (-4i16).to_le_bytes().to_vec(),
            raw(0xC000_0000_0000_0000, 0xC001),
            0x0608,
        ),
        (
            "FIMUL m32int",
            &[0xDA, 0x08][..],
            (-4i32).to_le_bytes().to_vec(),
            raw(0xC000_0000_0000_0000, 0xC001),
            0x0208,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        memory.write(0x100, &source).unwrap();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, p15);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x023F, 0, "{name}: exact");
            assert_eq!(x86.x87.data_ptr, 0x100, "{name}: FDP");
            assert_eq!(x86.x87.last_opcode, fop, "{name}: FOP");
        }
    }

    // Overflow and half-minimum-subnormal underflow use RC-dependent
    // infinity/max-finite and signed-zero/min-subnormal responses.
    let max = raw(u64::MAX, 0x7FFE);
    let nmax = raw(u64::MAX, 0xFFFE);
    let pinf = raw(0x8000_0000_0000_0000, 0x7FFF);
    let ninf = raw(0x8000_0000_0000_0000, 0xFFFF);
    for (name, rc, value, expected, expected_c1) in [
        ("nearest +overflow", 0u16, max, pinf, true),
        ("nearest -overflow", 0, nmax, ninf, true),
        ("down +overflow", 1, max, max, false),
        ("down -overflow", 1, nmax, ninf, true),
        ("up +overflow", 2, max, pinf, true),
        ("up -overflow", 2, nmax, nmax, false),
        ("zero +overflow", 3, max, max, false),
        ("zero -overflow", 3, nmax, nmax, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, value, two);
        execute_lifted_x86(&[0xD8, 0xC9], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0028, 0x0028, "{name}: OE/PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }
    }
    let min_normal = raw(0x8000_0000_0000_0000, 1);
    let nmin_normal = raw(0x8000_0000_0000_0000, 0x8001);
    let two_neg64 = raw(0x8000_0000_0000_0000, 0x3FBF);
    let pzero = raw(0, 0);
    let nzero = raw(0, 0x8000);
    let pmin_subnormal = raw(1, 0);
    let nmin_subnormal = raw(1, 0x8000);
    for (name, rc, value, expected, expected_c1) in [
        ("nearest +half-min", 0u16, min_normal, pzero, false),
        ("nearest -half-min", 0, nmin_normal, nzero, false),
        ("down +half-min", 1, min_normal, pzero, false),
        ("down -half-min", 1, nmin_normal, nmin_subnormal, true),
        ("up +half-min", 2, min_normal, pmin_subnormal, true),
        ("up -half-min", 2, nmin_normal, nzero, false),
        ("zero +half-min", 3, min_normal, pzero, false),
        ("zero -half-min", 3, nmin_normal, nzero, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, value, two_neg64);
        execute_lifted_x86(&[0xD8, 0xC9], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0030, 0x0030, "{name}: UE/PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    seed(&mut ctx, min_normal, raw(0x8000_0000_0000_0000, 0x3FFE));
    execute_lifted_x86(&[0xD8, 0xC9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x4000_0000_0000_0000, 0));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0030, 0, "exact denormal");
    }

    // Unmasked register range responses retain Intel's exponent bias and
    // still commit FMULP's pop; unmasked precision also commits the pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0008;
    }
    seed(&mut ctx, two, max);
    execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(u64::MAX, 0x1FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x82A8, 0x80A8);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0010;
    }
    seed(&mut ctx, two_neg64, min_normal);
    execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x8000_0000_0000_0000, 0x5FC1));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x82B0, 0x80B0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
    }
    seed(&mut ctx, a, a);
    execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x8000_0000_0000_0002, 0x3FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }

    // Special classes, sign XOR, masked invalid, and denormal operands.
    let qnan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, lhs, rhs, expected, flags) in [
        ("negative zero", nzero, two, nzero, 0u16),
        ("negative infinity", ninf, two, ninf, 0),
        (
            "zero times infinity",
            pzero,
            pinf,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        ("quiet NaN", one, qnan, qnan, 0),
        (
            "quiet NaN suppresses denormal exception",
            qnan,
            raw(1, 0),
            qnan,
            0,
        ),
        ("signaling NaN", one, snan, quiet_snan, 0x0001),
        (
            "unsupported",
            one,
            unsupported,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "denormal normalizes",
            raw(0x4000_0000_0000_0000, 0),
            two,
            min_normal,
            0x0002,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        seed(&mut ctx, lhs, rhs);
        execute_lifted_x86(&[0xD8, 0xC9], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // Memory denormal and SNaN classification survives exact widening.
    for (name, bits, expected, flags) in [
        (
            "m32 denormal",
            1u32,
            raw(0x8000_0000_0000_0000, 0x3F6B),
            0x0002u16,
        ),
        (
            "m32 SNaN",
            0x7F80_0001,
            raw(0xC000_0100_0000_0000, 0x7FFF),
            0x0001,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        memory.write(0x100, &bits.to_le_bytes()).unwrap();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, two);
        }
        execute_lifted_x86(&[0xD8, 0x08], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // Pre-computation exceptions suppress result/pop when unmasked. Masked
    // FMULP stack faults install indefinite in ST(1), then pop it into ST(0).
    for (name, lhs, rhs, mask, exception) in [
        ("invalid", pzero, pinf, 0x0001u16, 0x0001u16),
        (
            "denormal",
            raw(0x4000_0000_0000_0000, 0),
            two,
            0x0002,
            0x0002,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !mask;
        }
        seed(&mut ctx, lhs, rhs);
        execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}: pop suppressed");
            assert_eq!(logical(&ctx, 0), lhs, "{name}: destination unchanged");
            assert_eq!(
                x86.x87.status_word & (0x8080 | exception),
                0x8080 | exception
            );
        }
    }
    for missing_st0 in [true, false] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            if missing_st0 {
                x86.x87.set_logical_raw(1, two);
            } else {
                x86.x87.set_logical_raw(0, two);
            }
        }
        execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1);
            assert_eq!(logical(&ctx, 0), crate::smir::X86X87State::INDEFINITE);
            assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.control_word &= !1;
        x86.x87.set_logical_raw(0, two);
    }
    execute_lifted_x86(&[0xDE, 0xC9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(logical(&ctx, 0), two);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }

    // A short memory read faults before FIP/FOP/FDP, flags, operands, or
    // tags change.
    let mut ctx = SmirContext::new_x86_64();
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.set_logical_raw(0, p15);
        x86.x87.data_ptr = 0xCAFE;
    }
    let before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x104);
    let exit = execute_lifted_x86(&[0xDC, 0x08], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_fadd_fsub_exact_rounding_special_fault_and_pop_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn value(value: i64) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_i64(value)
    }
    fn seed(ctx: &mut SmirContext, st0: [u8; 10], st1: [u8; 10]) {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, st0);
            x86.x87.set_logical_raw(1, st1);
        }
    }
    fn logical(ctx: &SmirContext, st: u8) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(st)],
            _ => unreachable!(),
        }
    }

    let ten = value(10);
    let four = value(4);
    let fourteen = value(14);
    let six = value(6);
    let negative_six = value(-6);

    // All nine register direction/pop forms write the documented
    // destination before an optional stack pop.
    for (name, bytes, expected_st0, expected_st1) in [
        ("FADD ST0,ST1", &[0xD8, 0xC1][..], fourteen, four),
        ("FADD ST1,ST0", &[0xDC, 0xC1][..], ten, fourteen),
        ("FSUB ST0,ST1", &[0xD8, 0xE1][..], six, four),
        ("FSUB ST1,ST0", &[0xDC, 0xE9][..], ten, negative_six),
        ("FSUBR ST0,ST1", &[0xD8, 0xE9][..], negative_six, four),
        ("FSUBR ST1,ST0", &[0xDC, 0xE1][..], ten, six),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        seed(&mut ctx, ten, four);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected_st0, "{name}: ST0");
        assert_eq!(logical(&ctx, 1), expected_st1, "{name}: ST1");
    }
    for (name, bytes, expected) in [
        ("FADDP", &[0xDE, 0xC1][..], fourteen),
        ("FSUBP", &[0xDE, 0xE9][..], negative_six),
        ("FSUBRP", &[0xDE, 0xE1][..], six),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        seed(&mut ctx, ten, four);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1, "{name}: pop");
        }
    }

    // Every floating and integer memory form is acquired before state
    // changes and observes ordinary versus reverse subtraction direction.
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    for (name, bytes, source, expected, fop) in [
        (
            "FADD m32",
            &[0xD8, 0x00][..],
            4.0f32.to_bits().to_le_bytes().to_vec(),
            fourteen,
            0x0000,
        ),
        (
            "FSUB m32",
            &[0xD8, 0x20][..],
            4.0f32.to_bits().to_le_bytes().to_vec(),
            six,
            0x0020,
        ),
        (
            "FSUBR m32",
            &[0xD8, 0x28][..],
            4.0f32.to_bits().to_le_bytes().to_vec(),
            negative_six,
            0x0028,
        ),
        (
            "FADD m64",
            &[0xDC, 0x00][..],
            4.0f64.to_bits().to_le_bytes().to_vec(),
            fourteen,
            0x0400,
        ),
        (
            "FSUB m64",
            &[0xDC, 0x20][..],
            4.0f64.to_bits().to_le_bytes().to_vec(),
            six,
            0x0420,
        ),
        (
            "FSUBR m64",
            &[0xDC, 0x28][..],
            4.0f64.to_bits().to_le_bytes().to_vec(),
            negative_six,
            0x0428,
        ),
        (
            "FIADD m16",
            &[0xDE, 0x00][..],
            (-4i16).to_le_bytes().to_vec(),
            six,
            0x0600,
        ),
        (
            "FISUB m16",
            &[0xDE, 0x20][..],
            (-4i16).to_le_bytes().to_vec(),
            fourteen,
            0x0620,
        ),
        (
            "FISUBR m16",
            &[0xDE, 0x28][..],
            (-4i16).to_le_bytes().to_vec(),
            value(-14),
            0x0628,
        ),
        (
            "FIADD m32",
            &[0xDA, 0x00][..],
            (-4i32).to_le_bytes().to_vec(),
            six,
            0x0200,
        ),
        (
            "FISUB m32",
            &[0xDA, 0x20][..],
            (-4i32).to_le_bytes().to_vec(),
            fourteen,
            0x0220,
        ),
        (
            "FISUBR m32",
            &[0xDA, 0x28][..],
            (-4i32).to_le_bytes().to_vec(),
            value(-14),
            0x0228,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        memory.write(0x100, &source).unwrap();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, ten);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x023F, 0, "{name}: exact");
            assert_eq!(x86.x87.data_ptr, 0x100, "{name}: FDP");
            assert_eq!(x86.x87.last_opcode, fop, "{name}: FOP");
        }
    }

    // Half-ULP addition exercises all FCW.PC encodings and every RC mode.
    // Reserved PC=01 has the observed architectural 64-bit behavior.
    let one = value(1);
    for (pc, half_ulp, next) in [
        (
            0u16,
            raw(0x8000_0000_0000_0000, 0x3FE7),
            raw(0x8000_0100_0000_0000, 0x3FFF),
        ),
        (
            1,
            raw(0x8000_0000_0000_0000, 0x3FBF),
            raw(0x8000_0000_0000_0001, 0x3FFF),
        ),
        (
            2,
            raw(0x8000_0000_0000_0000, 0x3FCA),
            raw(0x8000_0000_0000_0800, 0x3FFF),
        ),
        (
            3,
            raw(0x8000_0000_0000_0000, 0x3FBF),
            raw(0x8000_0000_0000_0001, 0x3FFF),
        ),
    ] {
        for rc in 0u16..4 {
            let mut ctx = SmirContext::new_x86_64();
            let mut memory = FlatMemory::new(1);
            if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                x86.x87.control_word = (x86.x87.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            }
            seed(&mut ctx, one, half_ulp);
            execute_lifted_x86(&[0xD8, 0xC1], &mut ctx, &mut memory);
            assert_eq!(
                logical(&ctx, 0),
                if rc == 2 { next } else { one },
                "PC={pc} RC={rc}"
            );
            if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
                assert_eq!(x86.x87.status_word & 0x0020, 0x0020);
                assert_eq!(x86.x87.status_word & 0x0200 != 0, rc == 2);
            }
        }
    }

    // Exact cancellation follows RC, while the two unlike-signed-zero
    // subtraction identities preserve the minuend sign for every RC.
    let negative_one = value(-1);
    let positive_zero = raw(0, 0);
    let negative_zero = raw(0, 0x8000);
    for rc in 0u16..4 {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, one, negative_one);
        execute_lifted_x86(&[0xD8, 0xC1], &mut ctx, &mut memory);
        assert_eq!(
            logical(&ctx, 0),
            if rc == 1 {
                negative_zero
            } else {
                positive_zero
            }
        );

        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, positive_zero, negative_zero);
        execute_lifted_x86(&[0xD8, 0xE1], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), positive_zero);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, negative_zero, positive_zero);
        execute_lifted_x86(&[0xD8, 0xE1], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), negative_zero);
    }

    // Full-span carry, cancellation into the subnormal range, and reduced
    // precision underflow are rounded once from the exact limb magnitude.
    let maximum = raw(u64::MAX, 0x7FFE);
    let positive_infinity = raw(0x8000_0000_0000_0000, 0x7FFF);
    let negative_infinity = raw(0x8000_0000_0000_0000, 0xFFFF);
    let minimum_normal = raw(0x8000_0000_0000_0000, 1);
    let minimum_normal_plus_one = raw(0x8000_0000_0000_0001, 1);
    let minimum_subnormal = raw(1, 0);
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    seed(&mut ctx, maximum, maximum);
    execute_lifted_x86(&[0xD8, 0xC1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), positive_infinity);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0028, 0x0028);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0300; // PC=24
    }
    seed(&mut ctx, minimum_normal_plus_one, minimum_normal);
    execute_lifted_x86(&[0xD8, 0xE1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), positive_zero);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0030, 0x0030);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word = (x86.x87.control_word & !0x0300) | 0x0300;
    }
    seed(&mut ctx, minimum_normal_plus_one, minimum_normal);
    execute_lifted_x86(&[0xD8, 0xE1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), minimum_subnormal);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0030, 0);
    }

    // NaN/unsupported/infinity precedence, denormal reporting, and masked
    // versus unmasked pre-computation exceptions match the x87 pipeline.
    let qnan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, lhs, rhs, bytes, expected, flags) in [
        (
            "opposite infinities",
            positive_infinity,
            negative_infinity,
            &[0xD8, 0xC1][..],
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "like infinity subtract",
            positive_infinity,
            positive_infinity,
            &[0xD8, 0xE1][..],
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "QNaN suppresses DE",
            qnan,
            minimum_subnormal,
            &[0xD8, 0xC1][..],
            qnan,
            0,
        ),
        ("SNaN", one, snan, &[0xD8, 0xC1][..], quiet_snan, 0x0001),
        (
            "unsupported",
            one,
            unsupported,
            &[0xD8, 0xC1][..],
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "denormal",
            one,
            minimum_subnormal,
            &[0xD8, 0xC1][..],
            one,
            0x0022,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
        }
        seed(&mut ctx, lhs, rhs);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
    }
    seed(&mut ctx, snan, one);
    execute_lifted_x86(&[0xDE, 0xC1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), snan);
    assert_eq!(logical(&ctx, 1), one);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x8081, 0x8081);
    }

    // Post-computation overflow, underflow, and precision exceptions still
    // commit their defined result and the pop when their masks are clear.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0008;
    }
    seed(&mut ctx, maximum, maximum);
    execute_lifted_x86(&[0xDE, 0xC1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(u64::MAX, 0x1FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A8, 0x80A8);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
    }
    seed(&mut ctx, raw(0x8000_0000_0000_0000, 0x3FBF), one);
    execute_lifted_x86(&[0xDE, 0xC1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), one);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !(0x0010 | 0x0300); // UM clear, PC=24
    }
    seed(&mut ctx, minimum_normal, minimum_normal_plus_one);
    execute_lifted_x86(&[0xDE, 0xE9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x8000_0000_0000_0000, 0x5FC2));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80B0, 0x80B0);
    }

    // Masked stack underflow installs indefinite and completes FADDP;
    // unmasked #IS preserves both TOP and the empty destination.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xDE, 0xC1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), crate::smir::X86X87State::INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
    }
    execute_lifted_x86(&[0xDE, 0xC1], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.physical_tag(1), 3);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }

    // Widening must retain memory-only SNaN and denormal classifications.
    for (name, bits, destination, expected, flags) in [
        (
            "m32 SNaN",
            0x7F80_0001u32,
            one,
            SmirInterpreter::x86_x87_widen_ieee(0x7FC0_0001, 8, 23).0,
            0x0001u16,
        ),
        ("m32 denormal", 1, one, one, 0x0022),
        ("QNaN suppresses memory DE", 1, qnan, qnan, 0),
    ] {
        let mut memory_source = FlatMemory::new(0x200);
        memory_source.write(0x100, &bits.to_le_bytes()).unwrap();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw(0, destination);
        }
        ctx.write_vreg(rax, 0x100);
        execute_lifted_x86(&[0xD8, 0x00], &mut ctx, &mut memory_source);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // A memory fault precedes FIP/FDP/FOP, result, flag, and stack updates.
    let mut fault_ctx = SmirContext::new_x86_64();
    fault_ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut fault_ctx.arch_regs {
        x86.x87.instr_ptr = 0xAAAA;
        x86.x87.data_ptr = 0xBBBB;
        x86.x87.last_opcode = 0xCCCC;
        x86.x87.set_logical_raw(0, ten);
    }
    let before = match &fault_ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x102);
    let exit = execute_lifted_x86(&[0xDC, 0x00], &mut fault_ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &fault_ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_fdiv_fdivr_exact_rounding_special_fault_and_pop_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn value(value: i64) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_i64(value)
    }
    fn seed(ctx: &mut SmirContext, st0: [u8; 10], st1: [u8; 10]) {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, st0);
            x86.x87.set_logical_raw(1, st1);
        }
    }
    fn logical(ctx: &SmirContext, st: u8) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(st)],
            _ => unreachable!(),
        }
    }

    let one = value(1);
    let three = value(3);
    let four = value(4);
    let twelve = value(12);
    let quarter = raw(0x8000_0000_0000_0000, 0x3FFD);
    let negative_quarter = raw(0x8000_0000_0000_0000, 0xBFFD);

    // All six register direction/pop forms use the documented dividend
    // and divisor, including the no-operand pop aliases.
    for (name, bytes, st0, st1, expected_st0, expected_st1) in [
        (
            "FDIV ST0,ST1",
            &[0xD8, 0xF1][..],
            twelve,
            three,
            four,
            three,
        ),
        (
            "FDIV ST1,ST0",
            &[0xDC, 0xF9][..],
            three,
            twelve,
            three,
            four,
        ),
        (
            "FDIVR ST0,ST1",
            &[0xD8, 0xF9][..],
            three,
            twelve,
            four,
            twelve,
        ),
        (
            "FDIVR ST1,ST0",
            &[0xDC, 0xF1][..],
            three,
            twelve,
            three,
            quarter,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        seed(&mut ctx, st0, st1);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected_st0, "{name}: ST0");
        assert_eq!(logical(&ctx, 1), expected_st1, "{name}: ST1");
    }
    for (name, bytes, expected) in [
        ("FDIVP", &[0xDE, 0xF9][..], four),
        ("FDIVRP", &[0xDE, 0xF1][..], quarter),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        seed(&mut ctx, three, twelve);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1, "{name}: pop");
        }
    }

    // All eight memory forms retain floating class metadata and exact
    // signed-integer conversion before ordinary or reverse division.
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    for (name, bytes, source, expected, fop) in [
        (
            "FDIV m32",
            &[0xD8, 0x30][..],
            3.0f32.to_bits().to_le_bytes().to_vec(),
            four,
            0x0030,
        ),
        (
            "FDIVR m32",
            &[0xD8, 0x38][..],
            3.0f32.to_bits().to_le_bytes().to_vec(),
            quarter,
            0x0038,
        ),
        (
            "FDIV m64",
            &[0xDC, 0x30][..],
            3.0f64.to_bits().to_le_bytes().to_vec(),
            four,
            0x0430,
        ),
        (
            "FDIVR m64",
            &[0xDC, 0x38][..],
            3.0f64.to_bits().to_le_bytes().to_vec(),
            quarter,
            0x0438,
        ),
        (
            "FIDIV m16",
            &[0xDE, 0x30][..],
            (-3i16).to_le_bytes().to_vec(),
            value(-4),
            0x0630,
        ),
        (
            "FIDIVR m16",
            &[0xDE, 0x38][..],
            (-3i16).to_le_bytes().to_vec(),
            negative_quarter,
            0x0638,
        ),
        (
            "FIDIV m32",
            &[0xDA, 0x30][..],
            (-3i32).to_le_bytes().to_vec(),
            value(-4),
            0x0230,
        ),
        (
            "FIDIVR m32",
            &[0xDA, 0x38][..],
            (-3i32).to_le_bytes().to_vec(),
            negative_quarter,
            0x0238,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        memory.write(0x100, &source).unwrap();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, twelve);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x023F, 0, "{name}: exact");
            assert_eq!(x86.x87.data_ptr, 0x100, "{name}: FDP");
            assert_eq!(x86.x87.last_opcode, fop, "{name}: FOP");
        }
    }

    // 1/3 produces a nonzero exact remainder. Expected payloads cover all
    // PC encodings and all RC modes without a host-FP oracle.
    for (pc, nearest, down, up) in [
        (
            0u16,
            raw(0xAAAA_AB00_0000_0000, 0x3FFD),
            raw(0xAAAA_AA00_0000_0000, 0x3FFD),
            raw(0xAAAA_AB00_0000_0000, 0x3FFD),
        ),
        (
            1,
            raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_AAAA, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD),
        ),
        (
            2,
            raw(0xAAAA_AAAA_AAAA_A800, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_A800, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_B000, 0x3FFD),
        ),
        (
            3,
            raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_AAAA, 0x3FFD),
            raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD),
        ),
    ] {
        for rc in 0u16..4 {
            let mut ctx = SmirContext::new_x86_64();
            let mut memory = FlatMemory::new(1);
            ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
            ctx.flags.lazy = None;
            if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                x86.x87.control_word = (x86.x87.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            }
            seed(&mut ctx, one, three);
            execute_lifted_x86(&[0xD8, 0xF1], &mut ctx, &mut memory);
            let expected = match rc {
                0 => nearest,
                1 | 3 => down,
                2 => up,
                _ => unreachable!(),
            };
            assert_eq!(logical(&ctx, 0), expected, "PC={pc} RC={rc}");
            if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
                assert_eq!(x86.x87.status_word & 0x0020, 0x0020);
                assert_eq!(
                    x86.x87.status_word & 0x0200 != 0,
                    expected == up && up != down
                );
            }
            ctx.flags.materialize_all();
            assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7);
        }
    }

    // Masked overflow and half-minimum-subnormal underflow are RC- and
    // sign-dependent. Exact minimum subnormal division raises no #U/#P.
    let maximum = raw(u64::MAX, 0x7FFE);
    let negative_maximum = raw(u64::MAX, 0xFFFE);
    let positive_infinity = raw(0x8000_0000_0000_0000, 0x7FFF);
    let negative_infinity = raw(0x8000_0000_0000_0000, 0xFFFF);
    let half = raw(0x8000_0000_0000_0000, 0x3FFE);
    for (name, rc, numerator, expected, expected_c1) in [
        ("nearest +overflow", 0u16, maximum, positive_infinity, true),
        (
            "nearest -overflow",
            0,
            negative_maximum,
            negative_infinity,
            true,
        ),
        ("down +overflow", 1, maximum, maximum, false),
        (
            "down -overflow",
            1,
            negative_maximum,
            negative_infinity,
            true,
        ),
        ("up +overflow", 2, maximum, positive_infinity, true),
        ("up -overflow", 2, negative_maximum, negative_maximum, false),
        ("zero +overflow", 3, maximum, maximum, false),
        (
            "zero -overflow",
            3,
            negative_maximum,
            negative_maximum,
            false,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, numerator, half);
        execute_lifted_x86(&[0xD8, 0xF1], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0028, 0x0028, "{name}");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}");
        }
    }
    let minimum_normal = raw(0x8000_0000_0000_0000, 1);
    let two_pow_63 = raw(0x8000_0000_0000_0000, 0x403E);
    let two_pow_64 = raw(0x8000_0000_0000_0000, 0x403F);
    let positive_zero = raw(0, 0);
    let negative_zero = raw(0, 0x8000);
    let minimum_subnormal = raw(1, 0);
    let negative_minimum_subnormal = raw(1, 0x8000);
    for (name, rc, numerator, expected, expected_c1) in [
        (
            "nearest +half-min",
            0u16,
            minimum_normal,
            positive_zero,
            false,
        ),
        (
            "nearest -half-min",
            0,
            raw(0x8000_0000_0000_0000, 0x8001),
            negative_zero,
            false,
        ),
        ("down +half-min", 1, minimum_normal, positive_zero, false),
        (
            "down -half-min",
            1,
            raw(0x8000_0000_0000_0000, 0x8001),
            negative_minimum_subnormal,
            true,
        ),
        ("up +half-min", 2, minimum_normal, minimum_subnormal, true),
        (
            "up -half-min",
            2,
            raw(0x8000_0000_0000_0000, 0x8001),
            negative_zero,
            false,
        ),
        ("zero +half-min", 3, minimum_normal, positive_zero, false),
        (
            "zero -half-min",
            3,
            raw(0x8000_0000_0000_0000, 0x8001),
            negative_zero,
            false,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(1);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
        }
        seed(&mut ctx, numerator, two_pow_64);
        execute_lifted_x86(&[0xD8, 0xF1], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0030, 0x0030, "{name}");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}");
        }
    }
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    seed(&mut ctx, minimum_normal, two_pow_63);
    execute_lifted_x86(&[0xD8, 0xF1], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), minimum_subnormal);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0030, 0);
    }

    // Invalid, zero-divide, denormal, infinity, and NaN precedence follows
    // Intel's result table. Zero-divide bypasses denormal-numerator #D.
    let qnan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, lhs, rhs, expected, flags) in [
        (
            "positive zero divide",
            one,
            positive_zero,
            positive_infinity,
            0x0004u16,
        ),
        (
            "negative zero divide",
            one,
            negative_zero,
            negative_infinity,
            0x0004,
        ),
        ("zero numerator", negative_zero, one, negative_zero, 0),
        (
            "infinity over zero",
            positive_infinity,
            positive_zero,
            positive_infinity,
            0,
        ),
        (
            "zero over zero",
            positive_zero,
            positive_zero,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "infinity over infinity",
            positive_infinity,
            positive_infinity,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        ("QNaN suppresses zero divide", qnan, positive_zero, qnan, 0),
        ("SNaN", one, snan, quiet_snan, 0x0001),
        (
            "unsupported",
            one,
            unsupported,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "denormal over zero",
            minimum_subnormal,
            positive_zero,
            positive_infinity,
            0x0004,
        ),
        (
            "denormal exact",
            minimum_subnormal,
            one,
            minimum_subnormal,
            0x0002,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
        }
        seed(&mut ctx, lhs, rhs);
        execute_lifted_x86(&[0xD8, 0xF1], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // Memory widening preserves source-only SNaN/denormal classification,
    // and signed integer zero is converted to architectural +0.
    for (name, bytes, source, destination, expected, flags) in [
        (
            "m32 SNaN",
            &[0xD8, 0x30][..],
            0x7F80_0001u32.to_le_bytes().to_vec(),
            one,
            SmirInterpreter::x86_x87_widen_ieee(0x7FC0_0001, 8, 23).0,
            0x0001u16,
        ),
        (
            "m32 denormal divisor",
            &[0xD8, 0x30][..],
            1u32.to_le_bytes().to_vec(),
            one,
            raw(0x8000_0000_0000_0000, 0x4094),
            0x0002,
        ),
        (
            "QNaN suppresses memory DE",
            &[0xD8, 0x30][..],
            1u32.to_le_bytes().to_vec(),
            qnan,
            qnan,
            0,
        ),
        (
            "FIDIV integer +0",
            &[0xDA, 0x30][..],
            0i32.to_le_bytes().to_vec(),
            value(-1),
            negative_infinity,
            0x0004,
        ),
        (
            "FIDIVR integer +0",
            &[0xDA, 0x38][..],
            0i32.to_le_bytes().to_vec(),
            value(-1),
            negative_zero,
            0,
        ),
    ] {
        let mut source_memory = FlatMemory::new(0x200);
        source_memory.write(0x100, &source).unwrap();
        ctx.write_vreg(rax, 0x100);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw(0, destination);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut source_memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // Unmasked #Z and #D are pre-computation exceptions; post-computation
    // #O/#U/#P commit the biased/rounded result and FDIVP pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0004;
    }
    seed(&mut ctx, positive_zero, one);
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 1), one);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x8084, 0x8084);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0002;
    }
    seed(&mut ctx, minimum_subnormal, one);
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 1), one);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x8086, 0x8082);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0008;
    }
    seed(&mut ctx, half, maximum);
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(u64::MAX, 0x1FFF));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A8, 0x80A8);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0010;
    }
    seed(&mut ctx, two_pow_64, minimum_normal);
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x8000_0000_0000_0000, 0x5FC1));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80B0, 0x80B0);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
    }
    seed(&mut ctx, three, one);
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }

    // Masked stack underflow installs indefinite and pops; unmasked #IS
    // preserves TOP and the empty destination. Memory faults are atomic.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), crate::smir::X86X87State::INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
    }
    execute_lifted_x86(&[0xDE, 0xF9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.physical_tag(1), 3);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }

    let mut fault_ctx = SmirContext::new_x86_64();
    fault_ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut fault_ctx.arch_regs {
        x86.x87.instr_ptr = 0xAAAA;
        x86.x87.data_ptr = 0xBBBB;
        x86.x87.last_opcode = 0xCCCC;
        x86.x87.set_logical_raw(0, twelve);
    }
    let before = match &fault_ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x102);
    let exit = execute_lifted_x86(&[0xDC, 0x30], &mut fault_ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &fault_ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_fprem_fprem1_exact_partial_flags_and_exception_semantics() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_raw_parts(significand, exponent_sign)
    }
    fn value(value: i64) -> [u8; 10] {
        SmirInterpreter::x86_x87_from_i64(value)
    }
    fn seed(ctx: &mut SmirContext, st0: [u8; 10], st1: [u8; 10]) {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, st0);
            x86.x87.set_logical_raw(1, st1);
        }
    }
    fn logical(ctx: &SmirContext, st: u8) -> [u8; 10] {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.regs[x86.x87.physical_index(st)],
            _ => unreachable!(),
        }
    }
    fn condition_codes(ctx: &SmirContext) -> u16 {
        match &ctx.arch_regs {
            ArchRegState::X86_64(x86) => x86.x87.status_word & 0x4700,
            _ => unreachable!(),
        }
    }

    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(1);
    for (name, bytes, dividend, modulus, expected, codes) in [
        (
            "FPREM 7/3",
            &[0xD9, 0xF8][..],
            value(7),
            value(3),
            value(1),
            0x4000u16,
        ),
        (
            "FPREM -7/3",
            &[0xD9, 0xF8][..],
            value(-7),
            value(3),
            value(-1),
            0x4000,
        ),
        (
            "FPREM 7/-3",
            &[0xD9, 0xF8][..],
            value(7),
            value(-3),
            value(1),
            0x4000,
        ),
        (
            "FPREM1 7/2 tie-even",
            &[0xD9, 0xF5][..],
            value(7),
            value(2),
            value(-1),
            0x0100,
        ),
        (
            "FPREM1 5/2 tie-even",
            &[0xD9, 0xF5][..],
            value(5),
            value(2),
            value(1),
            0x4000,
        ),
        (
            "FPREM1 -7/2",
            &[0xD9, 0xF5][..],
            value(-7),
            value(2),
            value(1),
            0x0100,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
        }
        seed(&mut ctx, dividend, modulus);
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        assert_eq!(logical(&ctx, 1), modulus, "{name}: modulus unchanged");
        assert_eq!(condition_codes(&ctx), codes, "{name}: quotient bits");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, 0, "{name}: exact");
            assert_eq!(
                x86.x87.last_opcode,
                if bytes[1] == 0xF5 { 0x01F5 } else { 0x01F8 }
            );
        }
    }

    // PC and RC are both ignored; 7/2 remains the same exact IEEE
    // remainder and never raises #P under all 16 control combinations.
    for pc in 0u16..4 {
        for rc in 0u16..4 {
            if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                x86.x87 = Default::default();
                x86.x87.control_word = (x86.x87.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            }
            ctx.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
            ctx.flags.lazy = None;
            seed(&mut ctx, value(7), value(2));
            execute_lifted_x86(&[0xD9, 0xF5], &mut ctx, &mut memory);
            assert_eq!(logical(&ctx, 0), value(-1), "PC={pc} RC={rc}");
            assert_eq!(condition_codes(&ctx), 0x0100, "PC={pc} RC={rc}");
            if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
                assert_eq!(x86.x87.status_word & 0x003F, 0);
            }
            ctx.flags.materialize_all();
            assert_eq!(ctx.flags.materialized.to_rflags(), 0xCD7);
        }
    }

    // N=63 is the maximum conforming partial-reduction width. Incomplete
    // reduction sets C2 while preserving undefined C0/C1/C3; re-execution
    // completes and publishes the low three quotient-magnitude bits.
    let two_pow_100 = raw(0x8000_0000_0000_0000, 0x4063);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.status_word |= 0x4300;
    }
    seed(&mut ctx, two_pow_100, value(3));
    execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), raw(0x8000_0000_0000_0000, 0x4023));
    assert_eq!(condition_codes(&ctx), 0x4700);
    execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), value(1));
    assert_eq!(condition_codes(&ctx), 0x0300); // |Q| mod 8 = 5

    // Exact cancellation into the minimum subnormal does not raise #U or
    // #P. Denormal operands raise only #D and remain exactly reducible.
    let minimum_normal = raw(0x8000_0000_0000_0000, 1);
    let minimum_normal_plus_one = raw(0x8000_0000_0000_0001, 1);
    let minimum_subnormal = raw(1, 0);
    for (name, dividend, modulus, expected, expected_codes, flags) in [
        (
            "exact minimum subnormal",
            minimum_normal_plus_one,
            minimum_normal,
            minimum_subnormal,
            0x0200u16,
            0u16,
        ),
        (
            "denormal dividend",
            minimum_subnormal,
            value(3),
            minimum_subnormal,
            0,
            0x0002,
        ),
        (
            "denormal modulus partial",
            value(3),
            minimum_subnormal,
            raw(0, 0),
            0x0400,
            0x0002,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
        }
        seed(&mut ctx, dividend, modulus);
        execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        assert_eq!(condition_codes(&ctx), expected_codes, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    let positive_zero = raw(0, 0);
    let negative_zero = raw(0, 0x8000);
    let positive_infinity = raw(0x8000_0000_0000_0000, 0x7FFF);
    let qnan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let snan = raw(0x8123_4567_89AB_CDEF, 0x7FFF);
    let quiet_snan = raw(0xC123_4567_89AB_CDEF, 0x7FFF);
    let unsupported = raw(0x4123_4567_89AB_CDEF, 0x4000);
    for (name, dividend, modulus, expected, flags) in [
        (
            "positive zero dividend",
            positive_zero,
            value(3),
            positive_zero,
            0u16,
        ),
        (
            "negative zero dividend",
            negative_zero,
            value(3),
            negative_zero,
            0,
        ),
        ("infinite modulus", value(3), positive_infinity, value(3), 0),
        (
            "infinite dividend",
            positive_infinity,
            value(3),
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        (
            "zero modulus",
            value(3),
            positive_zero,
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
        ("quiet NaN", qnan, positive_zero, qnan, 0),
        ("signaling NaN", snan, value(3), quiet_snan, 0x0001),
        (
            "unsupported",
            unsupported,
            value(3),
            crate::smir::X86X87State::INDEFINITE,
            0x0001,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.status_word |= 0x4700;
        }
        seed(&mut ctx, dividend, modulus);
        execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
        assert_eq!(logical(&ctx, 0), expected, "{name}");
        assert_eq!(condition_codes(&ctx), 0, "{name}: complete Q=0");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x003F, flags, "{name}");
        }
    }

    // Unmasked pre-computation exceptions suppress the result and all
    // condition-code updates. Masked and unmasked stack underflow use the
    // standard indefinite/suppression responses.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
        x86.x87.status_word |= 0x4700;
    }
    seed(&mut ctx, positive_infinity, value(3));
    execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), positive_infinity);
    assert_eq!(condition_codes(&ctx), 0x4700);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x8081, 0x8081);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0002;
        x86.x87.status_word |= 0x4300;
    }
    seed(&mut ctx, minimum_subnormal, value(3));
    execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), minimum_subnormal);
    assert_eq!(condition_codes(&ctx), 0x4300);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x8082, 0x8082);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xD9, 0xF8], &mut ctx, &mut memory);
    assert_eq!(logical(&ctx, 0), crate::smir::X86X87State::INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0001;
    }
    execute_lifted_x86(&[0xD9, 0xF5], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.physical_tag(0), 3);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }
}
#[test]
fn lifted_x87_fst_fstp_narrow_flags_masks_pop_environment_and_faults() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let half_ulp_above_one = raw(0x8000_0080_0000_0000, 0x3FFF);

    for (rc, expected, expected_c1) in [
        (0u16, 0x3F80_0000u32, false),
        (1, 0x3F80_0000, false),
        (2, 0x3F80_0001, true),
        (3, 0x3F80_0000, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
            x86.x87.set_logical_raw(0, half_ulp_above_one);
        }
        execute_lifted_x86(&[0xD9, 0x18], &mut ctx, &mut memory); // FSTP m32fp
        let mut stored = [0u8; 4];
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(u32::from_le_bytes(stored), expected, "RC={rc}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1, "RC={rc}: pop");
            assert_eq!(x86.x87.status_word & 0x0030, 0x0020, "RC={rc}");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "RC={rc}");
            assert_eq!(x86.x87.data_ptr, 0x100, "RC={rc}: FDP");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "RC={rc}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x0118, "RC={rc}: FOP");
        }
    }

    // FST m64fp preserves TOP and stores the exact binary64 payload.
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x300);
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87
            .set_logical_raw(0, raw(0xC000_0000_0000_0000, 0x3FFF));
    }
    execute_lifted_x86(&[0xDD, 0x10], &mut ctx, &mut memory);
    let mut qword = [0u8; 8];
    memory.read(0x100, &mut qword).unwrap();
    assert_eq!(u64::from_le_bytes(qword), 1.5f64.to_bits());
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.last_opcode, 0x0510);
    }

    // Masked SNaN preserves and quiets its payload; unsupported encodings
    // use the canonical negative indefinite response.
    for (name, source, expected) in [
        ("SNaN", raw(0x8123_4567_89AB_CDEF, 0x7FFF), 0x7FC1_2345u32),
        (
            "unsupported",
            raw(0x4123_4567_89AB_CDEF, 0x4000),
            0xFFC0_0000,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw_tagged(0, source, 2);
        }
        execute_lifted_x86(&[0xD9, 0x18], &mut ctx, &mut memory);
        let mut stored = [0u8; 4];
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(u32::from_le_bytes(stored), expected, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 1, 1, "{name}: IE");
            assert_eq!(x86.x87.top(), 1, "{name}: pop");
        }
    }

    // Inexact tiny conversion reports both UE and PE even when rounded to
    // the minimum normal payload (tininess-before-rounding behavior).
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87
            .set_logical_raw(0, raw(0xFFFF_FF00_0000_0000, 0x3F80));
    }
    execute_lifted_x86(&[0xD9, 0x10], &mut ctx, &mut memory);
    let mut dword = [0u8; 4];
    memory.read(0x100, &mut dword).unwrap();
    assert_eq!(u32::from_le_bytes(dword), 0x0080_0000);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0230, 0x0230);
    }

    // At the upper rounding boundary, round-down reaches max-finite with
    // PE only; an exactly out-of-range exponent raises OE as well.
    for (source, expected_status) in [
        (raw(0xFFFF_FF80_0000_0000, 0x407E), 0x0020u16),
        (raw(0x8000_0000_0000_0000, 0x407F), 0x0028),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | 0x0400;
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xD9, 0x10], &mut ctx, &mut memory);
        memory.read(0x100, &mut dword).unwrap();
        assert_eq!(u32::from_le_bytes(dword), 0x7F7F_FFFF);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x0228, expected_status);
        }
    }

    // Masked stack underflow stores indefinite and executes FSTP's pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xD9, 0x18], &mut ctx, &mut memory);
    memory.read(0x100, &mut dword).unwrap();
    assert_eq!(u32::from_le_bytes(dword), 0xFFC0_0000);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }

    // Unmasked invalid, overflow, and underflow suppress both store and
    // pop; unmasked precision records ES/B but completes the operation.
    for (name, source, clear_mask, expected_exception) in [
        (
            "invalid",
            raw(0x8123_4567_89AB_CDEF, 0x7FFF),
            0x0001u16,
            0x0001u16,
        ),
        (
            "overflow",
            raw(0x8000_0000_0000_0000, 0x407F),
            0x0008,
            0x0008,
        ),
        (
            "underflow",
            raw(0x8000_0000_0000_0000, 0x3F69),
            0x0010,
            0x0010,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word &= !clear_mask;
            x86.x87
                .set_logical_raw_tagged(0, source, if name == "invalid" { 2 } else { 0 });
        }
        memory.write(0x100, &[0xA5; 4]).unwrap();
        execute_lifted_x86(&[0xD9, 0x18], &mut ctx, &mut memory);
        memory.read(0x100, &mut dword).unwrap();
        assert_eq!(dword, [0xA5; 4], "{name}: store suppression");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}: pop suppression");
            assert_eq!(
                x86.x87.status_word & (0x8080 | expected_exception),
                0x8080 | expected_exception,
                "{name}"
            );
            assert_eq!(x86.x87.status_word & 0x0020, 0, "{name}: no PE");
        }
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
        x86.x87.set_logical_raw(0, half_ulp_above_one);
    }
    execute_lifted_x86(&[0xD9, 0x18], &mut ctx, &mut memory);
    memory.read(0x100, &mut dword).unwrap();
    assert_eq!(u32::from_le_bytes(dword), 0x3F80_0000);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x80A0, 0x80A0);
    }

    // A partial m64 write fault commits no status, environment, or pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87
            .set_logical_raw(0, raw(0xC000_0000_0000_0000, 0x3FFF));
        x86.x87.data_ptr = 0xCAFE;
    }
    let before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x104);
    let exit = execute_lifted_x86(&[0xDD, 0x18], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_fbld_fbstp_exact_bcd_rounding_exceptions_and_faults() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }
    fn bcd(mut magnitude: u64, negative: bool) -> [u8; 10] {
        let mut result = [0u8; 10];
        for byte in &mut result[..9] {
            let low = (magnitude % 10) as u8;
            magnitude /= 10;
            let high = (magnitude % 10) as u8;
            magnitude /= 10;
            *byte = (high << 4) | low;
        }
        result[9] = u8::from(negative) << 7;
        result
    }

    const BCD_INDEFINITE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0xFF];
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));

    for (name, source, expected, expected_tag) in [
        ("positive zero", bcd(0, false), raw(0, 0), 1u16),
        ("negative zero", bcd(0, true), raw(0, 0x8000), 1),
        (
            "positive 123",
            bcd(123, false),
            raw(0xF600_0000_0000_0000, 0x4005),
            0,
        ),
        (
            "negative 123 with ignored sign bits",
            {
                let mut value = bcd(123, true);
                value[9] = 0xFF;
                value
            },
            raw(0xF600_0000_0000_0000, 0xC005),
            0,
        ),
        (
            "maximum 18 digits",
            bcd(999_999_999_999_999_999, false),
            raw(0xDE0B_6B3A_763F_FFF0, 0x403A),
            0,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        memory.write(0x100, &source).unwrap();
        execute_lifted_x86(&[0xDF, 0x20], &mut ctx, &mut memory); // FBLD [RAX]
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 7, "{name}");
            assert_eq!(x86.x87.regs[7], expected, "{name}");
            assert_eq!(x86.x87.physical_tag(7), expected_tag, "{name}");
            assert_eq!(x86.x87.status_word & 0x0241, 0, "{name}");
            assert_eq!(x86.x87.data_ptr, 0x100, "{name}: FDP");
            assert_eq!(x86.x87.instr_ptr, 0x1000, "{name}: FIP");
            assert_eq!(x86.x87.last_opcode, 0x0720, "{name}: FOP");
        }
    }

    let p15 = raw(0xC000_0000_0000_0000, 0x3FFF);
    let n15 = raw(0xC000_0000_0000_0000, 0xBFFF);
    for (name, rc, source, expected_magnitude, negative, expected_c1) in [
        ("nearest +1.5", 0u16, p15, 2u64, false, true),
        ("nearest -1.5", 0, n15, 2, true, true),
        ("down +1.5", 1, p15, 1, false, false),
        ("down -1.5", 1, n15, 2, true, true),
        ("up +1.5", 2, p15, 2, false, true),
        ("up -1.5", 2, n15, 1, true, false),
        ("truncate +1.5", 3, p15, 1, false, false),
        ("truncate -1.5", 3, n15, 1, true, false),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        let mut memory = FlatMemory::new(0x200);
        ctx.write_vreg(rax, 0x100);
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word = (x86.x87.control_word & !0x0C00) | (rc << 10);
            x86.x87.set_logical_raw(0, source);
        }
        execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory); // FBSTP [RAX]
        let mut stored = [0u8; 10];
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(stored, bcd(expected_magnitude, negative), "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 1, "{name}: pop");
            assert_eq!(x86.x87.status_word & 0x0020, 0x0020, "{name}: PE");
            assert_eq!(x86.x87.status_word & 0x0200 != 0, expected_c1, "{name}: C1");
            assert_eq!(x86.x87.data_ptr, 0x100, "{name}: FDP");
            assert_eq!(x86.x87.last_opcode, 0x0730, "{name}: FOP");
        }
    }

    // Exact maximum magnitude round-trips without precision loss.
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x300);
    ctx.write_vreg(rax, 0x100);
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87
            .set_logical_raw(0, raw(0xDE0B_6B3A_763F_FFF0, 0x403A));
    }
    execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory);
    let mut stored = [0u8; 10];
    memory.read(0x100, &mut stored).unwrap();
    assert_eq!(stored, bcd(999_999_999_999_999_999, false));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.status_word & 0x0021, 0);
    }

    // Every invalid source class and an exactly representable 10^18 use
    // the canonical masked packed-BCD indefinite response.
    for (name, source, tag) in [
        ("qnan", raw(0xC000_0000_0000_1234, 0x7FFF), 2u16),
        ("infinity", raw(0x8000_0000_0000_0000, 0x7FFF), 2),
        ("unsupported", raw(0x4000_0000_0000_0000, 0x4000), 2),
        (
            "magnitude 10^18",
            SmirInterpreter::x86_x87_from_signed_magnitude(1_000_000_000_000_000_000, false),
            0,
        ),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.set_logical_raw_tagged(0, source, tag);
        }
        memory.write(0x100, &[0xA5; 10]).unwrap();
        execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory);
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(stored, BCD_INDEFINITE, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 1, 1, "{name}: IE");
            assert_eq!(x86.x87.status_word & 0x0020, 0, "{name}: no PE");
            assert_eq!(x86.x87.top(), 1, "{name}: pop");
        }
    }

    // Masked stack underflow stores indefinite and pops. Unmasked #IS and
    // #IA suppress both the store and pop.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory);
    memory.read(0x100, &mut stored).unwrap();
    assert_eq!(stored, BCD_INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }

    for (name, source, tag) in [
        ("stack underflow", raw(0, 0), 3u16),
        ("invalid", raw(0xC000_0000_0000_1234, 0x7FFF), 2),
    ] {
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87 = Default::default();
            x86.x87.control_word &= !1;
            x86.x87.set_logical_raw_tagged(0, source, tag);
        }
        memory.write(0x100, &[0xA5; 10]).unwrap();
        execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory);
        memory.read(0x100, &mut stored).unwrap();
        assert_eq!(stored, [0xA5; 10], "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}: pop suppression");
            assert_eq!(x86.x87.status_word & 0x8081, 0x8081, "{name}");
        }
    }

    // Unmasked precision completes the store/pop while setting ES/B.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !0x0020;
        x86.x87.set_logical_raw(0, p15);
    }
    execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut memory);
    memory.read(0x100, &mut stored).unwrap();
    assert_eq!(stored, bcd(2, false));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x82A0, 0x82A0);
    }

    // Complete memory accesses precede architectural state changes.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_logical_raw(0, p15);
        x86.x87.data_ptr = 0xCAFE;
    }
    let before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    let mut short_memory = FlatMemory::new(0x105);
    let exit = execute_lifted_x86(&[0xDF, 0x30], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }

    let mut short_memory = FlatMemory::new(0x105);
    let exit = execute_lifted_x86(&[0xDF, 0x20], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
#[test]
fn lifted_x87_compare_nan_denormal_stack_and_eflags_exception_policies() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }
    let p1 = raw(0x8000_0000_0000_0000, 0x3FFF);
    let qnan = raw(0xC000_0000_0000_1234, 0x7FFF);
    let snan = raw(0x8000_0000_0000_1234, 0x7FFF);
    let unsupported = raw(0x4000_0000_0000_0000, 0x4000);
    let denormal = raw(1, 0);
    let mut memory = FlatMemory::new(0x10);

    for (name, bytes, rhs, rhs_tag, expect_ie, expect_de, expect_pop, codes) in [
        (
            "FCOM qnan",
            &[0xD8, 0xD1][..],
            qnan,
            2u16,
            true,
            false,
            0u8,
            0x4500u16,
        ),
        (
            "FUCOM qnan",
            &[0xDD, 0xE1][..],
            qnan,
            2,
            false,
            false,
            0,
            0x4500,
        ),
        (
            "FUCOMP snan",
            &[0xDD, 0xE9][..],
            snan,
            2,
            true,
            false,
            1,
            0x4500,
        ),
        (
            "FUCOM unsupported",
            &[0xDD, 0xE1][..],
            unsupported,
            2,
            true,
            false,
            0,
            0x4500,
        ),
        (
            "FCOM denormal",
            &[0xD8, 0xD1][..],
            denormal,
            2,
            false,
            true,
            0,
            0x0000,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, p1);
            x86.x87.set_logical_raw_tagged(1, rhs, rhs_tag);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 0x4500, codes, "{name}");
            assert_eq!(x86.x87.status_word & 1 != 0, expect_ie, "{name}");
            assert_eq!(x86.x87.status_word & 2 != 0, expect_de, "{name}");
            assert_eq!(x86.x87.top(), expect_pop, "{name}");
        }
    }

    // Unmasked invalid and denormal exceptions preserve result codes and
    // suppress the architectural pop.
    for (name, rhs, rhs_tag, clear_mask, expected_exception) in [
        ("invalid", qnan, 2u16, 0x0001u16, 0x8081u16),
        ("denormal", denormal, 2, 0x0002, 0x8082),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.control_word &= !clear_mask;
            x86.x87.set_logical_raw(0, p1);
            x86.x87.set_logical_raw_tagged(1, rhs, rhs_tag);
            x86.x87.status_word |= 0x0500;
        }
        execute_lifted_x86(&[0xD8, 0xD9], &mut ctx, &mut memory);
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.top(), 0, "{name}");
            assert_eq!(x86.x87.status_word & 0x4500, 0x0500, "{name}");
            assert_eq!(
                x86.x87.status_word & expected_exception,
                expected_exception,
                "{name}"
            );
        }
    }

    // Masked stack underflow reports unordered and performs FCOMP's pop;
    // unmasked #IS preserves TOP and prior condition codes.
    let mut ctx = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.set_logical_raw(0, p1);
    }
    execute_lifted_x86(&[0xD8, 0xD9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x4541, 0x4541);
    }
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
        x86.x87.set_logical_raw(0, p1);
        x86.x87.status_word |= 0x0500;
    }
    execute_lifted_x86(&[0xD8, 0xD9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x4500, 0x0500);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1);
    }

    // FCOMI/FUCOMI result truth table, flag clearing, NaN policy, and
    // denormal non-exception behavior.
    for (name, bytes, lhs, rhs, initial_flags, expected_zpc, expect_ie, pop) in [
        (
            "greater",
            &[0xDB, 0xF1][..],
            raw(0x8000_0000_0000_0000, 0x4000),
            p1,
            0x8D5u64,
            0x000u64,
            false,
            0u8,
        ),
        (
            "less",
            &[0xDB, 0xF1][..],
            p1,
            raw(0x8000_0000_0000_0000, 0x4000),
            0x8D5,
            0x001,
            false,
            0,
        ),
        (
            "equal-pop",
            &[0xDF, 0xF1][..],
            p1,
            p1,
            0x8D5,
            0x040,
            false,
            1,
        ),
        (
            "fcomi-qnan",
            &[0xDB, 0xF1][..],
            p1,
            qnan,
            0x8D5,
            0x045,
            true,
            0,
        ),
        (
            "fucomi-qnan",
            &[0xDB, 0xE9][..],
            p1,
            qnan,
            0x8D5,
            0x045,
            false,
            0,
        ),
        (
            "fucomip-snan",
            &[0xDF, 0xE9][..],
            p1,
            snan,
            0x8D5,
            0x045,
            true,
            1,
        ),
        (
            "denormal",
            &[0xDB, 0xF1][..],
            p1,
            denormal,
            0x8D5,
            0x000,
            false,
            0,
        ),
    ] {
        let mut ctx = SmirContext::new_x86_64();
        ctx.flags.materialized = MaterializedFlags::from_rflags(initial_flags);
        ctx.flags.lazy = None;
        if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
            x86.x87.set_logical_raw(0, lhs);
            x86.x87.set_logical_raw_tagged(1, rhs, 2);
        }
        execute_lifted_x86(bytes, &mut ctx, &mut memory);
        ctx.flags.materialize_all();
        let actual = ctx.flags.materialized.to_rflags();
        assert_eq!(actual & 0x8D5, expected_zpc, "{name}");
        if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
            assert_eq!(x86.x87.status_word & 1 != 0, expect_ie, "{name}");
            assert_eq!(x86.x87.status_word & 2, 0, "{name}: DE");
            assert_eq!(x86.x87.top(), pop, "{name}");
        }
    }

    // Unmasked FCOMIP invalid preserves ZF/PF/CF, clears OF/SF/AF, and
    // suppresses the pop.
    ctx.flags.materialized = MaterializedFlags::from_rflags(0x8D5);
    ctx.flags.lazy = None;
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
        x86.x87.set_logical_raw(0, p1);
        x86.x87.set_logical_raw_tagged(1, qnan, 2);
    }
    execute_lifted_x86(&[0xDF, 0xF1], &mut ctx, &mut memory);
    ctx.flags.materialize_all();
    assert_eq!(ctx.flags.materialized.to_rflags() & 0x8D5, 0x045);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x8081, 0x8081);
    }
}
#[test]
fn lifted_x87_exact_transfers_handle_masked_unmasked_stack_faults_and_memory_faults() {
    fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
        let mut value = [0u8; 10];
        value[..8].copy_from_slice(&significand.to_le_bytes());
        value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
        value
    }

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let normal = raw(0x8000_0000_0000_0000, 0x4000);
    let sentinel = raw(0xDEAD_BEEF_CAFE_BABE, 0x1234);
    let mut ctx = SmirContext::new_x86_64();
    let mut memory = FlatMemory::new(0x300);
    ctx.write_vreg(rax, 0x100);
    memory.write(0x100, &normal).unwrap();

    // Masked stack overflow decrements TOP and writes floating-point
    // indefinite over the occupied destination.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87.set_physical_tag(7, 0);
        x86.x87.regs[7] = sentinel;
    }
    execute_lifted_x86(&[0xDB, 0x28], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 7);
        assert_eq!(x86.x87.regs[7], crate::smir::X86X87State::INDEFINITE);
        assert_eq!(x86.x87.physical_tag(7), 2);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0241); // C1|SF|IE
        assert_eq!(x86.x87.status_word & 0x8080, 0);
    }

    // An empty FLD-register source has higher priority than a simultaneous
    // overflow and therefore reports underflow (C1=0).
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_physical_tag(7, 0); // push destination occupied
    }
    execute_lifted_x86(&[0xD9, 0xC2], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 7);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
        assert_eq!(x86.x87.regs[7], crate::smir::X86X87State::INDEFINITE);
    }

    // With IM clear, a stack overflow records a pending unmasked exception
    // but leaves TOP and all operand payloads/tags unchanged.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
        x86.x87.set_physical_tag(7, 0);
        x86.x87.regs[7] = sentinel;
    }
    execute_lifted_x86(&[0xDB, 0x28], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.regs[7], sentinel);
        assert_eq!(x86.x87.physical_tag(7), 0);
        assert_eq!(x86.x87.status_word & 0x82C1, 0x82C1); // B|C1|ES|SF|IE
    }

    // Masked FXCH underflow loads each empty input with indefinite before
    // exchanging; the nonempty operand remains exact.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.regs[0] = normal;
        x86.x87.set_physical_tag(0, 0);
    }
    execute_lifted_x86(&[0xD9, 0xC9], &mut ctx, &mut memory);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.regs[0], crate::smir::X86X87State::INDEFINITE);
        assert_eq!(x86.x87.physical_tag(0), 2);
        assert_eq!(x86.x87.regs[1], normal);
        assert_eq!(x86.x87.physical_tag(1), 0);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }

    // Masked empty-store writes indefinite and pops; unmasked empty-store
    // changes neither memory nor TOP.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
    }
    memory.write(0x120, &[0xA5; 10]).unwrap();
    ctx.write_vreg(rax, 0x120);
    execute_lifted_x86(&[0xDB, 0x38], &mut ctx, &mut memory);
    let mut stored = [0u8; 10];
    memory.read(0x120, &mut stored).unwrap();
    assert_eq!(stored, crate::smir::X86X87State::INDEFINITE);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 1);
        assert_eq!(x86.x87.status_word & 0x0241, 0x0041);
    }

    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.control_word &= !1;
    }
    memory.write(0x120, &[0x5A; 10]).unwrap();
    execute_lifted_x86(&[0xDB, 0x38], &mut ctx, &mut memory);
    memory.read(0x120, &mut stored).unwrap();
    assert_eq!(stored, [0x5A; 10]);
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87.top(), 0);
        assert_eq!(x86.x87.status_word & 0x80C1, 0x80C1); // B|ES|SF|IE
    }

    // A partial ten-byte store fault is reported as a write and commits no
    // pop, pointer, status, tag, or payload state.
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = Default::default();
        x86.x87.set_logical_raw(0, normal);
        x86.x87.data_ptr = 0xCAFE;
        x86.x87.instr_ptr = 0xBEEF;
        x86.x87.last_opcode = 0x123;
    }
    let before = match &ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87.clone(),
        _ => unreachable!(),
    };
    ctx.write_vreg(rax, 0x100);
    let mut short_memory = FlatMemory::new(0x105);
    let exit = execute_lifted_x86(&[0xDB, 0x38], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: true, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }

    // A partial load fault likewise preserves the complete x87 state.
    let exit = execute_lifted_x86(&[0xDB, 0x28], &mut ctx, &mut short_memory);
    assert!(matches!(
        exit,
        BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
    ));
    if let ArchRegState::X86_64(x86) = &ctx.arch_regs {
        assert_eq!(x86.x87, before);
    }
}
