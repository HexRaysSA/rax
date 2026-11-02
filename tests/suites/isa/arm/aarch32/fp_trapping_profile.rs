//! Optional synchronous-profile parent-engine regressions.
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};
fn execute(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = if cpu.cpsr.t {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap();
    let mut memory = FlatMemory::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(&insn)
}
fn profile(thumb: bool) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 12)) | (1 << 12);
    cpu
}
#[test]
fn advertised_trapping_profile_must_retain_guest_exception_enables() {
    for thumb in [false, true] {
        let mut cpu = profile(thumb);
        cpu.regs[0] = 0x9f00;
        assert!(matches!(
            execute(&mut cpu, 0xeee10a10),
            ExecResult::Continue
        ));
        assert!(matches!(
            execute(&mut cpu, 0xeef11a10),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[1], 0x9f00);
    }
}
#[test]
fn advertised_trapping_profile_must_raise_invalid_without_destination_commit() {
    for thumb in [false, true] {
        let mut cpu = profile(thumb);
        cpu.vfp.fpscr = Fpscr::from_bits(1 << 8);
        cpu.vfp.write_s_bits(0, 0x12345678);
        let before = cpu.vfp.dregs;
        assert!(matches!(
            execute(&mut cpu, 0xee810a02),
            ExecResult::Exception(_)
        ));
        assert_eq!(cpu.vfp.dregs, before);
        assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0x24000001);
    }
}

#[test]
fn six_causes_all_enable_subsets_and_old_sticky_bits_have_precise_commit() {
    // IEEE-754 exact input partitions; expected flags are independent of RAX helpers.
    let cases = [
        (0xee800a20, 0, 0, 0, 1),                      // 0/0
        (0xee800a20, 0x3f800000, 0, 0, 2),             // 1/0
        (0xee200a20, 0x7f7fffff, 0x40000000, 0, 0x14), // overflow + inexact
        (0xee200a20, 0x00800000, 0x33000000, 0, 0x18), // tiny, inexact
        (0xee300a20, 0x3f800000, 0x33800000, 0, 0x10), // halfway addition
        (0xee300a20, 1, 0, 1 << 24, 0x80),             // flushed input denormal
    ];
    for thumb in [false, true] {
        for rounding in 0..4 {
            for (word, a, b, control, raised) in cases {
                for subset in 0u32..64 {
                    let enables = (subset & 31) | ((subset & 32) << 2);
                    for old in [0, 0x9f] {
                        let mut cpu = profile(thumb);
                        cpu.vfp.write_s_bits(0, a);
                        cpu.vfp.write_s_bits(1, b);
                        let initial =
                            0xa8000000 | control | (rounding << 22) | (enables << 8) | old;
                        cpu.vfp.fpscr = Fpscr::from_bits(initial);
                        let before = (cpu.vfp.dregs, cpu.regs, cpu.cpsr.to_u32());
                        let result = execute(&mut cpu, word);
                        let trapped = raised & enables != 0;
                        if trapped {
                            assert!(
                                matches!(result, ExecResult::Exception(rax::isa::arm::aarch32::instructions::ExceptionType::FloatingPoint(flags)) if u32::from(flags) == (raised & enables)),
                                "{word:08x} {enables:02x} {result:?}"
                            );
                            assert_eq!(cpu.vfp.dregs, before.0);
                            assert_eq!(cpu.vfp.fpscr.bits(), initial | (raised & !enables));
                            assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0x24000000 | (raised & enables));
                        } else {
                            assert!(matches!(result, ExecResult::Continue), "{result:?}");
                            assert_eq!(cpu.vfp.fpscr.bits(), initial | raised);
                            assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0);
                        }
                        assert_eq!((cpu.regs, cpu.cpsr.to_u32()), (before.1, before.2));
                    }
                }
            }
        }
    }
}

#[test]
fn double_and_half_conversion_traps_preserve_complete_register_file() {
    for thumb in [false, true] {
        for (word, source, status) in [
            (0xee800b01, 0u64, 1u32),       // VDIV.F64 D0,D0,D1
            (0xeeb30a41, 0x3f801000, 0x10), // VCVTB.F16.F32 S0,S2
            (0xeeb20ac1, 0x7c010000, 1),    // VCVTT.F32.F16 S0,S2
        ] {
            let mut cpu = profile(thumb);
            cpu.vfp.dregs.fill(0x12345678_deadbeef);
            if word == 0xee800b01 {
                cpu.vfp.dregs[0] = 0;
            }
            cpu.vfp.dregs[1] = source;
            cpu.vfp.fpscr = Fpscr::from_bits(status << 8);
            let before = cpu.vfp.dregs;
            assert!(
                matches!(execute(&mut cpu, word), ExecResult::Exception(_)),
                "{word:08x}"
            );
            assert_eq!(cpu.vfp.dregs, before);
            assert_eq!(cpu.vfp.fpscr.bits(), status << 8);
        }
    }
}

#[test]
fn short_vectors_collect_later_lane_flags_before_any_destination_commit() {
    for thumb in [false, true] {
        let mut cpu = profile(thumb);
        cpu.vfp.mvfr0 |= 1 << 24;
        cpu.vfp.fpscr = Fpscr::from_bits((3 << 16) | 0x100);
        for lane in 0..4 {
            cpu.vfp.write_s(16 + lane, 1.0);
            cpu.vfp.write_s(24 + lane, 2.0);
        }
        cpu.vfp.write_s_bits(16, 0x7f800001); // lane 0 invalid
        cpu.vfp.write_s_bits(19, 0x7f7fffff);
        cpu.vfp.write_s_bits(27, 0x7f7fffff); // lane 3 overflow + inexact
        let before = cpu.vfp.dregs;
        assert!(matches!(
            execute(&mut cpu, 0xee384a0c),
            ExecResult::Exception(_)
        ));
        assert_eq!(cpu.vfp.dregs, before);
        assert_eq!(cpu.vfp.fpexc & 0x9f, 1);
        assert_eq!(cpu.vfp.fpscr.bits(), (3 << 16) | 0x114);
    }
}

#[test]
fn predicate_access_priority_and_reserved_profile_do_not_raise_fp_traps() {
    let mut cpu = profile(false);
    cpu.vfp.fpscr = Fpscr::from_bits(0x100);
    let before = cpu.vfp.dregs;
    cpu.cpsr.z = false;
    assert!(matches!(
        execute(&mut cpu, 0x0e810a02),
        ExecResult::Continue
    ));
    assert_eq!(cpu.vfp.dregs, before);
    cpu.vfp.fpexc &= !(1 << 30);
    assert!(matches!(
        execute(&mut cpu, 0xee810a02),
        ExecResult::Exception(
            rax::isa::arm::aarch32::instructions::ExceptionType::UndefinedInstruction
        )
    ));
    assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0);
    cpu.vfp.fpexc |= 1 << 30;
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 12)) | (2 << 12);
    assert!(matches!(
        execute(&mut cpu, 0xee810a02),
        ExecResult::Undefined
    ));
    assert_eq!(cpu.vfp.dregs, before);
}

#[test]
fn guest_identity_fpexc_acknowledgment_and_fpscr_reserved_bits_follow_profile() {
    for thumb in [false, true] {
        let mut cpu = profile(thumb);
        cpu.regs[0] = u32::MAX;
        assert!(matches!(
            execute(&mut cpu, 0xeee10a10),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.fpscr.bits(), 0xffc89f9f);
        assert!(matches!(
            execute(&mut cpu, 0xeef01a10),
            ExecResult::Continue
        )); // VMRS FPSID
        assert_eq!((cpu.regs[1] >> 16) & 0x7f, 0x41);
        assert!(matches!(
            execute(&mut cpu, 0xeee80a10),
            ExecResult::Continue
        )); // VMSR FPEXC
        assert!(matches!(
            execute(&mut cpu, 0xeef81a10),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[1], 0x6400079f);
        cpu.regs[0] = 1 << 30;
        assert!(matches!(
            execute(&mut cpu, 0xeee80a10),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.fpexc, 0x44000700);
    }
}

#[test]
fn local_hyp_and_tge_undefined_routes_keep_fp_report_and_fault_return_address() {
    use rax::isa::arm::{ProcessorMode, cp15::Cpacr};
    for thumb in [false, true] {
        for own_hyp in [false, true] {
            let mut cpu = profile(thumb);
            cpu.change_mode(if own_hyp {
                ProcessorMode::Hyp
            } else {
                ProcessorMode::User
            });
            cpu.set_nonsecure(true);
            cpu.cp15.scr |= 1;
            cpu.cp15.id_pfr1 |= 1 << 12;
            cpu.cp15.nsacr |= 3 << 10;
            cpu.cp15.cpacr = Cpacr::from_bits(0x00f00000);
            cpu.cp15.hcptr = 0;
            cpu.cp15.hcr = if own_hyp { 0 } else { 1 << 27 };
            cpu.cp15.hvbar = 0x2000;
            cpu.regs[15] = 0x100;
            cpu.vfp.fpscr = Fpscr::from_bits(0x100);
            let saved = cpu.cpsr.to_u32();
            let result = execute(&mut cpu, 0xee810a02);
            let ExecResult::Exception(exception) = result else {
                panic!("{result:?}")
            };
            assert_eq!(
                exception,
                rax::isa::arm::aarch32::instructions::ExceptionType::FloatingPoint(1)
            );
            let mut memory = FlatMemory::new(4096, 0);
            Executor::new(&mut cpu, &mut memory).take_exception(exception);
            assert_eq!(cpu.cpsr.mode, ProcessorMode::Hyp as u8);
            assert_eq!(cpu.cp15.elr_hyp, 0x100);
            assert_eq!(cpu.cp15.hsr, 1 << 25);
            assert_eq!(cpu.regs[15], 0x2000 + if own_hyp { 4 } else { 0x14 });
            assert_eq!(cpu.spsr_hyp.to_u32(), saved);
            assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0x24000001);
        }
    }
}

#[test]
fn active_enables_do_not_replay_memory_or_erase_partial_transfer_completion() {
    use rax::isa::arm::aarch32::cpu::{ArmMemory, MemoryError};
    use std::cell::Cell;
    struct Memory {
        reads: Cell<usize>,
        fail_second: bool,
    }
    impl ArmMemory for Memory {
        fn read_word(&self, addr: u32) -> Result<u32, MemoryError> {
            self.reads.set(self.reads.get() + 1);
            if addr == 4 && self.fail_second {
                Err(MemoryError::BusError(addr))
            } else {
                Ok(0x7f800001)
            }
        }
        fn write_word(&mut self, _: u32, _: u32) -> Result<(), MemoryError> {
            panic!("unexpected write")
        }
        fn read_halfword(&self, _: u32) -> Result<u16, MemoryError> {
            panic!("unexpected halfword")
        }
        fn write_halfword(&mut self, _: u32, _: u16) -> Result<(), MemoryError> {
            panic!("unexpected halfword")
        }
        fn read_byte(&self, _: u32) -> Result<u8, MemoryError> {
            panic!("unexpected byte")
        }
        fn write_byte(&mut self, _: u32, _: u8) -> Result<(), MemoryError> {
            panic!("unexpected byte")
        }
    }
    for thumb in [false, true] {
        for fail_second in [false, true] {
            let mut cpu = profile(thumb);
            cpu.vfp.fpscr = Fpscr::from_bits(0x101);
            cpu.regs[0] = 0;
            cpu.vfp.dregs[0] = 0xdeadbeef_deadbeef;
            let raw = 0xec900a02; // VLDMIA R0,{S0,S1}; signaling NaN is raw storage.
            let insn = if thumb {
                ThumbDecoder::decode_32bit(raw)
            } else {
                Aarch32Decoder::decode(raw)
            }
            .unwrap();
            let mut memory = Memory {
                reads: Cell::new(0),
                fail_second,
            };
            let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
            assert_eq!(memory.reads.get(), 2);
            assert_eq!(cpu.vfp.read_s_bits(0), 0x7f800001);
            assert_eq!(
                cpu.vfp.read_s_bits(1),
                if fail_second { 0xdeadbeef } else { 0x7f800001 }
            );
            assert_eq!(cpu.vfp.fpscr.bits(), 0x101);
            assert_eq!(cpu.vfp.fpexc & 0x2400009f, 0);
            if fail_second {
                assert!(matches!(result, ExecResult::MemoryFault(_)));
            } else {
                assert!(matches!(result, ExecResult::Continue));
            }
        }
    }
}

#[test]
fn tfv_ignores_guest_writes_and_is_fixed_one_without_short_vectors() {
    // DDI0487B.a G6.2.49: TFV is status/WI; RAO/WI if Stride/Len are RAZ.
    for thumb in [false, true] {
        for vectors in [false, true] {
            for previous in [0, 1 << 26] {
                for written in [0, u32::MAX] {
                    let mut cpu = profile(thumb);
                    if vectors {
                        cpu.vfp.mvfr0 |= 1 << 24;
                    }
                    cpu.vfp.fpexc = (1 << 30) | previous;
                    cpu.regs[0] = written;
                    assert!(matches!(
                        execute(&mut cpu, 0xeee80a10),
                        ExecResult::Continue
                    ));
                    assert!(matches!(
                        execute(&mut cpu, 0xeef81a10),
                        ExecResult::Continue
                    ));
                    let tfv = if vectors { previous } else { 1 << 26 };
                    assert_eq!(
                        cpu.regs[1],
                        (written & 0x6000009f) | tfv | 0x700,
                        "Thumb={thumb} vectors={vectors} old={previous:08x} write={written:08x}"
                    );
                }
            }
        }
    }
}

#[test]
fn exact_tiny_underflow_traps_but_output_flush_is_cumulative_only() {
    for thumb in [false, true] {
        for half in [false, true] {
            for flush_half in [false, true] {
                for flush_single in [false, true] {
                    let mut cpu = profile(thumb);
                    let control =
                        0x800 | u32::from(flush_half) << 19 | u32::from(flush_single) << 24;
                    cpu.vfp.fpscr = Fpscr::from_bits(control);
                    cpu.vfp.write_s_bits(0, 0xdeadbeef);
                    cpu.vfp
                        .write_s_bits(2, if half { 0x0400 } else { 0x00800000 });
                    cpu.vfp
                        .write_s_bits(4, if half { 0x3800 } else { 0x3f000000 });
                    let result = execute(&mut cpu, if half { 0xee210902 } else { 0xee210a02 });
                    if if half { flush_half } else { flush_single } {
                        assert!(
                            matches!(result, ExecResult::Continue),
                            "half={half} {control:08x} {result:?}"
                        );
                        assert_eq!(cpu.vfp.read_s_bits(0), 0);
                        assert_eq!(cpu.vfp.fpscr.bits(), control | 8);
                    } else {
                        assert!(matches!(result,ExecResult::Exception(rax::isa::arm::aarch32::instructions::ExceptionType::FloatingPoint(8))),"half={half} {control:08x} {result:?}");
                        assert_eq!(cpu.vfp.read_s_bits(0), 0xdeadbeef);
                        assert_eq!(cpu.vfp.fpscr.bits(), control);
                    }
                }
            }
        }
    }
}
