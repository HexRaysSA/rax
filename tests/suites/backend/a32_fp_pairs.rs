//! Arm VMOV_ss/VMOV_d: complete register fields, decode constraints and effects.
use rax::isa::arm::decoder::{
    Aarch32Decoder, DecodedInsn, FpRegister, Mnemonic, Operand, ThumbDecoder,
};
use rax::isa::arm::execution::{ArmMemory, MemoryError};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

struct NoMemory;
impl ArmMemory for NoMemory {
    fn read_word(&self, _: u32) -> Result<u32, MemoryError> {
        panic!("unexpected memory read")
    }
    fn read_halfword(&self, _: u32) -> Result<u16, MemoryError> {
        panic!("unexpected memory read")
    }
    fn read_byte(&self, _: u32) -> Result<u8, MemoryError> {
        panic!("unexpected memory read")
    }
    fn write_word(&mut self, _: u32, _: u32) -> Result<(), MemoryError> {
        panic!("unexpected memory write")
    }
    fn write_halfword(&mut self, _: u32, _: u16) -> Result<(), MemoryError> {
        panic!("unexpected memory write")
    }
    fn write_byte(&mut self, _: u32, _: u8) -> Result<(), MemoryError> {
        panic!("unexpected memory write")
    }
}

fn word(single: bool, read: bool, start: u8, rt: u8, rt2: u8) -> u32 {
    let register = if single {
        u32::from(start >> 1) | (u32::from(start & 1) << 5)
    } else {
        u32::from(start & 15) | (u32::from(start >> 4) << 5)
    };
    0xec40_0010
        | (u32::from(read) << 20)
        | (u32::from(rt2) << 16)
        | (u32::from(rt) << 12)
        | (if single { 10 } else { 11 } << 8)
        | register
}
fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}
fn seeded(thumb: bool) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.cpsr.n = true;
    cpu.cpsr.c = true;
    for i in 0..15 {
        cpu.regs[i] = 0x1020_3040u32.wrapping_mul(i as u32 + 1);
    }
    cpu.regs[15] = 0x8000;
    for i in 0..32 {
        cpu.vfp.dregs[i] = 0x7654_3210_89ab_cdefu64
            .rotate_left(i as u32)
            .wrapping_add(i as u64);
    }
    cpu
}

#[test]
fn decoder_reports_vm_m_and_m_vm_as_distinct_register_fields() {
    for thumb in [false, true] {
        for single in [false, true] {
            for start in 0..if single { 31 } else { 32 } {
                for read in [false, true] {
                    let decoded = decode(word(single, read, start, 0, 1), thumb);
                    assert_eq!(decoded.mnemonic, Mnemonic::VMOV);
                    assert_eq!(
                        decoded.operands[0],
                        Operand::FpReg(if single {
                            FpRegister::s(start)
                        } else {
                            FpRegister::d(start)
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn complete_legal_pair_field_matrix_preserves_all_other_registers_and_flags() {
    let mut rows = 0;
    for thumb in [false, true] {
        for single in [false, true] {
            for start in 0..if single { 31 } else { 32 } {
                for read in [false, true] {
                    for rt in 0..15 {
                        for rt2 in 0..15 {
                            if read && rt == rt2 {
                                continue;
                            }
                            let mut cpu = seeded(thumb);
                            let before = cpu.regs;
                            let psr = cpu.cpsr.to_u32();
                            let fp = cpu.vfp.dregs;
                            let fpscr = cpu.vfp.fpscr.bits();
                            let fpexc = cpu.vfp.fpexc;
                            let mut expected_regs = before;
                            let mut expected_fp = fp;
                            if single {
                                if read {
                                    expected_regs[usize::from(rt)] = cpu.vfp.read_s_bits(start);
                                    expected_regs[usize::from(rt2)] =
                                        cpu.vfp.read_s_bits(start + 1);
                                } else {
                                    for (s, value) in [
                                        (start, before[usize::from(rt)]),
                                        (start + 1, before[usize::from(rt2)]),
                                    ] {
                                        let index = usize::from(s / 2);
                                        let shift = u32::from(s & 1) * 32;
                                        expected_fp[index] = (expected_fp[index]
                                            & !(0xffff_ffffu64 << shift))
                                            | (u64::from(value) << shift);
                                    }
                                }
                            } else if read {
                                expected_regs[usize::from(rt)] = fp[usize::from(start)] as u32;
                                expected_regs[usize::from(rt2)] =
                                    (fp[usize::from(start)] >> 32) as u32;
                            } else {
                                expected_fp[usize::from(start)] =
                                    u64::from(before[usize::from(rt)])
                                        | (u64::from(before[usize::from(rt2)]) << 32);
                            }
                            let raw = word(single, read, start, rt, rt2);
                            let result =
                                Executor::new(&mut cpu, &mut NoMemory).execute(&decode(raw, thumb));
                            assert!(
                                matches!(result, ExecResult::Continue),
                                "{raw:#x},Thumb={thumb}: {result:?}"
                            );
                            assert_eq!(cpu.regs, expected_regs, "{raw:#x},Thumb={thumb}");
                            assert_eq!(cpu.vfp.dregs, expected_fp, "{raw:#x},Thumb={thumb}");
                            assert_eq!(cpu.cpsr.to_u32(), psr);
                            assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                            assert_eq!(cpu.vfp.fpexc, fpexc);
                            rows += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(rows, 54_810);
}

fn invalid_words() -> Vec<u32> {
    let mut words = Vec::new();
    for single in [false, true] {
        for read in [false, true] {
            words.push(word(single, read, 0, 15, 0));
            words.push(word(single, read, 0, 0, 15));
            if single {
                words.push(word(single, read, 31, 0, 1));
            }
            if read {
                for rt in 0..15 {
                    words.push(word(single, read, 0, rt, rt));
                }
            }
        }
    }
    words
}
#[test]
fn unpredictable_pair_operands_select_undefined_before_fp_control_checks() {
    for thumb in [false, true] {
        for enabled in [false, true] {
            for raw in invalid_words() {
                let decoded = decode(raw, thumb);
                assert_eq!(decoded.mnemonic, Mnemonic::UNDEFINED);
                let mut cpu = seeded(thumb);
                cpu.cpsr.mode = 0x1a;
                cpu.cp15.nsacr = 0xc00;
                cpu.cp15.hcptr = 0x37ff;
                if !enabled {
                    cpu.vfp.fpexc = 0;
                }
                let regs = cpu.regs;
                let fp = cpu.vfp.dregs;
                let psr = cpu.cpsr.to_u32();
                let result = Executor::new(&mut cpu, &mut NoMemory).execute(&decoded);
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "{raw:#x},Thumb={thumb}: {result:?}"
                );
                assert_eq!(cpu.regs, regs);
                assert_eq!(cpu.vfp.dregs, fp);
                assert_eq!(cpu.cpsr.to_u32(), psr);
            }
        }
    }
}
#[test]
fn failed_arm_and_thumb_it_predicates_suppress_invalid_pair_execution() {
    for thumb in [false, true] {
        for raw in invalid_words() {
            let mut cpu = seeded(thumb);
            cpu.cpsr.z = false;
            if thumb {
                cpu.cpsr.it_state = 8;
            }
            let raw = if thumb { raw } else { raw & 0x0fff_ffff }; // EQ, Z=0.
            let before = cpu.regs;
            let fp = cpu.vfp.dregs;
            let psr = cpu.cpsr.to_u32();
            let result = Executor::new(&mut cpu, &mut NoMemory).execute(&decode(raw, thumb));
            assert!(
                matches!(result, ExecResult::Continue),
                "{raw:#x},Thumb={thumb}: {result:?}"
            );
            assert_eq!(cpu.regs, before);
            assert_eq!(cpu.vfp.dregs, fp);
            assert_eq!(cpu.cpsr.to_u32(), psr);
        }
    }
}

#[test]
fn mixed_width_pair_execution_updates_only_the_enclosing_physical_registers() {
    use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
    use rax::isa::arm::common::cpu::{ArmCpu, CpuExit};
    use rax::isa::arm::common::memory::FlatMemory;
    use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
    let mut rows = 0;
    for thumb in [false, true] {
        for single in [false, true] {
            for start in 0..if single { 31 } else { 32 } {
                for read in [false, true] {
                    let mut cpu = AArch64Cpu::new(
                        AArch64Config {
                            initial_el: 3,
                            gic_config: None,
                            ..Default::default()
                        },
                        Box::new(FlatMemory::new(0, 0x4000)),
                    );
                    let mut state = cpu.export_sregs();
                    let system = &mut state.execution.as_mut().unwrap().sysregs;
                    system.scr_el3 = 1 | (1 << 10);
                    system.hcr_el2 = 0;
                    system.el1.cpacr = 3 << 20;
                    system
                        .impl_defined
                        .insert(Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(), 1 << 30);
                    cpu.import_sregs(&state).unwrap();
                    cpu.set_pstate_bits(0x1d3 | u64::from(thumb) << 5).unwrap();
                    cpu.set_pc(0x100);
                    cpu.set_x(0, 0x13579bdf);
                    cpu.set_x(1, 0x2468ace0);
                    let mut expected = std::array::from_fn::<_, 32, _>(|i| {
                        0x12345678_abcdef01_fedcba98_87654321u128.rotate_left(i as u32)
                    });
                    for (i, value) in expected.iter().copied().enumerate() {
                        cpu.set_simd(i as u8, value);
                    }
                    let mut expected_regs = [cpu.get_x(0), cpu.get_x(1)];
                    if single {
                        let i = usize::from(start);
                        let value = (expected[i / 4] >> ((i % 4) * 32)) as u32;
                        let value2 = (expected[(i + 1) / 4] >> (((i + 1) % 4) * 32)) as u32;
                        if read {
                            expected_regs = [u64::from(value), u64::from(value2)];
                        } else {
                            for (j, bits) in [(i, 0x13579bdfu128), (i + 1, 0x2468ace0u128)] {
                                let shift = (j % 4) * 32;
                                expected[j / 4] = (expected[j / 4] & !(0xffffffffu128 << shift))
                                    | (bits << shift);
                            }
                        }
                    } else {
                        let i = usize::from(start);
                        let shift = (i % 2) * 64;
                        let value = (expected[i / 2] >> shift) as u64;
                        if read {
                            expected_regs = [value & 0xffffffff, value >> 32];
                        } else {
                            expected[i / 2] = (expected[i / 2]
                                & !(0xffffffffffffffffu128 << shift))
                                | (0x2468ace0_13579bdfu128 << shift);
                        }
                    }
                    let raw = word(single, read, start, 0, 1);
                    let bytes = if thumb {
                        [
                            ((raw >> 16) as u16).to_le_bytes(),
                            (raw as u16).to_le_bytes(),
                        ]
                        .concat()
                    } else {
                        raw.to_le_bytes().to_vec()
                    };
                    cpu.write_memory(0x100, &bytes).unwrap();
                    let result = cpu.step();
                    assert!(
                        matches!(result, Ok(CpuExit::Continue)),
                        "{raw:#x},Thumb={thumb}: {result:?}"
                    );
                    assert_eq!([cpu.get_x(0), cpu.get_x(1)], expected_regs);
                    for (i, value) in expected.iter().enumerate() {
                        assert_eq!(cpu.get_simd(i as u8), *value, "{raw:#x},V{i}");
                    }
                    assert_eq!(cpu.get_pc(), 0x104);
                    assert_eq!(cpu.instruction_count(), 1);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 252);
}
