//! A Thumb scalar VSTR cannot use PC as its base.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode, vfp::Fpscr};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

const STORE: u32 = 0xed80_0802;
const D0: u64 = 0x1122_3344_5566_7788;
const MEMORY: u64 = 0xaabb_ccdd_0102_0304;

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}

#[test]
fn thumb_pc_base_vstr_is_undefined_across_scalar_registers_and_widths() {
    for size in 1..=3 {
        for add in [0, 1] {
            for high in [0, 1] {
                for reg in 0..16 {
                    for offset in [0, 1, 2, 127, 255] {
                        let raw = 0xed00_0800
                            | add << 23
                            | high << 22
                            | 15 << 16
                            | reg << 12
                            | size << 8
                            | offset;
                        assert_eq!(decode(raw, true).mnemonic, Mnemonic::UNDEFINED, "{raw:08x}");
                        assert_eq!(decode(raw, false).mnemonic, Mnemonic::VSTR, "{raw:08x}");
                        assert_eq!(decode(raw | (1 << 20), true).mnemonic, Mnemonic::VLDR);
                        assert_eq!(decode(raw & !(15 << 16), true).mnemonic, Mnemonic::VSTR);
                    }
                }
            }
        }
    }
}

fn run(raw: u32, thumb: bool, access: u8) -> (ExecResult, u64, u64) {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs[15] = 0x100;
    cpu.regs[0] = 0x100;
    cpu.vfp.dregs[0] = D0;
    cpu.vfp.fpscr = Fpscr::from_bits(0x10);
    cpu.cp15.cpacr = Cpacr::from_bits(0xf0_0000);
    match access {
        1 => cpu.cp15.cpacr = Cpacr::from_bits(0),
        2 => {
            cpu.cpsr.mode = ProcessorMode::Hyp as u8;
            cpu.cp15.scr = 1;
            cpu.cp15.nsacr = 1 << 10;
            cpu.cp15.hcptr = 1 << 10;
        }
        3 => cpu.vfp.fpexc = 0,
        4 => {
            cpu.cpsr.it_state = 0x18; // NE fails.
            cpu.cpsr.z = true;
        }
        5 => {
            cpu.cpsr.it_state = 0x18; // NE passes.
            cpu.cpsr.z = false;
        }
        6 => cpu.cpsr.z = true,
        _ => (),
    }
    let scale = if (raw >> 8) & 3 == 1 { 2 } else { 4 };
    let base = match (thumb, (raw >> 16) & 15) {
        (true, 15) => 0x104,
        (false, 15) => 0x108,
        (_, 0) => 0x100,
        _ => unreachable!(),
    };
    let addr = base + 2 * scale;
    let mut memory = FlatMemory::new(1024, 0);
    memory.write_word(addr, MEMORY as u32).unwrap();
    memory.write_word(addr + 4, (MEMORY >> 32) as u32).unwrap();
    let res = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
    assert_eq!(cpu.vfp.fpscr.bits(), 0x10);
    let memory = u64::from(memory.read_word(addr).unwrap())
        | u64::from(memory.read_word(addr + 4).unwrap()) << 32;
    (res, memory, cpu.vfp.dregs[0])
}

#[test]
fn thumb_pc_base_vstr_rejects_before_fp_access_and_leaves_memory_and_registers() {
    for size in 1..=3 {
        let raw = STORE | 15 << 16 | size << 8;
        for access in 0..=4 {
            let (res, memory, d0) = run(raw, true, access);
            assert_eq!((memory, d0), (MEMORY, D0), "{raw:08x}, {access}: {res:?}");
            if access == 4 {
                assert!(matches!(res, ExecResult::Continue), "{raw:08x}: {res:?}");
            } else {
                assert!(
                    matches!(res, ExecResult::Undefined),
                    "{raw:08x}, {access}: {res:?}"
                );
            }
        }
    }
}

#[test]
fn scalar_half_arm_memory_requires_always_condition() {
    for direction in [0, 1 << 20] {
        let half = STORE | 1 << 8 | direction;
        let arm_ne = (half & 0x0fff_ffff) | 0x1000_0000;
        assert_eq!(decode(arm_ne, false).mnemonic, Mnemonic::UNDEFINED);
        check_half_predicate(arm_ne, false, 0, 6);
    }
}

#[test]
fn scalar_half_thumb_memory_excludes_passing_it_instructions() {
    for direction in [0, 1 << 20] {
        check_half_predicate(STORE | 1 << 8 | direction, true, 5, 4);
    }
}

fn check_half_predicate(raw: u32, thumb: bool, passing: u8, failing: u8) {
    let (res, memory, d0) = run(raw, thumb, passing);
    assert_eq!((memory, d0), (MEMORY, D0), "{raw:08x}, {thumb}: {res:?}");
    assert!(
        matches!(res, ExecResult::Undefined),
        "{raw:08x}, {thumb}: {res:?}"
    );
    let (res, memory, d0) = run(raw, thumb, failing);
    assert_eq!((memory, d0), (MEMORY, D0), "{raw:08x}, {thumb}: {res:?}");
    assert!(
        matches!(res, ExecResult::Continue),
        "{raw:08x}, {thumb}: {res:?}"
    );
}

#[test]
fn legal_pc_relative_and_general_register_transfers_keep_their_effects() {
    for size in 1..=3 {
        let store = STORE | size << 8;
        let pc = 15 << 16;
        let load = 1 << 20;
        let bits = 8 << size;
        let mask = u64::MAX >> (64 - bits);
        for (raw, thumb) in [(store | pc, false), (store, true)] {
            let (res, memory, d0) = run(raw, thumb, 0);
            assert!(matches!(res, ExecResult::Continue), "{raw:08x}: {res:?}");
            assert_eq!((memory, d0), ((MEMORY & !mask) | (D0 & mask), D0));
        }
        for thumb in [false, true] {
            let (res, memory, d0) = run(store | pc | load, thumb, 0);
            assert!(matches!(res, ExecResult::Continue), "{store:08x}: {res:?}");
            let preserve = if size == 1 {
                0xffff_ffff_0000_0000
            } else {
                !mask
            };
            assert_eq!((memory, d0), (MEMORY, (D0 & preserve) | (MEMORY & mask)));
        }
    }
}
