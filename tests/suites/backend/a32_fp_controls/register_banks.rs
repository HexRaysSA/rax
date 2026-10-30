//! D16 register-bank admission; exact LLVM encodings retained with the reference notes.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, CpuExit};
use rax::isa::arm::common::memory::FlatMemory as Memory64;
use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// (name, A32, T32, family, permitted in the D16/no-Advanced-SIMD profile).
const CASES: &[(&str, u32, u32, &str, bool)] = &[
    ("scalar32", 0xee7ffaaf, 0xee7ffaaf, "scalar", true),
    ("scalar64", 0xee3ffb0f, 0xee3ffb0f, "scalar", true),
    ("destination16", 0xee700b00, 0xee700b00, "scalar", false),
    ("source_n16", 0xee300b80, 0xee300b80, "scalar", false),
    ("source_m16", 0xee300b20, 0xee300b20, "scalar", false),
    ("move15", 0xeeb0fb4f, 0xeeb0fb4f, "scalar", true),
    ("move16", 0xeef00b40, 0xeef00b40, "scalar", false),
    ("move_source16", 0xeeb00b60, 0xeeb00b60, "scalar", false),
    ("immediate15", 0xeeb7fb08, 0xeeb7fb08, "scalar", true),
    ("compare_zero15", 0xeeb5fb40, 0xeeb5fb40, "scalar", true),
    ("from_single15", 0xeeb7faef, 0xeeb7faef, "scalar", true),
    ("from_single16", 0xeef70aef, 0xeef70aef, "scalar", false),
    ("to_single15", 0xeef7fbcf, 0xeef7fbcf, "scalar", true),
    ("to_single16", 0xeef7fbe0, 0xeef7fbe0, "scalar", false),
    ("round_to_integer15", 0xfefcfbcf, 0xfefcfbcf, "scalar", true),
    (
        "round_to_integer16",
        0xfefcfbe0,
        0xfefcfbe0,
        "scalar",
        false,
    ),
    ("fixed15", 0xeebefbef, 0xeebefbef, "scalar", true),
    ("fixed16", 0xeefe0bef, 0xeefe0bef, "scalar", false),
    ("pair15", 0xec421b1f, 0xec421b1f, "transfer", true),
    ("pair16", 0xec421b30, 0xec421b30, "transfer", false),
    ("pair_out16", 0xec521b30, 0xec521b30, "transfer", false),
    ("lane15", 0xee2f1b10, 0xee2f1b10, "transfer", true),
    ("lane16", 0xee201b90, 0xee201b90, "transfer", false),
    ("load15", 0xed90fb00, 0xed90fb00, "transfer", true),
    ("load16", 0xedd00b00, 0xedd00b00, "transfer", false),
    ("store16", 0xedc00b00, 0xedc00b00, "transfer", false),
    ("block15", 0xecb0fb02, 0xecb0fb02, "block", true),
    ("block_cross_load", 0xecb0fb04, 0xecb0fb04, "block", false),
    ("block_cross_store", 0xeca0fb04, 0xeca0fb04, "block", false),
    ("block_all16", 0xecb00b20, 0xecb00b20, "block", true),
    ("single_block", 0xecb0fa02, 0xecb0fa02, "block", true),
    ("vector_fp", 0xf2000d40, 0xef000d40, "simd", false),
    ("vector_integer", 0xf2000840, 0xef000840, "simd", false),
    ("vector_load", 0xf420070f, 0xf920070f, "simd", false),
    ("vector_duplicate", 0xeea01b10, 0xeea01b10, "simd", false),
];

fn campaign(family: &str, restricted: bool, access_denied: bool) {
    for &(name, arm, thumb, group, allowed) in CASES {
        if group != family || access_denied && allowed {
            continue;
        }
        for is_thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.vfp.mvfr0 = if restricted { 0x1011_0221 } else { 0x1011_0222 };
            cpu.vfp.mvfr1 = if restricted { 0x1100_0011 } else { 0x1111_1111 };
            cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
            if access_denied {
                cpu.cp15.cpacr = Cpacr::from_bits(0);
                cpu.cp15.hcptr = 1 << 10;
                cpu.vfp.fpexc = 0;
            }
            cpu.regs[0] = 0x400;
            cpu.regs[1] = 0xdead_beef;
            cpu.regs[2] = 0x7654_3210;
            cpu.regs[15] = 0x100;
            cpu.cpsr.t = is_thumb;
            cpu.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
            let before = (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.vfp.fpscr.bits(),
                cpu.cpsr.to_u32(),
            );
            let mut memory = FlatMemory::new(4096, 0);
            let insn = if is_thumb {
                ThumbDecoder::decode_32bit(thumb).unwrap()
            } else {
                Aarch32Decoder::decode(arm).unwrap()
            };
            let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
            if restricted && !allowed {
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "{name}, thumb={is_thumb}: {result:?}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.dregs,
                        cpu.vfp.fpscr.bits(),
                        cpu.cpsr.to_u32()
                    ),
                    before,
                    "{name}"
                );
                assert!(
                    (0..4096)
                        .step_by(4)
                        .all(|a| memory.read_word(a).unwrap() == 0),
                    "{name}: rejected store modified memory"
                );
            } else {
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{name}, thumb={is_thumb}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn d16_scalar_sources_destinations_and_opcode_bits() {
    campaign("scalar", true, false);
}
#[test]
fn d16_register_memory_and_core_transfers() {
    campaign("transfer", true, false);
}
#[test]
fn d16_block_transfer_end_is_checked_before_writeback() {
    campaign("block", true, false);
}
#[test]
fn d16_profile_does_not_execute_advanced_simd() {
    campaign("simd", true, false);
}
#[test]
fn full_register_bank_preserves_all_positive_controls() {
    for family in ["scalar", "transfer", "block", "simd"] {
        campaign(family, false, false);
    }
}

#[test]
fn absent_registers_precede_fp_access_traps() {
    for family in ["scalar", "transfer", "block", "simd"] {
        campaign(family, true, true);
    }
}

#[test]
fn absent_and_reserved_register_banks_do_not_enable_fp() {
    for field in [0, 3, 15] {
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | field;
            cpu.cpsr.t = thumb;
            let mut memory = FlatMemory::new(4096, 0);
            let insn = if thumb {
                ThumbDecoder::decode_32bit(CASES[0].2).unwrap()
            } else {
                Aarch32Decoder::decode(CASES[0].1).unwrap()
            };
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&insn),
                ExecResult::Undefined
            ));
        }
    }
}

#[test]
fn mixed_width_full_bank_executes_all_controls_and_retires_once() {
    for &(name, arm, thumb, _, _) in CASES {
        for (raw, is_thumb) in [(arm, false), (thumb, true)] {
            let mut config = AArch64Config::v8_2();
            config.initial_el = 3;
            config.gic_config = None;
            let mut cpu = AArch64Cpu::new(config, Box::new(Memory64::new(0, 0x4000)));
            let mut state = cpu.export_sregs();
            let sys = &mut state.execution.as_mut().unwrap().sysregs;
            sys.scr_el3 = 0;
            sys.hcr_el2 = 0;
            sys.el1.cpacr = 3 << 20;
            sys.impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(), 1 << 30);
            cpu.import_sregs(&state).unwrap();
            cpu.set_pstate_bits(0x1d3 | if is_thumb { 32 } else { 0 })
                .unwrap();
            cpu.set_pc(0x100);
            cpu.set_x(0, 0x800);
            cpu.set_x(1, 0xdead_beef);
            cpu.set_x(2, 0x7654_3210);
            let bytes = if is_thumb {
                let high = ((raw >> 16) as u16).to_le_bytes();
                let low = (raw as u16).to_le_bytes();
                [high[0], high[1], low[0], low[1]]
            } else {
                raw.to_le_bytes()
            };
            cpu.write_memory(0x100, &bytes).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{name}");
            assert_eq!(cpu.get_pc(), 0x104, "{name}");
            assert_eq!(cpu.instruction_count(), 1, "{name}");
        }
    }
}
