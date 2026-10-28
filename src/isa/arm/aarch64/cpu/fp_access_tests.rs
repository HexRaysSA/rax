//! A denied instruction never commits a retirement, even when delivery succeeds.
use super::*;

const ENTRY: u64 = 0x100;
const DATA: u64 = 0x800;
const VBAR: u64 = 0x1000;
const WORDS: [u32; 9] = [
    0x1e22_2820, // FADD S0,S1,S2
    0x4e22_8420, // ADD V0.16B,V1.16B,V2.16B
    0x3dc0_0060, // LDR Q0,[X3]
    0x3d80_0060, // STR Q0,[X3]
    0xacc1_0860, // LDP Q0,Q2,[X3],#32
    0xadbf_0860, // STP Q0,Q2,[X3,#-32]!
    0x4cdf_7060, // LD1 {V0.16B},[X3],#16
    0x4c9f_7060, // ST1 {V0.16B},[X3],#16
    0x9e66_0020, // FMOV X0,D1
];

fn cpu(word: u32, el: u8, fpen: u64) -> AArch64Cpu {
    let config = AArch64Config {
        initial_el: el,
        gic_config: None,
        ..Default::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x4000)));
    cpu.pc = ENTRY;
    cpu.sp_sel = el != 0;
    cpu.btype = 2;
    cpu.v.fill(0x3f80_0000_3f80_0000_3f80_0000_3f80_0000);
    cpu.x[0] = 0xdead;
    cpu.x[3] = DATA;
    cpu.sysregs.el1.cpacr = fpen << 20;
    cpu.sysregs.el1.vbar = VBAR;
    cpu.sysregs.el1.elr = 0xfeed;
    cpu.sysregs.el1.esr = 0xbeef;
    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
    cpu.write_memory(DATA - 32, &[0xa5; 96]).unwrap();
    cpu
}

#[test]
fn direct_fp_denials_preserve_fault_pc_registers_memory_and_all_counters() {
    for el in [0, 1] {
        for fpen in 0..4 {
            for word in WORDS {
                let mut cpu = cpu(word, el, fpen);
                let permitted = fpen == 3 || (el == 1 && fpen == 1);
                let registers = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
                let memory = cpu.read_memory(DATA - 32, 96).unwrap();
                let result = cpu.step();
                if permitted {
                    assert_eq!(result.unwrap(), CpuExit::Continue, "{word:08x}");
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY + 4, 1, 1));
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(ArmError::ArchitecturalException {
                                ec: 7,
                                iss: 0,
                                target_el: None
                            })
                        ),
                        "{word:08x} EL{el} FPEN{fpen}"
                    );
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
                        registers
                    );
                    assert_eq!(cpu.read_memory(DATA - 32, 96).unwrap(), memory);
                    assert_eq!((cpu.sysregs.el1.elr, cpu.sysregs.el1.esr), (0xfeed, 0xbeef));
                }
            }
        }
    }
}

#[test]
fn system_fp_delivery_preserves_the_fault_spsr_and_retires_no_instruction() {
    for el in [0, 1] {
        for word in WORDS {
            for diagnostic in [false, true] {
                let mut cpu = cpu(word, el, 0);
                let pstate = cpu.pstate_bits();
                let before = cpu.v;
                let result = cpu.step_system_interpreted(diagnostic);
                if diagnostic {
                    assert!(matches!(
                        result,
                        Err(ArmError::ArchitecturalException { ec: 7, .. })
                    ));
                    assert_eq!(cpu.pc, ENTRY);
                    assert_eq!(cpu.pstate_bits(), pstate);
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.pc, VBAR + if el == 0 { 0x400 } else { 0x200 });
                    assert_eq!(cpu.sysregs.el1.elr, ENTRY);
                    assert_eq!(cpu.sysregs.el1.spsr, pstate);
                    assert_eq!(cpu.sysregs.el1.esr, (7 << 26) | (1 << 25));
                }
                assert_eq!(cpu.v, before);
                assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
                // This existing modeled system counter advances per attempt,
                // independently of the scheduler's retired-instruction clock.
                assert_eq!(cpu.sysregs.cntpct_el0, 16);
            }
        }
    }
}

#[test]
fn denied_fp_does_not_touch_unmapped_operands_or_overflow_maximum_counters() {
    for word in WORDS {
        let mut cpu = cpu(word, 1, 0);
        cpu.x[3] = 0x8000;
        cpu.insn_count = u64::MAX;
        cpu.cycle_count = u64::MAX;
        for _ in 0..2 {
            assert!(matches!(
                cpu.step(),
                Err(ArmError::ArchitecturalException { ec: 7, .. })
            ));
            assert_eq!(cpu.pc, ENTRY);
            assert_eq!((cpu.insn_count, cpu.cycle_count), (u64::MAX, u64::MAX));
        }
        cpu.reset();
        cpu.pc = ENTRY;
        cpu.sysregs.el1.cpacr = 3 << 20;
        cpu.x[3] = DATA;
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.insn_count, cpu.cycle_count), (1, 1));
    }
}

#[test]
fn delivering_fp_denial_clears_the_exclusive_monitor_without_retirement() {
    let mut cpu = cpu(WORDS[0], 1, 0);
    cpu.memory.mark_exclusive(DATA, 8);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException { ec: 7, .. })
    ));
    assert!(cpu.memory.check_exclusive(DATA, 8));
    assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
    assert!(!cpu.memory.check_exclusive(DATA, 8));
    assert_eq!(cpu.insn_count, 0);
}
