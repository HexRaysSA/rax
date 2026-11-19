use rax::isa::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit, Xlen};

const MIP: u16 = 0x344;
const SEIP: u64 = 1 << 9;
const SSIP: u64 = 1 << 1;
const MACHINE_PENDING: u64 = (1 << 3) | (1 << 7) | (1 << 11);
const PC: u64 = 0x100;

const ENTRY_POINTS: &[fn(&mut RiscVCpu) -> RiscVExit] = &[
    RiscVCpu::step,
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    |cpu| cpu.step_jit(rax::smir::optimize::OptLevel::O0),
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    |cpu| cpu.step_jit(rax::smir::optimize::OptLevel::O2),
];

fn hart(xlen: Xlen, instruction: u32) -> RiscVCpu {
    let cfg = RiscVConfig {
        xlen,
        ..RiscVConfig::rv64gc()
    };
    let mut cpu = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 4096)));
    cpu.write_memory(PC, &instruction.to_le_bytes()).unwrap();
    cpu.set_pc(PC);
    cpu
}

#[test]
fn external_interrupt_input_and_software_injection_are_independent_in_csr_operations() {
    // Zicsr instruction words use x5 as the destination and x6 as the
    // variable mask. Immediate forms use zimm=2 (SSIP, which leaves SEIP
    // alone for set/clear). rd=x0 and rs1=x0 are exercised separately.
    const CSRRW: u32 = 0x3443_12f3;
    const CSRRS: u32 = 0x3443_22f3;
    const CSRRC: u32 = 0x3443_32f3;
    const CSRRWI: u32 = 0x3441_52f3;
    const CSRRSI: u32 = 0x3441_62f3;
    const CSRRCI: u32 = 0x3441_72f3;
    const READ_ONLY: u32 = 0x3440_22f3;
    const WRITE_ONLY: u32 = 0x3443_1073;
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for (entry_index, entry) in ENTRY_POINTS.iter().enumerate() {
            for software in [0, SEIP] {
                for line in [false, true] {
                    for (word, source, expected_software) in [
                        (CSRRS, SSIP, software),
                        (CSRRS, SEIP, SEIP),
                        (CSRRC, SSIP, software),
                        (CSRRC, SEIP, 0),
                        (CSRRW, 0, 0),
                        (CSRRW, SEIP, SEIP),
                        (CSRRSI, 0, software),
                        (CSRRCI, 0, software),
                        (CSRRWI, 0, 0),
                        (READ_ONLY, 0, software),
                        (WRITE_ONLY, 0, 0),
                    ] {
                        let context = (xlen, entry_index, word, software, line, source);
                        let mut cpu = hart(xlen, word);
                        cpu.csr_write(0x303, SEIP).unwrap();
                        cpu.csr_write(MIP, software).unwrap();
                        cpu.set_interrupt_pending(SEIP, line);
                        cpu.set_x(5, u64::MAX);
                        cpu.set_x(6, source);
                        let visible_line = if line { SEIP } else { 0 };
                        assert_eq!(
                            cpu.csr_read(0x144),
                            Ok(software | visible_line),
                            "{context:?}"
                        );
                        assert_eq!(entry(&mut cpu), RiscVExit::Continue, "{context:?}");
                        assert_eq!(cpu.pc(), PC + 4, "{context:?}");
                        assert_eq!(cpu.instret(), 1, "{context:?}");
                        let old = if word == WRITE_ONLY {
                            xlen.mask()
                        } else {
                            software | visible_line
                        };
                        assert_eq!(cpu.x(5), old, "{context:?}");
                        assert_eq!(
                            cpu.csr_read(MIP).unwrap() & SEIP,
                            expected_software | visible_line,
                            "{context:?}"
                        );
                        let exported = cpu.export_csrs().into_iter().find(|&(n, _)| n == MIP);
                        assert_eq!(exported.unwrap().1 & SEIP, expected_software, "{context:?}");
                        cpu.set_interrupt_pending(SEIP, false);
                        assert_eq!(cpu.csr_read(0x144), Ok(expected_software), "{context:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn external_interrupt_input_cannot_be_forged_or_cleared_by_guest_machine_csr_writes() {
    const CSRRW: u32 = 0x3443_12f3; // csrrw x5,mip,x6
    const CSRRS: u32 = 0x3443_22f3; // csrrs x5,mip,x6
    const CSRRC: u32 = 0x3443_32f3; // csrrc x5,mip,x6
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for (entry_index, entry) in ENTRY_POINTS.iter().enumerate() {
            for (word, asserted, value) in [
                (CSRRW, 0, MACHINE_PENDING),
                (CSRRW, MACHINE_PENDING, 0),
                (CSRRS, 0, MACHINE_PENDING),
                (CSRRC, MACHINE_PENDING, MACHINE_PENDING),
            ] {
                let mut cpu = hart(xlen, word);
                cpu.set_interrupt_pending(asserted, true);
                cpu.set_x(6, value);
                assert_eq!(entry(&mut cpu), RiscVExit::Continue);
                assert_eq!(cpu.x(5), asserted);
                assert_eq!(
                    cpu.csr_read(MIP),
                    Ok(asserted),
                    "{xlen:?} entry {entry_index} word {word:#010x}"
                );
            }
        }
    }
}
