use super::*;
use crate::isa::riscv::{FlatMemory, decode};

const CODE: u64 = 0x100;
const TRAP_VECTOR: u64 = 0x200;
const TVM: u64 = 1 << 20;
const TW: u64 = 1 << 21;
const SATP: u16 = 0x180;
const WFI: u32 = 0x1050_0073;
const READ_SATP: u32 = 0x1800_2273; // csrrs x4, satp, x0
const WRITE_SATP: u32 = 0x1800_9073; // csrrw x0, satp, x1

fn hart(cfg: RiscVConfig, origin: Priv, status: u64, word: u32) -> RiscVCpu {
    let mut cpu = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 4096)));
    cpu.set_pc(CODE);
    cpu.write_memory(CODE, &word.to_le_bytes()).unwrap();
    cpu.csr_write(Csr::Mstatus as u16, status).unwrap();
    cpu.csr_write(Csr::Mtvec as u16, TRAP_VECTOR).unwrap();
    cpu.set_privilege(origin);
    cpu
}

fn assert_illegal(cpu: &mut RiscVCpu, word: u32) {
    assert_eq!(cpu.step(), RiscVExit::Trap(Trap::illegal(word)));
    assert_eq!(cpu.pc(), TRAP_VECTOR);
    assert_eq!(cpu.csr_read(Csr::Mepc as u16), Ok(CODE));
    assert_eq!(cpu.csr_read(Csr::Mcause as u16), Ok(cause::ILLEGAL_INSTR));
    assert_eq!(cpu.csr_read(Csr::Mtval as u16), Ok(u64::from(word)));
    assert_eq!(cpu.instret(), 0);
}

fn assert_retired(cpu: &mut RiscVCpu, exit: RiscVExit) {
    assert_eq!(cpu.step(), exit);
    assert_eq!(cpu.pc(), CODE + 4);
    assert_eq!(cpu.instret(), 1);
}

#[test]
fn translation_fences_obey_privilege_and_tvm() {
    let fences = [
        (0x1200_0073, true),  // sfence.vma
        (0x1600_0073, true),  // sinval.vma
        (0x1800_0073, false), // sfence.w.inval
        (0x1810_0073, false), // sfence.inval.ir
        (0x2200_0073, false), // hfence.vvma
        (0x2600_0073, false), // hinval.vvma
        (0x6200_0073, true),  // hfence.gvma
        (0x6600_0073, true),  // hinval.gvma
    ];
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        let cfg = RiscVConfig {
            xlen,
            ..RiscVConfig::rv64gc()
        };
        for (word, intercepted) in fences {
            assert_illegal(&mut hart(cfg, Priv::User, 0, word), word);
            assert_retired(
                &mut hart(cfg, Priv::Supervisor, 0, word),
                RiscVExit::Continue,
            );
            assert_retired(
                &mut hart(cfg, Priv::Machine, TVM, word),
                RiscVExit::Continue,
            );
            let mut supervisor = hart(cfg, Priv::Supervisor, TVM, word);
            if intercepted {
                assert_illegal(&mut supervisor, word);
            } else {
                assert_retired(&mut supervisor, RiscVExit::Continue);
            }
        }
    }
}

#[test]
fn hypervisor_invalidation_requires_both_extensions() {
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for h in [false, true] {
            for svinval in [false, true] {
                let isa = Isa {
                    h,
                    svinval,
                    ..Isa::rv64gc()
                };
                for word in [0x2600_0073, 0x6600_0073] {
                    assert_eq!(decode(word, xlen, &isa).is_illegal(), !(h && svinval));
                }
            }
        }
    }
}

#[test]
fn standard_satp_is_bare_and_checks_reads_and_writes_before_side_effects() {
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        let cfg = RiscVConfig {
            xlen,
            ..RiscVConfig::rv64gc()
        };
        for word in [READ_SATP, WRITE_SATP] {
            for (origin, status) in [(Priv::User, 0), (Priv::Supervisor, TVM)] {
                let mut cpu = hart(cfg, origin, status, word);
                cpu.set_x(1, u64::MAX);
                cpu.set_x(4, 127);
                assert_illegal(&mut cpu, word);
                assert_eq!(cpu.x(4), 127);
                assert_eq!(cpu.csr_read(SATP), Ok(0));
            }
            for (origin, status) in [(Priv::Supervisor, 0), (Priv::Machine, TVM)] {
                let mut cpu = hart(cfg, origin, status, word);
                cpu.set_x(1, u64::MAX);
                cpu.set_x(4, 127);
                assert_retired(&mut cpu, RiscVExit::Continue);
                assert_eq!(cpu.x(4), if word == READ_SATP { 0 } else { 127 });
                assert_eq!(cpu.csr_read(SATP), Ok(0));
            }
        }
    }
}

#[test]
fn xsoteria_sparse_csr_survives_a_checkpoint() {
    let cfg = RiscVConfig {
        xlen: Xlen::Rv32,
        isa: Isa::ti50(),
    };
    let mut cpu = hart(cfg, Priv::Supervisor, TVM, READ_SATP);
    cpu.csr_write(SATP, 0x1234_5678).unwrap();
    let state = cpu.checkpoint_state();
    cpu.csr_write(SATP, 0).unwrap();
    state.install(&mut cpu);
    assert_retired(&mut cpu, RiscVExit::Continue);
    assert_eq!(cpu.x(4), 0x1234_5678);
}

#[test]
fn wfi_admission_precedes_wakeup_and_survives_a_checkpoint() {
    let cfg = RiscVConfig::rv64gc();
    const SSIP: u64 = 1 << cause::INT_S_SOFTWARE;
    assert_illegal(&mut hart(cfg, Priv::User, 0, WFI), WFI);
    assert_retired(&mut hart(cfg, Priv::Supervisor, 0, WFI), RiscVExit::Wfi);
    assert_retired(&mut hart(cfg, Priv::Machine, TW, WFI), RiscVExit::Wfi);

    // The hart can see this interrupt for wakeup while SIE masks delivery.
    let mut cpu = hart(cfg, Priv::Supervisor, TVM | TW, WFI);
    cpu.csr_write(Csr::Mideleg as u16, SSIP).unwrap();
    cpu.csr_write(Csr::Mie as u16, SSIP).unwrap();
    cpu.csr_write(Csr::Mip as u16, SSIP).unwrap();
    let state = cpu.checkpoint_state();
    cpu.csr_write(Csr::Mstatus as u16, 0).unwrap();
    assert_retired(&mut cpu, RiscVExit::Continue);
    state.clone().install(&mut cpu);
    assert_illegal(&mut cpu, WFI);
    assert_eq!(cpu.csr_read(Csr::Mip as u16), Ok(SSIP));

    state.install(&mut cpu);
    cpu.write_memory(CODE, &READ_SATP.to_le_bytes()).unwrap();
    assert_illegal(&mut cpu, READ_SATP);
}
