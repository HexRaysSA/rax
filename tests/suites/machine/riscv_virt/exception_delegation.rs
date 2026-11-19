//! Synchronous delegation at direct and native-region entry points.
use rax::isa::riscv::cpu::Priv;
use rax::isa::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit, Xlen};

const PC: u64 = 0x100;
const MTVEC: u16 = 0x305;
const STVEC: u16 = 0x105;
const M_VECTOR: u64 = 0x300;
const S_VECTOR: u64 = 0x400;
const MEDELEG: u16 = 0x302;
const MSTATUS: u16 = 0x300;
const MEPC: u16 = 0x341;
const MCAUSE: u16 = 0x342;
const MTVAL: u16 = 0x343;
const SSTATUS: u16 = 0x100;
const SEPC: u16 = 0x141;
const SCAUSE: u16 = 0x142;
const STVAL: u16 = 0x143;
const ILLEGAL: u32 = 0xffff_ffff;
const ECALL: u32 = 0x0000_0073;
const SIE: u64 = 1 << 1;
const SPIE: u64 = 1 << 5;
const SPP: u64 = 1 << 8;
const M_TRAP_MASK: u64 = (3 << 11) | (1 << 7) | (1 << 3);
const ENTRY: &[fn(&mut RiscVCpu) -> RiscVExit] = &[
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

fn hart(xlen: Xlen, word: u32, privilege: Priv, enable: u64, deleg: u64) -> RiscVCpu {
    let config = RiscVConfig {
        xlen,
        ..RiscVConfig::rv64gc()
    };
    let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, 4096)));
    cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
    cpu.set_pc(PC);
    for (csr, value) in [
        (MTVEC, M_VECTOR | 1),
        (STVEC, S_VECTOR | 1),
        (MEDELEG, deleg),
        (MEPC, 0x240),
        (MCAUSE, 3),
        (MTVAL, 0x9a),
        (SSTATUS, enable),
    ] {
        cpu.csr_write(csr, value).unwrap();
    }
    cpu.set_privilege(privilege);
    cpu
}

#[test]
fn supervisor_illegal_delegation_delivers_direct_base_and_leaves_machine_state() {
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for entry in ENTRY {
            for privilege in [Priv::User, Priv::Supervisor] {
                for enable in [0, SIE] {
                    let mut cpu = hart(xlen, ILLEGAL, privilege, enable, 1 << 2);
                    let machine_status = cpu.csr_read(MSTATUS).unwrap() & M_TRAP_MASK;
                    let RiscVExit::Trap(trap) = entry(&mut cpu) else {
                        panic!("expected a synchronous trap");
                    };
                    assert_eq!(trap.cause, 2);
                    assert_eq!(cpu.pc(), S_VECTOR);
                    assert_eq!(cpu.privilege(), Priv::Supervisor);
                    assert_eq!(cpu.instret(), 0);
                    assert_eq!(cpu.csr_read(SEPC), Ok(PC));
                    assert_eq!(cpu.csr_read(SCAUSE), Ok(2));
                    assert_eq!(cpu.csr_read(STVAL), Ok(u64::from(ILLEGAL)));
                    let status = cpu.csr_read(SSTATUS).unwrap() & (SIE | SPIE | SPP);
                    let prior_priv = if privilege == Priv::Supervisor {
                        SPP
                    } else {
                        0
                    };
                    assert_eq!(status, prior_priv | ((enable != 0) as u64 * SPIE));
                    assert_eq!(cpu.csr_read(MEPC), Ok(0x240));
                    assert_eq!(cpu.csr_read(MCAUSE), Ok(3));
                    assert_eq!(cpu.csr_read(MTVAL), Ok(0x9a));
                    assert_eq!(cpu.csr_read(MSTATUS).unwrap() & M_TRAP_MASK, machine_status);
                }
            }
        }
    }
}

#[test]
fn machine_illegal_never_delegates_and_cleared_bit_uses_machine_base() {
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for entry in ENTRY {
            for (privilege, deleg) in [(Priv::Machine, 1 << 2), (Priv::Supervisor, 0)] {
                let mut cpu = hart(xlen, ILLEGAL, privilege, SIE, deleg);
                assert!(matches!(entry(&mut cpu), RiscVExit::Trap(_)));
                assert_eq!(cpu.pc(), M_VECTOR);
                assert_eq!(cpu.privilege(), Priv::Machine);
                assert_eq!(cpu.instret(), 0);
                assert_eq!(cpu.csr_read(MEPC), Ok(PC));
                assert_eq!(cpu.csr_read(MCAUSE), Ok(2));
            }
        }
    }
}

#[test]
fn delivering_user_ecall_honors_delegation_and_preserves_embedder_exit() {
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for entry in ENTRY {
            let mut cpu = hart(xlen, ECALL, Priv::User, SIE, 1 << 8);
            assert_eq!(entry(&mut cpu), RiscVExit::Ecall);
            assert_eq!(cpu.pc(), PC);
            assert_eq!(cpu.instret(), 0);
            cpu.deliver_ecall_trap();
            assert_eq!(cpu.pc(), S_VECTOR);
            assert_eq!(cpu.privilege(), Priv::Supervisor);
            assert_eq!(cpu.csr_read(SEPC), Ok(PC));
            assert_eq!(cpu.csr_read(SCAUSE), Ok(8));
            assert_eq!(cpu.csr_read(STVAL), Ok(0));
            assert_eq!(cpu.csr_read(MEPC), Ok(0x240));
        }
    }
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn native_region_delegates_a_precise_load_fault_after_the_retired_prefix() {
    use rax::isa::riscv::Trap;
    use rax::smir::optimize::OptLevel;

    const ADDI: u32 = 0x0072_8293; // addi x5,x5,7
    const LW: u32 = 0x0000_a283; // lw x5,0(x1)
    const ADDRESS: u64 = 0x1000; // first byte beyond the mapping
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        for level in [OptLevel::O0, OptLevel::O2] {
            let mut cpu = hart(xlen, ADDI, Priv::Supervisor, SIE, 1 << 5);
            cpu.write_memory(PC + 4, &LW.to_le_bytes()).unwrap();
            cpu.set_x(1, ADDRESS);
            cpu.set_x(5, 10);
            assert_eq!(
                cpu.run_jit(2, level),
                RiscVExit::Trap(Trap {
                    cause: 5,
                    tval: ADDRESS,
                })
            );
            assert_eq!(cpu.jit_stats().native_executions, 1);
            assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0);
            assert_eq!(cpu.pc(), S_VECTOR);
            assert_eq!(cpu.csr_read(SEPC), Ok(PC + 4));
            assert_eq!(cpu.csr_read(SCAUSE), Ok(5));
            assert_eq!(cpu.csr_read(STVAL), Ok(ADDRESS));
            assert_eq!(cpu.x(5), 17);
            assert_eq!(cpu.instret(), 1);
        }
    }
}
