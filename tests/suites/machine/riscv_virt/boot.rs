//! End-to-end integration test: a bare-metal RISC-V program runs through the
//! VMM emulator backend (`RiscVVcpu`), producing UART console output via MMIO
//! and halting via `ecall`. This exercises the full wiring of the
//! `rax::isa::riscv` interpreter into rax as a bootable architecture.

mod clint;
mod startup;

use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use rax::backend::emulator::riscv::RiscVVcpu;
use rax::vm::vcpu::{CpuState, RiscVRegisters, VCpu, VcpuExit};

const CODE_ADDR: u64 = 0x1000;
const UART_BASE: u64 = 0x1000_0000;

// RV64I instruction encoders.
fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | 0x37
}
fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}
fn sb(rs2: u32, rs1: u32, imm: i32) -> u32 {
    let u = (imm as u32) & 0xfff;
    ((u >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (0 << 12) | ((u & 0x1f) << 7) | 0x23
}
const ECALL: u32 = 0x0000_0073;

fn run_program(code: &[u32]) -> (Vec<u8>, RiscVRegisters) {
    let mem =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 64 * 1024)]).unwrap());
    let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
    mem.write_slice(&bytes, GuestAddress(CODE_ADDR)).unwrap();

    let mut vcpu = RiscVVcpu::new(0, mem.clone());
    let mut regs = RiscVRegisters::default();
    regs.pc = CODE_ADDR;
    vcpu.set_state(&CpuState::riscv(regs)).unwrap();

    let mut output = Vec::new();
    loop {
        match vcpu.run().unwrap() {
            VcpuExit::Shutdown => break,
            VcpuExit::MmioWrite { addr, data } => {
                // Writes to the 16550 THR (UART base + 0) are console bytes.
                if addr == UART_BASE {
                    output.extend_from_slice(&data);
                }
            }
            VcpuExit::Hlt => break,
            other => panic!("unexpected vcpu exit: {other:?}"),
        }
    }

    let state = match vcpu.get_state().unwrap() {
        CpuState::RiscV(s) => s.regs,
        _ => panic!("expected riscv state"),
    };
    (output, state)
}

#[test]
fn boots_and_prints_via_uart() {
    // x10 = UART base; write 'R','V'; compute x13 = 7 + 35 = 42; ecall.
    let prog = [
        lui(10, UART_BASE as u32 >> 12), // x10 = 0x10000000
        addi(11, 0, b'R' as i32),
        sb(11, 10, 0),
        addi(11, 0, b'V' as i32),
        sb(11, 10, 0),
        addi(12, 0, 7),
        addi(13, 12, 35),
        ECALL,
    ];
    let (output, regs) = run_program(&prog);
    assert_eq!(output, b"RV", "UART console output");
    assert_eq!(regs.x[12], 7);
    assert_eq!(regs.x[13], 42, "x13 = 7 + 35");
    assert_eq!(regs.x[10], UART_BASE, "x10 holds UART base");
}

#[test]
fn loads_and_stores_to_ram() {
    // Store a doubleword to RAM and read it back into a register.
    // x5 = 0x2000; x6 = 0x1234; sd x6, 0(x5); ld x7, 0(x5).
    fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let u = (imm as u32) & 0xfff;
        ((u >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((u & 0x1f) << 7) | 0x23
    }
    fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
        (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
    }
    let prog = [
        lui(5, 2),         // x5 = 0x2000
        addi(6, 0, 0x123), // x6 = 0x123
        sd(6, 5, 0),
        ld(7, 5, 0),
        ECALL,
    ];
    let (_out, regs) = run_program(&prog);
    assert_eq!(regs.x[7], 0x123, "loaded value matches stored value");
}

#[test]
fn delegated_supervisor_software_interrupt_preempts_fetch() {
    use rax::isa::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit, cpu::Priv};
    let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(FlatMemory::new(0, 4096)));
    cpu.csr_write(0x303, 2).unwrap(); // mideleg.SSI
    cpu.csr_write(0x304, 2).unwrap(); // mie.SSIE
    cpu.csr_write(0x344, 2).unwrap(); // mip.SSIP
    cpu.csr_write(0x100, 2).unwrap(); // sstatus.SIE
    cpu.set_privilege(Priv::Supervisor);
    cpu.set_pc(0x2000); // The pending interrupt must win over the fetch fault.

    assert_eq!(cpu.step(), RiscVExit::Continue);
    assert_eq!(cpu.privilege(), Priv::Supervisor);
    assert_eq!(cpu.pc(), 0);
    assert_eq!(cpu.csr_read(0x141), Ok(0x2000));
    assert_eq!(cpu.csr_read(0x142), Ok((1 << 63) | 1));
    assert_eq!(cpu.instret(), 0);
}

#[test]
fn interrupt_target_and_priority_match_at_interpreter_and_jit_entries() {
    use Priv::{Machine, Supervisor, User};
    use rax::isa::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit, Xlen, cpu::Priv};
    const SSI: u64 = 1 << 1;
    const STI: u64 = 1 << 5;
    const MTI: u64 = 1 << 7;
    const SEI: u64 = 1 << 9;
    const SIE: u64 = 1 << 1;
    const MIE: u64 = 1 << 3;
    const SPIE: u64 = 1 << 5;
    const SPP: u64 = 1 << 8;
    const PC: u64 = 0x100;

    let entries: &[fn(&mut RiscVCpu) -> RiscVExit] = &[
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

    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        let high = 1 << (xlen.bits() - 1);
        for entry in entries {
            for (origin, global, delegated, pending, expected) in [
                (Machine, MIE, SEI, SEI, None),
                (Supervisor, 0, SEI, SEI, None),
                (User, 0, SEI, SEI, Some((Supervisor, 9))),
                (
                    Supervisor,
                    SIE,
                    SSI | SEI | STI,
                    SSI | SEI | STI,
                    Some((Supervisor, 9)),
                ),
                (Supervisor, SIE, SSI | STI, SSI | STI, Some((Supervisor, 1))),
                (Supervisor, SIE, STI, STI, Some((Supervisor, 5))),
                (Supervisor, 0, 0, SEI, Some((Machine, 9))),
                (Supervisor, SIE, SEI, SEI | MTI, Some((Machine, 7))),
                (Machine, MIE, SSI, SSI | STI, Some((Machine, 5))),
            ] {
                let cfg = RiscVConfig {
                    xlen,
                    ..RiscVConfig::rv64gc()
                };
                let mut cpu = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 4096)));
                cpu.write_memory(PC, &0x0010_0093u32.to_le_bytes()).unwrap(); // addi x1,x0,1
                cpu.csr_write(0x105, 0x301).unwrap();
                cpu.csr_write(0x305, 0x401).unwrap();
                cpu.csr_write(0x142, 0x55).unwrap();
                cpu.csr_write(0x143, 0x66).unwrap();
                cpu.csr_write(0x300, global).unwrap();
                cpu.csr_write(0x303, delegated).unwrap();
                cpu.csr_write(0x304, pending).unwrap();
                cpu.csr_write(0x344, pending).unwrap();
                cpu.set_privilege(origin);
                cpu.set_pc(PC);

                assert_eq!(entry(&mut cpu), RiscVExit::Continue);
                assert_eq!(cpu.csr_read(0x344), Ok(pending));
                match expected {
                    None => {
                        assert_eq!(cpu.privilege(), origin);
                        assert_eq!(cpu.pc(), PC + 4);
                        assert_eq!(cpu.instret(), 1);
                        assert_eq!(cpu.x(1), 1);
                    }
                    Some((target, cause)) => {
                        assert_eq!(cpu.privilege(), target);
                        assert_eq!(cpu.instret(), 0);
                        assert_eq!(cpu.x(1), 0);
                        if target == Supervisor {
                            assert_eq!(cpu.pc(), 0x300 + 4 * cause);
                            assert_eq!(cpu.csr_read(0x141), Ok(PC));
                            assert_eq!(cpu.csr_read(0x142), Ok(high | cause));
                            assert_eq!(cpu.csr_read(0x143), Ok(0));
                            let status = if origin == Supervisor { SPP | SPIE } else { 0 };
                            assert_eq!(cpu.csr_read(0x100).unwrap() & (SPP | SPIE | SIE), status);
                            assert_eq!(cpu.csr_read(0x342), Ok(0));
                        } else {
                            assert_eq!(cpu.pc(), 0x400 + 4 * cause);
                            assert_eq!(cpu.csr_read(0x341), Ok(PC));
                            assert_eq!(cpu.csr_read(0x342), Ok(high | cause));
                            assert_eq!(cpu.csr_read(0x142), Ok(0x55));
                            assert_eq!(cpu.csr_read(0x143), Ok(0x66));
                        }
                    }
                }
            }
        }
    }
}
