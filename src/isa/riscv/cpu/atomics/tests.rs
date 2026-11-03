//! RISC-V Privileged Architecture 1.13, Machine Cause table: AMO failures
//! report store/AMO causes, including a failure during the read phase.

use super::*;
use crate::isa::riscv::memory::{FlatMemory, MemError, MemResult, Memory};

const PC: u64 = 0x100;
const SENTINEL: u64 = 0xfeed_face;

#[derive(Debug)]
struct ReadOnlyAtomicMemory(FlatMemory);

impl Memory for ReadOnlyAtomicMemory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> MemResult<()> {
        self.0.read(address, bytes)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> MemResult<()> {
        Err(MemError::OutOfBounds {
            addr: address,
            size: bytes.len(),
        })
    }

    fn probe(&self, address: u64, size: usize, write: bool) -> MemResult<()> {
        if write {
            return Err(MemError::OutOfBounds {
                addr: address,
                size,
            });
        }
        self.0.probe(address, size, false)
    }
}

#[test]
fn atomic_admission_compare_miss_still_requires_write_access() {
    // Unprivileged ISA 20250508,15.1: AMOCAS always needs write permission.
    // AMOCAS.W a1,a2,(a0), independently assembled with LLVM 23.
    let mut memory = FlatMemory::new(0, 4096);
    memory.write_u32(PC, 0x28c5_25af).unwrap();
    let mut cpu = RiscVCpu::new(
        RiscVConfig::rv64gc(),
        Box::new(ReadOnlyAtomicMemory(memory)),
    );
    cpu.set_pc(PC);
    cpu.set_x(10, 0x200);
    cpu.set_x(11, 1); // Comparison misses the zero-valued RAM operand.
    cpu.set_x(12, 2);
    let observed = cpu.step();
    assert!(
        matches!(observed, RiscVExit::Trap(t) if t.cause == cause::STORE_ACCESS_FAULT),
        "failed comparison must still check write access: {observed:?}"
    );
    assert_eq!(cpu.x(11), 1);
    assert_eq!(cpu.instret(), 0);
}

#[test]
fn atomic_admission_rv32_zacas_accepts_even_doubleword_pairs() {
    // AMOCAS.D x6,x8,(x10). Section15.1 defines this RV32 register-pair form.
    let word = 0x2885_332f;
    assert_eq!(
        crate::isa::riscv::decode::decode(word, Xlen::Rv32, &Isa::rv64gc()).op,
        Op::AmocasD
    );
}

fn instruction(funct5: u32, width: u32, ordering: u32) -> u32 {
    (funct5 << 27) | (ordering << 25) | (2 << 20) | (1 << 15) | (width << 12) | (6 << 7) | 0x2f
}

fn cpu(word: u32, address: u64) -> RiscVCpu {
    let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(FlatMemory::new(0, 0x1000)));
    cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
    cpu.set_pc(PC);
    cpu.set_x(1, address);
    cpu.set_x(2, 1);
    cpu.set_x(6, SENTINEL);
    cpu.set_x(7, SENTINEL);
    cpu
}

fn assert_fault(cpu: &mut RiscVCpu, expected_cause: u64, address: u64) {
    let RiscVExit::Trap(trap) = cpu.step() else {
        panic!("expected a trap");
    };
    assert_eq!(trap.cause, expected_cause);
    assert_eq!(trap.tval, address);
    assert_eq!(cpu.csr_read(0x342).unwrap(), expected_cause);
    assert_eq!(cpu.csr_read(0x341).unwrap(), PC);
    assert_eq!(cpu.x(6), SENTINEL);
    assert_eq!(cpu.x(7), SENTINEL);
}

#[test]
fn amo_read_failures_are_store_faults() {
    for operation in [0, 1, 4, 8, 12, 16, 20, 24, 28] {
        for width in [2, 3] {
            for ordering in 0..4 {
                let mut cpu = cpu(instruction(operation, width, ordering), 0x2000);
                assert_fault(&mut cpu, cause::STORE_ACCESS_FAULT, 0x2000);
            }
        }
    }
}

#[test]
fn amocas_read_failures_are_store_faults() {
    for width in [2, 3, 4] {
        for ordering in 0..4 {
            let mut cpu = cpu(instruction(5, width, ordering), 0x2000);
            assert_fault(&mut cpu, cause::STORE_ACCESS_FAULT, 0x2000);
        }
    }
}

#[test]
fn atomic_alignment_faults_preserve_destinations() {
    for operation in [0, 1, 4, 5, 8, 12, 16, 20, 24, 28] {
        for width in [2, 3] {
            let mut cpu = cpu(instruction(operation, width, 0), 0x201);
            assert_fault(&mut cpu, cause::STORE_MISALIGNED, 0x201);
        }
    }
    let mut cpu = cpu(instruction(5, 4, 0), 0x208);
    assert_fault(&mut cpu, cause::STORE_MISALIGNED, 0x208);
}

#[test]
fn lr_access_failures_remain_load_faults() {
    for width in [2, 3] {
        // LR requires rs2=x0.
        let word = instruction(2, width, 0) & !(31 << 20);
        let mut cpu = cpu(word, 0x2000);
        assert_fault(&mut cpu, cause::LOAD_ACCESS_FAULT, 0x2000);
    }
}

#[test]
fn failed_sc_access_remains_a_store_fault() {
    for width in [2, 3] {
        let mut cpu = cpu(instruction(3, width, 0), 0x2000);
        assert_fault(&mut cpu, cause::STORE_ACCESS_FAULT, 0x2000);
    }
}

#[test]
fn amoadd_success_preserves_word_sign_extension() {
    for (width, old, expected) in [(2, 0x8000_0000, 0xffff_ffff_8000_0000), (3, 7, 7)] {
        let mut cpu = cpu(instruction(0, width, 0), 0x200);
        cpu.write_memory(0x200, &u64::to_le_bytes(old)).unwrap();
        assert!(matches!(cpu.step(), RiscVExit::Continue));
        assert_eq!(cpu.x(6), expected);
        assert_eq!(cpu.mem_read_u64(0x200).unwrap(), old + 1);
        assert_eq!(cpu.pc(), PC + 4);
    }
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn native_atomic_read_failures_are_store_faults() {
    use crate::smir::optimize::OptLevel;

    for (operation, width) in [(0, 2), (0, 3), (5, 2), (5, 3), (5, 4)] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut cpu = cpu(instruction(operation, width, 0), 0x2000);
            let RiscVExit::Trap(trap) = cpu.step_jit(level) else {
                panic!("expected an atomic access fault at {level:?}");
            };
            assert_eq!(trap.cause, cause::STORE_ACCESS_FAULT);
            assert_eq!(trap.tval, 0x2000);
            assert_eq!(cpu.csr_read(0x341).unwrap(), PC);
            assert_eq!(cpu.x(6), SENTINEL);
            assert_eq!(cpu.x(7), SENTINEL);
            assert_eq!(cpu.jit_stats().native_executions, 1);
            assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0);
        }
    }
}

#[derive(Debug)]
struct WriteRejectingAtomicMemory(FlatMemory);
impl Memory for WriteRejectingAtomicMemory {
    fn read(&self, addr: u64, bytes: &mut [u8]) -> MemResult<()> {
        self.0.read(addr, bytes)
    }
    fn write(&mut self, addr: u64, bytes: &[u8]) -> MemResult<()> {
        Err(MemError::OutOfBounds {
            addr,
            size: bytes.len(),
        })
    }
}

fn atomic_execution_modes() -> Vec<(bool, u8)> {
    let mut modes = vec![(false, 0)];
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    modes.extend([(true, 0), (true, 1), (true, 2)]);
    modes
}
fn atomic_test_step(cpu: &mut RiscVCpu, native: bool, optimization: u8) -> RiscVExit {
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if native {
        use crate::smir::optimize::OptLevel;
        let result = cpu.step_jit(match optimization {
            0 => OptLevel::O0,
            1 => OptLevel::O1,
            2 => OptLevel::O2,
            _ => unreachable!(),
        });
        assert_eq!(cpu.jit_stats().native_executions, 1);
        assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0);
        return result;
    }
    assert!(!native);
    let _ = optimization;
    cpu.step()
}

#[test]
fn cas_miss_faults_on_read_only_memory_with_and_without_a_probe_for_all_widths() {
    for (rv32, width) in [(true, 2), (true, 3), (false, 2), (false, 3), (false, 4)] {
        for accurate_probe in [false, true] {
            for (native, level) in atomic_execution_modes() {
                let mut memory = FlatMemory::new(0, 4096);
                memory.write_u32(PC, instruction(5, width, 0)).unwrap();
                let memory: Box<dyn Memory> = if accurate_probe {
                    Box::new(ReadOnlyAtomicMemory(memory))
                } else {
                    Box::new(WriteRejectingAtomicMemory(memory))
                };
                let config = if rv32 {
                    RiscVConfig::rv32(Isa::rv64gc())
                } else {
                    RiscVConfig::rv64gc()
                };
                let mut cpu = RiscVCpu::new(config, memory);
                cpu.set_pc(PC);
                cpu.set_x(1, 0x200);
                cpu.set_x(2, 9);
                cpu.set_x(3, 10);
                cpu.set_x(6, 1);
                cpu.set_x(7, 2);
                let result = atomic_test_step(&mut cpu, native, level);
                assert!(
                    matches!(result,RiscVExit::Trap(t) if t.cause==cause::STORE_ACCESS_FAULT && t.tval==0x200),
                    "rv32={rv32}/width={width}/probe={accurate_probe}/native={native}/{level}: {result:?}"
                );
                assert_eq!((cpu.x(6), cpu.x(7), cpu.instret()), (1, 2, 0));
            }
        }
    }
}

#[test]
fn rv32_doubleword_and_rv64_quadword_cas_preserve_pairs_zero_and_aliases() {
    for rv32 in [true, false] {
        let bits = if rv32 { 32 } else { 64 };
        let size = if rv32 { 8 } else { 16 };
        let width = if rv32 { 3 } else { 4 };
        let mask = if rv32 { u64::from(u32::MAX) } else { u64::MAX };
        for (rd, rs1, rs2) in [
            (6, 10, 8),
            (6, 10, 6),
            (6, 6, 8),
            (6, 7, 8),
            (6, 8, 8),
            (6, 9, 8),
            (0, 10, 8),
            (6, 10, 0),
            (0, 10, 0),
            (30, 10, 28),
        ] {
            for success in [false, true] {
                for (native, level) in atomic_execution_modes() {
                    let config = if rv32 {
                        RiscVConfig::rv32(Isa::rv64gc())
                    } else {
                        RiscVConfig::rv64gc()
                    };
                    let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, 4096)));
                    for reg in 1..32u8 {
                        cpu.set_x(reg, 0xfedc_ba98_8000_0000u64.wrapping_add(u64::from(reg)));
                    }
                    cpu.set_x(rs1, 0x200);
                    let before: [u64; 32] = std::array::from_fn(|i| cpu.x(i as u8));
                    let pair = |reg: u8| {
                        if reg == 0 {
                            0
                        } else {
                            u128::from(before[usize::from(reg)] & mask)
                                | (u128::from(before[usize::from(reg + 1)] & mask) << bits)
                        }
                    };
                    let expected = pair(rd);
                    let replacement = pair(rs2);
                    let old = if success { expected } else { expected ^ 1 };
                    let mut memory = [0xa5; 16];
                    memory[..size].copy_from_slice(&old.to_le_bytes()[..size]);
                    cpu.write_memory(0x200, &memory).unwrap();
                    let word = (5u32 << 27)
                        | (u32::from(rs2) << 20)
                        | (u32::from(rs1) << 15)
                        | (width << 12)
                        | (u32::from(rd) << 7)
                        | 0x2f;
                    cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
                    cpu.set_pc(PC);
                    assert_eq!(
                        atomic_test_step(&mut cpu, native, level),
                        RiscVExit::Continue,
                        "{rv32}/{rd}/{rs1}/{rs2}/{success}/{native}/{level}"
                    );
                    for reg in 1..32u8 {
                        let expected_reg = if rd != 0 && reg == rd {
                            old as u64 & mask
                        } else if rd != 0 && reg == rd + 1 {
                            (old >> bits) as u64 & mask
                        } else {
                            before[usize::from(reg)]
                        };
                        assert_eq!(
                            cpu.x(reg),
                            expected_reg,
                            "rv32={rv32},x{reg},rd={rd},rs1={rs1},rs2={rs2},native={native},level={level}"
                        );
                    }
                    if success {
                        memory[..size].copy_from_slice(&replacement.to_le_bytes()[..size]);
                    }
                    let mut actual = [0; 16];
                    cpu.memory().read(0x200, &mut actual).unwrap();
                    assert_eq!(actual, memory);
                    assert_eq!((cpu.pc(), cpu.instret()), (PC + 4, 1));
                }
            }
        }
    }
}

#[test]
fn atomic_profiles_require_zalrsc_separately_and_reject_odd_cas_pairs() {
    use crate::isa::riscv::decode::decode;
    for xlen in [Xlen::Rv32, Xlen::Rv64] {
        let mut isa = Isa::rv64gc();
        isa.a = false;
        assert!(isa.zacas);
        assert_eq!(decode(0x1005_22af, xlen, &isa).op, Op::Illegal);
        assert_eq!(decode(0x1855_25af, xlen, &isa).op, Op::Illegal);
        assert_eq!(decode(0x00c5_25af, xlen, &isa).op, Op::AmoaddW);
        assert_eq!(decode(0x28c5_25af, xlen, &isa).op, Op::AmocasW);
        isa.zacas = false;
        assert_eq!(decode(0x28c5_25af, xlen, &isa).op, Op::Illegal);
        for (rd, rs2) in [(1, 8), (6, 1), (31, 30), (30, 31)] {
            let width = if xlen == Xlen::Rv32 { 3 } else { 4 };
            let word = (5u32 << 27) | (rs2 << 20) | (10 << 15) | (width << 12) | (rd << 7) | 0x2f;
            assert_eq!(decode(word, xlen, &Isa::rv64gc()).op, Op::Illegal);
        }
    }
}

#[test]
fn zero_pair_cas_preserves_x0_in_following_instruction() {
    for rv32 in [true, false] {
        for (native, level) in atomic_execution_modes() {
            let config = if rv32 {
                RiscVConfig::rv32(Isa::rv64gc())
            } else {
                RiscVConfig::rv64gc()
            };
            let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, 4096)));
            let width = if rv32 { 3 } else { 4 };
            let word: u32 = (5 << 27) | (10 << 15) | (width << 12) | 0x2f;
            cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
            // ADDI x28,x0,99 must read zero even after a discarded pair result.
            cpu.write_memory(PC + 4, &0x0630_0e13u32.to_le_bytes())
                .unwrap();
            cpu.write_memory(0x200, &[0x88; 16]).unwrap();
            cpu.set_pc(PC);
            cpu.set_x(1, 99);
            cpu.set_x(10, 0x200);
            if native {
                #[cfg(all(
                    feature = "smir-jit",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                {
                    use crate::smir::optimize::OptLevel;
                    let level = match level {
                        0 => OptLevel::O0,
                        1 => OptLevel::O1,
                        2 => OptLevel::O2,
                        _ => unreachable!(),
                    };
                    assert_eq!(cpu.run_jit(2, level), RiscVExit::Continue);
                    assert_eq!(cpu.jit_stats().native_executions, 2);
                    assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0);
                }
            } else {
                assert_eq!(cpu.step(), RiscVExit::Continue);
                assert_eq!(cpu.step(), RiscVExit::Continue);
            }
            assert_eq!((cpu.x(0), cpu.x(1), cpu.x(28)), (0, 99, 99));
            assert_eq!((cpu.pc(), cpu.instret()), (PC + 8, 2));
            let mut bytes = [0; 16];
            cpu.memory().read(0x200, &mut bytes).unwrap();
            assert_eq!(bytes, [0x88; 16]);
        }
    }
}
