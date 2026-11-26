//! Instruction fetch, execution, and retirement accounting.

use super::*;

impl RiscVCpu {
    pub(super) fn fetch_instruction(&mut self, pc: u64) -> Result<Insn, Trap> {
        let alignment_mask = if self.cfg.isa.c { 0b1 } else { 0b11 };
        if pc & alignment_mask != 0 {
            return Err(Trap {
                cause: cause::INSTR_MISALIGNED,
                tval: pc,
            });
        }
        self.fetch_instruction_parcels(pc)
    }

    /// Fetch, decode and execute one instruction.
    pub fn step(&mut self) -> RiscVExit {
        self.step_with_trap_handler(Self::deliver_trap)
    }

    /// Process emulation reports synchronous faults to the embedding kernel.
    /// Preserve the existing machine trap frame used by that adapter.
    pub(crate) fn step_for_process(&mut self) -> RiscVExit {
        self.step_with_trap_handler(Self::enter_machine_trap)
    }

    fn step_with_trap_handler(&mut self, deliver: fn(&mut Self, Trap, u64)) -> RiscVExit {
        if self.take_pending_interrupt() {
            return RiscVExit::Continue;
        }

        let pc = self.pc;
        let insn = match self.fetch_instruction(pc) {
            Ok(i) => i,
            Err(trap) => {
                deliver(self, trap, pc);
                return RiscVExit::Trap(trap);
            }
        };
        self.cycle = self.cycle.wrapping_add(1);
        match self.execute(&insn, pc) {
            Ok(exit) => {
                self.account_retired_exit(exit);
                exit
            }
            Err(trap) => {
                deliver(self, trap, pc);
                RiscVExit::Trap(trap)
            }
        }
    }

    /// Run until a non-`Continue` exit or `max_insns` instructions retire.
    /// Returns the exit that stopped the loop (`Continue` only if the budget
    /// was exhausted).
    pub fn run(&mut self, max_insns: u64) -> RiscVExit {
        for _ in 0..max_insns {
            match self.step() {
                RiscVExit::Continue => {}
                other => return other,
            }
        }
        RiscVExit::Continue
    }

    /// Account for an instruction that returned through the non-trap path.
    /// ECALL and EBREAK still raise synchronous exceptions through embedder
    /// exits, so they do not retire. WFI completes as a hint in this model.
    #[inline]
    pub(super) fn account_retired_exit(&mut self, exit: RiscVExit) {
        if matches!(exit, RiscVExit::Continue | RiscVExit::Wfi) {
            self.instret = self.instret.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::{FlatMemory, MemResult, Memory, decode};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const CODE: u64 = 0x100;

    fn cpu(isa: Isa) -> RiscVCpu {
        RiscVCpu::new(
            RiscVConfig {
                xlen: Xlen::Rv64,
                isa,
            },
            Box::new(FlatMemory::new(0, 0x1000)),
        )
    }

    fn run_word(cpu: &mut RiscVCpu, word: u32) -> RiscVExit {
        cpu.write_memory(CODE, &word.to_le_bytes()).unwrap();
        cpu.set_pc(CODE);
        cpu.step()
    }

    #[test]
    fn instruction_fetch_enforces_the_configured_ialign() {
        let mut without_c = cpu(Isa::rv_i());
        without_c.set_pc(CODE + 2);
        assert_eq!(
            without_c.step(),
            RiscVExit::Trap(Trap {
                cause: cause::INSTR_MISALIGNED,
                tval: CODE + 2,
            })
        );
        assert_eq!(without_c.csr_read(0x341), Ok(CODE));
        assert_eq!(without_c.csr_read(0x343), Ok(CODE + 2));

        let mut with_c = cpu(Isa {
            c: true,
            ..Isa::rv_i()
        });
        with_c
            .write_memory(CODE + 2, &0x0001u16.to_le_bytes()) // c.nop
            .unwrap();
        with_c.set_pc(CODE + 2);
        assert_eq!(with_c.step(), RiscVExit::Continue);
        assert_eq!(with_c.pc(), CODE + 4);

        with_c.set_pc(CODE + 1);
        assert_eq!(
            with_c.step(),
            RiscVExit::Trap(Trap {
                cause: cause::INSTR_MISALIGNED,
                tval: CODE + 1,
            })
        );
    }

    #[test]
    fn split_instruction_fetch_reports_the_faulting_parcel_and_instruction_epc() {
        const START: u64 = 0xffe;
        const NEXT_PARCEL: u64 = START + 2;
        const TRAP_VECTOR: u64 = 0x100;
        fn fixture() -> RiscVCpu {
            let mut cpu = cpu(Isa::rv64gc());
            // First parcel of `addi x1, x0, 1`; its second parcel is unmapped.
            cpu.write_memory(START, &0x0093u16.to_le_bytes()).unwrap();
            cpu.csr_write(Csr::Medeleg as u16, 1 << cause::INSTR_ACCESS_FAULT)
                .unwrap();
            cpu.csr_write(Csr::Stvec as u16, TRAP_VECTOR).unwrap();
            cpu.set_privilege(Priv::Supervisor);
            cpu.set_pc(START);
            cpu
        }

        fn check(cpu: &RiscVCpu, result: RiscVExit) {
            assert_eq!(
                result,
                RiscVExit::Trap(Trap {
                    cause: cause::INSTR_ACCESS_FAULT,
                    tval: NEXT_PARCEL,
                })
            );
            assert_eq!(cpu.pc(), TRAP_VECTOR);
            assert_eq!(cpu.csr_read(Csr::Sepc as u16), Ok(START));
            assert_eq!(cpu.csr_read(Csr::Stval as u16), Ok(NEXT_PARCEL));
            assert_eq!(cpu.instret(), 0);
            assert_eq!(cpu.x(1), 0);
        }

        let mut interpreted = fixture();
        let result = interpreted.step();
        check(&interpreted, result);

        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let mut jitted = fixture();
            let result = jitted.step_jit(crate::smir::optimize::OptLevel::O0);
            check(&jitted, result);
        }
    }

    fn csrr(rd: u32, csr: u32) -> u32 {
        (csr << 20) | (0b010 << 12) | (rd << 7) | 0x73
    }

    fn sc(funct3: u32) -> u32 {
        (0b00011 << 27) | (2 << 20) | (1 << 15) | (funct3 << 12) | (3 << 7) | 0x2f
    }

    #[derive(Debug)]
    struct WriteDeniedMemory {
        inner: FlatMemory,
        denied: u64,
        denied_reads: Arc<AtomicUsize>,
    }

    impl Memory for WriteDeniedMemory {
        fn probe(&self, addr: u64, size: usize, write: bool) -> MemResult<()> {
            if write && addr == self.denied {
                Err(MemError::OutOfBounds { addr, size })
            } else {
                self.inner.probe(addr, size, write)
            }
        }

        fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
            if addr == self.denied {
                self.denied_reads.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.read(addr, buf)
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
            if addr == self.denied {
                Err(MemError::OutOfBounds {
                    addr,
                    size: data.len(),
                })
            } else {
                self.inner.write(addr, data)
            }
        }
    }

    fn cpu_with_write_denied(addr: u64) -> (RiscVCpu, Arc<AtomicUsize>) {
        let denied_reads = Arc::new(AtomicUsize::new(0));
        let memory = WriteDeniedMemory {
            inner: FlatMemory::new(0, 0x1000),
            denied: addr,
            denied_reads: Arc::clone(&denied_reads),
        };
        (
            RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(memory)),
            denied_reads,
        )
    }

    #[test]
    fn only_normally_completed_instructions_increment_instret() {
        for (word, expected_exit, expected_instret) in [
            (0x0000_0013, RiscVExit::Continue, 1), // addi x0, x0, 0
            (0x1050_0073, RiscVExit::Wfi, 1),      // wfi completes as a hint
            (0x0000_0073, RiscVExit::Ecall, 0),
            (0x0010_0073, RiscVExit::Ebreak, 0),
        ] {
            let mut cpu = cpu(Isa::rv64gc());
            assert_eq!(run_word(&mut cpu, word), expected_exit);
            assert_eq!(cpu.cycle, 1, "word={word:#010x}");
            assert_eq!(cpu.instret(), expected_instret, "word={word:#010x}");
        }
    }

    #[test]
    fn wfi_does_not_stall_for_a_locally_enabled_pending_interrupt() {
        let meip = 1 << cause::INT_M_EXTERNAL;

        let mut pending = cpu(Isa::rv64gc());
        pending.csr_write(0x304, meip).unwrap();
        pending.csr_write(0x303, meip).unwrap(); // WFI wake ignores delegation.
        pending.set_interrupt_pending(meip, true);
        let wfi = decode(0x1050_0073, Xlen::Rv64, &Isa::rv64gc());
        assert_eq!(pending.execute_insn(&wfi, CODE), Ok(RiscVExit::Continue));
        assert_eq!(pending.pc(), CODE + 4);

        let mut individually_disabled = cpu(Isa::rv64gc());
        individually_disabled.set_interrupt_pending(meip, true);
        assert_eq!(
            individually_disabled.execute_insn(&wfi, CODE),
            Ok(RiscVExit::Wfi)
        );
    }

    #[test]
    fn unavailable_csrs_trap_before_register_commit() {
        let isa = Isa {
            zicsr: true,
            ..Isa::rv_i()
        };
        for csr in [0xC80, 0x001, 0x017, 0x008] {
            let mut cpu = cpu(isa);
            cpu.set_x(1, 0xfeed_face);
            assert_eq!(
                run_word(&mut cpu, csrr(1, csr)),
                RiscVExit::Trap(Trap::illegal(0)),
                "csr={csr:#05x}"
            );
            assert_eq!(cpu.x(1), 0xfeed_face, "csr={csr:#05x}");
            assert_eq!(cpu.instret(), 0, "csr={csr:#05x}");
        }
    }

    #[test]
    fn failed_store_conditionals_check_address_without_writing() {
        const VALID: u64 = 0x200;
        const INVALID: u64 = 0x1000;
        const ORIGINAL: [u8; 8] = 0x0123_4567_89ab_cdefu64.to_le_bytes();

        for (funct3, name) in [(0b010, "SC.W"), (0b011, "SC.D")] {
            let word = sc(funct3);

            let mut direct_fault = cpu(Isa::rv64gc());
            direct_fault.set_x(1, INVALID);
            direct_fault.set_x(2, u64::MAX);
            direct_fault.set_x(3, 0xfeed_face);
            direct_fault.reservation = Some(VALID);
            assert_eq!(
                run_word(&mut direct_fault, word),
                RiscVExit::Trap(Trap {
                    cause: cause::STORE_ACCESS_FAULT,
                    tval: INVALID,
                }),
                "direct {name}"
            );
            assert_eq!(direct_fault.x(3), 0xfeed_face, "direct {name}");
            assert_eq!(direct_fault.instret(), 0, "direct {name}");
            assert_eq!(direct_fault.reservation, None, "direct {name}");

            let mut direct_valid = cpu(Isa::rv64gc());
            direct_valid.write_memory(VALID, &ORIGINAL).unwrap();
            direct_valid.set_x(1, VALID);
            direct_valid.set_x(2, u64::MAX);
            assert_eq!(run_word(&mut direct_valid, word), RiscVExit::Continue);
            assert_eq!(direct_valid.x(3), 1, "direct {name}");
            assert_eq!(direct_valid.instret(), 1, "direct {name}");
            assert_eq!(direct_valid.reservation, None, "direct {name}");
            let mut observed = [0; 8];
            direct_valid.read_memory(VALID, &mut observed).unwrap();
            assert_eq!(observed, ORIGINAL, "direct {name}");

            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            for level in [
                crate::smir::optimize::OptLevel::O0,
                crate::smir::optimize::OptLevel::O2,
            ] {
                let mut jit_fault = cpu(Isa::rv64gc());
                jit_fault.set_x(1, INVALID);
                jit_fault.set_x(2, u64::MAX);
                jit_fault.set_x(3, 0xfeed_face);
                jit_fault.reservation = Some(VALID);
                assert_eq!(
                    {
                        jit_fault.write_memory(CODE, &word.to_le_bytes()).unwrap();
                        jit_fault.set_pc(CODE);
                        jit_fault.step_jit(level)
                    },
                    RiscVExit::Trap(Trap {
                        cause: cause::STORE_ACCESS_FAULT,
                        tval: INVALID,
                    }),
                    "{level:?} {name}"
                );
                assert_eq!(jit_fault.x(3), 0xfeed_face, "{level:?} {name}");
                assert_eq!(jit_fault.instret(), 0, "{level:?} {name}");
                assert_eq!(jit_fault.reservation, None, "{level:?} {name}");
                assert_eq!(
                    jit_fault.jit_stats().native_executions,
                    1,
                    "{level:?} {name}"
                );

                let mut jit_valid = cpu(Isa::rv64gc());
                jit_valid.write_memory(VALID, &ORIGINAL).unwrap();
                jit_valid.write_memory(CODE, &word.to_le_bytes()).unwrap();
                jit_valid.set_pc(CODE);
                jit_valid.set_x(1, VALID);
                jit_valid.set_x(2, u64::MAX);
                assert_eq!(jit_valid.step_jit(level), RiscVExit::Continue);
                assert_eq!(jit_valid.x(3), 1, "{level:?} {name}");
                assert_eq!(jit_valid.instret(), 1, "{level:?} {name}");
                assert_eq!(jit_valid.reservation, None, "{level:?} {name}");
                let mut observed = [0; 8];
                jit_valid.read_memory(VALID, &mut observed).unwrap();
                assert_eq!(observed, ORIGINAL, "{level:?} {name}");
                assert_eq!(
                    jit_valid.jit_stats().native_executions,
                    1,
                    "{level:?} {name}"
                );
            }
        }
    }

    #[test]
    fn failed_store_conditionals_use_write_probe_without_mmio_read() {
        const DENIED: u64 = 0x200;

        for (funct3, name) in [(0b010, "SC.W"), (0b011, "SC.D")] {
            let word = sc(funct3);
            let (mut direct, direct_reads) = cpu_with_write_denied(DENIED);
            direct.set_x(1, DENIED);
            direct.set_x(3, 0xfeed_face);
            direct.reservation = Some(DENIED + 8);
            assert_eq!(
                run_word(&mut direct, word),
                RiscVExit::Trap(Trap {
                    cause: cause::STORE_ACCESS_FAULT,
                    tval: DENIED,
                }),
                "direct {name}"
            );
            assert_eq!(direct.x(3), 0xfeed_face, "direct {name}");
            assert_eq!(direct.instret(), 0, "direct {name}");
            assert_eq!(direct.reservation, None, "direct {name}");
            assert_eq!(direct_reads.load(Ordering::SeqCst), 0, "direct {name}");

            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            for level in [
                crate::smir::optimize::OptLevel::O0,
                crate::smir::optimize::OptLevel::O2,
            ] {
                let (mut jit, jit_reads) = cpu_with_write_denied(DENIED);
                jit.write_memory(CODE, &word.to_le_bytes()).unwrap();
                jit.set_pc(CODE);
                jit.set_x(1, DENIED);
                jit.set_x(3, 0xfeed_face);
                jit.reservation = Some(DENIED + 8);
                assert_eq!(
                    jit.step_jit(level),
                    RiscVExit::Trap(Trap {
                        cause: cause::STORE_ACCESS_FAULT,
                        tval: DENIED,
                    }),
                    "{level:?} {name}"
                );
                assert_eq!(jit.x(3), 0xfeed_face, "{level:?} {name}");
                assert_eq!(jit.instret(), 0, "{level:?} {name}");
                assert_eq!(jit.reservation, None, "{level:?} {name}");
                assert_eq!(jit_reads.load(Ordering::SeqCst), 0, "{level:?} {name}");
                assert_eq!(jit.jit_stats().native_executions, 1, "{level:?} {name}");
            }
        }
    }
}
