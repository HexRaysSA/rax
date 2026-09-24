//! RV64 user-mode adapter.
//!
//! Drives a [`RiscVCpu`] in U-mode. The core returns `ECALL` and `EBREAK` to
//! the caller directly; other synchronous exceptions are delivered
//! architecturally to its M-mode trap vector, after which the adapter
//! restores U-mode at the faulting instruction and reports the exception.
//! Memory accesses go through [`UserRiscVMemory`], which enforces page
//! permissions, including execute permission on instruction fetch, and
//! records the precise first inaccessible byte of a failed access.

use std::sync::{Arc, Mutex};

use super::{AccessFault, AccessFaultKind, host_nanos};
use crate::error::{GuestMemoryFault, MemoryAccessKind};
use crate::isa::riscv::cpu::{Priv, cause};
use crate::isa::riscv::{MemError, MemResult, Memory, RiscVConfig, RiscVCpu, RiscVExit, Trap};
use crate::user::mm::AddressSpace;

/// Frequency of the `time` CSR in hertz: 10 MHz, the `timebase-frequency`
/// of QEMU's `virt` board and of common RV64 Linux platforms.
pub const TIMEBASE_HZ: u64 = 10_000_000;

/// `scounteren` value Linux 6.19 installs by default
/// (`sysctl kernel.perf_user_access = 1`): only `time` is readable from U-mode.
const SCOUNTEREN_TIME_ONLY: u64 = 0b010;

/// [`Memory`] over a user address space.
#[derive(Debug)]
pub struct UserRiscVMemory {
    space: AddressSpace,
    last_fault: Arc<Mutex<Option<GuestMemoryFault>>>,
}

impl UserRiscVMemory {
    fn fail(&self, fault: GuestMemoryFault, size: usize) -> MemError {
        *self.last_fault.lock().unwrap() = Some(fault);
        MemError::OutOfBounds {
            addr: fault.address,
            size,
        }
    }
}

impl Memory for UserRiscVMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.space
            .read(addr, buf)
            .map_err(|f| self.fail(f, buf.len()))
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        self.space
            .write(addr, data)
            .map_err(|f| self.fail(f, data.len()))
    }

    fn probe(&self, addr: u64, size: usize, write: bool) -> MemResult<()> {
        let access = if write {
            MemoryAccessKind::Write
        } else {
            MemoryAccessKind::Read
        };
        self.space
            .probe(addr, size, access)
            .map_err(|f| self.fail(f, size))
    }

    fn fetch_u16(&self, addr: u64) -> MemResult<u16> {
        let mut b = [0u8; 2];
        self.space
            .fetch(addr, &mut b)
            .map_err(|f| self.fail(f, 2))?;
        Ok(u16::from_le_bytes(b))
    }
}

/// Why an RV64 user-mode run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RvExit {
    /// `ECALL` at `pc`; the PC is left at it.
    Ecall {
        /// Address of the `ECALL`.
        pc: u64,
    },
    /// `EBREAK`/`C.EBREAK` at `pc`; the PC is left at it.
    Ebreak {
        /// Address of the instruction.
        pc: u64,
    },
    /// An illegal instruction; the PC is left at it.
    Illegal {
        /// Address of the instruction.
        pc: u64,
        /// The trap value (the instruction bits, or zero).
        tval: u64,
    },
    /// A misaligned instruction fetch or atomic access; the PC is left at the
    /// instruction.
    Misaligned {
        /// Address of the instruction.
        pc: u64,
        /// The misaligned address.
        addr: u64,
        /// The exception cause code.
        cause: u64,
    },
    /// A memory access faulted; the PC is left at the instruction.
    Fault(AccessFault),
    /// The instruction budget was spent.
    Yield,
    /// The core failed in a way no guest program can cause.
    Internal(String),
}

/// An RV64 guest thread's CPU.
pub struct RvUserCpu {
    cpu: RiscVCpu,
    space: AddressSpace,
    last_fault: Arc<Mutex<Option<GuestMemoryFault>>>,
    jit: bool,
}

impl RvUserCpu {
    /// Creates a U-mode hart with zeroed registers over `space`.
    pub fn new(space: &AddressSpace, config: RiscVConfig) -> Self {
        let last_fault = Arc::new(Mutex::new(None));
        let memory = UserRiscVMemory {
            space: space.clone(),
            last_fault: last_fault.clone(),
        };
        let mut cpu = RiscVCpu::new(config, Box::new(memory));
        cpu.csr_write(0x306, SCOUNTEREN_TIME_ONLY)
            .expect("mcounteren is writable from the embedder");
        cpu.csr_write(0x106, SCOUNTEREN_TIME_ONLY)
            .expect("scounteren is writable from the embedder");
        cpu.set_privilege(Priv::User);
        RvUserCpu {
            cpu,
            space: space.clone(),
            last_fault,
            jit: false,
        }
    }

    /// A new hart for another thread of the same process with this hart's
    /// register state (integer, floating-point, `fcsr`, vector registers and
    /// `vl`/`vtype`/`vcsr`/`vstart`).
    pub fn clone_thread(&self) -> Self {
        let mut child = RvUserCpu::new(&self.space, *self.cpu.config());
        child.jit = self.jit;
        for r in 1..32 {
            child.cpu.set_x(r, self.cpu.x(r));
            child.cpu.set_f(r, self.cpu.f(r));
        }
        child.cpu.set_f(0, self.cpu.f(0));
        child.cpu.set_pc(self.cpu.pc());
        child.cpu.set_fcsr(self.cpu.fcsr());
        for v in 0..32 {
            child.cpu.set_vreg(v, &self.cpu.vreg(v));
        }
        child.cpu.set_vl_vtype(self.cpu.vl(), self.cpu.vtype());
        child.cpu.set_vcsr(self.cpu.vcsr());
        child.cpu.set_vstart(self.cpu.vstart());
        child
    }

    /// Executes through the SMIR JIT where the host supports it. The JIT
    /// lifts each region on every entry, so it is opt-in.
    pub fn set_jit(&mut self, on: bool) {
        self.jit = on;
    }

    /// The underlying core.
    pub fn core(&self) -> &RiscVCpu {
        &self.cpu
    }

    /// Mutable access to the underlying core.
    pub fn core_mut(&mut self) -> &mut RiscVCpu {
        &mut self.cpu
    }

    /// The address space this hart executes in.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Current PC.
    pub fn pc(&self) -> u64 {
        self.cpu.pc()
    }

    /// Runs at most `budget` instructions, stopping at the first operating
    /// system event.
    pub fn run(&mut self, budget: u64) -> RvExit {
        // `ticks = ns * 10 MHz / 1e9 = ns / 100`.
        self.cpu
            .set_time(host_nanos() / (1_000_000_000 / TIMEBASE_HZ));
        *self.last_fault.lock().unwrap() = None;
        let exit = self.step_budget(budget);
        // Returning from a trap invalidates any LR reservation.
        self.cpu.clear_reservation();
        match exit {
            RiscVExit::Continue | RiscVExit::Wfi => RvExit::Yield,
            RiscVExit::Ecall => RvExit::Ecall { pc: self.cpu.pc() },
            RiscVExit::Ebreak => RvExit::Ebreak { pc: self.cpu.pc() },
            RiscVExit::Trap(trap) => self.trap(trap),
        }
    }

    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn step_budget(&mut self, budget: u64) -> RiscVExit {
        if self.jit {
            self.cpu
                .run_jit(budget, crate::smir::optimize::OptLevel::O1)
        } else {
            self.cpu.run(budget)
        }
    }

    #[cfg(not(all(
        feature = "smir-jit",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    fn step_budget(&mut self, budget: u64) -> RiscVExit {
        self.cpu.run(budget)
    }

    /// Undoes M-mode trap delivery and classifies the exception.
    fn trap(&mut self, trap: Trap) -> RvExit {
        let pc = self.cpu.csr_read(0x341).unwrap_or_else(|_| self.cpu.pc());
        self.cpu.set_privilege(Priv::User);
        self.cpu.set_pc(pc);
        let recorded = self.last_fault.lock().unwrap().take();
        match trap.cause {
            cause::ILLEGAL_INSTR => RvExit::Illegal {
                pc,
                tval: trap.tval,
            },
            cause::INSTR_MISALIGNED | cause::LOAD_MISALIGNED | cause::STORE_MISALIGNED => {
                RvExit::Misaligned {
                    pc,
                    addr: trap.tval,
                    cause: trap.cause,
                }
            }
            cause::INSTR_ACCESS_FAULT | cause::LOAD_ACCESS_FAULT | cause::STORE_ACCESS_FAULT => {
                let access = match trap.cause {
                    cause::INSTR_ACCESS_FAULT => MemoryAccessKind::Fetch,
                    cause::LOAD_ACCESS_FAULT => MemoryAccessKind::Read,
                    _ => MemoryAccessKind::Write,
                };
                match recorded {
                    Some(fault) => RvExit::Fault(AccessFault::from_memory(fault, pc)),
                    // A fault the memory view did not see (for example an
                    // address beyond XLEN masking): report the trap value.
                    None => RvExit::Fault(AccessFault {
                        addr: trap.tval,
                        access,
                        kind: AccessFaultKind::Unmapped,
                        pc,
                    }),
                }
            }
            cause::BREAKPOINT => RvExit::Ebreak { pc },
            other => RvExit::Internal(format!(
                "unexpected RISC-V trap cause {other} (tval {:#x}) at {pc:#x}",
                trap.tval
            )),
        }
    }
}
