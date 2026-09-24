//! AArch64 user-mode adapter.
//!
//! Drives an [`AArch64Cpu`] at EL0 through [`ArmCpu::step`], which returns
//! `SVC`, `BRK`, and synchronous faults to the caller instead of taking them
//! to EL1. Memory accesses go through [`UserArmMemory`], which translates
//! every access with the address space's page permissions: instruction
//! fetches require execute permission, and no alignment is enforced for
//! ordinary accesses (Linux runs EL0 with `SCTLR_EL1.A` clear).
//!
//! The core's native JIT tier is not used on this path; execution is
//! interpreted.

use super::{AccessFault, AccessFaultKind, host_nanos};
use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use crate::isa::arm::common::cpu::{AccessType, ArmCpu, ArmError, CpuExit, MemoryFaultType};
use crate::isa::arm::common::memory::{ArmMemory, MemResult, MemoryError, MmioHandler};
use crate::user::mm::AddressSpace;

/// [`ArmMemory`] over a user address space, with one local exclusive
/// monitor.
#[derive(Debug)]
pub struct UserArmMemory {
    space: AddressSpace,
    exclusive: Option<(u64, u8)>,
}

impl UserArmMemory {
    /// Creates a memory view of `space`.
    pub fn new(space: AddressSpace) -> Self {
        UserArmMemory {
            space,
            exclusive: None,
        }
    }
}

fn arm_access(access: MemoryAccessKind) -> AccessType {
    match access {
        MemoryAccessKind::Read => AccessType::Read,
        MemoryAccessKind::Write => AccessType::Write,
        MemoryAccessKind::Fetch => AccessType::InstructionFetch,
    }
}

fn to_memory_error(fault: GuestMemoryFault, size: usize) -> MemoryError {
    let access = arm_access(fault.access);
    match fault.kind {
        MemoryFaultKind::Unmapped => MemoryError::Unmapped {
            addr: fault.address,
            size,
            access,
        },
        MemoryFaultKind::Permission => MemoryError::Permission {
            addr: fault.address,
            access,
            reason: String::new(),
        },
        MemoryFaultKind::Other => MemoryError::BusError {
            addr: fault.address,
        },
    }
}

impl ArmMemory for UserArmMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.space
            .read(addr, buf)
            .map_err(|f| to_memory_error(f, buf.len()))
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        self.space
            .write(addr, data)
            .map_err(|f| to_memory_error(f, data.len()))
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.space
            .fetch(addr, buf)
            .map_err(|f| to_memory_error(f, buf.len()))
    }

    fn mark_exclusive(&mut self, addr: u64, size: u8) {
        self.exclusive = Some((addr, size));
    }

    fn check_exclusive(&mut self, addr: u64, size: u8) -> bool {
        self.exclusive.take() == Some((addr, size))
    }

    fn clear_exclusive(&mut self) {
        self.exclusive = None;
    }

    fn requires_alignment(&self) -> bool {
        false
    }

    /// User address spaces contain no device memory.
    fn register_mmio(&mut self, _base: u64, _size: u64, _handler: Box<dyn MmioHandler>) {}

    fn unregister_mmio(&mut self, _base: u64) {}
}

/// Why an AArch64 user-mode run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum A64Exit {
    /// `SVC #imm` at `pc`; the PC is already past it.
    Svc {
        /// The 16-bit immediate.
        imm: u16,
        /// Address of the `SVC`.
        pc: u64,
    },
    /// `BRK #imm` at `pc`; the PC is left at the `BRK`.
    Brk {
        /// The 16-bit immediate.
        imm: u16,
        /// Address of the `BRK`.
        pc: u64,
    },
    /// An UNDEFINED instruction at `pc` (including EL1-only system register
    /// accesses and `HVC`/`SMC`/`HLT` at EL0); the PC is left at it.
    Undefined {
        /// Address of the instruction.
        pc: u64,
        /// Why the core rejected it.
        reason: String,
    },
    /// A memory access faulted; the PC is left at the instruction.
    Fault(AccessFault),
    /// The instruction budget was spent.
    Yield,
    /// The core failed in a way no guest program can cause.
    Internal(String),
}

/// An AArch64 guest thread's CPU.
pub struct A64UserCpu {
    cpu: AArch64Cpu,
    space: AddressSpace,
}

impl A64UserCpu {
    /// Creates a CPU at EL0 with zeroed registers over `space`.
    pub fn new(space: &AddressSpace) -> Self {
        let config = AArch64Config {
            // No interrupt controller: user mode has no asynchronous
            // interrupts, and the GIC would be locked on every step.
            gic_config: None,
            ..AArch64Config::v8_2()
        };
        let mut cpu = AArch64Cpu::new(config, Box::new(UserArmMemory::new(space.clone())));
        cpu.enter_el0();
        A64UserCpu {
            cpu,
            space: space.clone(),
        }
    }

    /// A new CPU for another thread of the same process with this CPU's
    /// register state (X0-X30, SP, PC, NZCV, V0-V31, FPCR, FPSR, TPIDR_EL0,
    /// TPIDRRO_EL0).
    pub fn clone_thread(&self) -> Self {
        let mut child = A64UserCpu::new(&self.space);
        for r in 0..31 {
            child.cpu.set_x(r, self.cpu.get_x(r));
        }
        child.cpu.set_current_sp(self.cpu.get_sp());
        child.cpu.set_pc(self.cpu.get_pc());
        child.cpu.set_nzcv_bits(self.cpu.nzcv_bits());
        for v in 0..32 {
            child.cpu.set_simd(v, self.cpu.get_simd(v));
        }
        child.cpu.set_fpcr_value(self.cpu.fpcr_value());
        child.cpu.set_fpsr_value(self.cpu.fpsr_value());
        child.cpu.set_tpidr_el0(self.cpu.tpidr_el0());
        child.cpu.set_tpidrro_el0(self.cpu.tpidrro_el0());
        child
    }

    /// The underlying core.
    pub fn core(&self) -> &AArch64Cpu {
        &self.cpu
    }

    /// Discards the core's compiled native code.
    pub fn discard_native_code(&mut self) {
        self.cpu.clear_jit_cache();
    }

    /// Mutable access to the underlying core.
    pub fn core_mut(&mut self) -> &mut AArch64Cpu {
        &mut self.cpu
    }

    /// The address space this CPU executes in.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Current PC.
    pub fn pc(&self) -> u64 {
        self.cpu.get_pc()
    }

    /// Current SP_EL0.
    pub fn sp(&self) -> u64 {
        self.cpu.get_sp()
    }

    /// Sets SP_EL0.
    pub fn set_sp(&mut self, value: u64) {
        self.cpu.set_current_sp(value);
    }

    fn undefined(&mut self, pc: u64, reason: String) -> A64Exit {
        self.cpu.set_pc(pc);
        A64Exit::Undefined { pc, reason }
    }

    /// Runs at most `budget` instructions, stopping at the first operating
    /// system event.
    pub fn run(&mut self, budget: u64) -> A64Exit {
        // The system counter advances with host time: CNTFRQ_EL0 ticks per
        // second. `ticks = ns * freq / 1e9`, computed in 128 bits so neither
        // factor overflows.
        let freq = self.cpu.counter_frequency();
        let ticks = (u128::from(host_nanos()) * u128::from(freq) / 1_000_000_000) as u64;
        self.cpu.set_generic_counter(ticks);

        let exit = self.run_inner(budget);
        // Leaving the guest is an exception entry, which clears the local
        // exclusive monitor.
        self.cpu.clear_exclusive_monitor();
        exit
    }

    fn run_inner(&mut self, budget: u64) -> A64Exit {
        for _ in 0..budget {
            let pc = self.cpu.get_pc();
            match self.cpu.step() {
                Ok(CpuExit::Continue) => {}
                Ok(CpuExit::Svc(imm)) => {
                    return A64Exit::Svc {
                        imm: imm as u16,
                        pc,
                    };
                }
                Ok(CpuExit::Breakpoint(imm)) => {
                    // BRK retires with the PC advanced; the exception's
                    // preferred return address is the BRK itself.
                    self.cpu.set_pc(pc);
                    return A64Exit::Brk {
                        imm: imm as u16,
                        pc,
                    };
                }
                Ok(CpuExit::Hvc(_)) => return self.undefined(pc, "HVC at EL0".into()),
                Ok(CpuExit::Smc(_)) => return self.undefined(pc, "SMC at EL0".into()),
                Ok(CpuExit::Halt) => {
                    // HLT without halting debug enabled is UNDEFINED.
                    self.cpu.clear_halt();
                    return self.undefined(pc, "HLT at EL0".into());
                }
                Ok(CpuExit::Undefined(insn)) => {
                    return self.undefined(pc, format!("undefined instruction {insn:#010x}"));
                }
                Ok(CpuExit::Wfi) | Ok(CpuExit::Wfe) => {
                    // Linux lets EL0 execute WFI/WFE (SCTLR_EL1.nTWI/nTWE);
                    // with no interrupt source they complete immediately. A
                    // wait usually spins on another thread, so yield.
                    self.cpu.clear_wait();
                    return A64Exit::Yield;
                }
                Ok(other) => {
                    return A64Exit::Internal(format!(
                        "unexpected AArch64 exit {other:?} at {pc:#x}"
                    ));
                }
                Err(ArmError::MemoryError(info)) => {
                    let access = match info.access {
                        AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                        AccessType::Read => MemoryAccessKind::Read,
                        AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
                    };
                    let kind = match info.fault_type {
                        MemoryFaultType::Translation | MemoryFaultType::AddressSize => {
                            AccessFaultKind::Unmapped
                        }
                        MemoryFaultType::Permission | MemoryFaultType::AccessFlag => {
                            AccessFaultKind::Permission
                        }
                        MemoryFaultType::Alignment => AccessFaultKind::Alignment,
                        _ => AccessFaultKind::Bus,
                    };
                    self.cpu.set_pc(pc);
                    return A64Exit::Fault(AccessFault {
                        addr: info.address,
                        access,
                        kind,
                        pc,
                    });
                }
                Err(ArmError::UndefinedInstruction(insn)) => {
                    return self.undefined(pc, format!("undefined instruction {insn:#010x}"));
                }
                Err(ArmError::InvalidExceptionLevel(_)) => {
                    return self.undefined(pc, "EL1 system register or instruction at EL0".into());
                }
                Err(ArmError::Unimplemented(what)) => {
                    return self.undefined(pc, format!("not implemented by the emulator: {what}"));
                }
                Err(other) => return A64Exit::Internal(format!("{other} at {pc:#x}")),
            }
        }
        A64Exit::Yield
    }
}
