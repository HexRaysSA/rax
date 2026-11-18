//! The cores: the emulator's user-mode processors, and how code is called
//! on one and known to have returned.
//!
//! A core runs until something happens that an operating system would have
//! to see to. There is none here, so there is one such thing that is not
//! the end of the call in failure: the code returns. It is called with a
//! return address at which nothing is mapped, and has returned when the
//! core cannot fetch the instruction there, with its stack where the call
//! found it.

use std::time::Instant;

use rax::arm::ArmCpu;
use rax::error::MemoryAccessKind;
use rax::user::cpu::aarch64::{A64Exit, A64UserCpu};
use rax::user::cpu::x86_64::{X86Exit, X86UserCpu};
use rax::user::cpu::{AccessFault, AccessFaultKind};
use rax::user::mm::AddressSpace;
use rax_smir_portable::ir::{BridgeConvention, ForeignIsa};

/// Where foreign code returns to when it returns to the engine. Nothing is
/// ever mapped there; it is a multiple of four, as an AArch64 address of
/// code has to be.
pub(crate) const RETURN_AT: u64 = 0x7FFF_FFFF_0000;

/// How many AArch64 instructions run between two looks at the clock.
const SLICE: u64 = 1 << 14;

/// RFLAGS at entry: interrupts on, as user code has them, and the direction
/// flag clear, as both conventions require.
const FLAGS: u64 = 0x202;

/// What Win64 has above the return address: 32 bytes that are the callee's.
const HOME: u64 = 32;

/// A thread's processor.
pub(crate) enum Core {
    X86(Box<X86UserCpu>),
    A64(Box<A64UserCpu>),
}

fn late(deadline: Option<Instant>) -> Result<(), String> {
    match deadline {
        Some(deadline) if Instant::now() >= deadline => {
            Err("the code ran longer than it may".into())
        }
        _ => Ok(()),
    }
}

/// Whether a fault is the fetch at the return address.
fn returned(fault: &AccessFault) -> bool {
    fault.access == MemoryAccessKind::Fetch && fault.addr == RETURN_AT
}

fn described(fault: &AccessFault) -> String {
    let why = match fault.kind {
        AccessFaultKind::Unmapped => "nothing is there",
        AccessFaultKind::Permission => "the memory there is not for that",
        AccessFaultKind::Alignment => "the address is not aligned for it",
        AccessFaultKind::Bus => "there is no memory left for it",
    };
    format!(
        "a {} at {:#x} by the code at {:#x}: {why}",
        fault.access, fault.addr, fault.pc
    )
}

impl Core {
    /// A processor of `isa` in the state a new thread has.
    pub(crate) fn new(isa: ForeignIsa, space: &AddressSpace) -> Self {
        match isa {
            ForeignIsa::X86_64 => Self::X86(Box::new(X86UserCpu::new(space))),
            ForeignIsa::Aarch64 => Self::A64(Box::new(A64UserCpu::new(space))),
        }
    }

    /// Whether `convention` is one of this processor's.
    pub(crate) fn takes(isa: ForeignIsa, convention: BridgeConvention) -> bool {
        matches!(
            (isa, convention),
            (
                ForeignIsa::X86_64,
                BridgeConvention::SysV64 | BridgeConvention::Win64
            ) | (ForeignIsa::Aarch64, BridgeConvention::Aapcs64)
        )
    }

    /// Call the code at `entry` with `argument`, on the stack that ends at
    /// `top`, a multiple of 16, and run it until it returns or `deadline`
    /// has passed. An error says why the code did not return.
    pub(crate) fn call(
        &mut self,
        space: &AddressSpace,
        convention: BridgeConvention,
        entry: u64,
        argument: u64,
        top: u64,
        deadline: Option<Instant>,
    ) -> Result<(), String> {
        match self {
            Self::X86(cpu) => {
                // The return address is on the stack, and above it the
                // stack is aligned to 16; for Win64 the callee's 32 bytes
                // are there.
                let windows = convention == BridgeConvention::Win64;
                let sp = top - if windows { HOME } else { 0 } - 8;
                space
                    .write_raw(sp, &RETURN_AT.to_le_bytes())
                    .map_err(|_| "the thread has no stack")?;
                let core = cpu.vcpu_mut();
                core.set_user_rflags(FLAGS);
                let registers = core.user_regs_mut();
                (registers.rip, registers.rsp) = (entry, sp);
                if windows {
                    registers.rcx = argument;
                } else {
                    registers.rdi = argument;
                }
                loop {
                    return match cpu.run() {
                        X86Exit::Yield => {
                            late(deadline)?;
                            continue;
                        }
                        X86Exit::Fault(fault) if returned(&fault) => {
                            balanced(cpu.vcpu().user_regs().rsp, sp + 8)
                        }
                        X86Exit::Fault(fault) => Err(described(&fault)),
                        X86Exit::Syscall { insn_rip, .. } => Err(no_system(insn_rip)),
                        X86Exit::Event(event) => Err(format!("{event:?}")),
                        X86Exit::Internal(error) => Err(format!("the processor failed: {error}")),
                    };
                }
            }
            Self::A64(cpu) => {
                // The return address is in the link register.
                let core = cpu.core_mut();
                core.set_pc(entry);
                core.set_x(0, argument);
                core.set_x(30, RETURN_AT);
                cpu.set_sp(top);
                loop {
                    return match cpu.run(SLICE) {
                        A64Exit::Yield => {
                            late(deadline)?;
                            continue;
                        }
                        A64Exit::Fault(fault) if returned(&fault) => balanced(cpu.sp(), top),
                        A64Exit::Fault(fault) => Err(described(&fault)),
                        A64Exit::Svc { pc, .. } => Err(no_system(pc)),
                        A64Exit::Brk { imm, pc } => Err(format!("a breakpoint ({imm}) at {pc:#x}")),
                        A64Exit::Undefined { pc, reason } => {
                            Err(format!("an undefined instruction at {pc:#x}: {reason}"))
                        }
                        A64Exit::Exception { pc, ec, iss } => Err(format!(
                            "an exception of class {ec:#x} ({iss:#x}) at {pc:#x}"
                        )),
                        A64Exit::Internal(error) => Err(format!("the processor failed: {error}")),
                    };
                }
            }
        }
    }
}

/// Code that returns leaves the stack as a return leaves it.
fn balanced(sp: u64, expected: u64) -> Result<(), String> {
    if sp == expected {
        Ok(())
    } else {
        Err(format!(
            "the code returned with its stack at {sp:#x}, not at {expected:#x}"
        ))
    }
}

fn no_system(pc: u64) -> String {
    format!("a system call at {pc:#x}: foreign code has no system to call")
}
