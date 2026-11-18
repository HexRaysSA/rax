//! The cores: the emulator's user-mode processors, and how code is called
//! on one, known to have returned, and stopped where it calls back.
//!
//! A core runs until something happens that an operating system would have
//! to see to. There is none here, so there are two such things that are
//! not the end of the call in failure.
//!
//! The code returns. It is called with a return address at which nothing
//! is mapped, and has returned when the core cannot fetch the instruction
//! there.
//!
//! The code gets to the entry of a callback. The first instruction there
//! was replaced, when the entry was taken over, by one that stops the core:
//! a breakpoint. The code waits there, with the frame it brought in the
//! register a first argument is in, and is gone on with as if what it
//! called there had returned.

use std::collections::BTreeSet;
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

/// The x86-64 exception a breakpoint instruction raises.
const BREAKPOINT: u8 = 3;

/// A thread's processor.
pub(crate) enum Core {
    X86(Box<X86UserCpu>),
    A64(Box<A64UserCpu>),
}

/// How code that ran came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// It returned to the engine.
    Returned,
    /// It is at the entry of a callback, with this frame.
    Called { entry: u64, frame: u64 },
}

/// Code that waits at the entry of a callback: where its stack is, and,
/// where the return address is in a register, the return address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Waiting {
    pub sp: u64,
    link: u64,
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

fn no_system(pc: u64) -> String {
    format!("a system call at {pc:#x}: foreign code has no system to call")
}

/// The instruction that stops a core of `isa` at the entry of a callback:
/// `int3`, and `brk #0`.
pub(crate) fn breakpoint(isa: ForeignIsa) -> &'static [u8] {
    match isa {
        ForeignIsa::X86_64 => &[0xCC],
        ForeignIsa::Aarch64 => &[0x00, 0x00, 0x20, 0xD4],
    }
}

/// Whether `convention` is one of the processor's.
pub(crate) fn takes(isa: ForeignIsa, convention: BridgeConvention) -> bool {
    matches!(
        (isa, convention),
        (
            ForeignIsa::X86_64,
            BridgeConvention::SysV64 | BridgeConvention::Win64
        ) | (ForeignIsa::Aarch64, BridgeConvention::Aapcs64)
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

    /// Make the call of the code at `entry` with `argument`, on the stack
    /// that ends at `top`, a multiple of 16: when the core runs next, it
    /// runs that code. Returns where the stack is when the code has
    /// returned.
    pub(crate) fn call(
        &mut self,
        space: &AddressSpace,
        convention: BridgeConvention,
        entry: u64,
        argument: u64,
        top: u64,
    ) -> Result<u64, String> {
        match self {
            Self::X86(cpu) => {
                // The return address is on the stack, and above it the
                // stack is aligned to 16; for Win64 the callee's 32 bytes
                // are there.
                let windows = convention == BridgeConvention::Win64;
                let sp = top - if windows { HOME } else { 0 } - 8;
                space
                    .write(sp, &RETURN_AT.to_le_bytes())
                    .map_err(|_| "the thread has no stack left")?;
                let core = cpu.vcpu_mut();
                core.set_user_rflags(FLAGS);
                let registers = core.user_regs_mut();
                (registers.rip, registers.rsp) = (entry, sp);
                if windows {
                    registers.rcx = argument;
                } else {
                    registers.rdi = argument;
                }
                Ok(sp + 8)
            }
            Self::A64(cpu) => {
                // The return address is in the link register.
                let core = cpu.core_mut();
                core.set_pc(entry);
                core.set_x(0, argument);
                core.set_x(30, RETURN_AT);
                cpu.set_sp(top);
                Ok(top)
            }
        }
    }

    /// Run the code the core is at until it returns to the engine or gets
    /// to one of `entries`, or `deadline` has passed. An error says why it
    /// did neither.
    pub(crate) fn run(
        &mut self,
        convention: BridgeConvention,
        entries: &BTreeSet<u64>,
        deadline: Option<Instant>,
    ) -> Result<Stop, String> {
        match self {
            Self::X86(cpu) => loop {
                return match cpu.run() {
                    X86Exit::Yield => {
                        late(deadline)?;
                        continue;
                    }
                    X86Exit::Fault(fault) if returned(&fault) => Ok(Stop::Returned),
                    X86Exit::Fault(fault) => Err(described(&fault)),
                    X86Exit::Event(event)
                        if event.vector == BREAKPOINT && entries.contains(&event.insn_rip) =>
                    {
                        let registers = cpu.vcpu().user_regs();
                        Ok(Stop::Called {
                            entry: event.insn_rip,
                            frame: if convention == BridgeConvention::Win64 {
                                registers.rcx
                            } else {
                                registers.rdi
                            },
                        })
                    }
                    X86Exit::Event(event) => Err(format!("{event:?}")),
                    X86Exit::Syscall { insn_rip, .. } => Err(no_system(insn_rip)),
                    X86Exit::Internal(error) => Err(format!("the processor failed: {error}")),
                };
            },
            Self::A64(cpu) => loop {
                return match cpu.run(SLICE) {
                    A64Exit::Yield => {
                        late(deadline)?;
                        continue;
                    }
                    A64Exit::Fault(fault) if returned(&fault) => Ok(Stop::Returned),
                    A64Exit::Fault(fault) => Err(described(&fault)),
                    A64Exit::Brk { pc, .. } if entries.contains(&pc) => Ok(Stop::Called {
                        entry: pc,
                        frame: cpu.core().get_x(0),
                    }),
                    A64Exit::Brk { imm, pc } => Err(format!("a breakpoint ({imm}) at {pc:#x}")),
                    A64Exit::Svc { pc, .. } => Err(no_system(pc)),
                    A64Exit::Undefined { pc, reason } => {
                        Err(format!("an undefined instruction at {pc:#x}: {reason}"))
                    }
                    A64Exit::Exception { pc, ec, iss } => Err(format!(
                        "an exception of class {ec:#x} ({iss:#x}) at {pc:#x}"
                    )),
                    A64Exit::Internal(error) => Err(format!("the processor failed: {error}")),
                };
            },
        }
    }

    /// Where the core's stack is.
    pub(crate) fn sp(&self) -> u64 {
        match self {
            Self::X86(cpu) => cpu.vcpu().user_regs().rsp,
            Self::A64(cpu) => cpu.sp(),
        }
    }

    /// What code that has just stopped at the entry of a callback waits
    /// with.
    pub(crate) fn waiting(&self) -> Waiting {
        match self {
            Self::X86(cpu) => Waiting {
                sp: cpu.vcpu().user_regs().rsp,
                link: 0,
            },
            Self::A64(cpu) => Waiting {
                sp: cpu.sp(),
                link: cpu.core().get_x(30),
            },
        }
    }

    /// Put the core where the code that waits goes on: after its call of
    /// the entry, as a return from there leaves it. Other calls may have
    /// run on the core since; as calls do, they have left it what a call
    /// preserves.
    pub(crate) fn go_on(&mut self, space: &AddressSpace, waiting: Waiting) -> Result<(), String> {
        match self {
            Self::X86(cpu) => {
                let mut address = [0; 8];
                space
                    .read(waiting.sp, &mut address)
                    .map_err(|_| "the code that waits has no stack")?;
                let registers = cpu.vcpu_mut().user_regs_mut();
                registers.rip = u64::from_le_bytes(address);
                registers.rsp = waiting.sp + 8;
            }
            Self::A64(cpu) => {
                cpu.core_mut().set_pc(waiting.link);
                cpu.set_sp(waiting.sp);
            }
        }
        Ok(())
    }
}
