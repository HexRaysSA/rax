//! The vCPU an engine drives.
//!
//! System-mode engines use the architecture-neutral [`VCpu`] object
//! [`crate::arch::build_vcpu`] builds. User-mode engines (`RAX_MODE_USER`) keep the
//! concrete core so the run loop can take the system call or exception that
//! ended a step, which the neutral exit only signals.

use std::ops::{Deref, DerefMut};

use rax_engine::backend::emulator::aarch64::{A64_EC_BRK, A64UserTrap, Aarch64Vcpu};
use rax_engine::backend::emulator::riscv::{RiscVVcpu, RvUserTrap};
use rax_engine::cpu::VCpu;
use rax_engine::isa::riscv::cpu::cause;
use rax_engine::isa::x86_64::{X86_64Vcpu, X86EventSource, X86SyscallInsn, X86UserTrap};

use crate::user::{
    RAX_SYSCALL_INSN_ECALL, RAX_SYSCALL_INSN_SVC, RAX_SYSCALL_INSN_SYSCALL,
    RAX_SYSCALL_INSN_SYSENTER,
};

/// An engine's vCPU.
pub(crate) enum Vcpu {
    /// A system-mode vCPU.
    System(Box<dyn VCpu>),
    /// An x86-64 user-mode core (CPL 3, 64-bit or compatibility mode).
    X86User(Box<X86_64Vcpu>),
    /// An AArch64 user-mode core (EL0).
    Arm64User(Box<Aarch64Vcpu>),
    /// The shared AArch32 user-mode executor in ARM or Thumb state.
    ArmUser(Box<crate::arm_user::ArmUserVcpu>),
    /// An RV64 user-mode hart (U-mode).
    RiscvUser(Box<RiscVVcpu>),
}

/// A system call or exception a user-mode core reported, in C API terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserTrap {
    /// A system-call instruction at `pc` completed; the PC is its resume
    /// address, `pc + len`.
    Syscall {
        pc: u64,
        len: u32,
        insn: u32,
        imm: u32,
    },
    /// An exception raised by the instruction at `pc`. `return_pc` is the
    /// architectural return address.
    Exception {
        vector: u32,
        pc: u64,
        return_pc: u64,
        syndrome: Option<u64>,
        software: bool,
        undefined: bool,
    },
}

impl Vcpu {
    /// Whether this is a user-mode core.
    pub(crate) fn is_user(&self) -> bool {
        !matches!(self, Vcpu::System(_))
    }

    /// Removes the system call or exception that ended the last user-mode
    /// step or run. Always `None` in system mode.
    pub(crate) fn take_user_trap(&mut self) -> Option<UserTrap> {
        match self {
            Vcpu::System(_) => None,
            Vcpu::ArmUser(core) => core.take_trap(),
            Vcpu::X86User(core) => {
                let resume = core.current_pc();
                core.take_user_trap().map(|trap| match trap {
                    X86UserTrap::SystemCall { insn, insn_rip } => UserTrap::Syscall {
                        pc: insn_rip,
                        // RIP is the return address; the difference is the
                        // encoded length including any prefixes.
                        len: resume.wrapping_sub(insn_rip).min(15) as u32,
                        insn: match insn {
                            X86SyscallInsn::Syscall => RAX_SYSCALL_INSN_SYSCALL,
                            X86SyscallInsn::Sysenter => RAX_SYSCALL_INSN_SYSENTER,
                        },
                        imm: 0,
                    },
                    X86UserTrap::Event(event) => UserTrap::Exception {
                        vector: u32::from(event.vector),
                        pc: event.insn_rip,
                        return_pc: event.return_rip,
                        syndrome: event.error_code,
                        software: event.source == X86EventSource::SoftwareInterrupt,
                        // #UD.
                        undefined: event.vector == 6,
                    },
                })
            }
            Vcpu::Arm64User(core) => core.take_user_trap().map(|trap| match trap {
                A64UserTrap::Svc { imm, pc } => UserTrap::Syscall {
                    pc,
                    len: 4,
                    insn: RAX_SYSCALL_INSN_SVC,
                    imm: u32::from(imm),
                },
                A64UserTrap::Exception { ec, iss, pc } => UserTrap::Exception {
                    vector: u32::from(ec),
                    pc,
                    return_pc: pc,
                    syndrome: Some(u64::from(iss)),
                    software: ec == A64_EC_BRK,
                    undefined: ec != A64_EC_BRK,
                },
            }),
            Vcpu::RiscvUser(core) => core.take_user_trap().map(|trap| match trap {
                RvUserTrap::Ecall { pc } => UserTrap::Syscall {
                    pc,
                    len: 4,
                    insn: RAX_SYSCALL_INSN_ECALL,
                    imm: 0,
                },
                RvUserTrap::Exception {
                    cause: code,
                    tval,
                    pc,
                } => UserTrap::Exception {
                    vector: code.min(u64::from(u32::MAX)) as u32,
                    pc,
                    return_pc: pc,
                    syndrome: Some(tval),
                    software: code == cause::BREAKPOINT,
                    undefined: code == cause::ILLEGAL_INSTR,
                },
            }),
        }
    }

    /// Discards cached decodes and compiled code for `[start, start + len)`
    /// after a host write or a permission change. User mode maps linear
    /// addresses to guest memory one-to-one, so the range is both. The
    /// AArch64 and RV64 user cores interpret without code caches keyed by
    /// guest address.
    pub(crate) fn invalidate_code(&mut self, start: u64, len: u64) {
        if let Vcpu::X86User(core) = self {
            core.invalidate_code_range(start, len);
        }
    }

    /// Discards every cached decode and compiled region.
    pub(crate) fn invalidate_all_code(&mut self) {
        if let Vcpu::X86User(core) = self {
            core.invalidate_all_code();
        }
    }

    pub(crate) fn arm_user_state(&self) -> Option<crate::arm_user::ArmUserState> {
        match self {
            Self::ArmUser(core) => Some(core.user_state()),
            _ => None,
        }
    }

    pub(crate) fn set_arm_user_state(&mut self, state: crate::arm_user::ArmUserState) {
        if let Self::ArmUser(core) = self {
            core.set_user_state(state);
        }
    }
}

impl Deref for Vcpu {
    type Target = dyn VCpu;

    fn deref(&self) -> &Self::Target {
        match self {
            Vcpu::System(core) => core.as_ref(),
            Vcpu::X86User(core) => core.as_ref(),
            Vcpu::Arm64User(core) => core.as_ref(),
            Vcpu::ArmUser(core) => core.as_ref(),
            Vcpu::RiscvUser(core) => core.as_ref(),
        }
    }
}

impl DerefMut for Vcpu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Vcpu::System(core) => core.as_mut(),
            Vcpu::X86User(core) => core.as_mut(),
            Vcpu::Arm64User(core) => core.as_mut(),
            Vcpu::ArmUser(core) => core.as_mut(),
            Vcpu::RiscvUser(core) => core.as_mut(),
        }
    }
}
