//! x86-64 user-mode adapter.
//!
//! Wraps an [`X86_64Vcpu`] in user mode (see
//! `crate::isa::x86_64::user_mode`) over an [`AddressSpace`]. The x86 core
//! returns control at ~1 ms time-slice boundaries on its own, which the
//! adapter reports as [`X86Exit::Yield`].

use std::sync::Arc;

use super::{AccessFault, take_code_changes};
use crate::error::Error;
use crate::isa::x86_64::{X86_64Vcpu, X86SyscallInsn, X86UserEvent, X86UserTrap};
use crate::user::mm::{AddressSpace, CodeChanges, PAGE_SIZE};
use crate::vm::vcpu::{VCpu, VcpuExit};

/// Guest-physical frames the x86-64 MMU shadows and therefore must never be
/// handed out: the inline local-APIC MMIO page at 0xFEE0_0000.
pub const RESERVED_PHYS: [(u64, u64); 1] = [(0xFEE0_0000, PAGE_SIZE)];

/// Why an x86-64 user-mode run ended.
#[derive(Debug)]
pub enum X86Exit {
    /// A system-call instruction retired at `insn_rip`.
    Syscall {
        /// `SYSCALL` or `SYSENTER`.
        insn: X86SyscallInsn,
        /// Address of the instruction.
        insn_rip: u64,
    },
    /// An exception or software interrupt; RIP is the reporting instruction.
    Event(X86UserEvent),
    /// A memory access faulted; RIP is the faulting instruction.
    Fault(AccessFault),
    /// The time slice ended.
    Yield,
    /// The core failed in a way no guest program can cause.
    Internal(Error),
}

/// An x86-64 guest thread's CPU.
pub struct X86UserCpu {
    vcpu: X86_64Vcpu,
    space: AddressSpace,
    code_epoch: u64,
}

impl X86UserCpu {
    /// Creates a CPU in the Linux `execve` user state over `space`, which
    /// must reserve [`RESERVED_PHYS`].
    pub fn new(space: &AddressSpace) -> Self {
        let mut vcpu = X86_64Vcpu::new(0, space.physical_memory().clone());
        vcpu.enable_user_mode(Arc::new(space.clone()));
        X86UserCpu {
            vcpu,
            space: space.clone(),
            code_epoch: space.code_epoch(),
        }
    }

    /// A new CPU for another thread of the same process with this CPU's
    /// complete register state (integer, flags, x87/SSE/AVX, MXCSR, XCR0,
    /// FS/GS bases).
    pub fn clone_thread(&self) -> Self {
        let mut child = X86UserCpu::new(&self.space);
        if let Some(state) = self.vcpu.get_emulator_state() {
            let _ = child.vcpu.set_emulator_state(&state);
        }
        child
            .vcpu
            .set_xcr0(self.vcpu.xcr0())
            .expect("parent XCR0 is valid");
        *child.vcpu.user_regs_mut() = self.vcpu.user_regs().clone();
        child.vcpu.set_user_rflags(self.vcpu.user_rflags());
        child.vcpu.set_fs_base(self.vcpu.fs_base());
        child.vcpu.set_gs_base(self.vcpu.gs_base());
        child
    }

    /// The underlying core.
    pub fn vcpu(&self) -> &X86_64Vcpu {
        &self.vcpu
    }

    /// Mutable access to the underlying core.
    pub fn vcpu_mut(&mut self) -> &mut X86_64Vcpu {
        &mut self.vcpu
    }

    /// The address space this CPU executes in.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Current RIP.
    pub fn pc(&self) -> u64 {
        self.vcpu.user_regs().rip
    }

    /// Runs until an operating-system event or the end of the time slice.
    pub fn run(&mut self) -> X86Exit {
        match take_code_changes(&self.space, &mut self.code_epoch) {
            CodeChanges::None => {}
            CodeChanges::Ranges(ranges) => {
                for (start, len) in ranges {
                    self.vcpu.invalidate_code_range(start, len);
                }
            }
            CodeChanges::All => self.vcpu.invalidate_all_code(),
        }
        let result = self.vcpu.run();
        let pc = self.vcpu.user_regs().rip;
        let trap = self.vcpu.take_user_trap();
        match (result, trap) {
            (Ok(VcpuExit::SystemCall), Some(X86UserTrap::SystemCall { insn, insn_rip })) => {
                X86Exit::Syscall { insn, insn_rip }
            }
            (Err(Error::GuestEvent { .. }), Some(X86UserTrap::Event(event))) => {
                X86Exit::Event(event)
            }
            // The x86 core yields `Hlt` at time-slice boundaries; user mode
            // turns a guest HLT into #GP, so this is never a real halt.
            (Ok(VcpuExit::Hlt), None) => X86Exit::Yield,
            (Err(Error::GuestAccess(fault)), None) => {
                X86Exit::Fault(AccessFault::from_memory(fault, pc))
            }
            (result, trap) => X86Exit::Internal(Error::Emulator(format!(
                "unexpected x86-64 user-mode exit at {pc:#x}: {result:?} (trap {trap:?})"
            ))),
        }
    }
}
