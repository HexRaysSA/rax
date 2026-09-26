//! x86-64 user-mode adapter.
//!
//! Wraps an [`X86_64Vcpu`] in user mode (see
//! `crate::isa::x86_64::user_mode`) over an [`AddressSpace`]. The x86 core
//! returns control at ~1 ms time-slice boundaries on its own, which the
//! adapter reports as [`X86Exit::Yield`].

mod branch;

use std::sync::Arc;

use super::{AccessFault, take_code_changes};
use crate::error::Error;
use crate::isa::x86_64::{
    GDT_ENTRY_TLS_MAX, GDT_ENTRY_TLS_MIN, X86_64Vcpu, X86SyscallInsn, X86UserEvent, X86UserTrap,
};
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
        // The mode, the TLS entries, and the data segment registers with
        // their cached descriptors (copy_thread; the FS/GS bases with them).
        child.vcpu.set_user_compat(self.vcpu.user_compat());
        for index in GDT_ENTRY_TLS_MIN..=GDT_ENTRY_TLS_MAX {
            if let Some(entry) = self.vcpu.user_gdt_entry(index) {
                child.vcpu.set_user_tls_entry(index, entry);
            }
        }
        child.vcpu.copy_user_data_segments(&self.vcpu);
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

    /// Discards every cached decode and compiled region.
    pub fn discard_native_code(&mut self) {
        self.vcpu.invalidate_all_code();
    }

    /// Runs until an operating-system event or the end of the time slice.
    pub fn run(&mut self) -> X86Exit {
        self.sync_code();
        let result = self.vcpu.run();
        self.exit(result)
    }

    /// Runs exactly one instruction with the core's precise step (never
    /// native code); [`X86Exit::Yield`] when it retired without an event.
    pub fn step(&mut self) -> X86Exit {
        self.sync_code();
        let result = self
            .vcpu
            .step_with_faults()
            .map(|exit| exit.unwrap_or(VcpuExit::Hlt));
        self.exit(result)
    }

    /// Whether the instruction at RIP branches when it runs (see
    /// [`branch`]): the end of a block step. Code the thread cannot fetch
    /// does not branch; its step faults.
    pub fn branch_ahead(&self) -> bool {
        let rip = self.vcpu.user_regs().rip;
        let mut code = [0u8; 15];
        let mut n = 0;
        while n < code.len() && self.space.fetch(rip + n as u64, &mut code[n..=n]).is_ok() {
            n += 1;
        }
        let rcx = self.vcpu.user_regs().rcx;
        branch::taken(&code[..n], self.vcpu.user_rflags(), rcx)
    }

    /// Drops the decodes and native code of guest code written since the
    /// last run.
    fn sync_code(&mut self) {
        match take_code_changes(&self.space, &mut self.code_epoch) {
            CodeChanges::None => {}
            CodeChanges::Ranges(ranges) => {
                for (start, len) in ranges {
                    self.vcpu.invalidate_code_range(start, len);
                }
            }
            CodeChanges::All => self.vcpu.invalidate_all_code(),
        }
    }

    /// Classifies how a run or step ended.
    fn exit(&mut self, result: crate::error::Result<VcpuExit>) -> X86Exit {
        let pc = self.vcpu.user_regs().rip;
        let trap = self.vcpu.take_user_trap();
        match (result, trap) {
            (Ok(VcpuExit::SystemCall), Some(X86UserTrap::SystemCall { insn, insn_rip })) => {
                X86Exit::Syscall { insn, insn_rip }
            }
            (Err(Error::GuestEvent { .. }), Some(X86UserTrap::Event(event))) => {
                X86Exit::Event(event)
            }
            // The x86 core yields `Hlt` at time-slice boundaries (and a step
            // reports it for a retired instruction); user mode turns a guest
            // HLT into #GP, so this is never a real halt.
            (Ok(VcpuExit::Hlt), None) => X86Exit::Yield,
            // A step whose event was recorded without an error return.
            (Ok(VcpuExit::Hlt), Some(X86UserTrap::Event(event))) => X86Exit::Event(event),
            (Err(Error::GuestAccess(fault)), None) => {
                X86Exit::Fault(AccessFault::from_memory(fault, pc))
            }
            (result, trap) => X86Exit::Internal(Error::Emulator(format!(
                "unexpected x86-64 user-mode exit at {pc:#x}: {result:?} (trap {trap:?})"
            ))),
        }
    }
}
