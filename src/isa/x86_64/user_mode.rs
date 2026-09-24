//! Process-level (user-mode) execution for the x86-64 software CPU.
//!
//! In user mode the vCPU executes one guest process's ring-3 code while an
//! embedder implements the operating system. Three things change relative to
//! system emulation, and nothing else:
//!
//! 1. **Translation.** Paging is not used. Every linear access is translated
//!    by an installed [`FlatTranslation`], which enforces the page's read,
//!    write, and execute permissions; instruction fetches are checked as
//!    executes. A permission or unmapped fault is returned as
//!    [`Error::GuestAccess`] with the faulting linear address, and the
//!    instruction does not retire.
//! 2. **System calls.** `SYSCALL` performs its architectural register effects
//!    (RCX = return RIP, R11 = RFLAGS) and then returns
//!    [`VcpuExit::SystemCall`] with RIP at the return address, which is the
//!    state a `SYSRET` from the embedder's handler would restore. `SYSENTER`
//!    also exits, without architectural effects, so the embedder can apply its
//!    own ABI.
//! 3. **Events.** An exception or software interrupt that would be delivered
//!    through the IDT is instead recorded as an [`X86UserEvent`] and reported
//!    as [`Error::GuestEvent`]. The instruction does not retire: RIP is the
//!    faulting instruction, and the event carries the return RIP that the
//!    architectural exception frame would have held.
//!
//! Privilege checks are architectural: user code runs at CPL 3, so privileged
//! instructions raise #GP and become events. `HLT`, which system emulation
//! deliberately permits at any CPL for test harnesses, raises #GP(0) at CPL 3
//! in user mode as the SDM specifies.
//!
//! [`VcpuExit::SystemCall`]: crate::vm::vcpu::VcpuExit::SystemCall

use std::sync::Arc;

use super::cpu::X86_64Vcpu;
use crate::error::{Error, Result};
use crate::vm::memory::FlatTranslation;
use crate::vm::vcpu::Registers;

/// How the recorded event was raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86EventSource {
    /// A processor-detected exception (fault or trap class).
    Exception,
    /// `INT n`, `INT3`, or `INTO`: a software interrupt instruction.
    SoftwareInterrupt,
}

/// An exception or software interrupt reported to the user-mode embedder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86UserEvent {
    /// IDT vector the event would have used.
    pub vector: u8,
    /// Error code the event would have pushed, if any.
    pub error_code: Option<u64>,
    /// Exception or software-interrupt origin.
    pub source: X86EventSource,
    /// Address of the instruction that raised the event. After the report the
    /// vCPU's RIP equals this address.
    pub insn_rip: u64,
    /// RIP the architectural exception frame would have saved: `insn_rip` for
    /// fault-class exceptions, the following instruction for software
    /// interrupts and trap-class exceptions.
    pub return_rip: u64,
}

/// The system-call instruction that ended a user-mode run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86SyscallInsn {
    /// 64-bit `SYSCALL`. RCX and R11 hold the architectural save values and
    /// RIP is the return address.
    Syscall,
    /// `SYSENTER`. No register was modified and RIP is the return address
    /// (`SYSENTER` has no architectural return address; Linux's compat entry
    /// resumes after the instruction).
    Sysenter,
}

/// A user-mode trap recorded by the vCPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86UserTrap {
    /// A system-call instruction at `insn_rip` retired.
    SystemCall { insn: X86SyscallInsn, insn_rip: u64 },
    /// An exception or software interrupt.
    Event(X86UserEvent),
}

/// Per-vCPU user-mode state.
pub(super) struct UserMode {
    pub(super) trap: Option<X86UserTrap>,
}

/// Linux x86-64 user code selector (`__USER_CS`, GDT entry 6, RPL 3).
pub const LINUX_USER_CS: u16 = 0x33;
/// Linux x86-64 user data/stack selector (`__USER_DS`, GDT entry 5, RPL 3).
pub const LINUX_USER_DS: u16 = 0x2b;
/// Linux 32-bit compatibility code selector (`__USER32_CS`, GDT entry 4).
pub const LINUX_USER32_CS: u16 = 0x23;

/// XCR0 bits the emulated CPU accepts (x87, SSE, AVX, AVX-512 opmask/ZMM
/// state, PKRU); mirrors the `XSETBV` validation.
const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_AVX: u64 = 1 << 2;
const XCR0_AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);
const XCR0_PKRU: u64 = 1 << 9;
const XCR0_APX_F: u64 = 1 << 19;

impl X86_64Vcpu {
    /// Switches this vCPU to user mode with `translation` as its address
    /// space, and installs the flat ring-3 64-bit register state that Linux
    /// establishes at `execve`: long mode with paging disabled in the
    /// emulator (the translation replaces it), CS = `__USER_CS`, SS/DS/ES =
    /// `__USER_DS`, FS/GS null with zero bases, `EFER.SCE` set, and
    /// `CR4.OSFXSR | OSXMMEXCPT | OSXSAVE | FSGSBASE` so SSE, XSAVE-managed
    /// state, and the FS/GS-base instructions behave as they do under Linux.
    ///
    /// General-purpose, vector, and flag state are reset to their `execve`
    /// values (all zero except RFLAGS = 0x202 and MXCSR = 0x1F80). XCR0 is set
    /// to x87 | SSE | AVX | AVX-512 state, the set a Linux kernel enables on a
    /// CPU with this CPUID profile.
    pub fn enable_user_mode(&mut self, translation: Arc<dyn FlatTranslation>) {
        use crate::vm::vcpu::Segment;
        let flat = |selector: u16, code: bool, long: bool| Segment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector,
            type_: if code { 0xB } else { 0x3 },
            present: true,
            dpl: 3,
            db: !long,
            s: true,
            l: long,
            g: true,
            avl: false,
            unusable: false,
        };
        let null = crate::vm::vcpu::Segment {
            unusable: true,
            present: false,
            ..flat(0, false, false)
        };

        self.regs = Registers::default();
        self.regs.rflags = 0x202;
        self.lazy_flags = Default::default();
        self.sregs.cs = flat(LINUX_USER_CS, true, true);
        self.sregs.ss = flat(LINUX_USER_DS, false, false);
        self.sregs.ds = flat(LINUX_USER_DS, false, false);
        self.sregs.es = flat(LINUX_USER_DS, false, false);
        self.sregs.fs = null.clone();
        self.sregs.gs = null;
        // PE | MP | ET | NE | WP with PG clear: paging is replaced by the flat
        // translation, but protected-mode semantics remain in force.
        self.sregs.cr0 = 0x0001_0033;
        self.sregs.cr3 = 0;
        // PAE | OSFXSR | OSXMMEXCPT | FSGSBASE | OSXSAVE.
        self.sregs.cr4 = (1 << 5) | (1 << 9) | (1 << 10) | (1 << 16) | (1 << 18);
        // SCE | LME | LMA | NXE.
        self.sregs.efer = 1 | (1 << 8) | (1 << 10) | (1 << 11);
        self.fpu = Default::default();
        self.mxcsr = 0x1F80;
        self.xcr0 = XCR0_X87 | XCR0_SSE | XCR0_AVX | XCR0_AVX512;
        self.halted = false;
        self.interrupt_inhibit = false;
        self.mmu.set_flat_translation(Some(translation));
        self.user = Some(Box::new(UserMode { trap: None }));
        self.invalidate_all_code();
    }

    /// Whether [`X86_64Vcpu::enable_user_mode`] is in effect.
    pub fn user_mode_enabled(&self) -> bool {
        self.user.is_some()
    }

    /// Removes and returns the trap that ended the last user-mode run.
    pub fn take_user_trap(&mut self) -> Option<X86UserTrap> {
        self.user.as_mut().and_then(|u| u.trap.take())
    }

    /// Records a user-mode trap. Returns `false` when user mode is disabled.
    pub(super) fn record_user_trap(&mut self, trap: X86UserTrap) -> bool {
        match self.user.as_mut() {
            Some(user) => {
                user.trap = Some(trap);
                true
            }
            None => false,
        }
    }

    /// Whether a recorded trap is waiting to be taken.
    pub(super) fn user_trap_pending(&self) -> Option<u8> {
        match self.user.as_ref()?.trap? {
            X86UserTrap::Event(event) => Some(event.vector),
            X86UserTrap::SystemCall { .. } => None,
        }
    }

    /// The general-purpose register file. RFLAGS in the returned structure
    /// may be stale; use [`X86_64Vcpu::user_rflags`].
    pub fn user_regs(&self) -> &Registers {
        &self.regs
    }

    /// Mutable access to general-purpose, RIP, and vector registers. RFLAGS
    /// must be written through [`X86_64Vcpu::set_user_rflags`], which also
    /// discards any pending lazily-evaluated flags.
    pub fn user_regs_mut(&mut self) -> &mut Registers {
        &mut self.regs
    }

    /// Architectural RFLAGS with any pending lazy flags evaluated.
    pub fn user_rflags(&self) -> u64 {
        self.compute_materialized_rflags()
    }

    /// Replaces RFLAGS. Bit 1 always reads as one.
    pub fn set_user_rflags(&mut self, value: u64) {
        self.lazy_flags = Default::default();
        self.regs.rflags = value | 0x2;
    }

    /// FS segment base (the Linux x86-64 thread pointer).
    pub fn fs_base(&self) -> u64 {
        self.sregs.fs.base
    }

    /// Sets the FS segment base, as `arch_prctl(ARCH_SET_FS)` does.
    pub fn set_fs_base(&mut self, base: u64) {
        self.sregs.fs.base = base;
    }

    /// GS segment base.
    pub fn gs_base(&self) -> u64 {
        self.sregs.gs.base
    }

    /// Sets the GS segment base, as `arch_prctl(ARCH_SET_GS)` does.
    pub fn set_gs_base(&mut self, base: u64) {
        self.sregs.gs.base = base;
    }

    /// Current XCR0.
    pub fn xcr0(&self) -> u64 {
        self.xcr0
    }

    /// Sets XCR0 with the architectural `XSETBV` validity rules. Returns an
    /// error, leaving XCR0 unchanged, for a value `XSETBV` would reject with
    /// #GP(0).
    pub fn set_xcr0(&mut self, value: u64) -> Result<()> {
        let supported = XCR0_X87
            | XCR0_SSE
            | XCR0_AVX
            | XCR0_AVX512
            | XCR0_PKRU
            | if self.apx_enabled() { XCR0_APX_F } else { 0 };
        let avx512 = value & XCR0_AVX512;
        let invalid = value & XCR0_X87 == 0
            || value & !supported != 0
            || (value & XCR0_AVX != 0 && value & XCR0_SSE == 0)
            || (avx512 != 0
                && (avx512 != XCR0_AVX512 || value & (XCR0_SSE | XCR0_AVX) != XCR0_SSE | XCR0_AVX));
        if invalid {
            return Err(Error::InvalidConfig(format!(
                "XCR0 value {value:#x} would raise #GP(0) on XSETBV"
            )));
        }
        self.xcr0 = value;
        Ok(())
    }

    /// MXCSR.
    pub fn mxcsr(&self) -> u32 {
        self.mxcsr
    }

    /// Sets MXCSR. Returns an error for reserved bits, which `LDMXCSR` would
    /// reject with #GP(0).
    pub fn set_mxcsr(&mut self, value: u32) -> Result<()> {
        if !super::mxcsr_value_is_valid(value) {
            return Err(Error::InvalidConfig(format!(
                "MXCSR value {value:#x} sets reserved bits"
            )));
        }
        self.mxcsr = value;
        Ok(())
    }

    /// Discards every cached decode and compiled region whose source bytes
    /// overlap `[start, start + len)`. The embedder calls this after changing
    /// guest memory or permissions outside this vCPU's own stores (another
    /// vCPU's writes, host writes, unmapping, or removal of execute
    /// permission), so a stale translation can never execute.
    pub fn invalidate_code_range(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let first = start & !0xFFF;
        let last = start.saturating_add(len - 1) & !0xFFF;
        // Bound the page walk: a range larger than the decode cache footprint
        // is cheaper to flush wholesale.
        if (last - first) / 0x1000 >= 1024 {
            self.invalidate_all_code();
            return;
        }
        let mut page = first;
        loop {
            self.invalidate_code_page(page);
            if page == last {
                break;
            }
            page += 0x1000;
        }
    }

    /// Discards every cached decode and compiled region.
    pub fn invalidate_all_code(&mut self) {
        self.invalidate_translation_dependent_caches();
    }
}
