//! Signal frames: `setup_rt_frame` and `rt_sigreturn` per architecture.
//!
//! A frame is the `struct rt_sigframe` the kernel writes on the user stack
//! when it runs a handler: the `siginfo_t`, a `ucontext_t` holding every
//! register the handler may clobber, and the architecture's extended state.
//! `rt_sigreturn` reads it back. Each module reproduces its architecture's
//! layout, placement, register setup, and validation byte for byte:
//!
//! | Module | Source |
//! |---|---|
//! | [`x86_64`] | `arch/x86/kernel/signal.c`, `signal_64.c`, `fpu/signal.c` |
//! | [`ia32`] | `arch/x86/kernel/signal_32.c`, `fpu/signal.c`, `fpu/regset.c` |
//! | [`aarch64`] | `arch/arm64/kernel/signal.c`, `ptrace.c` (`valid_user_regs`) |
//! | [`riscv64`] | `arch/riscv/kernel/signal.c` |
//! | [`arm`] | `arch/arm64/kernel/signal32.c`, `ptrace.c` (`valid_compat_regs`) |
//!
//! Frames are written with the permission checks of `copy_to_user`: a store
//! the page tables forbid makes frame setup fail, and the caller forces
//! `SIGSEGV` as `signal_setup_done` does.

pub mod aarch64;
pub mod arm;
pub mod ia32;
pub mod riscv64;
pub mod x86_64;

use super::{AltStack, SigInfo, sa};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::process::{SigAction, Thread};
use crate::user::mm::AddressSpace;

/// A signal about to run a handler (`struct ksignal`).
#[derive(Clone, Copy, Debug)]
pub struct Delivery {
    /// The signal number.
    pub sig: i32,
    /// Its `siginfo`.
    pub info: SigInfo,
    /// The disposition in effect when it was dequeued.
    pub action: SigAction,
    /// The mask the frame records and `rt_sigreturn` reinstates
    /// (`sigmask_to_save`).
    pub saved_mask: u64,
}

/// A thread's architectural fault record, reported in signal frames:
/// x86 `thread.trap_nr`, `thread.error_code`, and `thread.cr2`; arm64
/// `thread.fault_address` and `thread.fault_code` (the ESR). The kernel
/// updates it when a trap raises a signal and never clears it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultState {
    /// x86 vector of the last trap.
    pub trap_nr: u64,
    /// x86 error code of the last trap.
    pub error_code: u64,
    /// x86 faulting linear address of the last page fault.
    pub cr2: u64,
    /// arm64 fault address.
    pub fault_address: u64,
    /// arm64 syndrome (`ESR_EL1`) of the last fault.
    pub fault_code: u64,
}

/// How a trap changes a thread's [`FaultState`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultUpdate {
    /// No change.
    #[default]
    None,
    /// x86 `do_trap`/`set_signal_archinfo`: `trap_nr` and `error_code`,
    /// and `cr2` for page faults.
    X86 {
        /// Vector.
        trap_nr: u64,
        /// Error code.
        error_code: u64,
        /// `cr2`, for page faults.
        cr2: Option<u64>,
    },
    /// arm64 `set_thread_esr`/`arm64_notify_die`.
    Arm64 {
        /// `fault_address`.
        address: u64,
        /// `fault_code`.
        esr: u64,
    },
}

impl FaultState {
    /// Applies a trap's update.
    pub fn apply(&mut self, update: FaultUpdate) {
        match update {
            FaultUpdate::None => {}
            FaultUpdate::X86 {
                trap_nr,
                error_code,
                cr2,
            } => {
                self.trap_nr = trap_nr;
                self.error_code = error_code;
                if let Some(cr2) = cr2 {
                    self.cr2 = cr2;
                }
            }
            FaultUpdate::Arm64 { address, esr } => {
                self.fault_address = address;
                self.fault_code = esr;
            }
        }
    }
}

/// Frame setup failed (`setup_rt_frame` returned an error).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameFault;

/// `rt_sigreturn` found a bad frame: the signal its `badframe` path forces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadFrame {
    /// The signal (always `SIGSEGV`).
    pub info: SigInfo,
    /// The fault-record update the path makes.
    pub fault: FaultUpdate,
}

/// What `rt_sigreturn` asks the process to do besides restoring registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigreturnError {
    /// The frame is invalid (`badframe`): the call returns zero and this
    /// signal is forced.
    Bad(BadFrame),
    /// The registers were restored, but returning to them faults (x86
    /// `IRET` refusing the code or stack selector): this signal is forced
    /// with the restored state.
    Fault(BadFrame),
    /// The frame selects an execution mode the emulator does not provide
    /// (x86 code of the other width than the task's).
    Unsupported(&'static str),
}

/// `copy_to_user`: a store with user permissions.
pub(crate) fn put(space: &AddressSpace, addr: u64, bytes: &[u8]) -> Result<(), FrameFault> {
    space.write(addr, bytes).map_err(|_| FrameFault)
}

/// `copy_from_user`: a load with user permissions.
pub(crate) fn get<const N: usize>(space: &AddressSpace, addr: u64) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    space.read(addr, &mut b).ok()?;
    Some(b)
}

/// Reads a little-endian `u64` from user memory.
pub(crate) fn get_u64(space: &AddressSpace, addr: u64) -> Option<u64> {
    get::<8>(space, addr).map(u64::from_le_bytes)
}

/// Reads a little-endian `u32` from user memory.
pub(crate) fn get_u32(space: &AddressSpace, addr: u64) -> Option<u32> {
    get::<4>(space, addr).map(u32::from_le_bytes)
}

/// The thread state `rt_sigreturn` changes besides the CPU registers.
pub struct SigreturnState<'a> {
    /// The blocked mask.
    pub sigmask: &'a mut u64,
    /// The alternate signal stack.
    pub altstack: &'a mut AltStack,
    /// `MINSIGSTKSZ` for `restore_altstack`.
    pub min_altstack: u64,
}

impl SigreturnState<'_> {
    /// `set_current_blocked`: SIGKILL and SIGSTOP can never be blocked.
    pub fn set_blocked(&mut self, mask: u64) {
        *self.sigmask = mask & !super::KERNEL_ONLY_MASK;
    }

    /// `restore_altstack`: installs the frame's `stack_t` as `sigaltstack`
    /// would for a thread at `sp`, ignoring every error but a fault reading
    /// the record.
    pub fn restore_altstack(&mut self, space: &AddressSpace, addr: u64, sp: u64) -> Result<(), ()> {
        let b = get::<24>(space, addr).ok_or(())?;
        let _ = self
            .altstack
            .install(AltStack::decode_stack_t(&b), sp, self.min_altstack);
        Ok(())
    }

    /// `compat_restore_altstack`: [`SigreturnState::restore_altstack`] for
    /// a `compat_stack_t`.
    pub fn restore_altstack32(
        &mut self,
        space: &AddressSpace,
        addr: u64,
        sp: u64,
    ) -> Result<(), ()> {
        let b = get::<12>(space, addr).ok_or(())?;
        let _ = self
            .altstack
            .install(AltStack::decode_compat_stack_t(&b), sp, self.min_altstack);
        Ok(())
    }
}

/// Maps the `[vdso]` page holding the signal-return trampolines that
/// handlers without `SA_RESTORER` return through, top-down below
/// `mmap_base` as `ARCH_SETUP_ADDITIONAL_PAGES` maps the vDSO after the
/// image and interpreter, and returns the trampoline's address (i386: the
/// page's, whose two trampolines [`ia32::VDSO_SIGRETURN`] and
/// [`ia32::VDSO_RT_SIGRETURN`] locate). The page holds the vDSO's
/// instructions (`arch/arm64/kernel/vdso/sigreturn.S`: `nop` then
/// `__kernel_rt_sigreturn: mov x8, #139; svc #0`;
/// `arch/riscv/kernel/vdso/rt_sigreturn.S`: `li a7, 139; ecall`;
/// `arch/x86/entry/vdso/vdso32/sigreturn.S`), which unwinders recognize by
/// their encoding. It is not an ELF image, so no `AT_SYSINFO_EHDR` is
/// advertised. x86-64 needs no trampoline.
pub fn map_sigtramp(
    abi: crate::user::linux::abi::LinuxAbi,
    space: &AddressSpace,
    mmap_base: u64,
) -> Result<u64, crate::user::mm::MmError> {
    use crate::user::linux::abi::{LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE};
    use crate::user::mm::{Mapping, MmError, Perms};
    let words = |code: &[u32]| -> Vec<u8> { code.iter().flat_map(|w| w.to_le_bytes()).collect() };
    let (bytes, entry): (Vec<u8>, u64) = match abi {
        LinuxAbi::X86_64 => return Ok(0),
        // The [vectors] page and the [sigpage].
        LinuxAbi::Arm => return arm::map_pages(space, mmap_base),
        LinuxAbi::I386 => (ia32::vdso_code().to_vec(), 0),
        LinuxAbi::Aarch64 => (words(&[0xd503_201f, 0xd280_1168, 0xd400_0001]), 4),
        LinuxAbi::Riscv64 => (words(&[0x08b0_0893, 0x0000_0073]), 0),
    };
    let page = space
        .find_free_top_down(PAGE_SIZE, PAGE_SIZE, MMAP_MIN_ADDR, mmap_base)
        .ok_or(MmError::OutOfMemory)?;
    let mut vdso = Mapping::anonymous(Perms::READ | Perms::EXEC).named("[vdso]");
    vdso.flags = crate::user::linux::abi::vma_flags::SPECIAL;
    space.map(page, PAGE_SIZE, vdso)?;
    space
        .write_raw(page, &bytes)
        .map_err(|_| MmError::OutOfMemory)?;
    Ok(page + entry)
}

/// Builds the handler frame for `d` on the thread's stack and points the
/// thread at the handler (x86 `setup_rt_frame`: a handler a 32-bit call
/// installed, `SA_IA32_ABI`, gets an i386 frame, RT with `SA_SIGINFO`).
/// `sigtramp` is the `[vdso]` return trampoline used when the action has
/// no `SA_RESTORER` (arm64, riscv, and i386).
pub fn setup_rt_frame(
    t: &mut Thread,
    space: &AddressSpace,
    d: &Delivery,
    sigtramp: u64,
) -> Result<(), FrameFault> {
    let (alt, fault) = (t.altstack, t.fault);
    let (ia32, siginfo) = (
        d.action.flags & sa::IA32_ABI != 0,
        d.action.flags & sa::SIGINFO != 0,
    );
    match &mut t.cpu {
        GuestCpu::X86_64(cpu) if ia32 && siginfo => {
            ia32::setup_rt_frame(cpu, &alt, &fault, space, d, sigtramp)
        }
        GuestCpu::X86_64(cpu) if ia32 => ia32::setup_frame(cpu, &alt, &fault, space, d, sigtramp),
        GuestCpu::X86_64(cpu) => x86_64::setup_rt_frame(cpu, &alt, &fault, space, d),
        GuestCpu::Aarch64(cpu) => aarch64::setup_rt_frame(cpu, &alt, &fault, space, d, sigtramp),
        GuestCpu::Riscv64(cpu) => riscv64::setup_rt_frame(cpu, &alt, space, d, sigtramp),
        GuestCpu::Arm(cpu) => arm::setup_frame(cpu, &alt, &fault, space, d, sigtramp),
    }
}

/// `rt_sigreturn`: restores the state the frame at the stack pointer holds;
/// `ia32` for the 32-bit call (`compat_sys_rt_sigreturn`) and its frame.
/// `min_altstack` is the ABI's `MINSIGSTKSZ`.
pub fn rt_sigreturn(
    t: &mut Thread,
    space: &AddressSpace,
    min_altstack: u64,
    ia32: bool,
) -> Result<(), SigreturnError> {
    let mut st = SigreturnState {
        sigmask: &mut t.sigmask,
        altstack: &mut t.altstack,
        min_altstack,
    };
    match &mut t.cpu {
        GuestCpu::X86_64(cpu) if ia32 => ia32::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::X86_64(cpu) => x86_64::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::Aarch64(cpu) => aarch64::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::Riscv64(cpu) => riscv64::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::Arm(cpu) => arm::sigreturn(cpu, &mut st, space, true),
    }
}

/// `sigreturn`, the non-RT frame's return: only the 32-bit x86 and ARM
/// calls (`compat_sys_sigreturn`) exist.
pub fn sigreturn(
    t: &mut Thread,
    space: &AddressSpace,
    min_altstack: u64,
) -> Result<(), SigreturnError> {
    let mut st = SigreturnState {
        sigmask: &mut t.sigmask,
        altstack: &mut t.altstack,
        min_altstack,
    };
    match &mut t.cpu {
        GuestCpu::X86_64(cpu) => ia32::sigreturn(cpu, &mut st, space),
        GuestCpu::Arm(cpu) => arm::sigreturn(cpu, &mut st, space, false),
        _ => Err(SigreturnError::Unsupported(
            "sigreturn outside the i386 and ARM ABIs",
        )),
    }
}
