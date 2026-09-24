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
//! | [`aarch64`] | `arch/arm64/kernel/signal.c`, `ptrace.c` (`valid_user_regs`) |
//! | [`riscv64`] | `arch/riscv/kernel/signal.c` |
//!
//! Frames are written with the permission checks of `copy_to_user`: a store
//! the page tables forbid makes frame setup fail, and the caller forces
//! `SIGSEGV` as `signal_setup_done` does.

pub mod aarch64;
pub mod riscv64;
pub mod x86_64;

use super::{AltStack, SigInfo};
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
    /// The frame is invalid; force this signal.
    Bad(BadFrame),
    /// The frame selects an execution mode the emulator does not provide
    /// (x86 32-bit compatibility code).
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
}

/// Maps the `[vdso]` page holding the signal-return trampoline that
/// handlers without `SA_RESTORER` return through, top-down below
/// `mmap_base` as `ARCH_SETUP_ADDITIONAL_PAGES` maps the vDSO after the
/// image and interpreter, and returns the trampoline's address. The page
/// holds the vDSO's instructions (`arch/arm64/kernel/vdso/sigreturn.S`:
/// `nop` then `__kernel_rt_sigreturn: mov x8, #139; svc #0`;
/// `arch/riscv/kernel/vdso/rt_sigreturn.S`: `li a7, 139; ecall`), which
/// unwinders recognize by their encoding. It is not an ELF image, so no
/// `AT_SYSINFO_EHDR` is advertised. x86-64 needs no trampoline.
pub fn map_sigtramp(
    abi: crate::user::linux::abi::LinuxAbi,
    space: &AddressSpace,
    mmap_base: u64,
) -> Result<u64, crate::user::mm::MmError> {
    use crate::user::linux::abi::{LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE};
    use crate::user::mm::{Mapping, MmError, Perms};
    let (code, entry): (&[u32], u64) = match abi {
        LinuxAbi::X86_64 => return Ok(0),
        LinuxAbi::Aarch64 => (&[0xd503_201f, 0xd280_1168, 0xd400_0001], 4),
        LinuxAbi::Riscv64 => (&[0x08b0_0893, 0x0000_0073], 0),
    };
    let page = space
        .find_free_top_down(PAGE_SIZE, PAGE_SIZE, MMAP_MIN_ADDR, mmap_base)
        .ok_or(MmError::OutOfMemory)?;
    space.map(
        page,
        PAGE_SIZE,
        Mapping::anonymous(Perms::READ | Perms::EXEC).named("[vdso]"),
    )?;
    let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
    space
        .write_raw(page, &bytes)
        .map_err(|_| MmError::OutOfMemory)?;
    Ok(page + entry)
}

/// Builds the handler frame for `d` on the thread's stack and points the
/// thread at the handler. `sigtramp` is the return trampoline used when the
/// action has no `SA_RESTORER` (arm64 and riscv).
pub fn setup_rt_frame(
    t: &mut Thread,
    space: &AddressSpace,
    d: &Delivery,
    sigtramp: u64,
) -> Result<(), FrameFault> {
    let (alt, fault) = (t.altstack, t.fault);
    match &mut t.cpu {
        GuestCpu::X86_64(cpu) => x86_64::setup_rt_frame(cpu, &alt, &fault, space, d),
        GuestCpu::Aarch64(cpu) => aarch64::setup_rt_frame(cpu, &alt, &fault, space, d, sigtramp),
        GuestCpu::Riscv64(cpu) => riscv64::setup_rt_frame(cpu, &alt, space, d, sigtramp),
    }
}

/// `rt_sigreturn`: restores the state the frame at the stack pointer holds.
/// `min_altstack` is the ABI's `MINSIGSTKSZ`.
pub fn rt_sigreturn(
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
        GuestCpu::X86_64(cpu) => x86_64::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::Aarch64(cpu) => aarch64::rt_sigreturn(cpu, &mut st, space),
        GuestCpu::Riscv64(cpu) => riscv64::rt_sigreturn(cpu, &mut st, space),
    }
}
