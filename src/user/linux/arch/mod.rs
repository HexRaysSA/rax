//! Per-architecture Linux thread state.
//!
//! [`GuestCpu`] binds a CPU adapter to its Linux ABI: the system-call
//! register convention, the register state `execve` establishes, the thread
//! pointer, the capabilities advertised in the auxiliary vector, and the
//! translation of hardware exceptions into the signals the architecture's
//! trap handlers send.

pub mod aarch64;
pub mod riscv64;
pub mod x86_64;

use super::abi::LinuxAbi;
use super::signal::SigInfo;
use crate::isa::riscv::RiscVConfig;
use crate::user::cpu::aarch64::A64UserCpu;
use crate::user::cpu::riscv64::RvUserCpu;
use crate::user::cpu::x86_64::X86UserCpu;
use crate::user::cpu::{AccessFault, AccessFaultKind};
use crate::user::mm::AddressSpace;

/// What a thread did when it ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpuEvent {
    /// A system call in the ABI's native convention. The PC is already past
    /// the call instruction.
    Syscall {
        /// System-call number register.
        nr: u64,
        /// The six argument registers.
        args: [u64; 6],
    },
    /// An x86-64 `INT 0x80`: a system call in the 32-bit (i386) convention.
    /// The PC is past the instruction.
    CompatSyscall {
        /// `EAX`.
        nr: u64,
        /// `EBX`, `ECX`, `EDX`, `ESI`, `EDI`, `EBP`, zero-extended.
        args: [u64; 6],
    },
    /// A synchronous signal. The PC is where the kernel's signal frame
    /// records it (the faulting instruction for faults, the following
    /// instruction for traps).
    Signal(SigInfo),
    /// The time slice ended.
    Yield,
    /// The emulator failed in a way no guest program can cause.
    Internal(String),
}

/// CPU configuration options.
#[derive(Clone, Copy, Debug)]
pub struct CpuOptions {
    /// Use the RISC-V SMIR JIT.
    pub riscv_jit: bool,
    /// RISC-V ISA configuration.
    pub riscv_config: RiscVConfig,
}

impl Default for CpuOptions {
    fn default() -> Self {
        CpuOptions {
            riscv_jit: false,
            riscv_config: RiscVConfig::rv64gc(),
        }
    }
}

/// Capabilities a Linux kernel advertises for the emulated CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchCaps {
    /// `AT_HWCAP`.
    pub hwcap: u64,
    /// `AT_HWCAP2`, if the ABI defines `ELF_HWCAP2`.
    pub hwcap2: Option<u64>,
    /// `ELF_PLATFORM`.
    pub platform: Option<&'static str>,
    /// `AT_MINSIGSTKSZ`: the signal frame size this implementation needs.
    pub minsigstksz: u64,
}

/// A guest thread's CPU with its Linux ABI.
pub enum GuestCpu {
    /// x86-64.
    X86_64(X86UserCpu),
    /// AArch64.
    Aarch64(A64UserCpu),
    /// RV64.
    Riscv64(RvUserCpu),
}

/// Maps an access fault to its Linux signal (`do_page_fault` and the
/// architectures' alignment handlers).
pub fn fault_signal(fault: &AccessFault) -> SigInfo {
    use super::signal::{SIGBUS, SIGSEGV, code};
    match fault.kind {
        AccessFaultKind::Unmapped => SigInfo::fault(SIGSEGV, code::SEGV_MAPERR, fault.addr),
        AccessFaultKind::Permission => SigInfo::fault(SIGSEGV, code::SEGV_ACCERR, fault.addr),
        AccessFaultKind::Alignment => SigInfo::fault(SIGBUS, code::BUS_ADRALN, fault.addr),
        AccessFaultKind::Bus => SigInfo::fault(SIGBUS, code::BUS_ADRERR, fault.addr),
    }
}

impl GuestCpu {
    /// A CPU for `abi` in the `execve` register state over `space`.
    pub fn new(abi: LinuxAbi, space: &AddressSpace, options: &CpuOptions) -> Self {
        match abi {
            LinuxAbi::X86_64 => GuestCpu::X86_64(X86UserCpu::new(space)),
            LinuxAbi::Aarch64 => GuestCpu::Aarch64(A64UserCpu::new(space)),
            LinuxAbi::Riscv64 => {
                let mut cpu = RvUserCpu::new(space, options.riscv_config);
                cpu.set_jit(options.riscv_jit);
                GuestCpu::Riscv64(cpu)
            }
        }
    }

    /// The ABI.
    pub fn abi(&self) -> LinuxAbi {
        match self {
            GuestCpu::X86_64(_) => LinuxAbi::X86_64,
            GuestCpu::Aarch64(_) => LinuxAbi::Aarch64,
            GuestCpu::Riscv64(_) => LinuxAbi::Riscv64,
        }
    }

    /// Capabilities to advertise for this CPU.
    pub fn caps(&self) -> ArchCaps {
        match self {
            GuestCpu::X86_64(cpu) => x86_64::caps(cpu),
            GuestCpu::Aarch64(_) => aarch64::caps(),
            GuestCpu::Riscv64(cpu) => riscv64::caps(cpu),
        }
    }

    /// Sets the entry state `start_thread` establishes: every register zero
    /// except the program counter and stack pointer.
    pub fn start(&mut self, entry: u64, sp: u64) {
        match self {
            GuestCpu::X86_64(cpu) => x86_64::start(cpu, entry, sp),
            GuestCpu::Aarch64(cpu) => aarch64::start(cpu, entry, sp),
            GuestCpu::Riscv64(cpu) => riscv64::start(cpu, entry, sp),
        }
    }

    /// Runs up to `budget` instructions (x86-64 uses its own ~1 ms slice).
    pub fn run(&mut self, budget: u64) -> CpuEvent {
        match self {
            GuestCpu::X86_64(cpu) => x86_64::run(cpu),
            GuestCpu::Aarch64(cpu) => aarch64::run(cpu, budget),
            GuestCpu::Riscv64(cpu) => riscv64::run(cpu, budget),
        }
    }

    /// Stores a system call's return value in the ABI's result register.
    pub fn set_syscall_result(&mut self, value: u64) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rax = value,
            GuestCpu::Aarch64(cpu) => cpu.core_mut().set_x(0, value),
            GuestCpu::Riscv64(cpu) => cpu.core_mut().set_x(10, value),
        }
    }

    /// Program counter.
    pub fn pc(&self) -> u64 {
        match self {
            GuestCpu::X86_64(cpu) => cpu.pc(),
            GuestCpu::Aarch64(cpu) => cpu.pc(),
            GuestCpu::Riscv64(cpu) => cpu.pc(),
        }
    }

    /// Stack pointer.
    pub fn sp(&self) -> u64 {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu().user_regs().rsp,
            GuestCpu::Aarch64(cpu) => cpu.sp(),
            GuestCpu::Riscv64(cpu) => cpu.core().x(2),
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, sp: u64) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rsp = sp,
            GuestCpu::Aarch64(cpu) => cpu.set_sp(sp),
            GuestCpu::Riscv64(cpu) => cpu.core_mut().set_x(2, sp),
        }
    }

    /// The thread pointer (x86-64 FS base, `TPIDR_EL0`, RISC-V `tp`).
    pub fn thread_pointer(&self) -> u64 {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu().fs_base(),
            GuestCpu::Aarch64(cpu) => cpu.core().tpidr_el0(),
            GuestCpu::Riscv64(cpu) => cpu.core().x(4),
        }
    }

    /// Sets the thread pointer, as `clone(CLONE_SETTLS)` does.
    pub fn set_thread_pointer(&mut self, tp: u64) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu_mut().set_fs_base(tp),
            GuestCpu::Aarch64(cpu) => cpu.core_mut().set_tpidr_el0(tp),
            GuestCpu::Riscv64(cpu) => cpu.core_mut().set_x(4, tp),
        }
    }

    /// A CPU for a new thread with this thread's register state.
    pub fn clone_thread(&self) -> Self {
        match self {
            GuestCpu::X86_64(cpu) => GuestCpu::X86_64(cpu.clone_thread()),
            GuestCpu::Aarch64(cpu) => GuestCpu::Aarch64(cpu.clone_thread()),
            GuestCpu::Riscv64(cpu) => GuestCpu::Riscv64(cpu.clone_thread()),
        }
    }

    /// The address space the CPU executes in.
    pub fn space(&self) -> &AddressSpace {
        match self {
            GuestCpu::X86_64(cpu) => cpu.space(),
            GuestCpu::Aarch64(cpu) => cpu.space(),
            GuestCpu::Riscv64(cpu) => cpu.space(),
        }
    }
}
