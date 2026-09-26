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
use super::signal::frame::FaultUpdate;
use crate::isa::arm::common::cpu::ArmCpu;
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
    /// A synchronous signal and the fault record the trap leaves in the
    /// thread. The PC is where the kernel's signal frame records it (the
    /// faulting instruction for faults, the following instruction for
    /// traps).
    Signal(SigInfo, FaultUpdate),
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
    /// Discards compiled native code, which a process created by forking
    /// the host process must not run: on Apple-Silicon macOS, JIT code
    /// inherited across the host `fork` intermittently faults on its first
    /// execution (`SIGBUS` on the instruction fetch at a region's entry).
    /// The code is compiled again as it becomes hot.
    pub fn discard_native_code(&mut self) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.discard_native_code(),
            GuestCpu::Aarch64(cpu) => cpu.discard_native_code(),
            GuestCpu::Riscv64(cpu) => cpu.discard_native_code(),
        }
    }

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

    /// Runs exactly one instruction (a traced thread's single step);
    /// [`CpuEvent::Yield`] when it retired without an event.
    pub fn step(&mut self) -> CpuEvent {
        match self {
            GuestCpu::X86_64(cpu) => x86_64::step(cpu),
            GuestCpu::Aarch64(cpu) => aarch64::run(cpu, 1),
            GuestCpu::Riscv64(cpu) => riscv64::run(cpu, 1),
        }
    }

    /// Whether the instruction about to run branches (x86-64's block
    /// step); never on the others, which cannot block-step.
    pub fn branch_ahead(&self) -> bool {
        match self {
            GuestCpu::X86_64(cpu) => cpu.branch_ahead(),
            _ => false,
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

    /// The system-call result register (RAX, X0, a0).
    pub fn syscall_return_value(&self) -> u64 {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu().user_regs().rax,
            GuestCpu::Aarch64(cpu) => cpu.core().get_x(0),
            GuestCpu::Riscv64(cpu) => cpu.core().x(10),
        }
    }

    /// Length of the system-call instruction (`SYSCALL` 2, `SVC`/`ECALL`
    /// 4 bytes).
    pub fn syscall_insn_len(&self) -> u64 {
        match self {
            GuestCpu::X86_64(_) => 2,
            GuestCpu::Aarch64(_) | GuestCpu::Riscv64(_) => 4,
        }
    }

    /// Prepares to re-execute the system call just returned from: the PC
    /// goes back to the call instruction and the register the call
    /// overwrote gets its entry value back (x86 `orig_ax`, the number; arm64
    /// `orig_x0` and riscv `orig_a0`, the first argument).
    pub fn rewind_syscall(&mut self, nr: u64, arg0: u64) {
        let pc = self.pc().wrapping_sub(self.syscall_insn_len());
        match self {
            GuestCpu::X86_64(cpu) => {
                let r = cpu.vcpu_mut().user_regs_mut();
                r.rax = nr;
                r.rip = pc;
            }
            GuestCpu::Aarch64(cpu) => {
                cpu.core_mut().set_x(0, arg0);
                cpu.core_mut().set_pc(pc);
            }
            GuestCpu::Riscv64(cpu) => {
                cpu.core_mut().set_x(10, arg0);
                cpu.core_mut().set_pc(pc);
            }
        }
    }

    /// Sets the system-call number register (RAX, X8, a7).
    pub fn set_syscall_number(&mut self, nr: u64) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rax = nr,
            GuestCpu::Aarch64(cpu) => cpu.core_mut().set_x(8, nr),
            GuestCpu::Riscv64(cpu) => cpu.core_mut().set_x(17, nr),
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        match self {
            GuestCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rip = pc,
            GuestCpu::Aarch64(cpu) => cpu.core_mut().set_pc(pc),
            GuestCpu::Riscv64(cpu) => cpu.core_mut().set_pc(pc),
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

    /// Applies `TIF_NOTSC`: on x86-64, CR4.TSD, so `RDTSC` and `RDTSCP`
    /// fault with `SIGSEGV`; other architectures have no such flag.
    pub fn set_tsc_disabled(&mut self, disabled: bool) {
        if let GuestCpu::X86_64(cpu) = self {
            cpu.vcpu_mut().set_user_tsc_disabled(disabled);
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
