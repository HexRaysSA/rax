//! Per-architecture Linux thread state.
//!
//! [`GuestCpu`] binds a CPU adapter to its Linux ABI: the system-call
//! register convention, the register state `execve` establishes, the thread
//! pointer, the capabilities advertised in the auxiliary vector, and the
//! translation of hardware exceptions into the signals the architecture's
//! trap handlers send.

pub mod aarch64;
pub mod arm;
mod fp_exceptions;
mod memory;

pub use memory::LinuxAddressSpace;
pub mod riscv64;
pub mod x86_64;

use super::abi::LinuxAbi;
use super::signal::SigInfo;
use super::signal::frame::FaultUpdate;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::isa::riscv::RiscVConfig;
use crate::user::cpu::aarch64::CpuWithSpace as A64UserCpu;
use crate::user::cpu::arm::A32UserCpu;
use crate::user::cpu::riscv64::CpuWithSpace as RvUserCpu;
use crate::user::cpu::x86_64::CpuWithSpace as X86UserCpu;
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
    /// `AT_HWCAP3`, if the ABI defines `ELF_HWCAP3`.
    pub hwcap3: Option<u64>,
    /// `ELF_PLATFORM`.
    pub platform: Option<&'static str>,
    /// `AT_MINSIGSTKSZ`, the signal frame size this implementation needs,
    /// if the ABI's `ARCH_DLINFO` gives it.
    pub minsigstksz: Option<u64>,
}

/// A guest thread's CPU with its Linux ABI.
pub type GuestCpu = CpuWithSpace<AddressSpace>;

/// A Linux ABI CPU bound to the selected authoritative storage.
pub enum CpuWithSpace<M: LinuxAddressSpace> {
    /// x86-64.
    X86_64(X86UserCpu<M>),
    /// AArch64.
    Aarch64(A64UserCpu<M>),
    /// RV64.
    Riscv64(RvUserCpu<M>),
    /// ARM EABI (AArch32) on arm64.
    Arm(A32UserCpu<M>),
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

impl CpuWithSpace<AddressSpace> {
    /// A CPU for `abi` in the `execve` register state over `space`.
    pub fn new(abi: LinuxAbi, space: &AddressSpace, options: &CpuOptions) -> Self {
        Self::with_space(abi, space, options)
    }
}

impl<M: LinuxAddressSpace> CpuWithSpace<M> {
    /// Discards compiled native code, which a process created by forking
    /// the host process must not run: on Apple-Silicon macOS, JIT code
    /// inherited across the host `fork` intermittently faults on its first
    /// execution (`SIGBUS` on the instruction fetch at a region's entry).
    /// The code is compiled again as it becomes hot.
    pub fn discard_native_code(&mut self) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.discard_native_code(),
            CpuWithSpace::Aarch64(cpu) => cpu.discard_native_code(),
            CpuWithSpace::Riscv64(cpu) => cpu.discard_native_code(),
            // The AArch32 core is interpreted.
            CpuWithSpace::Arm(_) => {}
        }
    }

    /// A CPU for `abi` in the `execve` register state over `space`.
    pub fn with_space(abi: LinuxAbi, space: &M, options: &CpuOptions) -> Self {
        match abi {
            LinuxAbi::X86_64 => CpuWithSpace::X86_64(X86UserCpu::with_space(space)),
            // start_thread_ia32: the same CPU in compatibility mode.
            LinuxAbi::I386 => {
                let mut cpu = X86UserCpu::with_space(space);
                cpu.set_compat(true);
                CpuWithSpace::X86_64(cpu)
            }
            LinuxAbi::Aarch64 => CpuWithSpace::Aarch64(A64UserCpu::with_space(space)),
            LinuxAbi::Arm => CpuWithSpace::Arm(A32UserCpu::new(space)),
            LinuxAbi::Riscv64 => {
                let mut cpu = RvUserCpu::with_space(space, options.riscv_config);
                cpu.set_jit(options.riscv_jit);
                CpuWithSpace::Riscv64(cpu)
            }
        }
    }

    /// The ABI.
    pub fn abi(&self) -> LinuxAbi {
        match self {
            CpuWithSpace::X86_64(cpu) if cpu.compat() => LinuxAbi::I386,
            CpuWithSpace::X86_64(_) => LinuxAbi::X86_64,
            CpuWithSpace::Aarch64(_) => LinuxAbi::Aarch64,
            CpuWithSpace::Riscv64(_) => LinuxAbi::Riscv64,
            CpuWithSpace::Arm(_) => LinuxAbi::Arm,
        }
    }

    /// Capabilities to advertise for this CPU.
    pub fn caps(&self) -> ArchCaps {
        match self {
            CpuWithSpace::X86_64(cpu) => x86_64::caps(cpu),
            CpuWithSpace::Aarch64(_) => aarch64::caps(),
            CpuWithSpace::Riscv64(cpu) => riscv64::caps(cpu),
            CpuWithSpace::Arm(_) => arm::caps(),
        }
    }

    /// Sets the entry state `start_thread` establishes: every register zero
    /// except the program counter and stack pointer.
    pub fn start(&mut self, entry: u64, sp: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => x86_64::start(cpu, entry, sp),
            CpuWithSpace::Aarch64(cpu) => aarch64::start(cpu, entry, sp),
            CpuWithSpace::Riscv64(cpu) => riscv64::start(cpu, entry, sp),
            CpuWithSpace::Arm(cpu) => arm::start(cpu, entry, sp),
        }
    }

    /// Runs up to `budget` instructions (x86-64 uses its own ~1 ms slice).
    pub fn run(&mut self, budget: u64) -> CpuEvent {
        match self {
            CpuWithSpace::X86_64(cpu) => x86_64::run(cpu),
            CpuWithSpace::Aarch64(cpu) => aarch64::run(cpu, budget),
            CpuWithSpace::Riscv64(cpu) => riscv64::run(cpu, budget),
            CpuWithSpace::Arm(cpu) => arm::run(cpu, budget),
        }
    }

    /// Runs exactly one instruction (a traced thread's single step);
    /// [`CpuEvent::Yield`] when it retired without an event.
    pub fn step(&mut self) -> CpuEvent {
        match self {
            CpuWithSpace::X86_64(cpu) => x86_64::step(cpu),
            CpuWithSpace::Aarch64(cpu) => aarch64::run(cpu, 1),
            CpuWithSpace::Riscv64(cpu) => riscv64::run(cpu, 1),
            CpuWithSpace::Arm(cpu) => arm::run(cpu, 1),
        }
    }

    /// Whether the instruction about to run branches (x86-64's block
    /// step); never on the others, which cannot block-step.
    pub fn branch_ahead(&self) -> bool {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.branch_ahead(),
            _ => false,
        }
    }

    /// Stores a system call's return value in the ABI's result register
    /// (for ARM, its low 32 bits in R0).
    pub fn set_syscall_result(&mut self, value: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rax = value,
            CpuWithSpace::Aarch64(cpu) => cpu.core_mut().set_x(0, value),
            CpuWithSpace::Riscv64(cpu) => cpu.core_mut().set_x(10, value),
            CpuWithSpace::Arm(cpu) => cpu.core_mut().regs[0] = value as u32,
        }
    }

    /// The system-call result register (RAX, X0, a0; ARM's R0
    /// sign-extended, as `syscall_get_return_value` reads a compat task's).
    pub fn syscall_return_value(&self) -> u64 {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu().user_regs().rax,
            CpuWithSpace::Aarch64(cpu) => cpu.core().get_x(0),
            CpuWithSpace::Riscv64(cpu) => cpu.core().x(10),
            CpuWithSpace::Arm(cpu) => cpu.core().regs[0] as i32 as i64 as u64,
        }
    }

    /// Length of the system-call instruction (`SYSCALL` 2, `SVC`/`ECALL`
    /// 4 bytes; ARM's `SVC` 2 bytes in Thumb state, as the restart code's
    /// `compat_thumb_mode(regs) ? 2 : 4`).
    pub fn syscall_insn_len(&self) -> u64 {
        match self {
            CpuWithSpace::X86_64(_) => 2,
            CpuWithSpace::Aarch64(_) | CpuWithSpace::Riscv64(_) => 4,
            CpuWithSpace::Arm(cpu) => {
                if cpu.thumb() {
                    2
                } else {
                    4
                }
            }
        }
    }

    /// Prepares to re-execute the system call just returned from: the PC
    /// goes back to the call instruction and the register the call
    /// overwrote gets its entry value back (x86 `orig_ax`, the number; arm64
    /// `orig_x0` and riscv `orig_a0`, the first argument).
    pub fn rewind_syscall(&mut self, nr: u64, arg0: u64) {
        let pc = self.pc().wrapping_sub(self.syscall_insn_len());
        match self {
            CpuWithSpace::X86_64(cpu) => {
                let r = cpu.vcpu_mut().user_regs_mut();
                r.rax = nr;
                r.rip = pc;
            }
            CpuWithSpace::Aarch64(cpu) => {
                cpu.core_mut().set_x(0, arg0);
                cpu.core_mut().set_pc(pc);
            }
            CpuWithSpace::Riscv64(cpu) => {
                cpu.core_mut().set_x(10, arg0);
                cpu.core_mut().set_pc(pc);
            }
            CpuWithSpace::Arm(cpu) => {
                cpu.core_mut().regs[0] = arg0 as u32;
                cpu.set_pc(pc);
            }
        }
    }

    /// Sets the system-call number register (RAX, X8, a7, R7).
    pub fn set_syscall_number(&mut self, nr: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rax = nr,
            CpuWithSpace::Aarch64(cpu) => cpu.core_mut().set_x(8, nr),
            CpuWithSpace::Riscv64(cpu) => cpu.core_mut().set_x(17, nr),
            CpuWithSpace::Arm(cpu) => cpu.core_mut().regs[7] = nr as u32,
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rip = pc,
            CpuWithSpace::Aarch64(cpu) => cpu.core_mut().set_pc(pc),
            CpuWithSpace::Riscv64(cpu) => cpu.core_mut().set_pc(pc),
            CpuWithSpace::Arm(cpu) => cpu.set_pc(pc),
        }
    }

    /// Program counter.
    pub fn pc(&self) -> u64 {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.pc(),
            CpuWithSpace::Aarch64(cpu) => cpu.pc(),
            CpuWithSpace::Riscv64(cpu) => cpu.pc(),
            CpuWithSpace::Arm(cpu) => cpu.pc(),
        }
    }

    /// Stack pointer.
    pub fn sp(&self) -> u64 {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu().user_regs().rsp,
            CpuWithSpace::Aarch64(cpu) => cpu.sp(),
            CpuWithSpace::Riscv64(cpu) => cpu.core().x(2),
            CpuWithSpace::Arm(cpu) => cpu.sp(),
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, sp: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rsp = sp,
            CpuWithSpace::Aarch64(cpu) => cpu.set_sp(sp),
            CpuWithSpace::Riscv64(cpu) => cpu.core_mut().set_x(2, sp),
            CpuWithSpace::Arm(cpu) => cpu.set_sp(sp),
        }
    }

    /// The thread pointer (x86-64 FS base, `TPIDR_EL0`, RISC-V `tp`, and
    /// an ARM task's `tp_value`, TPIDRURO).
    pub fn thread_pointer(&self) -> u64 {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu().fs_base(),
            CpuWithSpace::Aarch64(cpu) => cpu.core().tpidr_el0(),
            CpuWithSpace::Riscv64(cpu) => cpu.core().x(4),
            CpuWithSpace::Arm(cpu) => u64::from(cpu.core().cp15.tpidruro),
        }
    }

    /// Sets the thread pointer, as `clone(CLONE_SETTLS)` does.
    pub fn set_thread_pointer(&mut self, tp: u64) {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.vcpu_mut().set_fs_base(tp),
            CpuWithSpace::Aarch64(cpu) => cpu.core_mut().set_tpidr_el0(tp),
            CpuWithSpace::Riscv64(cpu) => cpu.core_mut().set_x(4, tp),
            CpuWithSpace::Arm(cpu) => cpu.core_mut().cp15.tpidruro = tp as u32,
        }
    }

    /// Applies `TIF_NOTSC`: on x86-64, CR4.TSD, so `RDTSC` and `RDTSCP`
    /// fault with `SIGSEGV`; other architectures have no such flag.
    pub fn set_tsc_disabled(&mut self, disabled: bool) {
        if let CpuWithSpace::X86_64(cpu) = self {
            cpu.vcpu_mut().set_user_tsc_disabled(disabled);
        }
    }

    /// A CPU for a new thread with this thread's register state.
    pub fn clone_thread(&self) -> Self {
        match self {
            CpuWithSpace::X86_64(cpu) => CpuWithSpace::X86_64(cpu.clone_thread()),
            CpuWithSpace::Aarch64(cpu) => CpuWithSpace::Aarch64(cpu.clone_thread()),
            CpuWithSpace::Riscv64(cpu) => CpuWithSpace::Riscv64(cpu.clone_thread()),
            CpuWithSpace::Arm(cpu) => CpuWithSpace::Arm(cpu.clone_thread()),
        }
    }

    /// Copy this thread's architecture state over the selected memory.
    /// Used when a process leaves a shared MM for an independent snapshot.
    pub(crate) fn clone_to_space<N: LinuxAddressSpace>(&self, space: &N) -> CpuWithSpace<N> {
        match self {
            CpuWithSpace::X86_64(cpu) => CpuWithSpace::X86_64(cpu.clone_to_space(space)),
            CpuWithSpace::Aarch64(cpu) => CpuWithSpace::Aarch64(cpu.clone_to_space(space)),
            CpuWithSpace::Riscv64(cpu) => CpuWithSpace::Riscv64(cpu.clone_to_space(space)),
            CpuWithSpace::Arm(cpu) => CpuWithSpace::Arm(cpu.clone_to_space(space)),
        }
    }

    /// The address space the CPU executes in.
    pub fn space(&self) -> &M {
        match self {
            CpuWithSpace::X86_64(cpu) => cpu.space(),
            CpuWithSpace::Aarch64(cpu) => cpu.space(),
            CpuWithSpace::Riscv64(cpu) => cpu.space(),
            CpuWithSpace::Arm(cpu) => cpu.space(),
        }
    }
}
