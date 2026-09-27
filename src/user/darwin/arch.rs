//! Per-architecture Darwin thread state and kernel-entry conventions.
//!
//! [`DarwinCpu`] binds a CPU adapter to the XNU ABI of its machine: how a
//! thread enters the kernel (`syscall` with a class in `RAX[31:24]` on
//! x86-64, `svc` with the call in `X16` on arm64), where the arguments are,
//! how results and errors return (the carry flag marks an error), the
//! thread-local-storage register, and the register state `exec` installs.
//!
//! Sources: `osfmk/x86_64/idt64.s` (`hndl_syscall`),
//! `bsd/dev/i386/systemcalls.c` (`unix_syscall64`), `osfmk/i386/bsd_i386.c`
//! (`mach_call_munger64`, `machdep_syscall64`), `osfmk/arm64/sleh.c`
//! (`handle_svc`), `bsd/dev/arm/systemcalls.c` (`unix_syscall`,
//! `arm_prepare_u64_syscall_return`), `osfmk/arm64/bsd_arm64.c`
//! (`mach_syscall`), and `osfmk/arm64/machine_routines.c`
//! (`platform_syscall`).

use super::abi::{self, DarwinAbi, Errno, Ret, class};
use crate::isa::arm::aarch64::AArch64Config;
use crate::isa::arm::common::cpu::{ArmCpu, ArmVersion};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::x86_64::{X86EventSource, X86UserEvent};
use crate::user::cpu::AccessFault;
use crate::user::cpu::aarch64::{A64Exit, A64UserCpu};
use crate::user::cpu::x86_64::{X86Exit, X86UserCpu};
use crate::user::image::macho::ThreadState;
use crate::user::mm::AddressSpace;

/// The system counter frequency of Apple silicon (24 MHz), which
/// `mach_timebase_info` reports as 125/3.
pub const ARM64_COUNTER_HZ: u64 = 24_000_000;

/// x86-64 `RFLAGS.CF`.
const EFL_CF: u64 = 1 << 0;
/// arm64 `PSTATE.C` in the four-bit NZCV field.
const NZCV_C: u8 = 0b0010;

/// The value a system call returns: `uu_rval[0]` and `uu_rval[1]`, as the
/// kernel's two 32-bit words for [`Ret::Int`]/[`Ret::UInt`] calls and as one
/// 64-bit value in the first for the others.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rv(pub u64, pub u64);

impl Rv {
    /// One value, the second word zero.
    pub fn one(v: u64) -> Self {
        Rv(v, 0)
    }
}

/// A BSD system call's outcome.
pub type SysResult = Result<Rv, Errno>;

/// A machine exception a thread raised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exception {
    /// A memory access faulted (`EXC_BAD_ACCESS`).
    Access(AccessFault),
    /// An undefined or privileged instruction (`EXC_BAD_INSTRUCTION`).
    Undefined {
        /// Address of the instruction.
        pc: u64,
        /// Why the core rejected it.
        reason: String,
    },
    /// `BRK #imm` or `INT3` (`EXC_BREAKPOINT`).
    Breakpoint {
        /// Address of the instruction.
        pc: u64,
        /// The `BRK` immediate (zero for `INT3`).
        imm: u16,
    },
    /// Another x86-64 exception vector.
    X86(X86UserEvent),
}

impl Exception {
    /// The faulting instruction's address.
    pub fn pc(&self) -> u64 {
        match self {
            Exception::Access(f) => f.pc,
            Exception::Undefined { pc, .. } | Exception::Breakpoint { pc, .. } => *pc,
            Exception::X86(e) => e.insn_rip,
        }
    }
}

/// How a thread left user mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trap {
    /// A BSD system call; `code` is the number as the machine delivered it
    /// (zero for the indirect `syscall(2)` form).
    Unix {
        /// `RAX[23:0]` or `(uint16_t)X16`.
        code: u32,
    },
    /// A Mach trap; `nr` is the positive trap number.
    Mach {
        /// The trap number.
        nr: u32,
    },
    /// An x86-64 machine-dependent call (class 3).
    Machdep {
        /// The call number.
        nr: u32,
    },
    /// An x86-64 diagnostics call (class 4).
    Diag {
        /// The call number.
        nr: u32,
    },
    /// An arm64 platform call (`X16 == 0x80000000`); `code` is `X3`.
    Platform {
        /// The operation.
        code: u32,
    },
    /// The arm64 fast `mach_absolute_time` trap (`X16 == -3`).
    AbsoluteTime,
    /// The arm64 fast `mach_continuous_time` trap (`X16 == -4`).
    ContinuousTime,
    /// A system call with an x86-64 class the kernel does not know, or an
    /// arm64 Mach trap number past the table: `EXC_SYSCALL`.
    BadSyscall {
        /// The number register.
        number: u64,
    },
    /// A machine exception.
    Exception(Exception),
    /// The time slice ended.
    Yield,
    /// The emulator failed in a way no guest program can cause.
    Internal(String),
}

/// A guest thread's CPU with its XNU ABI.
pub enum DarwinCpu {
    /// x86-64.
    X86_64(X86UserCpu),
    /// arm64.
    Arm64(A64UserCpu),
}

/// The arm64 architecture profile RAX presents to Darwin programs: an
/// ARMv8.5-A core with the extensions every Apple silicon Mac has (the
/// M1's set: pointer authentication, LSE and LSE2 atomics, RCPC and RCPC2,
/// FP16, FHM, dot product, FCMA, JSCVT, FRINTTS, flag manipulation, SB,
/// SSBS, DIT, BTI, the ARMv8 cryptographic extensions, SHA-512, and SHA-3).
pub fn apple_arm64_config() -> AArch64Config {
    AArch64Config {
        version: ArmVersion::V8_5A,
        features: ArmFeatures::armv8_5_base()
            | ArmFeatures::RCPC
            | ArmFeatures::DOTPROD
            | ArmFeatures::FRINTTS
            | ArmFeatures::CRYPTO_AES
            | ArmFeatures::CRYPTO_SHA1
            | ArmFeatures::CRYPTO_SHA256
            | ArmFeatures::CRYPTO_SHA512
            | ArmFeatures::CRYPTO_SHA3,
        ..AArch64Config::v8_2()
    }
}

impl DarwinCpu {
    /// A CPU for `abi` over `space`, every register zero
    /// (`thread_state_initialize`).
    pub fn new(abi: DarwinAbi, space: &AddressSpace) -> Self {
        match abi {
            DarwinAbi::X86_64 => DarwinCpu::X86_64(X86UserCpu::new(space)),
            DarwinAbi::Arm64 => {
                let mut cpu = A64UserCpu::with_config(space, apple_arm64_config());
                cpu.core_mut().set_counter_frequency(ARM64_COUNTER_HZ);
                DarwinCpu::Arm64(cpu)
            }
        }
    }

    /// The ABI.
    pub fn abi(&self) -> DarwinAbi {
        match self {
            DarwinCpu::X86_64(_) => DarwinAbi::X86_64,
            DarwinCpu::Arm64(_) => DarwinAbi::Arm64,
        }
    }

    /// The address space.
    pub fn space(&self) -> &AddressSpace {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.space(),
            DarwinCpu::Arm64(cpu) => cpu.space(),
        }
    }

    /// The program counter.
    pub fn pc(&self) -> u64 {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.pc(),
            DarwinCpu::Arm64(cpu) => cpu.pc(),
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rip = pc,
            DarwinCpu::Arm64(cpu) => cpu.core_mut().set_pc(pc),
        }
    }

    /// The stack pointer.
    pub fn sp(&self) -> u64 {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.vcpu().user_regs().rsp,
            DarwinCpu::Arm64(cpu) => cpu.sp(),
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, sp: u64) {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.vcpu_mut().user_regs_mut().rsp = sp,
            DarwinCpu::Arm64(cpu) => cpu.set_sp(sp),
        }
    }

    /// Installs an `LC_UNIXTHREAD` register state as `thread_setstatus`
    /// does: the general registers as given, the flags limited to those
    /// user code may set.
    pub fn set_thread_state(&mut self, state: &ThreadState) {
        match (self, state) {
            (DarwinCpu::X86_64(cpu), ThreadState::X86_64 { regs, .. }) => {
                let r = cpu.vcpu_mut().user_regs_mut();
                r.rax = regs[0];
                r.rbx = regs[1];
                r.rcx = regs[2];
                r.rdx = regs[3];
                r.rdi = regs[4];
                r.rsi = regs[5];
                r.rbp = regs[6];
                r.rsp = regs[7];
                r.r8 = regs[8];
                r.r9 = regs[9];
                r.r10 = regs[10];
                r.r11 = regs[11];
                r.r12 = regs[12];
                r.r13 = regs[13];
                r.r14 = regs[14];
                r.r15 = regs[15];
                r.rip = regs[16];
                // set_thread_state64: (rflags & ~EFL_USER_CLEAR) | EFL_USER_SET.
                const EFL_USER_SET: u64 = 0x202;
                const EFL_USER_CLEAR: u64 = 0x3000 | 0x4000 | 0x2_0000 | 0x8_0000 | 0x10_0000;
                cpu.vcpu_mut()
                    .set_user_rflags((regs[17] & !EFL_USER_CLEAR) | EFL_USER_SET);
            }
            (DarwinCpu::Arm64(cpu), ThreadState::Arm64 { x, sp, pc, cpsr }) => {
                let core = cpu.core_mut();
                for (i, v) in x.iter().enumerate() {
                    core.set_x(i as u8, *v);
                }
                core.set_pc(*pc);
                core.set_nzcv_bits((*cpsr >> 28) as u8);
                cpu.set_sp(*sp);
            }
            _ => {}
        }
    }

    /// Sets the thread's TSD base (`machine_thread_set_tsd_base`): `GS`
    /// base on x86-64 (zero for a non-canonical address), `TPIDRRO_EL0` on
    /// arm64 (zero past the top of the map).
    pub fn set_tsd_base(&mut self, base: u64) {
        match self {
            DarwinCpu::X86_64(cpu) => {
                let canonical = base < 0x0000_8000_0000_0000;
                cpu.vcpu_mut().set_gs_base(if canonical { base } else { 0 });
            }
            DarwinCpu::Arm64(cpu) => {
                let base = if base > DarwinAbi::Arm64.max_address() {
                    0
                } else {
                    base
                };
                cpu.core_mut().set_tpidrro_el0(base);
            }
        }
    }

    /// The thread's TSD base.
    pub fn tsd_base(&self) -> u64 {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.vcpu().gs_base(),
            DarwinCpu::Arm64(cpu) => cpu.core().tpidrro_el0(),
        }
    }

    /// General-purpose register `n` (x86-64 in `RAX..R15` order).
    pub fn reg(&self, n: usize) -> u64 {
        match self {
            DarwinCpu::X86_64(cpu) => {
                let r = cpu.vcpu().user_regs();
                [
                    r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10,
                    r.r11, r.r12, r.r13, r.r14, r.r15,
                ][n]
            }
            DarwinCpu::Arm64(cpu) => cpu.core().get_x(n as u8),
        }
    }

    /// Sets general-purpose register `n` (x86-64 in `RAX..R15` order).
    pub fn set_reg(&mut self, n: usize, v: u64) {
        match self {
            DarwinCpu::X86_64(cpu) => {
                let r = cpu.vcpu_mut().user_regs_mut();
                *[
                    &mut r.rax, &mut r.rcx, &mut r.rdx, &mut r.rbx, &mut r.rsp, &mut r.rbp,
                    &mut r.rsi, &mut r.rdi, &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11,
                    &mut r.r12, &mut r.r13, &mut r.r14, &mut r.r15,
                ][n] = v;
            }
            DarwinCpu::Arm64(cpu) => cpu.core_mut().set_x(n as u8, v),
        }
    }

    /// Runs until the thread enters the kernel or the slice ends.
    pub fn run(&mut self, budget: u64) -> Trap {
        match self {
            DarwinCpu::X86_64(cpu) => {
                let exit = cpu.run();
                x86_trap(cpu, exit)
            }
            DarwinCpu::Arm64(cpu) => {
                let exit = cpu.run(budget);
                arm64_trap(cpu, exit)
            }
        }
    }

    /// The register words a BSD call's arguments start from: `RDI`, `RSI`,
    /// `RDX`, `R10`, `R8`, `R9` on x86-64; `X0`-`X8` on arm64.
    fn arg_regs(&self) -> [u64; 9] {
        match self {
            DarwinCpu::X86_64(cpu) => {
                let r = cpu.vcpu().user_regs();
                [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9, 0, 0, 0]
            }
            DarwinCpu::Arm64(cpu) => {
                let c = cpu.core();
                std::array::from_fn(|i| c.get_x(i as u8))
            }
        }
    }

    /// The number of an indirect `syscall(2)`: `RDI` or `X0`.
    pub fn indirect_number(&self) -> u32 {
        let n = self.arg_regs()[0];
        match self {
            // unix_syscall64 compares the full register with nsysent.
            DarwinCpu::X86_64(_) => n.min(u64::from(u32::MAX)) as u32,
            // arm_get_syscall_number truncates to 16 bits.
            DarwinCpu::Arm64(_) => u32::from(n as u16),
        }
    }

    /// The `nargs` arguments of a BSD call, `indirect` when the number
    /// came in the first argument register. On x86-64, arguments past the
    /// sixth register are words on the stack above the return address;
    /// `EFAULT` when they cannot be read.
    pub fn unix_args(&self, nargs: usize, indirect: bool) -> Result<[u64; 8], Errno> {
        let regs = self.arg_regs();
        let mut out = [0u64; 8];
        match self {
            DarwinCpu::X86_64(cpu) => {
                let (start, in_regs) = if indirect { (1, 5) } else { (0, 6) };
                let n = nargs.min(8);
                let from_regs = n.min(in_regs);
                out[..from_regs].copy_from_slice(&regs[start..start + from_regs]);
                if n > from_regs {
                    let rsp = cpu.vcpu().user_regs().rsp;
                    for (i, slot) in out[from_regs..n].iter_mut().enumerate() {
                        let mut b = [0u8; 8];
                        cpu.space()
                            .read(rsp + 8 + 8 * i as u64, &mut b)
                            .map_err(|_| Errno::EFAULT)?;
                        *slot = u64::from_le_bytes(b);
                    }
                }
            }
            DarwinCpu::Arm64(_) => {
                let start = usize::from(indirect);
                let n = nargs.min(8);
                out[..n].copy_from_slice(&regs[start..start + n]);
            }
        }
        Ok(out)
    }

    /// The `nargs` arguments of a Mach trap (up to nine: six registers and
    /// stack words on x86-64, `X0`-`X8` on arm64).
    pub fn mach_args(&self, nargs: usize) -> Result<[u64; 9], Errno> {
        let regs = self.arg_regs();
        let mut out = [0u64; 9];
        let n = nargs.min(9);
        match self {
            DarwinCpu::X86_64(cpu) => {
                let in_regs = n.min(6);
                out[..in_regs].copy_from_slice(&regs[..in_regs]);
                let rsp = cpu.vcpu().user_regs().rsp;
                for (i, slot) in out[in_regs..n].iter_mut().enumerate() {
                    let mut b = [0u8; 8];
                    cpu.space()
                        .read(rsp + 8 + 8 * i as u64, &mut b)
                        .map_err(|_| Errno::EFAULT)?;
                    *slot = u64::from_le_bytes(b);
                }
            }
            DarwinCpu::Arm64(_) => out[..n].copy_from_slice(&regs[..n]),
        }
        Ok(out)
    }

    /// Returns a BSD call's outcome to the thread as
    /// `unix_syscall64`/`arm_prepare_u64_syscall_return` do: on success the
    /// value registers per `ret` and the carry clear; on error the error
    /// number in the first (and on arm64 zero in the second) and the carry
    /// set. `ERESTART` backs the PC up over the call instruction;
    /// `EJUSTRETURN` leaves every register alone.
    pub fn set_unix_result(&mut self, ret: Ret, result: SysResult) {
        match result {
            Err(Errno::EJUSTRETURN) => {}
            Err(Errno::ERESTART) => self.restart_syscall(),
            Err(e) => match self {
                DarwinCpu::X86_64(cpu) => {
                    cpu.vcpu_mut().user_regs_mut().rax = e.0 as u64;
                    let fl = cpu.vcpu().user_rflags();
                    cpu.vcpu_mut().set_user_rflags(fl | EFL_CF);
                }
                DarwinCpu::Arm64(cpu) => {
                    let core = cpu.core_mut();
                    core.set_x(0, e.0 as u64);
                    core.set_x(1, 0);
                    let nzcv = core.nzcv_bits();
                    core.set_nzcv_bits(nzcv | NZCV_C);
                }
            },
            Ok(Rv(v0, v1)) => {
                let values = match ret {
                    Ret::Int => Some((v0 as i32 as i64 as u64, v1 as i32 as i64 as u64)),
                    Ret::UInt => Some((u64::from(v0 as u32), u64::from(v1 as u32))),
                    Ret::Off | Ret::Addr | Ret::Size | Ret::SSize | Ret::U64 => Some((v0, 0)),
                    Ret::None => None,
                };
                match self {
                    DarwinCpu::X86_64(cpu) => {
                        if let Some((a, b)) = values {
                            let r = cpu.vcpu_mut().user_regs_mut();
                            r.rax = a;
                            r.rdx = b;
                        }
                        let fl = cpu.vcpu().user_rflags();
                        cpu.vcpu_mut().set_user_rflags(fl & !EFL_CF);
                    }
                    DarwinCpu::Arm64(cpu) => {
                        let core = cpu.core_mut();
                        if let Some((a, b)) = values {
                            core.set_x(0, a);
                            core.set_x(1, b);
                        }
                        let nzcv = core.nzcv_bits();
                        core.set_nzcv_bits(nzcv & !NZCV_C);
                    }
                }
            }
        }
    }

    /// Returns a Mach trap's `kern_return_t` (or port name) in `RAX`/`X0`,
    /// sign-extended from 32 bits as the kernel's `int` is.
    pub fn set_mach_result(&mut self, kr: i32) {
        self.set_reg(0, kr as i64 as u64);
    }

    /// Backs the PC up over the system-call instruction (2 bytes for
    /// `SYSCALL`, 4 for `SVC`) so the call runs again when the thread
    /// resumes.
    pub fn restart_syscall(&mut self) {
        let len = match self {
            DarwinCpu::X86_64(_) => 2,
            DarwinCpu::Arm64(_) => 4,
        };
        let pc = self.pc();
        self.set_pc(pc.wrapping_sub(len));
    }

    /// Discards compiled native code (after a host `fork`).
    pub fn discard_native_code(&mut self) {
        match self {
            DarwinCpu::X86_64(cpu) => cpu.discard_native_code(),
            DarwinCpu::Arm64(cpu) => cpu.discard_native_code(),
        }
    }
}

/// Classifies an x86-64 exit by `hndl_syscall`'s class dispatch.
fn x86_trap(cpu: &mut X86UserCpu, exit: X86Exit) -> Trap {
    match exit {
        X86Exit::Syscall { .. } => {
            let rax = cpu.vcpu().user_regs().rax;
            let eax = rax as u32;
            let nr = eax & !(0xFF << class::SHIFT);
            match eax >> class::SHIFT {
                class::UNIX => Trap::Unix { code: nr },
                class::MACH => match abi::mach_trap(nr) {
                    Some(t) if !t.is_invalid() => Trap::Mach { nr },
                    _ => Trap::BadSyscall { number: rax },
                },
                class::MDEP => Trap::Machdep { nr },
                class::DIAG => Trap::Diag { nr },
                _ => Trap::BadSyscall { number: rax },
            }
        }
        X86Exit::Event(event) => match (event.vector, event.source) {
            (3, X86EventSource::SoftwareInterrupt) => Trap::Exception(Exception::Breakpoint {
                pc: event.insn_rip,
                imm: 0,
            }),
            (6, _) => Trap::Exception(Exception::Undefined {
                pc: event.insn_rip,
                reason: "#UD".into(),
            }),
            _ => Trap::Exception(Exception::X86(event)),
        },
        X86Exit::Fault(f) => Trap::Exception(Exception::Access(f)),
        X86Exit::Yield => Trap::Yield,
        X86Exit::Internal(e) => Trap::Internal(e.to_string()),
    }
}

/// Classifies an arm64 exit by `handle_svc`'s dispatch on `X16`.
fn arm64_trap(cpu: &mut A64UserCpu, exit: A64Exit) -> Trap {
    match exit {
        A64Exit::Svc { .. } => {
            let x16 = cpu.core().get_x(16);
            let trap_no = x16 as u32;
            if trap_no == abi::PLATFORM_SYSCALL_TRAP_NO {
                return Trap::Platform {
                    code: cpu.core().get_x(3) as u32,
                };
            }
            let signed = trap_no as i32;
            if signed < 0 {
                return match signed {
                    abi::MACH_ARM_TRAP_ABSTIME => Trap::AbsoluteTime,
                    abi::MACH_ARM_TRAP_CONTTIME => Trap::ContinuousTime,
                    _ => {
                        let nr = signed.unsigned_abs();
                        match abi::mach_trap(nr) {
                            Some(t) if !t.is_invalid() => Trap::Mach { nr },
                            _ => Trap::BadSyscall { number: x16 },
                        }
                    }
                };
            }
            // arm_get_syscall_number: (uint16_t)X16.
            Trap::Unix {
                code: u32::from(x16 as u16),
            }
        }
        A64Exit::Brk { imm, pc } => Trap::Exception(Exception::Breakpoint { pc, imm }),
        A64Exit::Undefined { pc, reason } => Trap::Exception(Exception::Undefined { pc, reason }),
        A64Exit::Fault(f) => Trap::Exception(Exception::Access(f)),
        A64Exit::Yield => Trap::Yield,
        A64Exit::Internal(e) => Trap::Internal(e),
    }
}
