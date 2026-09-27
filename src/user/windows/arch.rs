//! Guest architectures and their CPUs.
//!
//! [`WinCpu`] binds a user-mode CPU adapter to a Windows architecture:
//!
//! | Architecture | Core and mode | TEB register |
//! |---|---|---|
//! | x86 | x86-64 core in IA-32e compatibility mode (WoW64 selectors: CS 0x23, DS/ES/SS 0x2B, FS 0x53) | FS base |
//! | x64 | x86-64 core in 64-bit mode (CS 0x33, DS/ES/SS 0x2B) | GS base |
//! | ARM64 | AArch64 core at EL0 | X18 |
//!
//! A run ends at the first event Windows would handle in the kernel or in
//! `ntdll`: an access fault (including the instruction fetch of a trap
//! slot, which is how calls into built-in DLLs arrive), an exception or
//! software interrupt, a system-call instruction, or the end of the time
//! slice.

use crate::isa::arm::common::cpu::ArmCpu;
use crate::isa::x86_64::{X86SyscallInsn, X86UserEvent, X86UserSegment};
use crate::user::cpu::AccessFault;
use crate::user::cpu::aarch64::{A64Exit, A64UserCpu};
use crate::user::cpu::x86_64::{X86Exit, X86UserCpu};
use crate::user::image::pe::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use crate::user::mm::AddressSpace;

/// A Windows guest architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WinArch {
    /// 32-bit x86 (a WoW64 process).
    X86,
    /// x64 (AMD64).
    X64,
    /// ARM64.
    Arm64,
}

/// `PROCESSOR_ARCHITECTURE_INTEL`.
pub const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
/// `PROCESSOR_ARCHITECTURE_AMD64`.
pub const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
/// `PROCESSOR_ARCHITECTURE_ARM64`.
pub const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;

/// The WoW64 FS selector (GDT entry 10, RPL 3) that maps the 32-bit TEB.
pub const WOW64_FS_SELECTOR: u16 = 0x53;
/// GDT index of [`WOW64_FS_SELECTOR`].
pub const WOW64_FS_GDT_INDEX: usize = 10;

impl WinArch {
    /// All architectures.
    pub const ALL: [WinArch; 3] = [WinArch::X86, WinArch::X64, WinArch::Arm64];

    /// The architecture of `IMAGE_FILE_HEADER.Machine`, if supported.
    pub fn from_machine(machine: u16) -> Option<Self> {
        match machine {
            IMAGE_FILE_MACHINE_I386 => Some(WinArch::X86),
            IMAGE_FILE_MACHINE_AMD64 => Some(WinArch::X64),
            IMAGE_FILE_MACHINE_ARM64 => Some(WinArch::Arm64),
            _ => None,
        }
    }

    /// `IMAGE_FILE_MACHINE_*`.
    pub fn machine(self) -> u16 {
        match self {
            WinArch::X86 => IMAGE_FILE_MACHINE_I386,
            WinArch::X64 => IMAGE_FILE_MACHINE_AMD64,
            WinArch::Arm64 => IMAGE_FILE_MACHINE_ARM64,
        }
    }

    /// Pointer size in bytes.
    pub fn ptr_size(self) -> u64 {
        match self {
            WinArch::X86 => 4,
            WinArch::X64 | WinArch::Arm64 => 8,
        }
    }

    /// Whether pointers are 64 bits wide.
    pub fn is64(self) -> bool {
        self != WinArch::X86
    }

    /// Truncates `v` to the pointer width.
    pub fn ptr(self, v: u64) -> u64 {
        match self {
            WinArch::X86 => v & 0xFFFF_FFFF,
            _ => v,
        }
    }

    /// Canonical short name.
    pub fn name(self) -> &'static str {
        match self {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        }
    }

    /// `SYSTEM_INFO.wProcessorArchitecture` a process of this architecture
    /// observes (`GetNativeSystemInfo` of a WoW64 process reports the host).
    pub fn processor_architecture(self) -> u16 {
        match self {
            WinArch::X86 => PROCESSOR_ARCHITECTURE_INTEL,
            WinArch::X64 => PROCESSOR_ARCHITECTURE_AMD64,
            WinArch::Arm64 => PROCESSOR_ARCHITECTURE_ARM64,
        }
    }

    /// The `PROCESSOR_ARCHITECTURE` environment variable's value.
    pub fn env_name(self) -> &'static str {
        match self {
            WinArch::X86 => "x86",
            WinArch::X64 => "AMD64",
            WinArch::Arm64 => "ARM64",
        }
    }
}

impl std::fmt::Display for WinArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a run stopped.
#[derive(Debug)]
pub enum CpuStop {
    /// A memory access faulted; the PC is the faulting instruction.
    Fault(AccessFault),
    /// An x86 exception or software interrupt; the PC is the instruction.
    X86Event(X86UserEvent),
    /// An x86 `SYSCALL` or `SYSENTER` retired; the PC is past it.
    X86Syscall {
        /// The instruction.
        insn: X86SyscallInsn,
        /// Its address.
        insn_rip: u64,
    },
    /// ARM64 `SVC #imm`; the PC is past it.
    Svc {
        /// The immediate.
        imm: u16,
        /// Address of the `SVC`.
        pc: u64,
    },
    /// ARM64 `BRK #imm`; the PC is at it.
    Brk {
        /// The immediate.
        imm: u16,
        /// Address of the `BRK`.
        pc: u64,
    },
    /// An ARM64 UNDEFINED instruction; the PC is at it.
    Undefined {
        /// Address of the instruction.
        pc: u64,
        /// The core's diagnosis.
        reason: String,
    },
    /// The time slice ended.
    Yield,
    /// The core failed in a way no guest program can cause.
    Internal(String),
}

/// A guest thread's CPU.
pub enum WinCpu {
    /// x86 or x64 on the x86-64 core.
    X86(X86UserCpu, WinArch),
    /// ARM64.
    Arm64(A64UserCpu),
}

impl WinCpu {
    /// A CPU for `arch` over `space` with zeroed registers.
    pub fn new(arch: WinArch, space: &AddressSpace) -> Self {
        match arch {
            WinArch::X86 => {
                let mut cpu = X86UserCpu::new(space);
                cpu.set_compat(true);
                WinCpu::X86(cpu, arch)
            }
            WinArch::X64 => WinCpu::X86(X86UserCpu::new(space), arch),
            WinArch::Arm64 => WinCpu::Arm64(A64UserCpu::new(space)),
        }
    }

    /// The architecture.
    pub fn arch(&self) -> WinArch {
        match self {
            WinCpu::X86(_, arch) => *arch,
            WinCpu::Arm64(_) => WinArch::Arm64,
        }
    }

    /// Points the architecture's TEB register at `teb`: the WoW64 FS
    /// segment (a 4 KiB data segment based at the TEB, DPL 3, in GDT entry
    /// 10), the GS base, or X18.
    pub fn set_teb(&mut self, teb: u64) {
        match self {
            WinCpu::X86(cpu, WinArch::X86) => {
                use crate::isa::x86_64::gdt_entry;
                // S | present | accessed | writable, DPL 3, 32-bit, byte
                // granular: the TEB32 segment Windows keeps at 0x53.
                const DATA_DPL3_32: u16 = 0x0010 | 0x0080 | 0x0001 | 0x0002 | (3 << 5) | 0x4000;
                let v = cpu.vcpu_mut();
                v.set_user_gdt_entry(
                    WOW64_FS_GDT_INDEX,
                    gdt_entry(DATA_DPL3_32, teb as u32, 0xFFF),
                );
                v.load_user_segment(X86UserSegment::Fs, WOW64_FS_SELECTOR)
                    .expect("the TEB descriptor is a present DPL 3 data segment");
            }
            WinCpu::X86(cpu, _) => cpu.vcpu_mut().set_gs_base(teb),
            WinCpu::Arm64(cpu) => cpu.core_mut().set_x(18, teb),
        }
    }

    /// The current architecture's TEB address (FS base, GS base, or X18).
    pub fn teb(&self) -> u64 {
        match self {
            WinCpu::X86(cpu, WinArch::X86) => u64::from(cpu.vcpu().fs_base() as u32),
            WinCpu::X86(cpu, _) => cpu.vcpu().gs_base(),
            WinCpu::Arm64(cpu) => cpu.core().get_x(18),
        }
    }

    /// Number of integer registers in this architecture's public numbering.
    /// SP/PC are separate on ARM64; x86 compatibility mode has no R8–R15.
    pub fn gpr_count(&self) -> usize {
        match self.arch() {
            WinArch::X86 => 8,
            WinArch::X64 => 16,
            WinArch::Arm64 => 31,
        }
    }

    /// Reads a numbered integer register without aliasing an invalid index.
    pub fn try_gpr(&self, n: usize) -> Option<u64> {
        (n < self.gpr_count()).then(|| self.gpr(n))
    }

    /// Writes a numbered integer register; returns false for an invalid index.
    pub fn try_set_gpr(&mut self, n: usize, value: u64) -> bool {
        if n >= self.gpr_count() {
            return false;
        }
        self.set_gpr(n, value);
        true
    }

    /// Program counter.
    pub fn pc(&self) -> u64 {
        match self {
            WinCpu::X86(cpu, arch) => arch.ptr(cpu.pc()),
            WinCpu::Arm64(cpu) => cpu.pc(),
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        match self {
            WinCpu::X86(cpu, arch) => cpu.vcpu_mut().user_regs_mut().rip = arch.ptr(pc),
            WinCpu::Arm64(cpu) => cpu.core_mut().set_pc(pc),
        }
    }

    /// Stack pointer.
    pub fn sp(&self) -> u64 {
        match self {
            WinCpu::X86(cpu, arch) => arch.ptr(cpu.vcpu().user_regs().rsp),
            WinCpu::Arm64(cpu) => cpu.sp(),
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, sp: u64) {
        match self {
            WinCpu::X86(cpu, arch) => cpu.vcpu_mut().user_regs_mut().rsp = arch.ptr(sp),
            WinCpu::Arm64(cpu) => cpu.set_sp(sp),
        }
    }

    /// General-purpose register `n` in the architecture's numbering: x86
    /// and x64 use the ModR/M order (RAX, RCX, RDX, RBX, RSP, RBP, RSI,
    /// RDI, R8-R15; the unwind-code order), ARM64 X0-X30. x86 values are
    /// the low 32 bits.
    pub fn gpr(&self, n: usize) -> u64 {
        if n >= self.gpr_count() {
            return 0;
        }
        match self {
            WinCpu::X86(cpu, arch) => {
                let r = cpu.vcpu().user_regs();
                let v = match n {
                    0 => r.rax,
                    1 => r.rcx,
                    2 => r.rdx,
                    3 => r.rbx,
                    4 => r.rsp,
                    5 => r.rbp,
                    6 => r.rsi,
                    7 => r.rdi,
                    8 => r.r8,
                    9 => r.r9,
                    10 => r.r10,
                    11 => r.r11,
                    12 => r.r12,
                    13 => r.r13,
                    14 => r.r14,
                    15 => r.r15,
                    _ => 0,
                };
                arch.ptr(v)
            }
            WinCpu::Arm64(cpu) => cpu.core().get_x(n as u8),
        }
    }

    /// Sets general-purpose register `n` (see [`WinCpu::gpr`]).
    pub fn set_gpr(&mut self, n: usize, value: u64) {
        if n >= self.gpr_count() {
            return;
        }
        match self {
            WinCpu::X86(cpu, arch) => {
                let value = arch.ptr(value);
                let r = cpu.vcpu_mut().user_regs_mut();
                let slot = match n {
                    0 => &mut r.rax,
                    1 => &mut r.rcx,
                    2 => &mut r.rdx,
                    3 => &mut r.rbx,
                    4 => &mut r.rsp,
                    5 => &mut r.rbp,
                    6 => &mut r.rsi,
                    7 => &mut r.rdi,
                    8 => &mut r.r8,
                    9 => &mut r.r9,
                    10 => &mut r.r10,
                    11 => &mut r.r11,
                    12 => &mut r.r12,
                    13 => &mut r.r13,
                    14 => &mut r.r14,
                    15 => &mut r.r15,
                    _ => return,
                };
                *slot = value;
            }
            WinCpu::Arm64(cpu) => cpu.core_mut().set_x(n as u8, value),
        }
    }

    /// The x86-64 core, if this is an x86 or x64 CPU.
    pub fn x86(&self) -> Option<&X86UserCpu> {
        match self {
            WinCpu::X86(cpu, _) => Some(cpu),
            WinCpu::Arm64(_) => None,
        }
    }

    /// Mutable access to the x86-64 core.
    pub fn x86_mut(&mut self) -> Option<&mut X86UserCpu> {
        match self {
            WinCpu::X86(cpu, _) => Some(cpu),
            WinCpu::Arm64(_) => None,
        }
    }

    /// The AArch64 core, if this is an ARM64 CPU.
    pub fn a64(&self) -> Option<&A64UserCpu> {
        match self {
            WinCpu::Arm64(cpu) => Some(cpu),
            WinCpu::X86(..) => None,
        }
    }

    /// Mutable access to the AArch64 core.
    pub fn a64_mut(&mut self) -> Option<&mut A64UserCpu> {
        match self {
            WinCpu::Arm64(cpu) => Some(cpu),
            WinCpu::X86(..) => None,
        }
    }

    /// A CPU for another thread with this CPU's complete register state and
    /// configuration. The caller replaces the entry registers and TEB.
    pub fn new_thread(&self) -> Self {
        match self {
            WinCpu::X86(cpu, arch) => {
                let mut child = cpu.clone_thread();
                // The OS-neutral adapter copies Linux's TLS GDT entries
                // (12–14), while Windows owns entry 10. Preserve its table
                // descriptor as well as the already-copied hidden FS cache:
                // guest MOV/POP FS must be able to reload selector 0x53.
                if let Some(entry) = cpu.vcpu().user_gdt_entry(WOW64_FS_GDT_INDEX) {
                    child
                        .vcpu_mut()
                        .set_user_gdt_entry(WOW64_FS_GDT_INDEX, entry);
                }
                WinCpu::X86(child, *arch)
            }
            WinCpu::Arm64(cpu) => WinCpu::Arm64(cpu.clone_thread()),
        }
    }

    /// Runs at most `budget` instructions. x86 uses the precise interpreter
    /// step because the OS-neutral x86 run API has only a time-slice bound.
    /// A zero budget executes no instruction on every architecture.
    pub fn run(&mut self, budget: u64) -> CpuStop {
        if budget == 0 {
            return CpuStop::Yield;
        }
        match self {
            WinCpu::X86(cpu, _) => {
                for _ in 0..budget {
                    match cpu.step() {
                        X86Exit::Syscall { insn, insn_rip } => {
                            return CpuStop::X86Syscall { insn, insn_rip };
                        }
                        X86Exit::Event(e) => return CpuStop::X86Event(e),
                        X86Exit::Fault(f) => return CpuStop::Fault(f),
                        X86Exit::Yield => {}
                        X86Exit::Internal(e) => return CpuStop::Internal(e.to_string()),
                    }
                }
                CpuStop::Yield
            }
            WinCpu::Arm64(cpu) => match cpu.run(budget) {
                A64Exit::Svc { imm, pc } => CpuStop::Svc { imm, pc },
                A64Exit::Brk { imm, pc } => CpuStop::Brk { imm, pc },
                A64Exit::Undefined { pc, reason } => CpuStop::Undefined { pc, reason },
                A64Exit::Fault(f) => CpuStop::Fault(f),
                A64Exit::Yield => CpuStop::Yield,
                A64Exit::Internal(e) => CpuStop::Internal(e),
            },
        }
    }

    /// Discards compiled native code.
    pub fn discard_native_code(&mut self) {
        match self {
            WinCpu::X86(cpu, _) => cpu.discard_native_code(),
            WinCpu::Arm64(cpu) => cpu.discard_native_code(),
        }
    }

    /// Copies the complete enabled x86 floating-point/SIMD state without
    /// changing integer registers, control flow, segments, or the TEB.
    ///
    /// Fiber flag-zero sharing is a personality profile on x86: Microsoft
    /// specifies that floating-point state is not switched, but does not
    /// specify mixed flag combinations or the exact extended-state subset.
    pub(crate) fn inherit_fiber_fp(&mut self, source: &WinCpu) -> Result<(), u32> {
        use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;
        match (self, source) {
            (WinCpu::X86(target, a), WinCpu::X86(source, b)) if a == b => {
                // x87/SSE/AVX/opmask/ZMM only. APX's XSAVE component 19
                // contains integer EGPRs and is not floating-point state.
                const FP_SIMD: u64 = 0xE7;
                let image = source.vcpu().xsave_image(FP_SIMD);
                target
                    .vcpu_mut()
                    .set_xcr0(source.vcpu().xcr0())
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
                target
                    .vcpu_mut()
                    .xrstor_image(&image.bytes, FP_SIMD)
                    .map_err(|_| STATUS_INVALID_PARAMETER)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::cpu::x86_64::RESERVED_PHYS;
    use crate::user::mm::{Mapping, PAGE_SIZE, Perms, SpaceConfig};
    use crate::user::windows::memory::Mem;

    const CODE: u64 = 0x10000;
    const TEB: u64 = 0x20000;

    fn space(code: &[u8]) -> AddressSpace {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: RESERVED_PHYS.to_vec(),
        })
        .unwrap();
        space
            .map(
                CODE,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::EXEC),
            )
            .unwrap();
        space
            .map(
                TEB,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        space.write_raw(CODE, code).unwrap();
        space
    }

    #[test]
    fn windows_machine_pointer_and_processor_mappings() {
        for arch in WinArch::ALL {
            assert_eq!(WinArch::from_machine(arch.machine()), Some(arch));
            assert_eq!(arch.ptr_size(), if arch == WinArch::X86 { 4 } else { 8 });
        }
        assert_eq!(WinArch::from_machine(0xAA64), Some(WinArch::Arm64));
        assert_eq!(WinArch::from_machine(0x8664), Some(WinArch::X64));
        assert_eq!(WinArch::from_machine(0x014C), Some(WinArch::X86));
        assert_eq!(WinArch::from_machine(0xA641), None); // ARM64EC is distinct.
        assert_eq!(WinArch::X86.ptr(0x1234_5678_ABCD_EF01), 0xABCD_EF01);
    }

    #[test]
    fn windows_integer_register_width_and_invalid_indices() {
        let space = space(&[]);
        for arch in WinArch::ALL {
            let mut cpu = WinCpu::new(arch, &space);
            assert!(cpu.try_set_gpr(0, u64::MAX));
            assert_eq!(cpu.try_gpr(0), Some(arch.ptr(u64::MAX)));
            assert_eq!(cpu.try_gpr(cpu.gpr_count()), None);
            assert!(!cpu.try_set_gpr(256, 0));
            assert_eq!(cpu.gpr(0), arch.ptr(u64::MAX));
            cpu.set_pc(u64::MAX);
            cpu.set_sp(u64::MAX);
            assert_eq!(cpu.pc(), arch.ptr(u64::MAX));
            assert_eq!(cpu.sp(), arch.ptr(u64::MAX));
        }
    }

    #[test]
    fn windows_teb_registers_are_visible_to_guest_instructions() {
        // MOV EAX, FS:[0x30]; MOV RAX, GS:[0x60]; LDR X0,[X18,#0x60].
        let cases: [(WinArch, &[u8], u64); 3] = [
            (WinArch::X86, &[0x64, 0xA1, 0x30, 0, 0, 0], 0x30),
            (
                WinArch::X64,
                &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0],
                0x60,
            ),
            (WinArch::Arm64, &[0x40, 0x32, 0x40, 0xF9], 0x60),
        ];
        for (arch, code, offset) in cases {
            let space = space(code);
            space
                .wptr(TEB + offset, arch.ptr_size(), 0x1020_3040)
                .unwrap();
            let mut cpu = WinCpu::new(arch, &space);
            cpu.set_pc(CODE);
            cpu.set_teb(TEB);
            assert_eq!(cpu.teb(), TEB);
            assert!(matches!(cpu.run(1), CpuStop::Yield));
            assert_eq!(cpu.gpr(0), 0x1020_3040, "{arch}");
        }
    }

    #[test]
    fn windows_cloned_x86_thread_can_reload_the_teb_selector() {
        let space = space(&[]);
        let mut parent = WinCpu::new(WinArch::X86, &space);
        parent.set_teb(TEB);
        parent.set_gpr(0, 0x7654_3210);
        let mut child = parent.new_thread();
        assert_eq!(child.gpr(0), 0x7654_3210);
        let x = child.x86_mut().unwrap().vcpu_mut();
        x.load_user_segment(X86UserSegment::Fs, 0).unwrap();
        assert_eq!(x.fs_base(), 0);
        x.load_user_segment(X86UserSegment::Fs, WOW64_FS_SELECTOR)
            .unwrap();
        assert_eq!(child.teb(), TEB);
        child.set_teb(TEB + 0x100);
        assert_eq!(parent.teb(), TEB);
        assert_eq!(child.teb(), TEB + 0x100);
    }

    #[test]
    fn windows_instruction_budget_is_exact_and_zero_is_a_noop() {
        for arch in WinArch::ALL {
            let code: &[u8] = if arch == WinArch::Arm64 {
                &[0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x20, 0xD4] // NOP; BRK #0
            } else {
                &[0x90, 0xCC] // NOP; INT3
            };
            let space = space(code);
            let mut cpu = WinCpu::new(arch, &space);
            cpu.set_pc(CODE);
            assert!(matches!(cpu.run(0), CpuStop::Yield));
            assert_eq!(cpu.pc(), CODE);
            assert!(matches!(cpu.run(1), CpuStop::Yield));
            assert_eq!(cpu.pc(), CODE + if arch == WinArch::Arm64 { 4 } else { 1 });
            let stop = cpu.run(1);
            assert!(
                matches!(stop, CpuStop::X86Event(_) | CpuStop::Brk { imm: 0, .. }),
                "{arch}: {stop:?}"
            );
        }
    }
}
