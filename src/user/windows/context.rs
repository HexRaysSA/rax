//! `CONTEXT` and `EXCEPTION_RECORD`.
//!
//! [`RegContext`] holds a `CONTEXT` image in the guest architecture's
//! layout (winnt.h; offsets verified against the mingw-w64 headers, see
//! [`super::layout`]), so it copies to and from guest memory unchanged.
//! [`RegContext::capture`] fills it from a thread's CPU and
//! [`RegContext::apply`] loads it back, honoring `ContextFlags` as
//! `SetThreadContext` documents: only the selected register groups change,
//! and privileged status bits are sanitized. Restoration is transactional.
//! Unsupported groups or rejected architectural state return
//! `STATUS_INVALID_PARAMETER`; exact native `NtContinue` rejection statuses
//! are unknown. Debug/XSTATE/CET groups and execution-mode changes are not
//! implemented by this personality.

use super::arch::{WinArch, WinCpu};
use super::memory::{Mem, MemFault};
use super::nt::status::STATUS_INVALID_PARAMETER;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::isa::x86_64::X86UserSegment;
use crate::vm::vcpu::VCpu;

/// `CONTEXT_i386`.
pub const CONTEXT_I386: u32 = 0x0001_0000;
/// `CONTEXT_AMD64`.
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
/// `CONTEXT_ARM64`.
pub const CONTEXT_ARM64: u32 = 0x0040_0000;
/// `CONTEXT_CONTROL` (without the architecture bit).
pub const CONTROL: u32 = 0x1;
/// `CONTEXT_INTEGER` (without the architecture bit).
pub const INTEGER: u32 = 0x2;
/// x86/x64 `CONTEXT_SEGMENTS` (without the architecture bit).
pub const SEGMENTS: u32 = 0x4;
/// x86/x64 `CONTEXT_FLOATING_POINT` (without the architecture bit).
pub const FLOATING_POINT_X86: u32 = 0x8;
/// ARM64 `CONTEXT_FLOATING_POINT` (without the architecture bit).
pub const FLOATING_POINT_ARM64: u32 = 0x4;
/// x86 `CONTEXT_EXTENDED_REGISTERS` (without the architecture bit).
pub const EXTENDED_REGISTERS: u32 = 0x20;
/// ARM64's independent `CONTEXT_ARM64_X18` group (without architecture bit).
pub const ARM64_X18: u32 = 0x10;
/// `CONTEXT_UNWOUND_TO_CALL`.
pub const CONTEXT_UNWOUND_TO_CALL: u32 = 0x2000_0000;

/// `EXCEPTION_NONCONTINUABLE`.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
/// `EXCEPTION_UNWINDING`.
pub const EXCEPTION_UNWINDING: u32 = 0x2;
/// `EXCEPTION_EXIT_UNWIND`.
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
/// `EXCEPTION_STACK_INVALID`.
pub const EXCEPTION_STACK_INVALID: u32 = 0x8;
/// `EXCEPTION_NESTED_CALL`.
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
/// `EXCEPTION_TARGET_UNWIND`.
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
/// `EXCEPTION_COLLIDED_UNWIND`.
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;
/// `EXCEPTION_MAXIMUM_PARAMETERS`.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// x86 `CONTEXT` offsets.
pub mod x86 {
    /// `sizeof(CONTEXT)`.
    pub const SIZE: usize = 0x2CC;
    /// `FloatSave` (`FLOATING_SAVE_AREA`, 0x70 bytes).
    pub const FLOAT_SAVE: usize = 0x1C;
    /// `SegGs`.
    pub const SEG_GS: usize = 0x8C;
    /// `SegFs`.
    pub const SEG_FS: usize = 0x90;
    /// `SegEs`.
    pub const SEG_ES: usize = 0x94;
    /// `SegDs`.
    pub const SEG_DS: usize = 0x98;
    /// `Eip`.
    pub const EIP: usize = 0xB8;
    /// `SegCs`.
    pub const SEG_CS: usize = 0xBC;
    /// `EFlags`.
    pub const EFLAGS: usize = 0xC0;
    /// `SegSs`.
    pub const SEG_SS: usize = 0xC8;
    /// `ExtendedRegisters` (an `FXSAVE` image).
    pub const EXTENDED: usize = 0xCC;
    /// General registers in ModR/M order: EAX, ECX, EDX, EBX, ESP, EBP,
    /// ESI, EDI.
    pub const GPR: [usize; 8] = [0xB0, 0xAC, 0xA8, 0xA4, 0xC4, 0xB4, 0xA0, 0x9C];
}

/// x64 `CONTEXT` offsets.
pub mod x64 {
    /// `sizeof(CONTEXT)`.
    pub const SIZE: usize = 0x4D0;
    /// `ContextFlags`.
    pub const FLAGS: usize = 0x30;
    /// `MxCsr`.
    pub const MXCSR: usize = 0x34;
    /// `SegCs`.
    pub const SEG_CS: usize = 0x38;
    /// `SegDs`.
    pub const SEG_DS: usize = 0x3A;
    /// `SegEs`.
    pub const SEG_ES: usize = 0x3C;
    /// `SegFs`.
    pub const SEG_FS: usize = 0x3E;
    /// `SegGs`.
    pub const SEG_GS: usize = 0x40;
    /// `SegSs`.
    pub const SEG_SS: usize = 0x42;
    /// `EFlags`.
    pub const EFLAGS: usize = 0x44;
    /// `Rax`; register n (unwind-code order) is at `RAX + 8 * n`.
    pub const RAX: usize = 0x78;
    /// `Rip`.
    pub const RIP: usize = 0xF8;
    /// `FltSave` (`XMM_SAVE_AREA32`, an `FXSAVE64` image).
    pub const FLT_SAVE: usize = 0x100;
    /// `Xmm0`.
    pub const XMM0: usize = 0x1A0;
}

/// ARM64 `CONTEXT` offsets.
pub mod arm64 {
    /// `sizeof(CONTEXT)`.
    pub const SIZE: usize = 0x390;
    /// `Cpsr`.
    pub const CPSR: usize = 0x04;
    /// `X0`; register n (0-30, with X29 = `Fp` and X30 = `Lr`) is at
    /// `X0 + 8 * n`.
    pub const X0: usize = 0x08;
    /// `Sp`.
    pub const SP: usize = 0x100;
    /// `Pc`.
    pub const PC: usize = 0x108;
    /// `V[0]`.
    pub const V0: usize = 0x110;
    /// `Fpcr`.
    pub const FPCR: usize = 0x310;
    /// `Fpsr`.
    pub const FPSR: usize = 0x314;
}

/// A `CONTEXT` image.
#[derive(Clone, PartialEq, Eq)]
pub struct RegContext {
    arch: WinArch,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for RegContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RegContext({} pc={:#x} sp={:#x})",
            self.arch,
            self.pc(),
            self.sp()
        )
    }
}

/// EFLAGS bits a thread may set through a context: CF, PF, AF, ZF, SF,
/// TF, DF, OF, AC, ID. IF and bit 1 are always set.
const EFLAGS_USER: u32 = 0x0024_0DD5;

impl RegContext {
    /// `sizeof(CONTEXT)` for `arch`.
    pub fn size(arch: WinArch) -> usize {
        match arch {
            WinArch::X86 => x86::SIZE,
            WinArch::X64 => x64::SIZE,
            WinArch::Arm64 => arm64::SIZE,
        }
    }

    /// Required alignment of a `CONTEXT` in memory (the x64 structure is
    /// `DECLSPEC_ALIGN(16)`).
    pub fn align(arch: WinArch) -> u64 {
        match arch {
            WinArch::X86 => 4,
            _ => 16,
        }
    }

    /// A zeroed context.
    pub fn new(arch: WinArch) -> Self {
        RegContext {
            arch,
            bytes: vec![0; Self::size(arch)],
        }
    }

    /// A context from its image.
    pub fn from_bytes(arch: WinArch, bytes: Vec<u8>) -> Self {
        let mut bytes = bytes;
        bytes.resize(Self::size(arch), 0);
        RegContext { arch, bytes }
    }

    /// Reads a context from guest memory.
    pub fn read(mem: &impl Mem, arch: WinArch, addr: u64) -> Result<Self, MemFault> {
        Ok(Self::from_bytes(arch, mem.bytes(addr, Self::size(arch))?))
    }

    /// Writes the context to guest memory.
    pub fn write(&self, mem: &impl Mem, addr: u64) -> Result<(), MemFault> {
        mem.wr(addr, &self.bytes)
    }

    /// The architecture.
    pub fn arch(&self) -> WinArch {
        self.arch
    }

    /// The image.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn get32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.bytes[off..off + 4].try_into().unwrap())
    }

    fn put32(&mut self, off: usize, v: u32) {
        self.bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn get16(&self, off: usize) -> u16 {
        u16::from_le_bytes(self.bytes[off..off + 2].try_into().unwrap())
    }

    fn put16(&mut self, off: usize, v: u16) {
        self.bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn get64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.bytes[off..off + 8].try_into().unwrap())
    }

    fn put64(&mut self, off: usize, v: u64) {
        self.bytes[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn get128(&self, off: usize) -> u128 {
        u128::from_le_bytes(self.bytes[off..off + 16].try_into().unwrap())
    }

    fn put128(&mut self, off: usize, v: u128) {
        self.bytes[off..off + 16].copy_from_slice(&v.to_le_bytes());
    }

    /// The architecture bit of `ContextFlags`.
    pub fn arch_flag(arch: WinArch) -> u32 {
        match arch {
            WinArch::X86 => CONTEXT_I386,
            WinArch::X64 => CONTEXT_AMD64,
            WinArch::Arm64 => CONTEXT_ARM64,
        }
    }

    /// `CONTEXT_ALL` without debug registers: every group this personality
    /// captures.
    pub fn all_flags(arch: WinArch) -> u32 {
        Self::arch_flag(arch)
            | match arch {
                WinArch::X86 => {
                    CONTROL | INTEGER | SEGMENTS | FLOATING_POINT_X86 | EXTENDED_REGISTERS
                }
                WinArch::X64 => CONTROL | INTEGER | SEGMENTS | FLOATING_POINT_X86,
                WinArch::Arm64 => CONTROL | INTEGER | FLOATING_POINT_ARM64 | ARM64_X18,
            }
    }

    fn flags_offset(&self) -> usize {
        match self.arch {
            WinArch::X64 => x64::FLAGS,
            _ => 0,
        }
    }

    /// `ContextFlags`.
    pub fn flags(&self) -> u32 {
        self.get32(self.flags_offset())
    }

    /// Sets `ContextFlags`.
    pub fn set_flags(&mut self, v: u32) {
        let off = self.flags_offset();
        self.put32(off, v);
    }

    /// The program counter.
    pub fn pc(&self) -> u64 {
        match self.arch {
            WinArch::X86 => u64::from(self.get32(x86::EIP)),
            WinArch::X64 => self.get64(x64::RIP),
            WinArch::Arm64 => self.get64(arm64::PC),
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, v: u64) {
        match self.arch {
            WinArch::X86 => self.put32(x86::EIP, v as u32),
            WinArch::X64 => self.put64(x64::RIP, v),
            WinArch::Arm64 => self.put64(arm64::PC, v),
        }
    }

    /// The stack pointer.
    pub fn sp(&self) -> u64 {
        match self.arch {
            WinArch::Arm64 => self.get64(arm64::SP),
            _ => self.gpr(4),
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, v: u64) {
        match self.arch {
            WinArch::Arm64 => self.put64(arm64::SP, v),
            _ => self.set_gpr(4, v),
        }
    }

    /// Restores the five saved slots of an x64 interrupt machine frame.
    /// The caller has already checked the context architecture and read
    /// the complete frame; this operation does not sanitize saved state.
    pub(crate) fn set_x64_machine_frame(&mut self, pc: u64, cs: u16, flags: u32, sp: u64, ss: u16) {
        self.put64(x64::RIP, pc);
        self.put16(x64::SEG_CS, cs);
        self.put32(x64::EFLAGS, flags);
        self.put64(x64::RAX + 4 * 8, sp);
        self.put16(x64::SEG_SS, ss);
    }

    /// General-purpose register `n`: x86/x64 in ModR/M (unwind-code) order,
    /// ARM64 X0-X30.
    pub fn gpr(&self, n: usize) -> u64 {
        match self.arch {
            WinArch::X86 => x86::GPR.get(n).map_or(0, |&off| u64::from(self.get32(off))),
            WinArch::X64 if n < 16 => self.get64(x64::RAX + 8 * n),
            WinArch::Arm64 if n <= 30 => self.get64(arm64::X0 + 8 * n),
            _ => 0,
        }
    }

    /// Sets general-purpose register `n` (see [`RegContext::gpr`]).
    pub fn set_gpr(&mut self, n: usize, v: u64) {
        match self.arch {
            WinArch::X86 => {
                if let Some(&off) = x86::GPR.get(n) {
                    self.put32(off, v as u32);
                }
            }
            WinArch::X64 if n < 16 => self.put64(x64::RAX + 8 * n, v),
            WinArch::Arm64 if n <= 30 => self.put64(arm64::X0 + 8 * n, v),
            _ => {}
        }
    }

    /// The flags register: EFLAGS or CPSR.
    pub fn flags_register(&self) -> u32 {
        match self.arch {
            WinArch::X86 => self.get32(x86::EFLAGS),
            WinArch::X64 => self.get32(x64::EFLAGS),
            WinArch::Arm64 => self.get32(arm64::CPSR),
        }
    }

    /// XMM register `n` (x64; x86 through `ExtendedRegisters`).
    pub fn xmm(&self, n: usize) -> u128 {
        match self.arch {
            WinArch::X64 => self.get128(x64::XMM0 + 16 * n),
            WinArch::X86 => self.get128(x86::EXTENDED + 160 + 16 * n),
            WinArch::Arm64 => 0,
        }
    }

    /// Sets XMM register `n`.
    pub fn set_xmm(&mut self, n: usize, v: u128) {
        match self.arch {
            WinArch::X64 => self.put128(x64::XMM0 + 16 * n, v),
            WinArch::X86 => self.put128(x86::EXTENDED + 160 + 16 * n, v),
            WinArch::Arm64 => {}
        }
    }

    /// ARM64 V register `n`.
    pub fn v(&self, n: usize) -> u128 {
        self.get128(arm64::V0 + 16 * n)
    }

    /// Sets ARM64 V register `n`.
    pub fn set_v(&mut self, n: usize, v: u128) {
        self.put128(arm64::V0 + 16 * n, v);
    }

    /// Captures every register group of `cpu`.
    pub fn capture(cpu: &WinCpu) -> Self {
        let arch = cpu.arch();
        let mut c = RegContext::new(arch);
        c.set_flags(Self::all_flags(arch));
        match cpu {
            WinCpu::X86(x, WinArch::X86) => {
                let v = x.vcpu();
                for n in 0..8 {
                    c.set_gpr(n, cpu.gpr(n));
                }
                c.put32(x86::EIP, cpu.pc() as u32);
                c.put32(x86::EFLAGS, v.user_rflags() as u32);
                for (off, seg) in [
                    (x86::SEG_CS, X86UserSegment::Cs),
                    (x86::SEG_SS, X86UserSegment::Ss),
                    (x86::SEG_DS, X86UserSegment::Ds),
                    (x86::SEG_ES, X86UserSegment::Es),
                    (x86::SEG_FS, X86UserSegment::Fs),
                    (x86::SEG_GS, X86UserSegment::Gs),
                ] {
                    c.put32(off, u32::from(v.user_selector(seg)));
                }
                let fx = v.xsave_image(3).bytes;
                c.bytes[x86::EXTENDED..x86::EXTENDED + 512].copy_from_slice(&fx[..512]);
                let fsave = fxsave_to_fsave(&fx[..512]);
                c.bytes[x86::FLOAT_SAVE..x86::FLOAT_SAVE + 0x70].copy_from_slice(&fsave);
            }
            WinCpu::X86(x, _) => {
                let v = x.vcpu();
                for n in 0..16 {
                    c.set_gpr(n, cpu.gpr(n));
                }
                c.put64(x64::RIP, cpu.pc());
                c.put32(x64::EFLAGS, v.user_rflags() as u32);
                for (off, seg) in [
                    (x64::SEG_CS, X86UserSegment::Cs),
                    (x64::SEG_SS, X86UserSegment::Ss),
                    (x64::SEG_DS, X86UserSegment::Ds),
                    (x64::SEG_ES, X86UserSegment::Es),
                    (x64::SEG_FS, X86UserSegment::Fs),
                    (x64::SEG_GS, X86UserSegment::Gs),
                ] {
                    c.put16(off, v.user_selector(seg));
                }
                c.put32(x64::MXCSR, v.mxcsr());
                let fx = v.xsave_image(3).bytes;
                c.bytes[x64::FLT_SAVE..x64::FLT_SAVE + 512].copy_from_slice(&fx[..512]);
            }
            WinCpu::Arm64(a) => {
                let core = a.core();
                for n in 0..31 {
                    c.set_gpr(n, core.get_x(n as u8));
                }
                c.put64(arm64::SP, a.sp());
                c.put64(arm64::PC, a.pc());
                c.put32(arm64::CPSR, u32::from(core.nzcv_bits()) << 28);
                for n in 0..32 {
                    c.set_v(n, core.get_simd(n as u8));
                }
                c.put32(arm64::FPCR, core.fpcr_value());
                c.put32(arm64::FPSR, core.fpsr_value());
            }
        }
        c
    }

    /// Loads selected groups, or leaves the entire CPU unchanged on error.
    /// Informational CONTEXT_EXCEPTION_* / SERVICE_ACTIVE / UNWOUND_TO_CALL
    /// flags are accepted; unsupported register groups are rejected.
    /// Work and temporary storage are bounded by one CPU-state copy.
    pub fn apply(&self, cpu: &mut WinCpu) -> Result<(), u32> {
        let next = self.prepare(cpu)?;
        match (cpu, next) {
            (WinCpu::X86(original, _), WinCpu::X86(copy, _)) => {
                let state = copy
                    .vcpu()
                    .get_state()
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
                let emulator = copy
                    .vcpu()
                    .get_emulator_state()
                    .ok_or(STATUS_INVALID_PARAMETER)?;
                // Both commit APIs reject only a wrong architecture or
                // invalid MXCSR. These properties are checked before any
                // original state changes; no guest memory is touched here.
                if !crate::isa::x86_64::mxcsr_value_is_valid(emulator.mxcsr) {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let v = original.vcpu_mut();
                v.set_emulator_state(&emulator)
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
                v.set_state(&state).map_err(|_| STATUS_INVALID_PARAMETER)?;
                let mut index = 0;
                while let Some(descriptor) = copy.vcpu().user_gdt_entry(index) {
                    v.set_user_gdt_entry(index, descriptor);
                    index += 1;
                }
                Ok(())
            }
            (original @ WinCpu::Arm64(_), WinCpu::Arm64(_)) => {
                // ARM64 restoration has no fallible architectural writes
                // after prepare validates the selected register groups.
                // Preserve the original core and its instruction counter.
                self.apply_checked(original)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    /// Checks restoration without mutating `cpu` or guest memory.
    pub fn validate(&self, cpu: &WinCpu) -> Result<(), u32> {
        self.prepare(cpu).map(|_| ())
    }

    fn prepare(&self, cpu: &WinCpu) -> Result<WinCpu, u32> {
        let flags = self.flags();
        const INFORMATIONAL: u32 = 0xF800_0000;
        if self.arch != cpu.arch()
            || flags & 0x00FF_0000 != Self::arch_flag(self.arch)
            || flags & !(Self::all_flags(self.arch) | INFORMATIONAL) != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut next = cpu.new_thread();
        // clone_thread copies the OS's normal TLS entries; a checked
        // restoration must also retain every configurable GDT descriptor.
        if let (WinCpu::X86(original, _), WinCpu::X86(copy, _)) = (cpu, &mut next) {
            // The ordinary thread-clone contract excludes system segment
            // caches such as SS. Retain them for unselected groups here.
            let state = original
                .vcpu()
                .get_state()
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            copy.vcpu_mut()
                .set_state(&state)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let mut index = 0;
            while let Some(descriptor) = original.vcpu().user_gdt_entry(index) {
                copy.vcpu_mut().set_user_gdt_entry(index, descriptor);
                index += 1;
            }
        }
        self.apply_checked(&mut next)?;
        Ok(next)
    }

    fn apply_checked(&self, cpu: &mut WinCpu) -> Result<(), u32> {
        let flags = self.flags();
        let has = |g: u32| flags & g != 0;
        match cpu {
            WinCpu::X86(x, WinArch::X86) => {
                if has(INTEGER) {
                    for n in [0, 1, 2, 3, 6, 7] {
                        let v = self.gpr(n);
                        set_x86_gpr(x, n, v);
                    }
                }
                if has(CONTROL) {
                    let v = x.vcpu_mut();
                    if self.get32(x86::SEG_CS) != u32::from(v.user_selector(X86UserSegment::Cs)) {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    let ss = u16::try_from(self.get32(x86::SEG_SS))
                        .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    if v.user_selector(X86UserSegment::Ss) != ss {
                        v.load_user_segment(X86UserSegment::Ss, ss)
                            .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    }
                    set_x86_gpr(x, 4, self.gpr(4));
                    set_x86_gpr(x, 5, self.gpr(5));
                    let v = x.vcpu_mut();
                    v.user_regs_mut().rip = u64::from(self.get32(x86::EIP));
                    let fl = (self.get32(x86::EFLAGS) & EFLAGS_USER) | 0x202;
                    v.set_user_rflags(u64::from(fl));
                }
                if has(SEGMENTS) {
                    let v = x.vcpu_mut();
                    for (off, seg) in [
                        (x86::SEG_DS, X86UserSegment::Ds),
                        (x86::SEG_ES, X86UserSegment::Es),
                        (x86::SEG_FS, X86UserSegment::Fs),
                        (x86::SEG_GS, X86UserSegment::Gs),
                    ] {
                        let sel =
                            u16::try_from(self.get32(off)).map_err(|_| STATUS_INVALID_PARAMETER)?;
                        if v.user_selector(seg) != sel {
                            v.load_user_segment(seg, sel)
                                .map_err(|_| STATUS_INVALID_PARAMETER)?;
                        }
                    }
                }
                let v = x.vcpu_mut();
                if has(EXTENDED_REGISTERS) {
                    let fx = &self.bytes[x86::EXTENDED..x86::EXTENDED + 512];
                    v.fxrstor_image(fx).map_err(|_| STATUS_INVALID_PARAMETER)?;
                }
                if has(FLOATING_POINT_X86) {
                    let mut fx = v.xsave_image(3).bytes;
                    fx.truncate(512);
                    fsave_into_fxsave(
                        &self.bytes[x86::FLOAT_SAVE..x86::FLOAT_SAVE + 0x70],
                        &mut fx,
                    );
                    v.fxrstor_image(&fx).map_err(|_| STATUS_INVALID_PARAMETER)?;
                }
            }
            WinCpu::X86(x, _) => {
                if has(INTEGER) {
                    for n in (0..16).filter(|&n| n != 4) {
                        set_x86_gpr(x, n, self.gpr(n));
                    }
                }
                if has(CONTROL) {
                    let v = x.vcpu_mut();
                    if self.get16(x64::SEG_CS) != v.user_selector(X86UserSegment::Cs) {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    let ss = self.get16(x64::SEG_SS);
                    if v.user_selector(X86UserSegment::Ss) != ss {
                        v.load_user_segment(X86UserSegment::Ss, ss)
                            .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    }
                    set_x86_gpr(x, 4, self.gpr(4));
                    let v = x.vcpu_mut();
                    v.user_regs_mut().rip = self.get64(x64::RIP);
                    let fl = (self.get32(x64::EFLAGS) & EFLAGS_USER) | 0x202;
                    v.set_user_rflags(u64::from(fl));
                }
                if has(SEGMENTS) {
                    // 64-bit FS/GS bases are OS-owned thread bindings,
                    // not contained in CONTEXT. A selector change here is
                    // deliberately unsupported rather than silently lost.
                    let v = x.vcpu();
                    for (off, seg) in [
                        (x64::SEG_DS, X86UserSegment::Ds),
                        (x64::SEG_ES, X86UserSegment::Es),
                        (x64::SEG_FS, X86UserSegment::Fs),
                        (x64::SEG_GS, X86UserSegment::Gs),
                    ] {
                        if self.get16(off) != v.user_selector(seg) {
                            return Err(STATUS_INVALID_PARAMETER);
                        }
                    }
                }
                if has(FLOATING_POINT_X86) {
                    let v = x.vcpu_mut();
                    let mut fx = self.bytes[x64::FLT_SAVE..x64::FLT_SAVE + 512].to_vec();
                    // MxCsr is authoritative over FltSave.MxCsr.
                    fx[24..28].copy_from_slice(&self.get32(x64::MXCSR).to_le_bytes());
                    v.fxrstor_image(&fx).map_err(|_| STATUS_INVALID_PARAMETER)?;
                }
            }
            WinCpu::Arm64(a) => {
                if has(INTEGER) {
                    for n in (0..29).filter(|&n| n != 18) {
                        a.core_mut().set_x(n as u8, self.gpr(n));
                    }
                }
                if has(ARM64_X18) {
                    a.core_mut().set_x(18, self.gpr(18));
                }
                if has(CONTROL) {
                    let core = a.core_mut();
                    core.set_x(29, self.gpr(29));
                    core.set_x(30, self.gpr(30));
                    core.set_pc(self.get64(arm64::PC));
                    core.set_nzcv_bits((self.get32(arm64::CPSR) >> 28) as u8);
                    a.set_sp(self.get64(arm64::SP));
                }
                if has(FLOATING_POINT_ARM64) {
                    let core = a.core_mut();
                    for n in 0..32 {
                        core.set_simd(n as u8, self.v(n));
                    }
                    core.set_fpcr_value(self.get32(arm64::FPCR));
                    core.set_fpsr_value(self.get32(arm64::FPSR));
                }
            }
        }
        Ok(())
    }
}

fn set_x86_gpr(x: &mut crate::user::cpu::x86_64::X86UserCpu, n: usize, v: u64) {
    let r = x.vcpu_mut().user_regs_mut();
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
    *slot = v;
}

/// The two-bit x87 tag of an 80-bit register image (SDM Vol. 1 §8.1.7):
/// 00 valid, 01 zero, 10 special (NaN, infinity, denormal, unsupported).
fn x87_tag(reg: &[u8]) -> u16 {
    let exponent = u16::from_le_bytes([reg[8], reg[9]]) & 0x7FFF;
    let significand = u64::from_le_bytes(reg[..8].try_into().unwrap());
    let integer = significand >> 63 != 0;
    match exponent {
        0 if significand == 0 => 1,
        0 => 2,
        0x7FFF => 2,
        _ if integer => 0,
        _ => 2,
    }
}

/// Converts the x87 part of an `FXSAVE` image to the `FSAVE` layout of
/// `FLOATING_SAVE_AREA` (SDM Vol. 1 §8.1.10, figures 8-9/8-10 and table
/// 10-2): full tag word rebuilt from the abridged one and the register
/// contents, registers in stack order.
pub fn fxsave_to_fsave(fx: &[u8]) -> [u8; 0x70] {
    let mut out = [0u8; 0x70];
    let fcw = u16::from_le_bytes([fx[0], fx[1]]);
    let fsw = u16::from_le_bytes([fx[2], fx[3]]);
    let abridged = fx[4];
    let fop = u16::from_le_bytes([fx[6], fx[7]]);
    let fip = u32::from_le_bytes(fx[8..12].try_into().unwrap());
    let fcs = u16::from_le_bytes([fx[12], fx[13]]);
    let fdp = u32::from_le_bytes(fx[16..20].try_into().unwrap());
    let fds = u16::from_le_bytes([fx[20], fx[21]]);
    let top = (fsw >> 11) & 7;
    let mut tag = 0u16;
    for phys in 0..8u16 {
        let st = (phys + 8 - top) & 7;
        let reg = &fx[32 + 16 * st as usize..32 + 16 * st as usize + 10];
        let t = if abridged & (1 << phys) == 0 {
            3
        } else {
            x87_tag(reg)
        };
        tag |= t << (2 * phys);
    }
    out[0..4].copy_from_slice(&u32::from(fcw).to_le_bytes());
    out[4..8].copy_from_slice(&u32::from(fsw).to_le_bytes());
    out[8..12].copy_from_slice(&u32::from(tag).to_le_bytes());
    out[0xC..0x10].copy_from_slice(&fip.to_le_bytes());
    out[0x10..0x14].copy_from_slice(&(u32::from(fcs) | u32::from(fop & 0x7FF) << 16).to_le_bytes());
    out[0x14..0x18].copy_from_slice(&fdp.to_le_bytes());
    out[0x18..0x1C].copy_from_slice(&u32::from(fds).to_le_bytes());
    for i in 0..8 {
        out[0x1C + 10 * i..0x1C + 10 * i + 10].copy_from_slice(&fx[32 + 16 * i..32 + 16 * i + 10]);
    }
    out
}

/// Loads an `FSAVE`-layout `FLOATING_SAVE_AREA` into the x87 part of an
/// `FXSAVE` image (the abridged tag marks every non-empty register valid).
pub fn fsave_into_fxsave(fs: &[u8], fx: &mut [u8]) {
    let get = |o: usize| u32::from_le_bytes(fs[o..o + 4].try_into().unwrap());
    let tag = get(8);
    let mut abridged = 0u8;
    for phys in 0..8 {
        if (tag >> (2 * phys)) & 3 != 3 {
            abridged |= 1 << phys;
        }
    }
    fx[0..2].copy_from_slice(&(get(0) as u16).to_le_bytes());
    fx[2..4].copy_from_slice(&(get(4) as u16).to_le_bytes());
    fx[4] = abridged;
    let sel = get(0x10);
    fx[6..8].copy_from_slice(&((sel >> 16) as u16 & 0x7FF).to_le_bytes());
    fx[8..12].copy_from_slice(&get(0xC).to_le_bytes());
    fx[12..14].copy_from_slice(&(sel as u16).to_le_bytes());
    fx[16..20].copy_from_slice(&get(0x14).to_le_bytes());
    fx[20..22].copy_from_slice(&(get(0x18) as u16).to_le_bytes());
    for i in 0..8 {
        fx[32 + 16 * i..32 + 16 * i + 10].copy_from_slice(&fs[0x1C + 10 * i..0x1C + 10 * i + 10]);
        fx[32 + 16 * i + 10..32 + 16 * i + 16].fill(0);
    }
}

/// An `EXCEPTION_RECORD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    /// `ExceptionCode`.
    pub code: u32,
    /// `ExceptionFlags`.
    pub flags: u32,
    /// `ExceptionRecord` (a nested record's address).
    pub nested: u64,
    /// `ExceptionAddress`.
    pub address: u64,
    /// `ExceptionInformation[0..NumberParameters]`.
    pub params: Vec<u64>,
}

impl ExceptionRecord {
    /// A record for `code` at `address` with `params`.
    pub fn new(code: u32, address: u64, params: Vec<u64>) -> Self {
        ExceptionRecord {
            code,
            flags: 0,
            nested: 0,
            address,
            params,
        }
    }

    /// `sizeof(EXCEPTION_RECORD)`.
    pub fn size(arch: WinArch) -> u64 {
        if arch.is64() { 0x98 } else { 0x50 }
    }

    /// Writes the record at `addr`.
    pub fn write(&self, mem: &impl Mem, arch: WinArch, addr: u64) -> Result<(), MemFault> {
        let p = arch.ptr_size();
        let mut b = vec![0u8; Self::size(arch) as usize];
        b[0..4].copy_from_slice(&self.code.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        let put = |b: &mut [u8], off: usize, v: u64| {
            if p == 4 {
                b[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
            } else {
                b[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
        };
        put(&mut b, 8, self.nested);
        let (addr_off, n_off, info_off) = if p == 4 {
            (0xC, 0x10, 0x14)
        } else {
            (0x10, 0x18, 0x20)
        };
        put(&mut b, addr_off, self.address);
        let n = self.params.len().min(EXCEPTION_MAXIMUM_PARAMETERS);
        b[n_off..n_off + 4].copy_from_slice(&(n as u32).to_le_bytes());
        for (i, &v) in self.params.iter().take(n).enumerate() {
            put(&mut b, info_off + p as usize * i, v);
        }
        mem.wr(addr, &b)
    }

    /// Reads the record at `addr`. `NumberParameters` above the maximum is
    /// clamped.
    pub fn read(mem: &impl Mem, arch: WinArch, addr: u64) -> Result<Self, MemFault> {
        let p = arch.ptr_size();
        let b = mem.bytes(addr, Self::size(arch) as usize)?;
        let get = |off: usize| -> u64 {
            if p == 4 {
                u64::from(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()))
            } else {
                u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
            }
        };
        let (addr_off, n_off, info_off) = if p == 4 {
            (0xC, 0x10, 0x14)
        } else {
            (0x10, 0x18, 0x20)
        };
        let n = (u32::from_le_bytes(b[n_off..n_off + 4].try_into().unwrap()) as usize)
            .min(EXCEPTION_MAXIMUM_PARAMETERS);
        Ok(ExceptionRecord {
            code: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            nested: get(8),
            address: get(addr_off),
            params: (0..n).map(|i| get(info_off + p as usize * i)).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};
    use crate::user::windows::arch::{CpuStop, WOW64_FS_SELECTOR};

    const CODE: u64 = 0x10000;
    const TEB: u64 = 0x20000;
    fn cpu(arch: WinArch) -> WinCpu {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: if arch == WinArch::Arm64 {
                Vec::new()
            } else {
                crate::user::cpu::x86_64::RESERVED_PHYS.to_vec()
            },
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
            .write_raw(
                CODE,
                if arch == WinArch::Arm64 {
                    &[0x1f, 0x20, 0x03, 0xd5]
                } else {
                    &[0x90]
                },
            )
            .unwrap();
        let mut cpu = WinCpu::new(arch, &space);
        cpu.set_pc(CODE);
        cpu.set_sp(0x40000);
        cpu.set_teb(TEB);
        cpu
    }

    #[test]
    fn context_capture_apply_round_trip_all_architectures() {
        for arch in WinArch::ALL {
            let mut cpu = cpu(arch);
            cpu.set_gpr(0, 0x1234);
            let ctx = RegContext::capture(&cpu);
            assert_eq!(ctx.validate(&cpu), Ok(()));
            cpu.set_gpr(0, 0xabcd);
            cpu.set_pc(CODE + 4);
            ctx.apply(&mut cpu).unwrap();
            assert_eq!(RegContext::capture(&cpu), ctx);
            assert_eq!(cpu.teb(), TEB);
        }
    }
    #[test]
    fn context_bad_architecture_flags_and_unsupported_groups_are_transactional() {
        for arch in WinArch::ALL {
            let mut cpu = cpu(arch);
            let before = RegContext::capture(&cpu);
            for flags in [
                INTEGER,
                RegContext::arch_flag(arch) | 0x40,
                RegContext::arch_flag(arch) | 0x8000,
            ] {
                let mut ctx = before.clone();
                ctx.set_gpr(0, 0xdead);
                ctx.set_flags(flags);
                assert_eq!(ctx.validate(&cpu), Err(STATUS_INVALID_PARAMETER));
                assert_eq!(ctx.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
                assert_eq!(RegContext::capture(&cpu), before);
            }
            let wrong = RegContext::new(if arch == WinArch::X64 {
                WinArch::Arm64
            } else {
                WinArch::X64
            });
            assert_eq!(wrong.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(RegContext::capture(&cpu), before);
        }
    }
    #[test]
    fn context_bad_mxcsr_cannot_partially_restore_integer_control_or_segments() {
        for arch in [WinArch::X86, WinArch::X64] {
            let mut cpu = cpu(arch);
            let before = RegContext::capture(&cpu);
            let mut ctx = before.clone();
            ctx.set_gpr(0, 0xdead);
            ctx.set_pc(CODE + 4);
            if arch == WinArch::X86 {
                ctx.put32(x86::EXTENDED + 24, 0x1_0000);
            } else {
                ctx.put32(x64::MXCSR, 0x1_0000);
            }
            assert_eq!(ctx.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(RegContext::capture(&cpu), before);
            assert_eq!(cpu.teb(), TEB);
        }
    }
    #[test]
    fn context_bad_selector_and_execution_mode_changes_are_transactional() {
        let mut cpu = cpu(WinArch::X86);
        let before = RegContext::capture(&cpu);
        for (off, selector) in [
            (x86::SEG_FS, 0xffff),
            (x86::SEG_SS, 0x23),
            (x86::SEG_CS, 0x33),
            (x86::SEG_DS, 0x1_002b),
        ] {
            let mut ctx = before.clone();
            ctx.set_gpr(0, 0xdead);
            ctx.put32(off, selector);
            assert_eq!(ctx.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(RegContext::capture(&cpu), before);
            assert_eq!(cpu.teb(), TEB);
        }
    }
    #[test]
    fn context_apply_preserves_instruction_counter_teb_and_unselected_float_state() {
        for arch in [WinArch::X86, WinArch::X64] {
            let mut cpu = cpu(arch);
            assert!(matches!(cpu.run(1), CpuStop::Yield));
            let count = cpu.x86().unwrap().vcpu().instruction_count();
            assert_eq!(count, 1);
            let before = RegContext::capture(&cpu);
            let mut ctx = before.clone();
            ctx.set_flags(RegContext::arch_flag(arch) | INTEGER | CONTEXT_UNWOUND_TO_CALL);
            ctx.set_gpr(0, 0x1234);
            ctx.apply(&mut cpu).unwrap();
            assert_eq!(cpu.gpr(0), 0x1234);
            assert_eq!(cpu.pc(), before.pc());
            assert_eq!(cpu.sp(), before.sp());
            assert_eq!(cpu.teb(), TEB);
            assert_eq!(cpu.x86().unwrap().vcpu().instruction_count(), count);
            let after = RegContext::capture(&cpu);
            let fx = if arch == WinArch::X86 {
                x86::EXTENDED
            } else {
                x64::FLT_SAVE
            };
            assert_eq!(&after.bytes()[fx..fx + 512], &before.bytes()[fx..fx + 512]);
            if arch == WinArch::X86 {
                assert_eq!(
                    cpu.x86().unwrap().vcpu().user_selector(X86UserSegment::Fs),
                    WOW64_FS_SELECTOR
                );
            }
        }
    }
    #[test]
    fn context_arm64_x18_is_an_independently_selected_group() {
        let mut cpu = cpu(WinArch::Arm64);
        assert!(matches!(cpu.run(1), CpuStop::Yield));
        let count = cpu.a64().unwrap().core().instruction_count();
        assert_eq!(count, 1);
        let mut ctx = RegContext::capture(&cpu);
        ctx.set_flags(CONTEXT_ARM64 | INTEGER);
        ctx.set_gpr(0, 0x1234);
        ctx.set_gpr(18, 0x30000);
        ctx.apply(&mut cpu).unwrap();
        assert_eq!(cpu.gpr(0), 0x1234);
        assert_eq!(cpu.teb(), TEB);
        ctx.set_flags(CONTEXT_ARM64 | ARM64_X18);
        ctx.set_gpr(0, 0xabcd);
        ctx.apply(&mut cpu).unwrap();
        assert_eq!(cpu.gpr(0), 0x1234);
        assert_eq!(cpu.teb(), 0x30000);
        assert_eq!(cpu.a64().unwrap().core().instruction_count(), count);
    }
    #[test]
    fn context_x64_mxcsr_field_is_authoritative_and_status_bits_are_sanitized() {
        let mut cpu = cpu(WinArch::X64);
        let mut ctx = RegContext::capture(&cpu);
        ctx.put32(x64::MXCSR, 0x1f80);
        ctx.put32(x64::FLT_SAVE + 24, 0xffff_ffff);
        ctx.put32(x64::EFLAGS, 0xffff_ffff);
        ctx.apply(&mut cpu).unwrap();
        let after = RegContext::capture(&cpu);
        assert_eq!(after.get32(x64::MXCSR), 0x1f80);
        assert_eq!(after.flags_register(), EFLAGS_USER | 0x202);
        ctx = after.clone();
        ctx.put16(x64::SEG_GS, 0xffff);
        assert_eq!(ctx.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(RegContext::capture(&cpu), after);
    }
    #[test]
    fn context_apply_preserves_unselected_ss_gdt_and_extended_vector_state() {
        let mut cpu = cpu(WinArch::X86);
        let v = cpu.x86_mut().unwrap().vcpu_mut();
        const GDT_INDEX: usize = 11;
        const SELECTOR: u16 = (GDT_INDEX as u16) * 8 + 3;
        const DATA_DPL3_32: u16 = 0x0010 | 0x0080 | 0x0001 | 0x0002 | (3 << 5) | 0x4000;
        let descriptor = crate::isa::x86_64::gdt_entry(DATA_DPL3_32, 0x30000, 0xffff);
        assert!(v.set_user_gdt_entry(GDT_INDEX, descriptor));
        v.load_user_segment(X86UserSegment::Ss, SELECTOR).unwrap();
        v.user_regs_mut().ymm_high[0] = [0x1234, 0x5678];
        v.user_regs_mut().zmm_ext[15] = [0x9876; 8];
        let mut ctx = RegContext::capture(&cpu);
        ctx.set_flags(CONTEXT_I386 | INTEGER);
        ctx.set_gpr(0, 0xdead);
        ctx.apply(&mut cpu).unwrap();
        let v = cpu.x86().unwrap().vcpu();
        assert_eq!(v.user_selector(X86UserSegment::Ss), SELECTOR);
        assert_eq!(v.user_gdt_entry(GDT_INDEX), Some(descriptor));
        assert_eq!(v.user_regs().ymm_high[0], [0x1234, 0x5678]);
        assert_eq!(v.user_regs().zmm_ext[15], [0x9876; 8]);
        assert_eq!(cpu.teb(), TEB);
    }
}
